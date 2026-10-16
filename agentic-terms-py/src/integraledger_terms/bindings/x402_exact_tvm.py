"""The buyer half of x402/exact/tvm: read, build with complete, and bound. The ATR hash rides in the option's
extra.forwardPayload as a TEP-74 text comment holding its LCP string; the payer's W5 wallet signs a request whose one
Jetton transfer carries that payload. Nothing here fetches or signs."""

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._codec import b64_decode
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._ton_cell import Bag, Builder, Cell, Malformed, cells_of, layout_of, merkle_depth, serialize_boc
from ._ton_tlb import (
    MAINNET,
    MAX_MERKLE_DEPTH,
    TESTNET,
    Address,
    TonConfiguration,
    deploys_from,
    is_state_init,
    load_address,
    load_maybe_address,
    message_of,
    raw_address,
    store_address,
    store_internal_message,
)
from ._x402 import chosen, is_amount, payment_with, presented_with, read_for, timeout_seconds, x402_broadcaster

ID = "x402/exact/tvm"
OP_JETTON_TRANSFER = 0x0F8A7EA5
OP_INTERNAL_SIGNED = 0x73696E74
OP_SEND_MSG = 0x0EC3C86D
MAX_BOC_BYTES = 8192
MAX_CELLS = 512
MAX_DEPTH = 32
COINS_LIMIT = 1 << 120
UINT32_LIMIT = 1 << 32
SIGNATURE_BITS = 512
# The fewest bits of a request W5 reads as signed: the op, wallet id, valid_until and seqno, then the signature
# (wallet_v5.fc, recv_internal). W5 takes a shorter body as a plain transfer and runs no request.
_REQUEST_MIN_BITS = 32 + 32 + 32 + 32 + SIGNATURE_BITS
SEND_MODE = 3
# The send modes TON's action phase sends a message with (try_action_send_msg): +16 is bounce-on-fail and is set aside
# from global version 4, and the rest must be +1, +2, +32, +64 and +128 alone, never +64 with +128. Any other mode is
# refused, or skipped under +2 from global version 13: the message is not sent either way.
_SEND_MODES = 0xE3

# The two networks the pairing serves, as x402's TON scheme names them, each with the configuration its messages are
# read at: tvm:-239 (mainnet) and tvm:-3 (testnet).
_CONFIGURATIONS: Mapping[str, TonConfiguration] = {"tvm:-239": MAINNET, "tvm:-3": TESTNET}
_DECIMAL = re.compile(r"[0-9]{1,78}")


def lcp_comment(h: AtrHash) -> Cell | Refusal:
    """TEP-74's text comment: 32 zero bits, then the UTF-8 of the hash's LCP string. A value that is not a 32-byte
    hash is x402/payload-malformed."""
    nh = normal_hash(h)
    if nh is None:
        return Refusal("x402/payload-malformed")
    return Builder().uint(0, 32).buf(to_lcp_string(nh).encode("utf-8")).end()


def boc_of(c: Cell) -> str:
    """One root cell as a bag of cells with a CRC-32C and no index, in base64."""
    return base64.b64encode(serialize_boc(c)).decode("ascii")


def _cell_count(root: Cell) -> int:
    seen: set[bytes] = set()
    stack = [root]
    while stack and len(seen) <= MAX_CELLS:
        c = stack.pop()
        if c.hash in seen:
            continue
        seen.add(c.hash)
        stack.extend(c.refs)
    return len(seen)


def bag_of(boc: object) -> Bag | Refusal:
    """A bag of cells' bytes, written in padded standard base64: a text that is not that base64 in its canonical form
    (RFC 4648 §3.5) is tvm/boc-malformed before its size is read; more than 8 KiB is tvm/boc-too-large; and bytes whose
    layout or CRC-32C TON refuses (layout_of) are tvm/boc-malformed."""
    data = None if boc == "" else b64_decode(boc)
    if data is None:
        return Refusal("tvm/boc-malformed")
    if len(data) > MAX_BOC_BYTES:
        return Refusal("tvm/boc-too-large")
    try:
        return layout_of(data)
    except Malformed:
        return Refusal("tvm/boc-malformed")


def root_in(bag: Bag) -> Cell | Refusal:
    """The bag's one root, its cells read as TON deserializes them (cells_of), at most 512 cells and depth 32: cells TON
    refuses are tvm/boc-malformed. An exotic cell TON accepts is refused only where a read parses it."""
    try:
        root = cells_of(bag)
    except Malformed:
        return Refusal("tvm/boc-malformed")
    if root.depth > MAX_DEPTH or _cell_count(root) > MAX_CELLS:
        return Refusal("tvm/boc-too-large")
    return root


def root_of(boc: object) -> Cell | Refusal:
    """The one root of a bag of cells written in padded standard base64, or the refusal: its bytes as bag_of reads
    them, then its cells as root_in reads them."""
    bag = bag_of(boc)
    return bag if isinstance(bag, Refusal) else root_in(bag)


def _comment_hash(c: Cell) -> AtrHash | None:
    """The hash in an ordinary text comment cell holding an LCP string and no references, or None. The text is
    strict UTF-8 and a leading byte-order mark is a character, so a comment that begins with one holds no hash."""
    if c.exotic or c.refs or c.length < 32 or (c.length - 32) % 8 != 0:
        return None
    s = c.slice()
    if s.uint(32) != 0:
        return None
    data = s.buf((c.length - 32) // 8)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return from_lcp_string(text)


def _jetton_payload(body: Cell) -> Cell | None | Refusal:
    """The forward payload of a Jetton transfer body, which must be a reference; None when it is inline."""
    try:
        s = body.slice()
        if s.remaining_bits < 32 or s.uint(32) != OP_JETTON_TRANSFER:
            return Refusal("tvm/not-jetton-transfer")
        s.uint(64)
        s.coins()
        load_address(s)
        load_maybe_address(s)
        s.maybe_ref()
        s.coins()
        return s.ref() if s.bit() else None
    except Malformed:
        return Refusal("tvm/not-jetton-transfer")


def _send_message(actions: Cell) -> tuple[int, Cell] | Refusal:
    """The send mode and the outgoing message of an action list holding exactly one action_send_msg behind an empty
    prev (action_send_msg#0ec3c86d mode:(## 8) out_msg:^(MessageRelaxed Any)). An exotic action list is
    tvm/boc-malformed."""
    if actions.exotic:
        return Refusal("tvm/boc-malformed")
    if actions.length != 40 or len(actions.refs) != 2:
        return Refusal("tvm/actions")
    prev = actions.refs[0]
    if prev.length != 0 or prev.refs:
        return Refusal("tvm/actions")
    s = actions.slice()
    if s.uint(32) != OP_SEND_MSG:
        return Refusal("tvm/actions")
    return s.uint(8), actions.refs[1]


def _sends_with(mode: int, config: TonConfiguration) -> bool:
    """True when TON's action phase sends a message with this mode at the configuration (_SEND_MODES)."""
    m = mode & ~16 if config.global_version >= 4 else mode
    return m & ~_SEND_MODES == 0 and m & 0xC0 != 0xC0


def tvm_carrier(settlement_boc: object, network: object) -> tuple[AtrHash, Cell] | Refusal:
    """The hash and the forward payload of the signed request in a settlement bag of cells: an internal message whose
    body is a W5 internal_signed request with exactly one action_send_msg behind an empty list, carrying a Jetton
    transfer whose forward payload is a reference to a text comment holding an LCP string. The request is read as
    W5's internal_signed path reads it (ton-blockchain/wallet-contract-v5 contracts/wallet_v5.fc, recv_internal,
    process_signed_request and process_actions): at least 640 bits, its signature the body's last 512 bits, and the
    signed part the rest with all its references, in which the wallet id, valid_until, seqno, the action list's
    Maybe ^Cell and has_other_actions are read; W5 reads nothing after has_other_actions 0, and neither does this, so
    bits and references there are carried, not read. A body W5 does not run as a signed request, or whose signed part
    ends before those fields, is tvm/not-w5-signed, and an empty action list or has_other_actions 1 is tvm/actions.
    The signature is not verified. Each message is read as TON's action phase sends it (message_of), at the
    configuration held for the network: a source of addr_none or an addr_std with no anycast (the outgoing message's
    the W5 wallet's own), a destination TON sends to, a value and an extra_flags of at
    most 3 each in its shortest form, no extra currency, its state init validated as TON validates it, a referenced
    body that is an ordinary cell with nothing after it, and at most two nested Merkle proofs or updates; the W5
    action's send mode is one TON sends with (_sends_with). The settlement message TON would not send is
    tvm/boc-malformed, and the outgoing one, or a send mode TON refuses or skips, tvm/not-jetton-transfer. The
    settlement message's source names the account that relays it, which the bag cannot show: one naming another
    account is read, and TON sends it when that account relays it. The network is tvm:-239 (mainnet) or tvm:-3
    (testnet), and any other is tvm/network-malformed."""
    config = _CONFIGURATIONS.get(network) if isinstance(network, str) else None
    if config is None:
        return Refusal("tvm/network-malformed")
    root = root_of(settlement_boc)
    return root if isinstance(root, Refusal) else _carrier_in(root, config)


def _carrier_in(root: Cell, config: TonConfiguration) -> tuple[AtrHash, Cell] | Refusal:
    """tvm_carrier of the settlement message's root at the network's configuration."""
    message = message_of(root, None, config)
    if message is None:
        return Refusal("tvm/boc-malformed")
    body = message.body
    try:
        op = body.slice()
        if op.remaining_bits < 32 or op.uint(32) != OP_INTERNAL_SIGNED or body.length < _REQUEST_MIN_BITS:
            return Refusal("tvm/not-w5-signed")
        s = Cell(body.value >> SIGNATURE_BITS, body.length - SIGNATURE_BITS, body.refs).slice()
        s.uint(32)
        s.uint(32)
        s.uint(32)
        s.uint(32)
        actions = s.maybe_ref()
        has_other_actions = s.bit()
        if actions is None or has_other_actions:
            return Refusal("tvm/actions")
    except Malformed:
        return Refusal("tvm/not-w5-signed")
    send = _send_message(actions)
    if isinstance(send, Refusal):
        return send
    mode, sent = send
    if not _sends_with(mode, config):
        return Refusal("tvm/not-jetton-transfer")
    out = message_of(sent, message.dest, config)
    if out is None:
        return Refusal("tvm/not-jetton-transfer")
    payload = _jetton_payload(out.body)
    if isinstance(payload, Refusal):
        return payload
    if payload is None:
        return Refusal("tvm/payload-not-lcp")
    h = _comment_hash(payload)
    return (h, payload) if h is not None else Refusal("tvm/payload-not-lcp")


def _decimal_below(value: object, limit: int) -> int | None:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        return None
    n = int(value)
    return n if n < limit else None


def check(o: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """The pairing's option filter: the option's scheme, network, asset, payTo and extra, the amount as a positive
    Jetton amount (is_amount) below 2^120, a forward TON amount below 2^120 - 1 (build attaches more TON than it, and
    the attached value is a Grams, below 2^120), and maxTimeoutSeconds a positive integer below 2^32, which build writes
    into the request (the wallet message's valid_until, a uint32, is now plus maxTimeoutSeconds). The network is one of
    the two the pairing serves (_CONFIGURATIONS), whose configuration the messages are read at; any other tvm: network
    is tvm/network-malformed. read and build apply it, and bound holds the option a presented payment echoes to it."""
    if not is_object(o) or o.get("scheme") != "exact":
        return Refusal("x402/option-not-this-pairing")
    network = o.get("network")
    if not isinstance(network, str) or not network.startswith("tvm:"):
        return Refusal("x402/option-not-this-pairing")
    extra = o.get("extra")
    if "extra" in o and not is_object(extra):
        return Refusal("tvm/option-malformed")
    if is_object(extra) and "assetTransferMethod" in extra:
        return Refusal("x402/option-not-this-pairing")
    if is_object(extra) and "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return Refusal("x402/option-not-this-pairing")
    if network not in _CONFIGURATIONS:
        return Refusal("tvm/network-malformed")
    if raw_address(o.get("asset")) is None or raw_address(o.get("payTo")) is None:
        return Refusal("tvm/option-malformed")
    if not is_object(extra) or extra.get("areFeesSponsored") is not True:
        return Refusal("tvm/option-malformed")
    if "forwardTonAmount" in extra and _decimal_below(extra["forwardTonAmount"], COINS_LIMIT - 1) is None:
        return Refusal("tvm/option-malformed")
    if "responseDestination" in extra and raw_address(extra["responseDestination"]) is None:
        return Refusal("tvm/option-malformed")
    if not is_amount(o.get("amount")) or _decimal_below(o.get("amount"), COINS_LIMIT) is None:
        return Refusal("tvm/option-malformed")
    timeout = timeout_seconds(o.get("maxTimeoutSeconds"))
    if timeout is None or timeout >= UINT32_LIMIT:
        return Refusal("tvm/option-malformed")
    return True


def _uint32(value: object) -> int | None:
    """A safe integer in [0, 2^32), or None."""
    n = safe_int(value)
    return n if n is not None and 0 <= n < UINT32_LIMIT else None


@dataclass(frozen=True, slots=True)
class TvmUnsigned:
    """The 32-byte representation hash of the W5 request the wallet key signs, and how the signature completes the
    payment."""

    request: dict[str, Any]
    _request_cell: Cell
    _wallet: Address
    _init: Cell | None
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signature: object) -> dict[str, Any] | Refusal:
        """Takes the 64-byte Ed25519 signature; the payment's settlementBoc is the internal message to the wallet,
        carrying the given state init cell as its init."""
        if not isinstance(signature, bytes) or len(signature) != SIGNATURE_BITS // 8:
            return Refusal("x402/signature-malformed")
        signed = Builder().slice(self._request_cell.slice()).buf(signature).end()
        b = Builder()
        store_internal_message(b, bounce=False, dest=self._wallet, coins=0, body=signed, init=self._init)
        payload = {"settlementBoc": boc_of(b.end()), "asset": self._accepted["asset"]}
        return payment_with(self._required, self._accepted, payload)


@dataclass(frozen=True, slots=True)
class X402ExactTvm:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the options this pairing pays, in document order."""
        return read_for(check)(doc)

    def build(self, c: Json, h: AtrHash) -> TvmUnsigned | Refusal:
        """The W5 request for the chosen option: one Jetton transfer whose forward payload is the hash's comment,
        which must be the option's extra.forwardPayload. wallet and jettonWallet are on a workchain the option's
        network's configuration holds, -1 or 0. A stateInit must be exactly one StateInitWithLibs, as TON validates a
        message's state init, with at most two Merkle proofs or updates nested in it, and one TON deploys a wallet
        from at that configuration (deploys_from): no libraries dictionary, a fixed prefix length of at most
        ConfigParam 43's max_acc_fixed_prefix_length, 8, and a representation hash that is wallet's 256-bit address,
        except the first fixed-prefix-length bits, which may differ, since TON deploys an account only from a state
        init whose hash is its address. Else x402/option-malformed. The settlement message carries that cell as
        given. Every check of the input's own form comes first: H; the form of the choice's wallets, walletId, seqno,
        now and attachNanotons, each x402/option-malformed, and of a state init given as a bag of cells, its bytes
        (bag_of); then its document and option; the option's forward payload's bytes (bag_of, else
        tvm/carrier-mismatch); the wallets' workchains and now with the option's timeout, each x402/option-malformed;
        and the attached value against the option's forward amount (tvm/value-too-low). Then the forward payload's
        cells, which must be the hash's comment cell, and the state init's cells. A state init given as an object or
        a list holds no bag of cells: it is tvm/boc-malformed at that step. The state init's fields and hash against
        the wallet come last."""
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        if not is_object(c):
            return Refusal("x402/option-malformed")
        wallet = raw_address(c.get("wallet"))
        jetton_wallet = raw_address(c.get("jettonWallet"))
        if wallet is None or jetton_wallet is None:
            return Refusal("x402/option-malformed")
        wallet_id, seqno, now = _uint32(c.get("walletId")), _uint32(c.get("seqno")), safe_int(c.get("now"))
        if wallet_id is None or seqno is None or now is None or now < 0:
            return Refusal("x402/option-malformed")
        attach = c.get("attachNanotons")
        if not isinstance(attach, int) or isinstance(attach, bool) or attach >= COINS_LIMIT:
            return Refusal("x402/option-malformed")
        state_init = c.get("stateInit")
        init_bag: Bag | None = None
        if "stateInit" in c and not isinstance(state_init, (Mapping, list)):
            read_bag = bag_of(state_init)
            if isinstance(read_bag, Refusal):
                return read_bag
            init_bag = read_bag
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, check)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        extra = accepted["extra"]
        carried = bag_of(extra.get("forwardPayload"))
        if isinstance(carried, Refusal):
            return Refusal("tvm/carrier-mismatch")
        config = _CONFIGURATIONS[accepted["network"]]
        if wallet.workchain not in config.workchains or jetton_wallet.workchain not in config.workchains:
            return Refusal("x402/option-malformed")
        timeout = safe_int(accepted.get("maxTimeoutSeconds"))
        assert timeout is not None
        valid_until = _uint32(now + timeout)
        if valid_until is None:
            return Refusal("x402/option-malformed")
        forward_ton = int(extra["forwardTonAmount"]) if "forwardTonAmount" in extra else 0
        if attach <= forward_ton:
            return Refusal("tvm/value-too-low")
        comment = lcp_comment(nh)
        assert not isinstance(comment, Refusal)
        held = root_in(carried)
        if isinstance(held, Refusal) or not held.equals(comment):
            return Refusal("tvm/carrier-mismatch")
        init_cell: Cell | None = None
        if "stateInit" in c:
            given = Refusal("tvm/boc-malformed") if init_bag is None else root_in(init_bag)
            if isinstance(given, Refusal):
                return given
            init_cell = given
        response = raw_address(extra["responseDestination"]) if "responseDestination" in extra else None
        pay_to = raw_address(accepted["payTo"])
        assert pay_to is not None

        body = Builder().uint(OP_JETTON_TRANSFER, 32).uint(0, 64).coins(int(accepted["amount"]))
        store_address(body, pay_to)
        store_address(body, response)
        body.bit(0).coins(forward_ton).bit(1).ref(comment)
        out = Builder()
        store_internal_message(out, bounce=True, dest=jetton_wallet, coins=attach, body=body.end())
        actions = Builder().ref(Builder().end()).uint(OP_SEND_MSG, 32).uint(SEND_MODE, 8).ref(out.end()).end()
        request = (
            Builder()
            .uint(OP_INTERNAL_SIGNED, 32)
            .uint(wallet_id, 32)
            .uint(valid_until, 32)
            .uint(seqno, 32)
            .bit(1)
            .ref(actions)
            .bit(0)
            .end()
        )
        # The checks read the state init's form only: complete carries the cell itself.
        if init_cell is not None and (
            not is_state_init(init_cell)
            or merkle_depth([init_cell]) > MAX_MERKLE_DEPTH
            or not deploys_from(init_cell, config, wallet)
        ):
            return Refusal("x402/option-malformed")
        return TvmUnsigned(
            request={"kind": "ton-w5", "hash": request.hash},
            _request_cell=request,
            _wallet=wallet,
            _init=init_cell,
            _required=required,
            _accepted=accepted,
        )

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the forward payload of the transfer the payer's W5 wallet signed, which must be the option's,
        under an option the pairing's filter serves. The signature is not verified here. A state init that holds a
        libraries dictionary, has a fixed prefix longer than 8 bits, or does not hash to the settlement message's
        destination is read, since whether TON deploys the wallet from it is chain state. The payment and its option
        come first, then the settlement's bytes (bag_of), then the forward payload's bytes (else tvm/carrier-mismatch),
        then the settlement's cells and the forward payload's, which must be the payment's comment cell."""
        p = presented_with(presented, check)
        if isinstance(p, Refusal):
            return p
        accepted, payload, _ = p
        boc = payload.get("settlementBoc")
        if not isinstance(boc, str):
            return Refusal("x402/payload-malformed")
        settlement = bag_of(boc)
        if isinstance(settlement, Refusal):
            return settlement
        extra = accepted.get("extra")
        forward = bag_of(extra.get("forwardPayload") if is_object(extra) else None)
        if isinstance(forward, Refusal):
            return Refusal("tvm/carrier-mismatch")
        root = root_in(settlement)
        if isinstance(root, Refusal):
            return root
        carried = _carrier_in(root, _CONFIGURATIONS[accepted["network"]])
        if isinstance(carried, Refusal):
            return carried
        held = root_in(forward)
        if isinstance(held, Refusal) or not held.equals(carried[1]):
            return Refusal("tvm/carrier-mismatch")
        return carried[0]

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's facilitator sends the request the payer's W5 wallet signed. The payment is
        held to x402_shape's gate, the one bound applies first; any other gets its refusal."""
        return x402_broadcaster(presented, "payee")
