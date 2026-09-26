"""The buyer half of x402/exact/tvm: read, build with complete, and bound. The ATR hash rides in the option's
extra.forwardPayload as a TEP-74 text comment holding its LCP string; the payer's W5 wallet signs a request whose one
Jetton transfer carries that payload. Nothing here fetches or signs."""

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._ton_cell import Builder, Cell, Malformed, parse_boc, serialize_boc
from ._ton_tlb import (
    Address,
    StateInit,
    load_address,
    load_maybe_address,
    load_message_relaxed,
    load_state_init,
    raw_address,
    store_address,
    store_internal_message,
)
from ._x402 import chosen, payment_with, presented_with, read_for

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
SEND_MODE = 3

_NETWORK = re.compile(r"tvm:(-?(?:0|[1-9][0-9]{0,15}))")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_DECIMAL = re.compile(r"[0-9]{1,78}")
_MAX_SAFE_INTEGER = 2**53 - 1
_BOM = b"\xef\xbb\xbf"


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


def root_of(boc: object) -> Cell | Refusal:
    """The one root of a base64 bag of cells of at most 8 KiB, at most 512 cells and depth 32, or the refusal."""
    if not isinstance(boc, str) or len(boc) == 0 or _BASE64.fullmatch(boc) is None:
        return Refusal("tvm/boc-malformed")
    pad = 2 if boc.endswith("==") else 1 if boc.endswith("=") else 0
    if len(boc) // 4 * 3 - pad > MAX_BOC_BYTES:
        return Refusal("tvm/boc-too-large")
    try:
        roots = parse_boc(base64.b64decode(boc))
    except Malformed:
        return Refusal("tvm/boc-malformed")
    if len(roots) != 1:
        return Refusal("tvm/boc-malformed")
    root = roots[0]
    if root.depth > MAX_DEPTH or _cell_count(root) > MAX_CELLS:
        return Refusal("tvm/boc-too-large")
    return root


def _comment_hash(c: Cell) -> AtrHash | None:
    """The hash in a text comment cell holding an LCP string and no references, or None."""
    if c.refs or c.length < 32 or (c.length - 32) % 8 != 0:
        return None
    s = c.slice()
    if s.uint(32) != 0:
        return None
    data = s.buf((c.length - 32) // 8)
    try:
        text = (data[len(_BOM) :] if data.startswith(_BOM) else data).decode("utf-8")
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


def _send_message(actions: Cell) -> Cell | Refusal:
    """The outgoing message of an action list holding exactly one action_send_msg behind an empty prev."""
    if actions.length != 40 or len(actions.refs) != 2:
        return Refusal("tvm/actions")
    prev = actions.refs[0]
    if prev.length != 0 or prev.refs:
        return Refusal("tvm/actions")
    if actions.slice().uint(32) != OP_SEND_MSG:
        return Refusal("tvm/actions")
    return actions.refs[1]


def tvm_carrier(settlement_boc: object) -> tuple[AtrHash, Cell] | Refusal:
    """The hash and the forward payload of the signed request in a settlement bag of cells: an internal message whose
    body is a W5 internal_signed request with exactly one action_send_msg behind an empty list, carrying a Jetton
    transfer whose forward payload is a reference to a text comment holding an LCP string."""
    root = root_of(settlement_boc)
    if isinstance(root, Refusal):
        return root
    try:
        message = load_message_relaxed(root.slice())
    except Malformed:
        return Refusal("tvm/boc-malformed")
    if not message.internal:
        return Refusal("tvm/boc-malformed")
    try:
        s = message.body.slice()
        if s.remaining_bits < 32 or s.uint(32) != OP_INTERNAL_SIGNED:
            return Refusal("tvm/not-w5-signed")
        s.uint(32)
        s.uint(32)
        s.uint(32)
        actions = s.maybe_ref()
        if actions is None or s.bit():
            return Refusal("tvm/actions")
        if s.remaining_bits != SIGNATURE_BITS or s.remaining_refs != 0:
            return Refusal("tvm/not-w5-signed")
    except Malformed:
        return Refusal("tvm/not-w5-signed")
    send = _send_message(actions)
    if isinstance(send, Refusal):
        return send
    try:
        out = load_message_relaxed(send.slice())
    except Malformed:
        return Refusal("tvm/not-jetton-transfer")
    if not out.internal:
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


def check(o: Mapping[str, Any]) -> bool | Refusal | None:
    """True for an exact option on a tvm: network, with sponsored fees, that this pairing pays."""
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
    m = _NETWORK.fullmatch(network)
    if m is None or abs(int(m.group(1))) > _MAX_SAFE_INTEGER:
        return Refusal("tvm/network-malformed")
    if raw_address(o.get("asset")) is None or raw_address(o.get("payTo")) is None:
        return Refusal("tvm/option-malformed")
    if not is_object(extra) or extra.get("areFeesSponsored") is not True:
        return Refusal("tvm/option-malformed")
    if "forwardTonAmount" in extra and _decimal_below(extra["forwardTonAmount"], COINS_LIMIT) is None:
        return Refusal("tvm/option-malformed")
    if "responseDestination" in extra and raw_address(extra["responseDestination"]) is None:
        return Refusal("tvm/option-malformed")
    if _decimal_below(o.get("amount"), COINS_LIMIT) is None:
        return Refusal("tvm/option-malformed")
    timeout = safe_int(o.get("maxTimeoutSeconds"))
    if timeout is None or timeout < 1:
        return Refusal("tvm/option-malformed")
    return True


def _carries(option: Mapping[str, Any], payload: Cell) -> bool:
    """True when the option's extra.forwardPayload is one cell whose hash is the payload's."""
    extra = option.get("extra")
    cell = root_of(extra.get("forwardPayload") if is_object(extra) else None)
    return not isinstance(cell, Refusal) and cell.equals(payload)


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
    _init: StateInit | None
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signature: object) -> dict[str, Any] | Refusal:
        """Takes the 64-byte Ed25519 signature; the payment's settlementBoc is the internal message to the wallet."""
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
        which must be the option's extra.forwardPayload."""
        if not is_object(c):
            return Refusal("x402/option-malformed")
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, check)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        comment = lcp_comment(nh)
        if isinstance(comment, Refusal):
            return comment
        if not _carries(accepted, comment):
            return Refusal("tvm/carrier-mismatch")
        wallet = raw_address(c.get("wallet"))
        jetton_wallet = raw_address(c.get("jettonWallet"))
        if wallet is None or jetton_wallet is None:
            return Refusal("x402/option-malformed")
        wallet_id, seqno, now = _uint32(c.get("walletId")), _uint32(c.get("seqno")), safe_int(c.get("now"))
        if wallet_id is None or seqno is None or now is None or now < 0:
            return Refusal("x402/option-malformed")
        timeout = safe_int(accepted.get("maxTimeoutSeconds"))
        assert timeout is not None
        valid_until = _uint32(now + timeout)
        if valid_until is None:
            return Refusal("x402/option-malformed")
        init_cell: Cell | None = None
        if "stateInit" in c:
            given = root_of(c.get("stateInit"))
            if isinstance(given, Refusal):
                return given
            init_cell = given
        extra = accepted["extra"]
        forward_ton = int(extra["forwardTonAmount"]) if "forwardTonAmount" in extra else 0
        attach = c.get("attachNanotons")
        if not isinstance(attach, int) or isinstance(attach, bool) or attach >= COINS_LIMIT:
            return Refusal("x402/option-malformed")
        if attach <= forward_ton:
            return Refusal("tvm/value-too-low")
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
        init: StateInit | None = None
        if init_cell is not None:
            try:
                init = load_state_init(init_cell.slice())
            except Malformed:
                return Refusal("x402/option-malformed")
        return TvmUnsigned(
            request={"kind": "ton-w5", "hash": request.hash},
            _request_cell=request,
            _wallet=wallet,
            _init=init,
            _required=required,
            _accepted=accepted,
        )

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the forward payload of the transfer the payer's W5 wallet signed, which must be the option's.
        The signature is not verified here."""
        p = presented_with(presented, check)
        if isinstance(p, Refusal):
            return p
        boc = p[1].get("settlementBoc")
        if not isinstance(boc, str):
            return Refusal("x402/payload-malformed")
        carried = tvm_carrier(boc)
        if isinstance(carried, Refusal):
            return carried
        if not _carries(p[0], carried[1]):
            return Refusal("tvm/carrier-mismatch")
        return carried[0]
