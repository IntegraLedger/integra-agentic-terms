"""The buyer half of MPP's session intent under the stock solana method of @solana/mpp 0.7.0, as two pairings.

mpp/session/solana/memo, under the challenge whose modes is exactly ["pull"] and whose pullVoucherStrategy is
clientVoucher: build composes the stock open of a payment channel, its fee payer and rent payer the challenge's
operator, and adds one Memo instruction whose data is H's LCP string; the payer signs the message, and the seller's
server co-signs it as the operator and submits it. bound refuses, before anything is submitted, an open action that
carries no transaction and an open without the memo (svm/no-carrier), an open whose fee payer or rent payer is not the
operator or whose payer is (svm/open-not-operator), and a memo spelled otherwise, more than one, or one naming another H
than the challenge's id. The channel members read the opening's channel for the buyer's channel steps; no voucher is
built here.

mpp/session/solana/stock, at coverage none: the buyer's stock client composes, signs and broadcasts the open itself,
with a random salt, so nothing the payer signs carries H, nothing is built, and bound answers mpp/no-signed-place for an
opening. Nothing here fetches or signs."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._channel import ChannelKind, ChannelRef
from ._lcp import is_object, to_lcp_string
from ._mpp import Echoed, EchoedChallenge, chosen_for, credential_of, echoed_for, measured, measuring, read, session_broadcaster
from ._mpp_checks import decode_object, solana_network_of
from ._svm import (
    ATA_PROGRAM,
    MEMO_V3,
    PAYMENT_CHANNELS,
    READONLY,
    RENT_SYSVAR,
    SYSTEM,
    TOKEN,
    WRITABLE,
    WRITABLE_SIGNER,
    Instruction,
    SvmInstruction,
    SvmTx,
    ata,
    compile_v0,
    decode_svm_tx,
    find_pda,
    key_bytes,
    key_string,
    signed_wire,
    to_base64,
    u32le,
    u64le,
    wire_of,
)
from .mpp_charge_solana import mpp_svm_carrier

MEMO_ID = "mpp/session/solana/memo"
STOCK_ID = "mpp/session/solana/stock"

# The largest packet a Solana transaction travels in, its signatures included.
SOLANA_PACKET_BYTES = 1232
# The signature the stock client writes while the server has yet to submit the opening (src/client/PaymentChannels.ts:47).
_PENDING_SERVER_SIGNATURE = "1" * 64
# The grace period the stock client opens with when the caller gives none (src/client/PaymentChannels.ts:45).
_DEFAULT_GRACE_PERIOD = 900
_U64_LIMIT = 1 << 64
_OPEN_DISCRIMINATOR = 1
_OPEN_MIN_DATA = 33
_OPEN_MIN_ACCOUNTS = 6
_OPEN_CHANNEL_ACCOUNT = 5


def _kind(presented: object) -> ChannelKind | Refusal:
    """The kind of a session credential by its action: open; voucher and commit within the channel; close. Any other
    action is mpp/session-action."""
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    action = c["payload"].get("action")
    if action == "open":
        return "open"
    if action in ("voucher", "commit"):
        return "within"
    if action == "close":
        return "close"
    return Refusal("mpp/session-action")


def _network_of(request: Mapping[str, Any]) -> str | Refusal:
    """The CAIP-2 network the request's own network names (absent: mainnet); localnet is svm/network-undeclared."""
    n = solana_network_of(request, False)
    return Refusal("svm/network-undeclared") if n is None else n


def _program_of(request: Mapping[str, Any]) -> str:
    program = request.get("programId")
    return program if isinstance(program, str) else PAYMENT_CHANNELS


def _opening_of(credential: Mapping[str, Any], pairing: str) -> Echoed | Refusal:
    """The echoed challenge of an open action for pairing, else its refusal; any other action is mpp/not-an-opening."""
    e = echoed_for(credential, pairing)
    if isinstance(e, Refusal):
        return e
    return e if e.payload.get("action") == "open" else Refusal("mpp/not-an-opening")


def open_instruction(tx: SvmTx, program: str) -> SvmInstruction | Refusal:
    """The one top-level instruction of program whose data starts with the open discriminator, with at least 33 bytes
    of data and 6 accounts, whose channel (account 5) is one of the message's keys. Else svm/open-not-found."""
    program_key = key_bytes(program)
    if program_key is None:
        return Refusal("svm/open-not-found")
    opens = [
        ix
        for ix in tx.instructions
        if ix.program < len(tx.keys)
        and tx.keys[ix.program] == program_key
        and ix.data[:1] == bytes([_OPEN_DISCRIMINATOR])
        and len(ix.data) >= _OPEN_MIN_DATA
        and len(ix.accounts) >= _OPEN_MIN_ACCOUNTS
    ]
    if len(opens) != 1 or opens[0].accounts[_OPEN_CHANNEL_ACCOUNT] >= len(tx.keys):
        return Refusal("svm/open-not-found")
    return opens[0]


@dataclass(frozen=True, slots=True)
class MemoOpening:
    h: AtrHash
    checked: EchoedChallenge
    tx: SvmTx


def _memo_opening(credential: Mapping[str, Any]) -> MemoOpening | Refusal:
    """The opening's checks, in order: an open action of the echoed challenge; its transaction, without which no
    payer-signed opening carries H (svm/no-carrier); the transaction decodes and holds one open of the request's
    payment-channels program (svm/open-not-found); its fee payer and rent payer are the challenge's operator, and its
    payer is not (svm/open-not-operator); and its one LCP memo names the challenge's H (mpp/carrier-not-challenge)."""
    e = _opening_of(credential, MEMO_ID)
    if isinstance(e, Refusal):
        return e
    if "transaction" not in e.payload:
        return Refusal("svm/no-carrier")
    wire = wire_of(e.payload["transaction"])
    if isinstance(wire, Refusal):
        return wire
    tx = decode_svm_tx(wire)
    if isinstance(tx, Refusal):
        return tx
    opened = open_instruction(tx, _program_of(e.checked.request))
    if isinstance(opened, Refusal):
        return opened
    operator = key_bytes(e.checked.request.get("operator"))

    def same(i: int | None) -> bool:
        return i is not None and i < len(tx.keys) and operator is not None and tx.keys[i] == operator

    if not same(0) or not same(opened.accounts[1]) or same(opened.accounts[0]):
        return Refusal("svm/open-not-operator")
    carrier = mpp_svm_carrier(tx)
    if isinstance(carrier, Refusal):
        return carrier
    if not hash_equals(carrier.h, e.h):
        return Refusal("mpp/carrier-not-challenge")
    return MemoOpening(e.h, e.checked, tx)


def _open_instruction_for(
    program: str,
    payer: str,
    operator: str,
    payee: str,
    mint: str,
    token_program: str,
    authorized_signer: str,
    salt: int,
    deposit: int,
    grace_period: int,
    open_slot: int,
    recipients: Sequence[Mapping[str, Any]],
) -> tuple[Instruction, str] | Refusal:
    """The open instruction @solana/mpp 0.7.0 composes (src/client/PaymentChannels.ts:104-173;
    src/generated/payment-channels/instructions/open.ts:209-273): its fourteen accounts in order, the payer and the rent
    payer writable signers; its data the discriminator 1, then salt u64, deposit u64, gracePeriod u32, openSlot u64 and
    the recipients as a u32 count of 34-byte entries, each an address and a u16 of basis points, all little-endian. The
    channel is the PDA of ["channel", payer, payee, mint, authorizedSigner, salt, openSlot] and the two token accounts
    are associated token accounts. A key that does not decode, or a PDA with no bump, is svm/input-malformed; the
    channel is returned beside the instruction."""
    names = [program, payer, operator, payee, mint, token_program, authorized_signer, *(r.get("recipient") for r in recipients)]
    k: dict[str, bytes] = {}
    for name in names:
        key = key_bytes(name)
        if key is None:
            return Refusal("svm/input-malformed")
        k[str(name)] = key
    if not 0 <= open_slot < _U64_LIMIT:
        return Refusal("svm/input-malformed")
    channel = find_pda([b"channel", k[payer], k[payee], k[mint], k[authorized_signer], u64le(salt), u64le(open_slot)], program)
    if isinstance(channel, Refusal):
        return Refusal("svm/input-malformed")
    payer_ata, channel_ata = ata(payer, token_program, mint), ata(channel.address, token_program, mint)
    event_authority = find_pda([b"event_authority"], program)
    if isinstance(payer_ata, Refusal) or isinstance(channel_ata, Refusal) or isinstance(event_authority, Refusal):
        return Refusal("svm/input-malformed")
    data = bytes([_OPEN_DISCRIMINATOR]) + u64le(salt) + u64le(deposit) + u32le(grace_period) + u64le(open_slot)
    data += u32le(len(recipients))
    for r in recipients:
        data += k[str(r["recipient"])] + int(r["bps"]).to_bytes(2, "little")
    accounts = (
        (payer, WRITABLE_SIGNER),
        (operator, WRITABLE_SIGNER),
        (payee, READONLY),
        (mint, READONLY),
        (authorized_signer, READONLY),
        (channel.address, WRITABLE),
        (payer_ata, WRITABLE),
        (channel_ata, WRITABLE),
        (token_program, READONLY),
        (SYSTEM, READONLY),
        (RENT_SYSVAR, READONLY),
        (ATA_PROGRAM, READONLY),
        (event_authority.address, READONLY),
        (program, READONLY),
    )
    return Instruction(program, accounts, data), channel.address


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _int_in(value: object, low: int, high: int) -> int | None:
    """value where it is an int from low to high, a boolean being none; else None."""
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else None


def _slot(slot: object) -> int | None:
    """The channel's openSlot, an integer or a decimal string, as an int; else None."""
    if _is_int(slot):
        assert isinstance(slot, int)
        return slot
    return int(slot) if isinstance(slot, str) and slot.isascii() and slot.isdigit() else None


@dataclass(frozen=True, slots=True)
class SolanaSessionUnsigned:
    """The message the payer signs, with its composed size and channel, and how the payer's 64-byte Ed25519 signature
    completes the open credential, the operator's signature slot left zero."""

    request: dict[str, Any]
    _complete: Callable[[object], dict[str, Any] | Refusal]

    def complete(self, signature: object) -> dict[str, Any] | Refusal:
        return self._complete(signature)


def _memo_ref(presented: object) -> ChannelRef | Refusal:
    """The channel a credential names: on open, the open's channel (account 5) once the opening reads as bound reads
    it; on a voucher or commit, its voucher's channelId; on a close, its channelId. Each on the request's network."""
    k = _kind(presented)
    if isinstance(k, Refusal):
        return k
    assert is_object(presented)
    if k == "open":
        o = _memo_opening(presented)
        if isinstance(o, Refusal):
            return o
        network = _network_of(o.checked.request)
        if isinstance(network, Refusal):
            return network
        opened = open_instruction(o.tx, _program_of(o.checked.request))
        if isinstance(opened, Refusal):
            return opened
        return ChannelRef(network, key_string(o.tx.keys[opened.accounts[_OPEN_CHANNEL_ACCOUNT]]))
    return _named_channel(presented)


def _named_channel(presented: Mapping[str, Any]) -> ChannelRef | Refusal:
    """The channel a later credential names, on its echoed challenge's network, read without the opening's checks."""
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    challenge = c["challenge"]
    if challenge.get("intent") != "session" or challenge.get("method") != "solana":
        return Refusal("mpp/not-this-pairing")
    request = decode_object(challenge.get("request"))
    if request is None:
        return Refusal("mpp/request-malformed")
    network = _network_of(request)
    if isinstance(network, Refusal):
        return network
    payload = c["payload"]
    voucher = payload.get("voucher")
    data = voucher.get("data") if is_object(voucher) else None
    channel = payload.get("channelId") if payload.get("action") == "close" else data.get("channelId") if is_object(data) else None
    return Refusal("mpp/credential-malformed") if key_bytes(channel) is None else ChannelRef(network, str(channel))


@dataclass(frozen=True, slots=True)
class MppSessionSolanaMemo:
    id: str = MEMO_ID
    coverage: Coverage = "full"
    agreement: AgreementData | None = None

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash, act: Act | None = None) -> SolanaSessionUnsigned | Refusal:
        """The opening for the payer to sign: the stock open with the challenge's operator as fee payer and rent payer,
        the request's recipient as payee and its splits as the distribution, then one Memo instruction carrying H's
        LCP string, as a v0 message. Its composed size, its two signatures included, is stated, and one past the
        1,232-byte packet is svm/tx-too-large, with no message to sign. A payer that is the operator is
        svm/open-not-operator. The choice names the payer, the authorizedSigner and the salt, a u64; the deposit is the
        request's cap, the grace period 900, the open slot and blockhash the request's, the mint the request's currency
        where it is a key, and the token program Token, where the choice gives none."""
        if not is_object(choice):
            return Refusal("svm/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, MEMO_ID)
        if isinstance(checked, Refusal):
            return checked
        r = checked.request
        operator = r["operator"]
        payer = choice.get("payer")
        if payer == operator:
            return Refusal("svm/open-not-operator")
        currency = r["currency"]
        mint = currency if key_bytes(currency) is not None else choice.get("mint")
        deposit = choice.get("deposit")
        deposit = int(r["cap"]) if deposit is None else deposit
        slot_given = choice.get("openSlot") if r.get("recentSlot") is None else r["recentSlot"]
        slot = _slot(slot_given)
        blockhash = r["recentBlockhash"] if isinstance(r.get("recentBlockhash"), str) else choice.get("recentBlockhash")
        grace_period = choice.get("gracePeriod")
        grace_period = _DEFAULT_GRACE_PERIOD if grace_period is None else grace_period
        salt = _int_in(choice.get("salt"), 0, _U64_LIMIT - 1)
        signer = choice.get("authorizedSigner")
        token_program = choice.get("tokenProgram")
        token_program = TOKEN if token_program is None else token_program
        if (
            not isinstance(mint, str)
            or not isinstance(blockhash, str)
            or slot is None
            or not isinstance(payer, str)
            or not isinstance(signer, str)
            or not isinstance(token_program, str)
            or salt is None
            or _int_in(deposit, 1, _U64_LIMIT - 1) is None
            or _int_in(grace_period, 0, 0xFFFFFFFF) is None
        ):
            return Refusal("svm/input-malformed")
        splits = r.get("splits")
        recipients: list[Mapping[str, Any]] = list(splits) if isinstance(splits, list) else []
        opened = _open_instruction_for(
            _program_of(r), payer, operator, r["recipient"], mint, token_program, signer, salt, deposit, grace_period, slot, recipients
        )
        if isinstance(opened, Refusal):
            return opened
        instruction, channel = opened
        memo = Instruction(MEMO_V3, (), to_lcp_string(h).encode("utf-8"))
        message = compile_v0(operator, blockhash, [instruction, memo])
        if isinstance(message, Refusal):
            return message
        size = 1 + 64 * 2 + len(message)
        if size > SOLANA_PACKET_BYTES:
            return Refusal("svm/tx-too-large")
        challenge = dict(checked.challenge)
        payload = {
            "action": "open",
            "authorizedSigner": signer,
            "channelId": channel,
            "deposit": str(deposit),
            "gracePeriod": grace_period,
            "mint": mint,
            "mode": "pull",
            "payee": r["recipient"],
            "payer": payer,
            "recentSlot": str(slot_given),
            "salt": str(salt),
            "signature": _PENDING_SERVER_SIGNATURE,
        }

        def complete(signature: object) -> dict[str, Any] | Refusal:
            """The open credential for the payer's 64-byte Ed25519 signature over the message."""
            wire = signed_wire(message, payer, signature)
            if isinstance(wire, Refusal):
                return wire
            return measured({"challenge": challenge, "payload": {**payload, "transaction": to_base64(wire)}})

        return SolanaSessionUnsigned({"kind": "solana-session-open", "message": message, "size": size, "channel": channel}, complete)

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H from the echoed challenge, once the opening passes its checks (_memo_opening). The act changes nothing:
        the opening carries H itself. No signature is verified here."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        o = _memo_opening(credential)
        return o if isinstance(o, Refusal) else o.h

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payee broadcasts every payment the session takes, for the actions channel_kind takes: the opening, which
        the seller's server co-signs as the operator and submits, a voucher, a commit and the close. A top-up, which the
        payer's client broadcasts, and any other action get mpp/not-an-opening, as bound refuses them."""
        return session_broadcaster(presented, _kind, lambda c: "payee", "mpp/not-an-opening")

    @measuring
    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """open; voucher and commit within the channel; close."""
        return _kind(presented)

    @measuring
    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The network and the channel a credential names (_memo_ref)."""
        return _memo_ref(presented)

    @measuring
    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """No later credential of the session signs a value holding H: mpp/not-bound-within."""
        return Refusal("mpp/not-bound-within")


def _stock_kind(presented: object) -> ChannelKind | Refusal:
    """A stock opening's kind: the opening alone is this pairing's; every later credential is mpp/session-action."""
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    return "open" if c["payload"].get("action") == "open" else Refusal("mpp/session-action")


@dataclass(frozen=True, slots=True)
class MppSessionSolanaStock:
    id: str = STOCK_ID
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "same-network"

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash, act: Act | None = None) -> Refusal:
        """The protocol package builds nothing for this pairing: the buyer's stock client composes the open."""
        return Refusal("mpp/nothing-to-sign")

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """Nothing the payer signs carries H: an opening of the echoed challenge is mpp/no-signed-place; any other
        action is mpp/not-an-opening. The act changes nothing."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        e = _opening_of(credential, STOCK_ID)
        return e if isinstance(e, Refusal) else Refusal("mpp/no-signed-place")

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payer broadcasts the opening; every later credential is mpp/not-an-opening."""
        return session_broadcaster(presented, _stock_kind, lambda c: "payer", "mpp/not-an-opening")
