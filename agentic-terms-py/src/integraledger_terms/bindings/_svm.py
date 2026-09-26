"""Solana rail pieces for the buyer half: the legacy and v0 wire transaction, its one Memo instruction carrying the ATR
hash in LCP string form, the partially signed wire, program-derived and associated token addresses, and v0 message
compilation with the account order of @solana/kit 8.3.0.

Nothing here fetches, hashes an ATR or signs.
"""

import hashlib
import re
import struct
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Refusal
from ._codec import b58_decode, b58_encode, b64_decode, b64_encode
from ._lcp import from_lcp_string

MEMO_V3 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MEMO_V4 = "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH"
TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SYSTEM = "11111111111111111111111111111111"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
PAYMENT_CHANNELS = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"
RENT_SYSVAR = "SysvarRent111111111111111111111111111111111"

MAX_WIRE = 1232
MAX_SEEDS = 16
MAX_SEED = 32
U64_LIMIT = 1 << 64
U32_LIMIT = 1 << 32

_NETWORK = re.compile(r"solana:[1-9A-HJ-NP-Za-km-z]{32}")
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_PDA_MARKER = b"ProgramDerivedAddress"

# Account roles as @solana/kit numbers them: bit 1 signer, bit 0 writable.
READONLY = 0
WRITABLE = 1
READONLY_SIGNER = 2
WRITABLE_SIGNER = 3

Role = Literal[0, 1, 2, 3]


# ── keys and networks ───────────────────────────────────────────────────────────────────────────────────────────


def key_bytes(value: object) -> bytes | None:
    """The 32 bytes of a base58 public key of 32 to 44 characters, or None."""
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return None
    decoded = b58_decode(value)
    return decoded if decoded is not None and len(decoded) == 32 else None


def is_key(value: object) -> bool:
    return key_bytes(value) is not None


def key_string(data: bytes) -> str:
    return b58_encode(data)


def is_solana_network(value: object) -> bool:
    return isinstance(value, str) and _NETWORK.fullmatch(value) is not None


_MEMO_V3_BYTES = b58_decode(MEMO_V3)
_MEMO_V4_BYTES = b58_decode(MEMO_V4)
_PAYMENT_CHANNELS_BYTES = b58_decode(PAYMENT_CHANNELS)


# ── the wire ────────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SvmInstruction:
    program: int
    accounts: tuple[int, ...]
    data: bytes


@dataclass(frozen=True, slots=True)
class SvmTx:
    signatures: tuple[bytes, ...]
    # Exactly the bytes every signer signed.
    message: bytes
    # The static account keys, in order.
    keys: tuple[bytes, ...]
    instructions: tuple[SvmInstruction, ...]
    blockhash: bytes
    required_signatures: int


class _Cursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def byte(self) -> int:
        if self.at >= len(self.data):
            raise IndexError
        value = self.data[self.at]
        self.at += 1
        return value

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise IndexError
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def compact(self) -> int:
        """Solana's compact-u16, in its shortest form only."""
        value = 0
        for i in range(3):
            c = self.byte()
            value |= (c & 0x7F) << (7 * i)
            if c & 0x80 == 0:
                if i > 0 and c == 0:
                    raise ValueError
                if value > 0xFFFF:
                    raise ValueError
                return value
        raise ValueError


def decode_svm_tx(wire: object) -> SvmTx | Refusal:
    """A legacy or v0 wire transaction of at most 1,232 bytes, decoded."""
    if not isinstance(wire, (bytes, bytearray)) or len(wire) == 0:
        return Refusal("svm/tx-malformed")
    if len(wire) > MAX_WIRE:
        return Refusal("svm/tx-too-large")
    data = bytes(wire)
    try:
        c = _Cursor(data)
        count = c.compact()
        signatures = tuple(c.take(64) for _ in range(count))
        start = c.at
        first = c.byte()
        versioned = False
        if first & 0x80:
            if first & 0x7F:
                return Refusal("svm/tx-malformed")
            versioned = True
            required = c.byte()
        else:
            required = first
        readonly_signed = c.byte()
        readonly_unsigned = c.byte()
        n_keys = c.compact()
        keys = tuple(c.take(32) for _ in range(n_keys))
        if required == 0 or required > n_keys or count != required:
            return Refusal("svm/tx-malformed")
        if readonly_signed >= required or readonly_unsigned > n_keys - required:
            return Refusal("svm/tx-malformed")
        blockhash = c.take(32)
        n_ix = c.compact()
        instructions = []
        for _ in range(n_ix):
            program = c.byte()
            accounts = tuple(c.take(c.compact()))
            instructions.append(SvmInstruction(program, accounts, c.take(c.compact())))
        if versioned:
            for _ in range(c.compact()):
                c.take(32)
                c.take(c.compact())
                c.take(c.compact())
        if c.at != len(data):
            return Refusal("svm/tx-malformed")
    except (IndexError, ValueError):
        return Refusal("svm/tx-malformed")
    return SvmTx(signatures, data[start:], keys, tuple(instructions), blockhash, required)


def _program_is(tx: SvmTx, ix: SvmInstruction, program: bytes | None) -> bool:
    return ix.program < len(tx.keys) and tx.keys[ix.program] == program


@dataclass(frozen=True, slots=True)
class Carrier:
    h: AtrHash
    memo: str


def svm_carrier(tx: SvmTx) -> Carrier | Refusal:
    """The one top-level Memo instruction (v3 or v4) and the ATR hash its UTF-8 data carries in LCP string form. None,
    or more than one, is svm/memo-count."""
    memos = [ix for ix in tx.instructions if _program_is(tx, ix, _MEMO_V3_BYTES) or _program_is(tx, ix, _MEMO_V4_BYTES)]
    if len(memos) != 1:
        return Refusal("svm/memo-count")
    try:
        memo = memos[0].data.decode("utf-8")
    except UnicodeDecodeError:
        return Refusal("svm/memo-not-utf8")
    h = from_lcp_string(memo)
    if h is None:
        return Refusal("svm/memo-not-lcp")
    return Carrier(h, memo)


def wire_of(text: object) -> bytes | Refusal:
    """The base64 wire in a payment, decoded, or the refusal naming what is wrong with it."""
    if not isinstance(text, str) or text == "":
        return Refusal("svm/tx-malformed")
    if len(text) > -(-MAX_WIRE // 3) * 4 + 4:
        return Refusal("svm/tx-too-large")
    if _B64.fullmatch(text) is None or len(text) % 4 != 0:
        return Refusal("svm/tx-malformed")
    data = b64_decode(text)
    if data is None:
        return Refusal("svm/tx-malformed")
    if len(data) > MAX_WIRE:
        return Refusal("svm/tx-too-large")
    return data


def to_base64(data: bytes) -> str:
    return b64_encode(data)


def _compact(value: int) -> bytes:
    out = bytearray()
    while True:
        c = value & 0x7F
        value >>= 7
        if value == 0:
            out.append(c)
            return bytes(out)
        out.append(c | 0x80)


def signed_wire(message: bytes, signer: str, signature: object) -> bytes | Refusal:
    """The wire for a message and one signer's signature: the compact-u16 signature count, one 64-byte slot per
    required signer in key order with the signature in the signer's slot and zeros in every other, then the
    message."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return Refusal("svm/input-malformed")
    signer_key = key_bytes(signer)
    if signer_key is None or len(message) < 2:
        return Refusal("svm/input-malformed")
    required = message[1] if message[0] & 0x80 else message[0]
    head = _compact(required)
    wire = bytearray(head + bytes(64 * required) + message)
    decoded = decode_svm_tx(bytes(wire))
    if isinstance(decoded, Refusal):
        return decoded
    signers = decoded.keys[: decoded.required_signatures]
    if signer_key not in signers:
        return Refusal("svm/input-malformed")
    slot = signers.index(signer_key)
    at = len(head) + 64 * slot
    wire[at : at + 64] = signature
    return bytes(wire)


@dataclass(frozen=True, slots=True)
class SvmSigning:
    """What the payer signs, and how its signature becomes the partially signed wire."""

    message: bytes
    signer: str

    @property
    def request(self) -> dict[str, Any]:
        return {"kind": "solana-message", "message": self.message}

    def wire(self, signature: object) -> bytes | Refusal:
        return signed_wire(self.message, self.signer, signature)


# ── addresses ───────────────────────────────────────────────────────────────────────────────────────────────────

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def is_point(data: bytes) -> bool:
    """Whether 32 bytes decode as an Ed25519 point by RFC 8032 §5.1.3: y is the little-endian integer with bit 255
    cleared, taken modulo p; x² = (y² - 1) / (d·y² + 1) must have a square root; x = 0 with the sign bit set does not
    decode."""
    if len(data) != 32:
        return False
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    sign = data[31] >> 7
    y2 = y * y % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    x = u * pow(v, 3, _P) * pow(u * pow(v, 7, _P), (_P - 5) // 8, _P) % _P
    vx2 = v * x * x % _P
    if vx2 == u:
        pass
    elif vx2 == (-u) % _P:
        x = x * _SQRT_M1 % _P
    else:
        return False
    return not (x == 0 and sign == 1)


@dataclass(frozen=True, slots=True)
class Pda:
    address: str
    bump: int


def find_pda(seeds: Sequence[bytes], program: str) -> Pda | Refusal:
    """The program-derived address of seeds under program: for bumps 255 down to 0, the first
    SHA-256(seeds ‖ bump ‖ program ‖ "ProgramDerivedAddress") that does not decode as an Ed25519 point."""
    program_bytes = key_bytes(program)
    if (
        program_bytes is None
        or len(seeds) > MAX_SEEDS
        or any(not isinstance(s, bytes) or len(s) > MAX_SEED for s in seeds)
    ):
        return Refusal("svm/pda-not-found")
    joined = b"".join(seeds)
    for bump in range(255, -1, -1):
        candidate = hashlib.sha256(joined + bytes([bump]) + program_bytes + _PDA_MARKER).digest()
        if not is_point(candidate):
            return Pda(key_string(candidate), bump)
    return Refusal("svm/pda-not-found")


def ata(owner: str, token_program: str, mint: str) -> str | Refusal:
    """The associated token address of (owner, mint) under token_program."""
    parts = [key_bytes(owner), key_bytes(token_program), key_bytes(mint)]
    if any(p is None for p in parts):
        return Refusal("svm/input-malformed")
    pda = find_pda([p for p in parts if p is not None], ATA_PROGRAM)
    return pda if isinstance(pda, Refusal) else pda.address


# ── compiling ───────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Instruction:
    program: str
    accounts: tuple[tuple[str, int], ...]
    data: bytes


def _case_key(text: str) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """The sort key of an alphanumeric ASCII string under Intl.Collator("en", {caseFirst: "lower", sensitivity:
    "variant"}): digits before letters and letters in alphabetical order at the first level, then lower case before
    upper case, from the left, at the third."""
    primary = tuple(ord(c) - 48 if c.isdigit() else 10 + ord(c.lower()) - 97 for c in text)
    tertiary = tuple(1 if c.isupper() else 0 for c in text)
    return primary, tertiary


class _Invalid(Exception):
    pass


def compile_v0(fee_payer: str, recent_blockhash: str, instructions: Sequence[Instruction]) -> bytes | Refusal:
    """The v0 message bytes, with no lookup tables, for instructions under fee_payer and recent_blockhash. The fee
    payer is the first account; the others follow signers before non-signers, writable before read-only, and by
    address in collation order within each class. An account's roles across instructions are joined. A program
    that is the fee payer or is writable is refused."""
    blockhash = key_bytes(recent_blockhash)
    if key_bytes(fee_payer) is None or blockhash is None:
        return Refusal("svm/input-malformed")
    roles: dict[str, int] = {fee_payer: WRITABLE_SIGNER}
    invoked: set[str] = set()
    try:
        for ix in instructions:
            if key_bytes(ix.program) is None:
                raise _Invalid
            if ix.program == fee_payer or roles.get(ix.program, READONLY) & WRITABLE:
                raise _Invalid
            roles.setdefault(ix.program, READONLY)
            invoked.add(ix.program)
            for address, role in ix.accounts:
                if key_bytes(address) is None:
                    raise _Invalid
                if address == fee_payer:
                    continue
                merged = roles[address] | role if address in roles else role
                if merged & WRITABLE and address in invoked:
                    raise _Invalid
                roles[address] = merged
    except _Invalid:
        return Refusal("svm/input-malformed")
    others = sorted(
        (a for a in roles if a != fee_payer),
        key=lambda a: (0 if roles[a] & READONLY_SIGNER else 1, 0 if roles[a] & WRITABLE else 1, _case_key(a)),
    )
    ordered = [fee_payer, *others]
    index = {a: i for i, a in enumerate(ordered)}
    if len(ordered) > 256:
        return Refusal("svm/input-malformed")
    signers = [a for a in ordered if roles[a] & READONLY_SIGNER]
    readonly_signers = [a for a in signers if not roles[a] & WRITABLE]
    readonly_unsigned = [a for a in ordered if not roles[a] & READONLY_SIGNER and not roles[a] & WRITABLE]
    out = bytearray([0x80, len(signers), len(readonly_signers), len(readonly_unsigned)])
    out += _compact(len(ordered))
    for a in ordered:
        key = key_bytes(a)
        assert key is not None
        out += key
    out += blockhash
    out += _compact(len(instructions))
    for ix in instructions:
        out.append(index[ix.program])
        out += _compact(len(ix.accounts))
        out += bytes(index[a] for a, _ in ix.accounts)
        out += _compact(len(ix.data))
        out += ix.data
    out += _compact(0)
    return bytes(out)


def u32le(value: int) -> bytes:
    return struct.pack("<I", value)


def u64le(value: int) -> bytes:
    return struct.pack("<Q", value)


def is_u64(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < U64_LIMIT


def _is_u32(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < U32_LIMIT


def _compute_budget(limit: int, price: int) -> list[Instruction]:
    return [
        Instruction(COMPUTE_BUDGET, (), b"\x02" + u32le(limit)),
        Instruction(COMPUTE_BUDGET, (), b"\x03" + u64le(price)),
    ]


@dataclass(frozen=True, slots=True)
class SvmBuildInput:
    fee_payer: str
    payer: str
    mint: str
    token_program: str
    decimals: int
    pay_to: str
    amount: int
    recent_blockhash: str
    memo: str
    compute_unit_limit: int
    compute_unit_price: int


def _is_build_input(i: SvmBuildInput) -> bool:
    return (
        is_key(i.fee_payer)
        and is_key(i.payer)
        and is_key(i.mint)
        and i.token_program in (TOKEN, TOKEN_2022)
        and isinstance(i.decimals, int)
        and not isinstance(i.decimals, bool)
        and 0 <= i.decimals <= 255
        and is_key(i.pay_to)
        and is_u64(i.amount)
        and is_key(i.recent_blockhash)
        and isinstance(i.memo, str)
        and _is_u32(i.compute_unit_limit)
        and is_u64(i.compute_unit_price)
    )


def build_svm_message(i: SvmBuildInput) -> bytes | Refusal:
    """The v0 message bytes for a token payment: SetComputeUnitLimit, SetComputeUnitPrice, TransferChecked from the
    payer's associated token account to the payee's, then one v3 Memo instruction whose data is the memo's UTF-8
    bytes. No lookup tables."""
    if not _is_build_input(i):
        return Refusal("svm/input-malformed")
    try:
        memo = i.memo.encode("utf-8")
    except UnicodeEncodeError:
        return Refusal("svm/input-malformed")
    source = ata(i.payer, i.token_program, i.mint)
    destination = ata(i.pay_to, i.token_program, i.mint)
    if isinstance(source, Refusal):
        return source
    if isinstance(destination, Refusal):
        return destination
    transfer = Instruction(
        i.token_program,
        ((source, WRITABLE), (i.mint, READONLY), (destination, WRITABLE), (i.payer, READONLY_SIGNER)),
        b"\x0c" + u64le(i.amount) + bytes([i.decimals]),
    )
    return compile_v0(
        i.fee_payer,
        i.recent_blockhash,
        [*_compute_budget(i.compute_unit_limit, i.compute_unit_price), transfer, Instruction(MEMO_V3, (), memo)],
    )


@dataclass(frozen=True, slots=True)
class SvmUnsigned:
    """What the payer signs, and how its 64-byte Ed25519 signature completes the payment."""

    request: dict[str, Any]
    _complete: Callable[[bytes], Any]

    def complete(self, signature: bytes) -> Any:
        return self._complete(signature)


def memo_length(memo: str) -> int:
    """The UTF-8 length of a memo, a lone surrogate counting as the three bytes of its replacement."""
    return len(memo.encode("utf-8", "surrogatepass"))


def integer_of(value: object) -> Any:
    """An integral JSON number as an int; any other value unchanged, for the build's own checks to refuse."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


# ── the payment-channels program ────────────────────────────────────────────────────────────────────────────────


def channel_pda(payer: str, payee: str, mint: str, signer: str, salt: int, open_slot: int) -> str | Refusal:
    """The channel PDA: seeds "channel", payer, payee, mint, signer, u64le(salt), u64le(openSlot)."""
    keys = [key_bytes(payer), key_bytes(payee), key_bytes(mint), key_bytes(signer)]
    if any(k is None for k in keys) or not is_u64(salt) or not is_u64(open_slot):
        return Refusal("svm/input-malformed")
    pda = find_pda([b"channel", *(k for k in keys if k is not None), u64le(salt), u64le(open_slot)], PAYMENT_CHANNELS)
    return pda if isinstance(pda, Refusal) else pda.address


def open_instruction_data(salt: int, deposit: int, grace_period: int, open_slot: int, recipient: str) -> bytes | None:
    """The open instruction's data: 01 ‖ salt u64 ‖ deposit u64 ‖ gracePeriod u32 ‖ openSlot u64 ‖ one recipient
    (01000000 ‖ recipient ‖ bps 10 000 as u16), little-endian. 67 bytes. None for a value out of range."""
    key = key_bytes(recipient)
    if key is None or not is_u64(salt) or not is_u64(deposit) or not is_u64(open_slot) or not _is_u32(grace_period):
        return None
    head = b"\x01" + u64le(salt) + u64le(deposit) + u32le(grace_period) + u64le(open_slot)
    return head + u32le(1) + key + b"\x10\x27"


def channel_voucher_message(channel_id: str, cumulative: int, expires_at: int) -> bytes | None:
    """The 50 bytes a channel voucher signs: 56 01 ‖ channelId ‖ cumulative u64 LE ‖ expiresAt i64 LE. None when the
    channel id is not a base58 key or a number is out of range."""
    key = key_bytes(channel_id)
    if (
        key is None
        or not is_u64(cumulative)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or not -(1 << 63) <= expires_at < (1 << 63)
    ):
        return None
    return b"\x56\x01" + key + u64le(cumulative) + struct.pack("<q", expires_at)


@dataclass(frozen=True, slots=True)
class ChannelIx:
    kind: Literal["open", "top_up", "request_close"]
    channel: str
    data: bytes


# Each channel instruction by its discriminator: its kind, its account count, and the position of the channel
# account.
_CHANNEL_KINDS: dict[int, tuple[Literal["open", "top_up", "request_close"], int, int]] = {
    1: ("open", 14, 5),
    3: ("top_up", 6, 1),
    5: ("request_close", 2, 1),
}


def channel_instruction(tx: SvmTx) -> ChannelIx | Refusal:
    """The transaction's one top-level payment-channels instruction, by its discriminator."""
    found = [ix for ix in tx.instructions if _program_is(tx, ix, _PAYMENT_CHANNELS_BYTES)]
    if not found:
        return Refusal("svm/no-channel-instruction")
    if len(found) > 1:
        return Refusal("svm/channel-instruction")
    ix = found[0]
    shape = _CHANNEL_KINDS.get(ix.data[0]) if ix.data else None
    if shape is None or len(ix.accounts) != shape[1]:
        return Refusal("svm/channel-instruction")
    position = ix.accounts[shape[2]]
    if position >= len(tx.keys):
        return Refusal("svm/channel-instruction")
    return ChannelIx(shape[0], key_string(tx.keys[position]), ix.data)


@dataclass(frozen=True, slots=True)
class ChannelOpen:
    channel: str
    signer: str
    salt: int
    deposit: int
    grace_period: int
    open_slot: int
    recipient: str
    kind: Literal["open"] = "open"


@dataclass(frozen=True, slots=True)
class ChannelTopUp:
    channel: str
    amount: int
    kind: Literal["top_up"] = "top_up"


@dataclass(frozen=True, slots=True)
class ChannelRequestClose:
    channel: str
    kind: Literal["request_close"] = "request_close"


@dataclass(frozen=True, slots=True)
class ChannelBuildInput:
    fee_payer: str
    payer: str
    mint: str
    token_program: str
    recent_blockhash: str
    memo: str | None
    compute_unit_limit: int
    compute_unit_price: int
    instruction: ChannelOpen | ChannelTopUp | ChannelRequestClose


def build_channel_message(i: ChannelBuildInput) -> bytes | Refusal:
    """The v0 message for a channel instruction: SetComputeUnitLimit, SetComputeUnitPrice, the payment-channels
    instruction with its accounts in the program's order, then one v3 Memo instruction when memo is given. The fee
    payer is also the open's rent payer and payee."""
    ix = i.instruction
    if (
        not is_key(i.fee_payer)
        or not is_key(i.payer)
        or not is_key(i.mint)
        or i.token_program not in (TOKEN, TOKEN_2022)
        or not is_key(i.recent_blockhash)
        or not (i.memo is None or isinstance(i.memo, str))
        or not _is_u32(i.compute_unit_limit)
        or not is_u64(i.compute_unit_price)
        or not isinstance(ix, (ChannelOpen, ChannelTopUp, ChannelRequestClose))
        or not is_key(ix.channel)
    ):
        return Refusal("svm/input-malformed")
    if isinstance(ix, ChannelOpen):
        if not is_key(ix.signer):
            return Refusal("svm/input-malformed")
        opened = open_instruction_data(ix.salt, ix.deposit, ix.grace_period, ix.open_slot, ix.recipient)
        if opened is None:
            return Refusal("svm/input-malformed")
        data = opened
    elif isinstance(ix, ChannelTopUp):
        if not is_u64(ix.amount):
            return Refusal("svm/input-malformed")
        data = b"\x03" + u64le(ix.amount)
    else:
        data = b"\x05"
    try:
        memo = None if i.memo is None else i.memo.encode("utf-8")
    except UnicodeEncodeError:
        return Refusal("svm/input-malformed")
    event_authority = find_pda([b"event_authority"], PAYMENT_CHANNELS)
    if isinstance(event_authority, Refusal):
        return event_authority
    accounts: tuple[tuple[str, int], ...]
    payer_ata = channel_ata = ""
    if not isinstance(ix, ChannelRequestClose):
        found_payer, found_channel = ata(i.payer, i.token_program, i.mint), ata(ix.channel, i.token_program, i.mint)
        if isinstance(found_payer, Refusal) or isinstance(found_channel, Refusal):
            return Refusal("svm/input-malformed")
        payer_ata, channel_ata = found_payer, found_channel
    if isinstance(ix, ChannelOpen):
        accounts = (
            (i.payer, WRITABLE_SIGNER),
            (i.fee_payer, WRITABLE_SIGNER),
            (i.fee_payer, READONLY),
            (i.mint, READONLY),
            (ix.signer, READONLY),
            (ix.channel, WRITABLE),
            (payer_ata, WRITABLE),
            (channel_ata, WRITABLE),
            (i.token_program, READONLY),
            (SYSTEM, READONLY),
            (RENT_SYSVAR, READONLY),
            (ATA_PROGRAM, READONLY),
            (event_authority.address, READONLY),
            (PAYMENT_CHANNELS, READONLY),
        )
    elif isinstance(ix, ChannelTopUp):
        accounts = (
            (i.payer, WRITABLE_SIGNER),
            (ix.channel, WRITABLE),
            (payer_ata, WRITABLE),
            (channel_ata, WRITABLE),
            (i.mint, READONLY),
            (i.token_program, READONLY),
        )
    else:
        accounts = ((i.payer, READONLY_SIGNER), (ix.channel, WRITABLE))
    return compile_v0(
        i.fee_payer,
        i.recent_blockhash,
        [
            *_compute_budget(i.compute_unit_limit, i.compute_unit_price),
            Instruction(PAYMENT_CHANNELS, accounts, data),
            *([] if memo is None else [Instruction(MEMO_V3, (), memo)]),
        ],
    )


def signature_bytes(value: object) -> bytes | None:
    """The 64 bytes of a base58 Ed25519 signature of at most 90 characters, or None."""
    if not isinstance(value, str) or len(value) > 90:
        return None
    decoded = b58_decode(value)
    return decoded if decoded is not None and len(decoded) == 64 else None


def build_sol_message(
    fee_payer: str,
    payer: str,
    pay_to: str,
    lamports: int,
    recent_blockhash: str,
    memo: str,
    compute_unit_limit: int,
    compute_unit_price: int,
) -> bytes | Refusal:
    """The v0 message for a native SOL payment: SetComputeUnitLimit, SetComputeUnitPrice, System transfer of lamports
    from the payer to the recipient, then one v3 Memo instruction carrying memo."""
    if not is_u64(lamports) or not _is_u32(compute_unit_limit) or not is_u64(compute_unit_price):
        return Refusal("svm/input-malformed")
    try:
        data = memo.encode("utf-8")
    except UnicodeEncodeError:
        return Refusal("svm/input-malformed")
    transfer = Instruction(SYSTEM, ((payer, WRITABLE_SIGNER), (pay_to, WRITABLE)), u32le(2) + u64le(lamports))
    return compile_v0(
        fee_payer,
        recent_blockhash,
        [*_compute_budget(compute_unit_limit, compute_unit_price), transfer, Instruction(MEMO_V3, (), data)],
    )
