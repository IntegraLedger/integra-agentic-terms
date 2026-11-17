"""Solana rail pieces for the buyer half: the legacy, v0 and v1 wire transaction, its one Memo instruction carrying
the ATR hash in LCP string form, the partially signed wire, program-derived and associated token addresses, and v0
and version-1 message compilation with the account order of @solana/kit 8.4.0.

Nothing here fetches, hashes an ATR or signs.
"""

import hashlib
import re
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Refusal
from ._codec import b58_decode, b58_encode, b64_decode, b64_encode, text_encode
from ._ed25519 import x_of
from ._jose import js_length
from ._lcp import from_lcp_string, is_list, is_object, to_lcp_string

MEMO_V3 = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
MEMO_V4 = "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH"
TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SYSTEM = "11111111111111111111111111111111"
COMPUTE_BUDGET = "ComputeBudget111111111111111111111111111111"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
PAYMENT_CHANNELS = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX"
RENT_SYSVAR = "SysvarRent111111111111111111111111111111111"

# The serialized size bound of a legacy or v0 transaction.
MAX_WIRE = 1232
# The serialized size bound of a v1 transaction (SIMD-0385, Transaction Constraints).
MAX_WIRE_V1 = 4096
# The first byte of a v1 wire transaction, its message's version byte (SIMD-0385, VersionByte).
_V1_VERSION_BYTE = 0x81
# SIMD-0385's bounds on a v1 message: signatures, account addresses and instructions.
_V1_MAX_SIGNATURES = 12
_V1_MAX_ADDRESSES = 64
_V1_MAX_INSTRUCTIONS = 64
# The TransactionConfigMask bits SIMD-0385 assigns: 0 and 1 the priority fee (a u64, both bits set together), 2 the
# compute unit limit, 3 the loaded accounts data size limit, 4 the requested heap size (each a u32).
_V1_CONFIG_BITS = 0b11111
_V1_PRIORITY_FEE_BITS = 0b11
_V1_HEAP_SIZE_BIT = 0b10000
MAX_SEEDS = 16
MAX_SEED = 32
U64_LIMIT = 1 << 64
U32_LIMIT = 1 << 32

_NETWORK = re.compile(r"solana:[1-9A-HJ-NP-Za-km-z]{32}")
_PDA_MARKER = b"ProgramDerivedAddress"

# Account roles as @solana/kit numbers them: bit 1 signer, bit 0 writable.
READONLY = 0
WRITABLE = 1
READONLY_SIGNER = 2
WRITABLE_SIGNER = 3


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


_SYSTEM_BYTES = b58_decode(SYSTEM)
_ADVANCE_NONCE_ACCOUNT = bytes([4, 0, 0, 0])
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
class SvmLookup:
    """One address table lookup of a v0 message: the table's address, and the indexes it loads, writable and
    read-only."""

    table: str
    writable: tuple[int, ...]
    readonly: tuple[int, ...]


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
    # The message's address table lookups, in order; none for a legacy message.
    lookups: tuple[SvmLookup, ...]


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
    """A legacy or v0 wire transaction of at most 1,232 bytes, or a v1 wire transaction (SIMD-0385) of at most 4,096
    bytes, decoded; a longer one is svm/tx-too-large. Bytes that are not one well-formed transaction are
    svm/tx-malformed, as is a v0 message with an address table lookup that names no index, which the runtime refuses
    ("each lookup table must be used to load at least one account"), and a v1 message that SIMD-0385's sanitization
    refuses (_decode_v1)."""
    if not isinstance(wire, (bytes, bytearray)) or len(wire) == 0:
        return Refusal("svm/tx-malformed")
    if wire[0] == _V1_VERSION_BYTE:
        return _decode_v1(bytes(wire))
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
        lookups = []
        if versioned:
            for _ in range(c.compact()):
                table = key_string(c.take(32))
                writable = tuple(c.take(c.compact()))
                readonly = tuple(c.take(c.compact()))
                # A v0 message's sanitize refuses a lookup that loads no account (anza-xyz/solana-sdk 648387ee, tag
                # message@v3.0.0, message/src/versions/v0/mod.rs:118-129).
                if not writable and not readonly:
                    return Refusal("svm/tx-malformed")
                lookups.append(SvmLookup(table, writable, readonly))
        if c.at != len(data):
            return Refusal("svm/tx-malformed")
    except (IndexError, ValueError):
        return Refusal("svm/tx-malformed")
    return SvmTx(signatures, data[start:], keys, tuple(instructions), blockhash, required, tuple(lookups))


def _decode_v1(data: bytes) -> SvmTx | Refusal:
    """A v1 wire transaction, laid out as SIMD-0385's Transaction V1 Specification states: the version byte 129, the
    legacy header, the TransactionConfigMask (u32 little-endian), the lifetime specifier (the recent blockhash or
    durable nonce), the instruction count and address count (one byte each), the addresses, one 4-byte config value per
    mask bit, one 4-byte header per instruction (program index, account count, data length as a u16 little-endian),
    each instruction's account indexes and data, then one 64-byte signature per required signer. The message every
    signer signs is every byte before the signatures, and no byte follows them. A v1 message has no address table
    lookups. svm/tx-malformed where SIMD-0385's sanitization refuses the message: no signer, or a read-only signer
    count not below the signer count; fewer addresses than the signers and read-only unsigned accounts, or more than 64;
    more than 12 signers or 64 instructions; an address listed twice; a program or account index not below the address
    count; only one of the priority fee's two mask bits set; or a requested heap size that is not a multiple of 1,024
    from 32,768 to 262,144. A set mask bit SIMD-0385 assigns no field, for which it states no rule, is svm/tx-malformed
    too, since the 4 bytes it stands for have no meaning this package can read. Over 4,096 bytes is svm/tx-too-large."""
    if len(data) > MAX_WIRE_V1:
        return Refusal("svm/tx-too-large")
    try:
        c = _Cursor(data)
        c.byte()
        required = c.byte()
        readonly_signed = c.byte()
        readonly_unsigned = c.byte()
        mask = int.from_bytes(c.take(4), "little")
        blockhash = c.take(32)
        n_ix = c.byte()
        n_keys = c.byte()
        if required == 0 or readonly_signed >= required:
            return Refusal("svm/tx-malformed")
        if n_keys < required + readonly_unsigned or n_keys > _V1_MAX_ADDRESSES:
            return Refusal("svm/tx-malformed")
        if required > _V1_MAX_SIGNATURES or n_ix > _V1_MAX_INSTRUCTIONS:
            return Refusal("svm/tx-malformed")
        if mask & ~_V1_CONFIG_BITS:
            return Refusal("svm/tx-malformed")
        fee = mask & _V1_PRIORITY_FEE_BITS
        if fee not in (0, _V1_PRIORITY_FEE_BITS):
            return Refusal("svm/tx-malformed")
        keys = tuple(c.take(32) for _ in range(n_keys))
        if len(set(keys)) != len(keys):
            return Refusal("svm/tx-malformed")
        values = c.take(4 * bin(mask).count("1"))
        if mask & _V1_HEAP_SIZE_BIT:
            heap = int.from_bytes(values[-4:], "little")
            if heap % 1024 != 0 or heap < 32 * 1024 or heap > 256 * 1024:
                return Refusal("svm/tx-malformed")
        headers = []
        for _ in range(n_ix):
            h = c.take(4)
            headers.append((h[0], h[1], h[2] | (h[3] << 8)))
        instructions = []
        for program, n_acc, n_data in headers:
            accounts = tuple(c.take(n_acc))
            if program >= n_keys or any(a >= n_keys for a in accounts):
                return Refusal("svm/tx-malformed")
            instructions.append(SvmInstruction(program, accounts, c.take(n_data)))
        message_end = c.at
        signatures = tuple(c.take(64) for _ in range(required))
        if c.at != len(data):
            return Refusal("svm/tx-malformed")
    except (IndexError, ValueError):
        return Refusal("svm/tx-malformed")
    return SvmTx(signatures, data[:message_end], keys, tuple(instructions), blockhash, required, ())


def _program_is(tx: SvmTx, ix: SvmInstruction, program: bytes | None) -> bool:
    return ix.program < len(tx.keys) and tx.keys[ix.program] == program


@dataclass(frozen=True, slots=True)
class Carrier:
    h: AtrHash
    memo: str


def svm_carrier(tx: SvmTx) -> Carrier | Refusal:
    """The one top-level Memo instruction (v3 or v4) and the ATR hash its UTF-8 data carries in LCP string form. None,
    or more than one, is svm/memo-count. The memo must be the hash's LCP string exactly, in lower-case hex; the same
    hash in any other spelling is svm/carrier-not-canonical."""
    memos = memo_data(tx)
    if len(memos) != 1:
        return Refusal("svm/memo-count")
    return memo_carrier(memos[0])


def memo_data(tx: SvmTx) -> list[bytes]:
    """The data of each top-level Memo instruction (v3 or v4), in order."""
    return [
        ix.data for ix in tx.instructions if _program_is(tx, ix, _MEMO_V3_BYTES) or _program_is(tx, ix, _MEMO_V4_BYTES)
    ]


def memo_carrier(data: bytes) -> Carrier | Refusal:
    """The ATR hash one Memo instruction's UTF-8 data carries in LCP string form, exactly its LCP string."""
    try:
        memo = data.decode("utf-8")
    except UnicodeDecodeError:
        return Refusal("svm/memo-not-utf8")
    h = from_lcp_string(memo)
    if h is None:
        return Refusal("svm/memo-not-lcp")
    return canonical_carrier(h, memo)


def canonical_carrier(h: AtrHash, memo: str) -> Carrier | Refusal:
    """The carrier when memo is the hash's LCP string exactly, else svm/carrier-not-canonical."""
    return Carrier(h, memo) if memo == to_lcp_string(h) else Refusal("svm/carrier-not-canonical")


def _is_number(value: object, of: int) -> bool:
    """True when value is a JSON number equal to of, as JavaScript's === compares a number: a boolean is none."""
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value == of


def built_version(fields: object) -> int | None:
    """The message version a Solana build writes under fields, an x402 Solana option's extra or an MPP Solana charge
    challenge's Solana details: the highest version both the field and this package admit, 1 where transactionVersions
    holds 1, 0 where it holds 0 alone or is absent; None where it is present and is not a non-empty array of the JSON
    integers 0 and 1, which admits neither. The field is the set of versions the sponsor or server accepts, and absent it
    is [0] (x402: scheme_exact_svm.md §1.5 at x402-foundation/x402 88b66dd4, and resolveTransactionVersion of @x402/svm
    2.31.0, which refuses an empty list, a value that is not an array and any entry other than 0 and 1; MPP: the draft
    methodDetails.transactionVersions of tempoxyz/mpp-specs pull request 355, as solana-foundation/pay-kit 86400da reads
    it in typescript/packages/mpp/src/utils/transaction-versions.ts, where a present, empty list accepts nothing, and
    builds it in src/client/Charge.ts:211-220)."""
    if not is_object(fields) or "transactionVersions" not in fields:
        return 0
    versions = fields["transactionVersions"]
    if not is_list(versions) or not versions or not all(_is_number(v, 0) or _is_number(v, 1) for v in versions):
        return None
    return 1 if any(_is_number(v, 1) for v in versions) else 0


def version_not_admitted(fields: object, tx: SvmTx, on: Literal["x402", "mpp"]) -> Refusal | None:
    """svm/version-not-admitted where the signed message's version is one the transactionVersions of fields (an x402
    Solana option's extra, or an MPP Solana charge challenge's Solana details) does not admit, else None: a payment the
    option does not admit is no answer to it. The version is read as @x402/svm 2.31.0 reads it, from the message's first
    byte, legacy where its high bit is clear and its low seven bits otherwise (version 1's prefix being 129, SIMD-0385);
    the list absent is [0], and a list that is not an array admits nothing.
    - On x402 a version is admitted as the facilitator admits it, legacy where the list holds 0: its server copies the
      facilitator's list into the option, so a version the option does not list is one its facilitator refuses.
    - On MPP the server refuses a legacy message whatever the list holds, the list absent being [0]
      (solana-foundation/pay-kit 86400da, typescript/packages/mpp/src/utils/transaction-versions.ts:15-16 and :218-226),
      so legacy is refused on every MPP Solana charge challenge."""
    listed = fields["transactionVersions"] if is_object(fields) and "transactionVersions" in fields else [0]
    if not is_list(listed) or not tx.message:
        return Refusal("svm/version-not-admitted")
    first = tx.message[0]
    legacy = first & 0x80 == 0
    if legacy and on == "mpp":
        return Refusal("svm/version-not-admitted")
    version = 0 if legacy else first & 0x7F
    return None if any(_is_number(v, version) for v in listed) else Refusal("svm/version-not-admitted")


def unbuilt_option(extra: object) -> Refusal | None:
    """The refusal an x402 Solana option filter gives an option of its pairing that no Solana build honours, else None:
    an extra.transactionVersions that admits neither version (built_version), which scheme_exact_svm.md §1.5 makes
    invalid, is x402/option-malformed; an extra.splits is svm/input-malformed, since no Solana build writes split legs
    and each pays the whole amount to payTo."""
    if built_version(extra) is None:
        return Refusal("x402/option-malformed")
    if is_object(extra) and "splits" in extra:
        return Refusal("svm/input-malformed")
    return None


def svm_option_filter(
    check: Callable[[Mapping[str, Any]], "Literal[True] | Refusal | None"],
) -> Callable[[Mapping[str, Any]], "Literal[True] | Refusal | None"]:
    """An x402 Solana pairing's option filter: check, then unbuilt_option over an option it serves."""

    def filtered(option: Mapping[str, Any]) -> "Literal[True] | Refusal | None":
        f = check(option)
        if f is not True:
            return f
        unbuilt = unbuilt_option(option.get("extra"))
        return True if unbuilt is None else unbuilt

    return filtered


def static_nonce(tx: SvmTx) -> Refusal | None:
    """svm/nonce-account-not-static when the message's first instruction is the System program's AdvanceNonceAccount
    (data 04000000) and its nonce account is an address lookup table entry, past the static keys: a durable message
    names its nonce account as a static key (SIMD-0242), and the message alone cannot show the nonce account it uses.
    The RecentBlockhashes sysvar may come from a table. Else None."""
    first = tx.instructions[0] if tx.instructions else None
    if first is None or not _program_is(tx, first, _SYSTEM_BYTES) or first.data[:4] != _ADVANCE_NONCE_ACCOUNT:
        return None
    named = first.accounts[:1]
    return Refusal("svm/nonce-account-not-static") if any(i >= len(tx.keys) for i in named) else None



def loaded_keys(tx: SvmTx, loads: object) -> tuple[bytes, ...] | Refusal:
    """Every key a message's instructions may index once its address table lookups are resolved, in the runtime's
    order: the static keys, then each lookup's writable entries, then each lookup's read-only entries (anza-xyz/agave
    f516a892, tag v3.0.14, runtime/src/bank/address_lookup_table.rs L41-68 appends lookup by lookup, writable to
    writable and read-only to read-only, accounts-db/src/accounts.rs L145-156). loads holds, for each lookup in order,
    its table's address and as many base58 keys as the lookup names writable and read-only indexes, as a seller's
    reader writes them; any other value is svm/read-first. A loaded key that repeats a static key or another loaded key
    is svm/table-unusable: the runtime refuses a transaction that loads one account twice (AccountLoadedTwice,
    accounts-db/src/account_locks.rs L160-170)."""
    if not is_list(loads) or len(loads) != len(tx.lookups):
        return Refusal("svm/read-first")
    writable: list[bytes] = []
    readonly: list[bytes] = []
    for lookup, load in zip(tx.lookups, loads):
        if not is_object(load) or load.get("address") != lookup.table:
            return Refusal("svm/read-first")
        w = _key_list(load.get("writable"), len(lookup.writable))
        r = _key_list(load.get("readonly"), len(lookup.readonly))
        if w is None or r is None:
            return Refusal("svm/read-first")
        writable += w
        readonly += r
    seen = set(tx.keys)
    for key in writable + readonly:
        if key in seen:
            return Refusal("svm/table-unusable")
        seen.add(key)
    return tx.keys + tuple(writable) + tuple(readonly)


def _key_list(value: object, n: int) -> list[bytes] | None:
    """The 32-byte keys of a list of exactly n base58 keys, else None."""
    if not is_list(value) or len(value) != n:
        return None
    keys = [key_bytes(v) for v in value]
    return [k for k in keys if k is not None] if all(k is not None for k in keys) else None

def wire_of(text: object) -> bytes | Refusal:
    """The wire in a payment, padded standard base64 in its canonical form (RFC 4648 §3.5), decoded, or the refusal
    naming what is wrong with it. The text's length is measured in UTF-16 code units, as String.prototype.length
    counts it."""
    if not isinstance(text, str) or text == "":
        return Refusal("svm/tx-malformed")
    if js_length(text) > -(-MAX_WIRE_V1 // 3) * 4 + 4:
        return Refusal("svm/tx-too-large")
    data = b64_decode(text)
    if data is None:
        return Refusal("svm/tx-malformed")
    if len(data) > (MAX_WIRE_V1 if data[:1] == bytes([_V1_VERSION_BYTE]) else MAX_WIRE):
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
    """The wire for a message and one signer's signature, with one 64-byte slot per required signer in key order, the
    signature in the signer's slot and zeros in every other: for a legacy or v0 message, the compact-u16 signature
    count, the slots, then the message; for a version-1 message, the message, then the slots, as SIMD-0385's Transaction
    V1 Specification lays the wire out (the message every signer signs is every byte before the signatures). A message
    under 2 bytes is svm/tx-malformed."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return Refusal("svm/input-malformed")
    signer_key = key_bytes(signer)
    if signer_key is None:
        return Refusal("svm/input-malformed")
    if len(message) < 2:
        return Refusal("svm/tx-malformed")
    required = message[1] if message[0] & 0x80 else message[0]
    v1 = message[0] == _V1_VERSION_BYTE
    head = b"" if v1 else _compact(required)
    wire = bytearray(message + bytes(64 * required)) if v1 else bytearray(head + bytes(64 * required) + message)
    decoded = decode_svm_tx(bytes(wire))
    if isinstance(decoded, Refusal):
        return decoded
    signers = decoded.keys[: decoded.required_signatures]
    if signer_key not in signers:
        return Refusal("svm/input-malformed")
    slot = signers.index(signer_key)
    at = (len(message) if v1 else len(head)) + 64 * slot
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

def is_point(data: bytes) -> bool:
    """Whether 32 bytes decompress as an Ed25519 point as @noble/curves' Point.fromBytes(b, true) does: y is the
    little-endian integer with bit 255 cleared, taken modulo p, and x² = (y² - 1) / (d·y² + 1) must have a square
    root."""
    return len(data) == 32 and x_of(int.from_bytes(data, "little") & ((1 << 255) - 1)) is not None


def is_curve_key(value: object) -> bool:
    """A base58 public key whose 32 bytes are a point on the Ed25519 curve, by the rule find_pda applies to a
    candidate: a key that can sign, which a program-derived address is not."""
    data = key_bytes(value)
    return data is not None and is_point(data)


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


@dataclass(frozen=True, slots=True)
class V1Header:
    """The form of a version-1 message's header, which carries the compute budget in place of Compute Budget
    instructions: the loaded-account-data limit it carries, in bytes, and whether it carries a priority fee of 0
    lamports (otherwise a fee of 0 is left out)."""

    loaded_accounts_data_size_limit: int
    zero_priority_fee: bool


# The header @x402/svm 2.31.0's clients write (applyTransactionV1Config): a priority fee only where it is above 0, and
# DEFAULT_LOADED_ACCOUNTS_DATA_SIZE_LIMIT, 4 MiB.
X402_V1 = V1Header(4_194_304, False)
# The header solana-foundation/pay-kit 86400da's MPP charge client writes (typescript/packages/mpp/src/client/
# Charge.ts:451-464): the priority fee always, and the runtime maximum of 64 MiB, the one value its server admits.
MPP_V1 = V1Header(67_108_864, True)
# The largest compute unit limit @solana/kit 8.4.0 writes into a version-1 header.
_V1_MAX_COMPUTE_UNITS = 1_400_000


@dataclass(frozen=True, slots=True)
class _Accounts:
    """The accounts a message names, in @solana/kit 8.4.0's order, with each one's joined role."""

    ordered: list[str]
    roles: dict[str, int]
    index: dict[str, int]


def _accounts(fee_payer: str, instructions: Sequence[Instruction], max_instructions: int) -> _Accounts | Refusal:
    """The fee payer first; the others signers before non-signers, writable before read-only, and by address in
    collation order within each class. An account's roles across instructions are joined. A program that is the fee
    payer or is writable is refused, and so are @solana/kit 8.4.0's limits: more than 64 accounts, 12 signers or
    max_instructions instructions, an instruction naming more than 255 accounts, and data past 65 535 bytes."""
    if key_bytes(fee_payer) is None:
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
    signers = [a for a in ordered if roles[a] & READONLY_SIGNER]
    if (
        len(ordered) > 64
        or len(signers) > 12
        or len(instructions) > max_instructions
        or any(len(ix.accounts) > 255 or len(ix.data) > 0xFFFF for ix in instructions)
    ):
        return Refusal("svm/input-malformed")
    return _Accounts(ordered, roles, {a: i for i, a in enumerate(ordered)})


def _header(a: _Accounts) -> bytes:
    """The legacy header: the signer count, the read-only signers and the read-only unsigned accounts."""
    signers = [x for x in a.ordered if a.roles[x] & READONLY_SIGNER]
    readonly_signers = [x for x in signers if not a.roles[x] & WRITABLE]
    readonly_unsigned = [x for x in a.ordered if not a.roles[x] & READONLY_SIGNER and not a.roles[x] & WRITABLE]
    return bytes([len(signers), len(readonly_signers), len(readonly_unsigned)])


def _keys(a: _Accounts) -> bytes:
    out = bytearray()
    for x in a.ordered:
        key = key_bytes(x)
        assert key is not None
        out += key
    return bytes(out)


def compile_v0(fee_payer: str, recent_blockhash: str, instructions: Sequence[Instruction]) -> bytes | Refusal:
    """The v0 message bytes, with no lookup tables, for instructions under fee_payer and recent_blockhash, the accounts
    in @solana/kit 8.4.0's order (_accounts), with its v0 limits: at most 64 instructions, and data within what the
    compact-u16 length holds."""
    blockhash = key_bytes(recent_blockhash)
    if blockhash is None:
        return Refusal("svm/input-malformed")
    a = _accounts(fee_payer, instructions, 64)
    if isinstance(a, Refusal):
        return a
    out = bytearray([0x80]) + _header(a)
    out += _compact(len(a.ordered))
    out += _keys(a)
    out += blockhash
    out += _compact(len(instructions))
    for ix in instructions:
        out.append(a.index[ix.program])
        out += _compact(len(ix.accounts))
        out += bytes(a.index[x] for x, _ in ix.accounts)
        out += _compact(len(ix.data))
        out += ix.data
    out += _compact(0)
    return bytes(out)


def compile_v1(
    fee_payer: str, recent_blockhash: str, instructions: Sequence[Instruction], limit: int, price: int, v1: V1Header
) -> bytes | Refusal:
    """The version-1 message bytes (SIMD-0385) for instructions under fee_payer and recent_blockhash, as @solana/kit
    8.4.0 compiles one, the budget in the header as v1 names it: the priority fee, the limit times the price per unit in
    micro-lamports over 10^6, rounded up, left out where it is 0 unless v1.zero_priority_fee (both its mask bits, a
    u64); the compute unit limit, which must be above 0 and at most 1,400,000 (a u32); and v1's loaded-account-data
    limit (a u32). The layout: the version byte 129, the legacy header, the config mask as a u32 little-endian, the
    blockhash, the instruction and address counts as one byte each, the addresses, the config values in mask-bit order,
    one header per instruction (program index, account count, data length as a u16 little-endian), then each
    instruction's account indexes and data. Anything else is svm/input-malformed."""
    if not _is_u32(limit) or limit == 0 or limit > _V1_MAX_COMPUTE_UNITS or not is_u64(price):
        return Refusal("svm/input-malformed")
    if not _is_u32(v1.loaded_accounts_data_size_limit) or not isinstance(v1.zero_priority_fee, bool):
        return Refusal("svm/input-malformed")
    blockhash = key_bytes(recent_blockhash)
    if blockhash is None:
        return Refusal("svm/input-malformed")
    a = _accounts(fee_payer, instructions, _V1_MAX_INSTRUCTIONS)
    if isinstance(a, Refusal):
        return a
    fee = (limit * price + 999_999) // 1_000_000
    if fee >= U64_LIMIT:
        return Refusal("svm/input-malformed")
    mask = 0b1100
    values = bytearray()
    if fee > 0 or v1.zero_priority_fee:
        mask |= _V1_PRIORITY_FEE_BITS
        values += u64le(fee)
    values += u32le(limit) + u32le(v1.loaded_accounts_data_size_limit)
    out = bytearray([_V1_VERSION_BYTE]) + _header(a) + u32le(mask) + blockhash
    out += bytes([len(instructions), len(a.ordered)])
    out += _keys(a)
    out += values
    for ix in instructions:
        out += bytes([a.index[ix.program], len(ix.accounts)]) + struct.pack("<H", len(ix.data))
    for ix in instructions:
        out += bytes(a.index[x] for x, _ in ix.accounts)
        out += ix.data
    return bytes(out)


def compile_budgeted(
    fee_payer: str,
    recent_blockhash: str,
    instructions: Sequence[Instruction],
    limit: int,
    price: int,
    v1: V1Header | None,
) -> bytes | Refusal:
    """Instructions compiled with the budget limit and price: as a v0 message led by SetComputeUnitLimit and
    SetComputeUnitPrice where v1 is None, else as a version-1 message whose header carries the budget in the form v1
    names (compile_v1)."""
    if v1 is not None:
        return compile_v1(fee_payer, recent_blockhash, instructions, limit, price, v1)
    return compile_v0(fee_payer, recent_blockhash, [*_compute_budget(limit, price), *instructions])


def u32le(value: int) -> bytes:
    return struct.pack("<I", value)


def u64le(value: int) -> bytes:
    return struct.pack("<Q", value)


def is_u64(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < U64_LIMIT


def _is_u32(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < U32_LIMIT


def is_payer_input(c: Mapping[str, Any]) -> bool:
    """True when the members a payer passes to every x402 Solana build have their rail form: the payer and the recent
    blockhash base58 public keys, the token program Token's or Token-2022's, and the compute unit limit and price, when
    given, a u32 and a u64. Each build checks them before the choice's document and option, so a malformed one is
    svm/input-malformed, the code the message builders give it, whatever the document holds."""
    limit, price = c.get("computeUnitLimit"), c.get("computeUnitPrice")
    return (
        is_key(c.get("payer"))
        and c.get("tokenProgram") in (TOKEN, TOKEN_2022)
        and is_key(c.get("recentBlockhash"))
        and _is_u32(0 if limit is None else integer_of(limit))
        and is_u64(0 if price is None else price)
    )


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
    # Present, a version-1 message (SIMD-0385) whose header carries the compute budget in this form; absent, v0.
    v1: V1Header | None = None


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
        and (i.v1 is None or isinstance(i.v1, V1Header))
    )


def build_svm_message(i: SvmBuildInput) -> bytes | Refusal:
    """The message bytes for a token payment: SetComputeUnitLimit, SetComputeUnitPrice, TransferChecked from the payer's
    associated token account to the payee's, then one v3 Memo instruction whose data is the memo's UTF-8 bytes, as a v0
    message; with v1, the same without the two Compute Budget instructions, as a version-1 message whose header carries
    the budget (compile_budgeted). No lookup tables."""
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
    return compile_budgeted(
        i.fee_payer,
        i.recent_blockhash,
        [transfer, Instruction(MEMO_V3, (), memo)],
        i.compute_unit_limit,
        i.compute_unit_price,
        i.v1,
    )


@dataclass(frozen=True, slots=True)
class SvmUnsigned:
    """What the payer signs, and how its 64-byte Ed25519 signature completes the payment."""

    request: dict[str, Any]
    _complete: Callable[[bytes], Any]

    def complete(self, signature: bytes) -> Any:
        return self._complete(signature)


def memo_length(memo: str) -> int:
    """The UTF-8 length TextEncoder writes for the memo as a JavaScript string of its UTF-16 code units: a surrogate
    pair is one four-byte character, held as one code point or as two, and a lone surrogate is U+FFFD's three
    bytes."""
    return len(text_encode(memo))


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
    v1: V1Header | None = None


def build_channel_message(i: ChannelBuildInput) -> bytes | Refusal:
    """The message for a channel instruction: SetComputeUnitLimit, SetComputeUnitPrice, the payment-channels
    instruction with its accounts in the program's order, then one v3 Memo instruction when memo is given, as a v0
    message; with v1, the same without the two Compute Budget instructions, as a version-1 message whose header carries
    the budget (compile_budgeted). The fee payer is also the open's rent payer and payee."""
    return channel_message(i, [] if i.memo is None else [i.memo])


def channel_message(i: ChannelBuildInput, memos: Sequence[object]) -> bytes | Refusal:
    """build_channel_message with one v3 Memo instruction per entry of memos, in order, in place of i.memo. A memo
    that is not a string with a UTF-8 form is svm/input-malformed, with nothing built."""
    ix = i.instruction
    if (
        not is_key(i.fee_payer)
        or not is_key(i.payer)
        or not is_key(i.mint)
        or i.token_program not in (TOKEN, TOKEN_2022)
        or not is_key(i.recent_blockhash)
        or not all(isinstance(m, str) for m in memos)
        or not _is_u32(i.compute_unit_limit)
        or not is_u64(i.compute_unit_price)
        or (i.v1 is not None and not isinstance(i.v1, V1Header))
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
        memo_data = [m.encode("utf-8") for m in memos if isinstance(m, str)]
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
    return compile_budgeted(
        i.fee_payer,
        i.recent_blockhash,
        [Instruction(PAYMENT_CHANNELS, accounts, data), *(Instruction(MEMO_V3, (), m) for m in memo_data)],
        i.compute_unit_limit,
        i.compute_unit_price,
        i.v1,
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
    v1: V1Header | None = None,
) -> bytes | Refusal:
    """The message for a native SOL payment: SetComputeUnitLimit, SetComputeUnitPrice, System transfer of lamports from
    the payer to the recipient, then one v3 Memo instruction carrying memo, as a v0 message; with v1, the same without
    the two Compute Budget instructions, as a version-1 message whose header carries the budget (compile_budgeted)."""
    if not is_u64(lamports) or not _is_u32(compute_unit_limit) or not is_u64(compute_unit_price):
        return Refusal("svm/input-malformed")
    try:
        data = memo.encode("utf-8")
    except UnicodeEncodeError:
        return Refusal("svm/input-malformed")
    transfer = Instruction(SYSTEM, ((payer, WRITABLE_SIGNER), (pay_to, WRITABLE)), u32le(2) + u64le(lamports))
    return compile_budgeted(
        fee_payer,
        recent_blockhash,
        [transfer, Instruction(MEMO_V3, (), data)],
        compute_unit_limit,
        compute_unit_price,
        v1,
    )
