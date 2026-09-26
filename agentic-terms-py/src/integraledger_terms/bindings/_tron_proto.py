"""The Tron wire subset: protobuf varints and length-delimited fields for the Transaction.raw fields a TRC-20
transfer uses, the transaction read and written as java-tron serialises it, and base58check addresses."""

import hashlib
from dataclasses import dataclass, replace

from .._types import Refusal
from ._codec import b58_decode

TRIGGER_SMART_CONTRACT = 31
TRIGGER_URL = b"type.googleapis.com/protocol.TriggerSmartContract"
INT64_LIMIT = 1 << 63
MAX_TX_HEX = 8192
MAX_SIGNATURES = 5
SIGNATURE_BYTES = 65
_UINT64_LIMIT = 1 << 64
_LOWER_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True, slots=True)
class TronRaw:
    ref_block_bytes: bytes = b""
    ref_block_hash: bytes = b""
    expiration: int = 0
    data: bytes = b""
    owner: bytes = b""
    contract_address: bytes = b""
    call_data: bytes = b""
    timestamp: int = 0
    fee_limit: int = 0


# ── write ─────────────────────────────────────────────────────────────────────────────────────────────────────────


def _varint(n: int) -> bytes:
    out = bytearray()
    while n >= 0x80:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _bytes_field(no: int, b: bytes) -> bytes:
    """A length-delimited field; an empty value is not written."""
    return _varint((no << 3) | 2) + _varint(len(b)) + b if b else b""


def _int_field(no: int, v: int) -> bytes:
    """A varint field; a zero value is not written."""
    return _varint(no << 3) + _varint(v) if v else b""


def encode_tron_raw(r: TronRaw) -> bytes:
    """Transaction.raw as java-tron serialises it: fields in ascending order, default values omitted."""
    trigger = _bytes_field(1, r.owner) + _bytes_field(2, r.contract_address) + _bytes_field(4, r.call_data)
    any_value = _bytes_field(1, TRIGGER_URL) + _bytes_field(2, trigger)
    contract = _int_field(1, TRIGGER_SMART_CONTRACT) + _bytes_field(2, any_value)
    return (
        _bytes_field(1, r.ref_block_bytes)
        + _bytes_field(4, r.ref_block_hash)
        + _int_field(8, r.expiration)
        + _bytes_field(10, r.data)
        + _bytes_field(11, contract)
        + _int_field(14, r.timestamp)
        + _int_field(18, r.fee_limit)
    )


def encode_transaction(raw_bytes: bytes, signatures: list[bytes]) -> bytes:
    return _bytes_field(1, raw_bytes) + b"".join(_bytes_field(2, s) for s in signatures)


# ── read ──────────────────────────────────────────────────────────────────────────────────────────────────────────

# (field number, wire type, value): an int for wire type 0, bytes for wire type 2.
_Field = tuple[int, int, int | bytes]


def _fields_of(b: bytes) -> list[_Field] | None:
    """The fields of one message, in the order written; None when the bytes are not well formed."""
    fields: list[_Field] = []
    i = 0

    def varint() -> int | None:
        nonlocal i
        v = 0
        for shift in range(0, 70, 7):
            if i >= len(b):
                return None
            c = b[i]
            i += 1
            v |= (c & 0x7F) << shift
            if c & 0x80 == 0:
                return v if v < _UINT64_LIMIT else None
        return None

    while i < len(b):
        key = varint()
        if key is None or key > 0xFFFFFFFF:
            return None
        no, wire = key >> 3, key & 7
        if no == 0:
            return None
        if wire == 0:
            v = varint()
            if v is None:
                return None
            fields.append((no, 0, v))
        elif wire == 2:
            length = varint()
            if length is None or length > len(b) - i:
                return None
            fields.append((no, 2, b[i : i + length]))
            i += length
        else:
            return None
    return fields


def decode_tron_tx(text: object) -> tuple[TronRaw, bytes, list[bytes]] | Refusal:
    """A signed Transaction from lowercase hex: raw_data with exactly one TriggerSmartContract and only the fields
    TronRaw names, and 1 to 5 signatures of 65 bytes. The raw bytes must be exactly what encode_tron_raw writes for the
    fields read."""
    if not isinstance(text, str):
        return Refusal("tron/tx-malformed")
    if len(text) > MAX_TX_HEX:
        return Refusal("tron/tx-too-large")
    if len(text) == 0 or len(text) % 2 != 0 or not set(text) <= _LOWER_HEX:
        return Refusal("tron/tx-malformed")
    outer = _fields_of(bytes.fromhex(text))
    if outer is None:
        return Refusal("tron/tx-malformed")
    raw_bytes: bytes | None = None
    signatures: list[bytes] = []
    for no, wire, value in outer:
        if no == 1 and wire == 2 and raw_bytes is None and isinstance(value, bytes):
            raw_bytes = value
        elif no == 2 and wire == 2 and isinstance(value, bytes):
            signatures.append(value)
        else:
            return Refusal("tron/tx-malformed")
    if raw_bytes is None:
        return Refusal("tron/tx-malformed")
    if not 1 <= len(signatures) <= MAX_SIGNATURES or any(len(s) != SIGNATURE_BYTES for s in signatures):
        return Refusal("tron/signature-malformed")
    raw = decode_raw(raw_bytes)
    if isinstance(raw, Refusal):
        return raw
    return raw, raw_bytes, signatures


def decode_raw(raw_bytes: bytes) -> TronRaw | Refusal:
    fields = _fields_of(raw_bytes)
    if fields is None:
        return Refusal("tron/tx-malformed")
    raw = TronRaw()
    contracts: list[bytes] = []
    for no, wire, value in fields:
        if wire == 2 and isinstance(value, bytes) and no in (1, 4, 10, 11):
            if no == 1:
                raw = replace(raw, ref_block_bytes=value)
            elif no == 4:
                raw = replace(raw, ref_block_hash=value)
            elif no == 10:
                raw = replace(raw, data=value)
            else:
                contracts.append(value)
        elif wire == 0 and isinstance(value, int) and no in (8, 14, 18):
            if value >= INT64_LIMIT:
                return Refusal("tron/tx-malformed")
            if no == 8:
                raw = replace(raw, expiration=value)
            elif no == 14:
                raw = replace(raw, timestamp=value)
            else:
                raw = replace(raw, fee_limit=value)
        else:
            return Refusal("tron/tx-malformed")
    if len(contracts) != 1:
        return Refusal("tron/contracts")

    contract = _fields_of(contracts[0])
    if contract is None:
        return Refusal("tron/tx-malformed")
    kind = 0
    any_value: bytes | None = None
    for no, wire, value in contract:
        if no == 1 and wire == 0 and isinstance(value, int):
            kind = value
        elif no == 2 and wire == 2 and isinstance(value, bytes):
            any_value = value
        else:
            return Refusal("tron/tx-malformed")
    if kind != TRIGGER_SMART_CONTRACT or any_value is None:
        return Refusal("tron/not-trigger")
    any_fields = _fields_of(any_value)
    if any_fields is None:
        return Refusal("tron/tx-malformed")
    url: bytes | None = None
    trigger_bytes: bytes | None = None
    for no, wire, value in any_fields:
        if no == 1 and wire == 2 and isinstance(value, bytes):
            url = value
        elif no == 2 and wire == 2 and isinstance(value, bytes):
            trigger_bytes = value
        else:
            return Refusal("tron/tx-malformed")
    if url != TRIGGER_URL:
        return Refusal("tron/not-trigger")
    trigger = _fields_of(trigger_bytes if trigger_bytes is not None else b"")
    if trigger is None:
        return Refusal("tron/tx-malformed")
    for no, wire, value in trigger:
        if wire == 2 and isinstance(value, bytes) and no in (1, 2, 4):
            if no == 1:
                raw = replace(raw, owner=value)
            elif no == 2:
                raw = replace(raw, contract_address=value)
            else:
                raw = replace(raw, call_data=value)
        else:
            return Refusal("tron/tx-malformed")
    if encode_tron_raw(raw) != raw_bytes:
        return Refusal("tron/raw-not-canonical")
    return raw


# ── addresses ─────────────────────────────────────────────────────────────────────────────────────────────────────


def base58_shape(address: object) -> bytes | None:
    """The 25 decoded bytes of a base58 string of 34 characters whose first byte is 0x41, or None."""
    if not isinstance(address, str) or len(address) != 34:
        return None
    b = b58_decode(address)
    return b if b is not None and len(b) == 25 and b[0] == 0x41 else None


def tron_address(address: object) -> bytes | Refusal:
    """A base58check address as its 21 bytes, which begin 0x41. The checksum is SHA-256 twice."""
    b = base58_shape(address)
    if b is None:
        return Refusal("tron/address-malformed")
    payload = b[:21]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != b[21:25]:
        return Refusal("tron/address-malformed")
    return payload
