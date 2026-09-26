"""Algorand encodings the buyer half writes and reads: canonical msgpack (keys sorted, empty values omitted, integers in
their smallest form), base32 addresses with their SHA-512/256 checksum, the fee rule, the group id, the bytes a
transaction is signed over, and a signed transaction's type and note.
"""

import base64
import binascii
import hashlib
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

ADDRESS_LENGTH = 58
# msgpack arrays and maps nest at most MAX_DEPTH levels, the outermost container being level 1.
MAX_DEPTH = 32
# The bytes a signature and its key add to a transaction's encoded length.
SIGNATURE_OVERHEAD = 75
TRANSACTION_TYPES = frozenset({"pay", "keyreg", "acfg", "axfer", "afrz", "appl", "stpf", "hb"})
_BASE32 = re.compile(r"[A-Z2-7]*")


class Malformed(Exception):
    """The bytes are not a msgpack value, or not a signed transaction."""


def sha512_256(data: bytes) -> bytes:
    return hashlib.new("sha512_256", data).digest()


# ── msgpack ──────────────────────────────────────────────────────────────────────────────────────────────────────


def _uint(value: int) -> bytes:
    if value >= 1 << 64:
        raise ValueError("above uint64")
    if value < 0x80:
        return bytes([value])
    if value < 0x100:
        return b"\xcc" + bytes([value])
    if value < 0x10000:
        return b"\xcd" + value.to_bytes(2, "big")
    if value < 0x100000000:
        return b"\xce" + value.to_bytes(4, "big")
    return b"\xcf" + value.to_bytes(8, "big")


def _sized(length: int, fix: tuple[int, int] | None, codes: tuple[int, int, int]) -> bytes:
    """A length header: the fix form when it fits, else the 8-, 16- or 32-bit form; a code of 0 is a form the type
    does not have."""
    if fix is not None and length < fix[1]:
        return bytes([fix[0] | length])
    for code, width in zip(codes, (1, 2, 4)):
        if code and length < 1 << (8 * width):
            return bytes([code]) + length.to_bytes(width, "big")
    raise ValueError("too long")


def pack(value: Any) -> bytes:
    """Canonical msgpack: map keys sorted, integers in their smallest form."""
    if isinstance(value, bool):
        return b"\xc3" if value else b"\xc2"
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative")
        return _uint(value)
    if isinstance(value, (bytes, bytearray)):
        return _sized(len(value), None, (0xC4, 0xC5, 0xC6)) + bytes(value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _sized(len(data), (0xA0, 32), (0xD9, 0xDA, 0xDB)) + data
    if isinstance(value, Mapping):
        keys = sorted(value)
        return _sized(len(keys), (0x80, 16), (0, 0xDE, 0xDF)) + b"".join(pack(k) + pack(value[k]) for k in keys)
    if isinstance(value, Sequence):
        return _sized(len(value), (0x90, 16), (0, 0xDC, 0xDD)) + b"".join(pack(v) for v in value)
    raise TypeError("not packable")


@dataclass(frozen=True, slots=True)
class Ext:
    """A msgpack extension value."""

    code: int
    data: bytes


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def read(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise Malformed
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def int(self, width: int, signed: bool = False) -> int:
        return int.from_bytes(self.read(width), "big", signed=signed)


def _text(data: bytes) -> str:
    """UTF-8, with each ill-formed sequence replaced by U+FFFD."""
    return data.decode("utf-8", errors="replace")


def _container(depth: int) -> None:
    """An array or map inside depth others: it is level depth + 1, at most MAX_DEPTH."""
    if depth + 1 > MAX_DEPTH:
        raise Malformed


def _unpack(r: _Reader, depth: int) -> Any:
    """One value inside depth arrays and maps."""
    b = r.int(1)
    if b < 0x80:
        return b
    if b >= 0xE0:
        return b - 0x100
    if 0x80 <= b <= 0x8F:
        return _map(r, b & 0x0F, depth)
    if 0x90 <= b <= 0x9F:
        _container(depth)
        return [_unpack(r, depth + 1) for _ in range(b & 0x0F)]
    if 0xA0 <= b <= 0xBF:
        return _text(r.read(b & 0x1F))
    if b == 0xC0:
        return None
    if b in (0xC2, 0xC3):
        return b == 0xC3
    sized = {0xC4: 1, 0xC5: 2, 0xC6: 4}
    if b in sized:
        return r.read(r.int(sized[b]))
    if b == 0xCA:
        return struct.unpack(">f", r.read(4))[0]
    if b == 0xCB:
        return struct.unpack(">d", r.read(8))[0]
    unsigned = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}
    if b in unsigned:
        return r.int(unsigned[b])
    signed = {0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}
    if b in signed:
        return r.int(signed[b], signed=True)
    fixext = {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}
    if b in fixext:
        return Ext(r.int(1, signed=True), r.read(fixext[b]))
    ext = {0xC7: 1, 0xC8: 2, 0xC9: 4}
    if b in ext:
        length = r.int(ext[b])
        return Ext(r.int(1, signed=True), r.read(length))
    text = {0xD9: 1, 0xDA: 2, 0xDB: 4}
    if b in text:
        return _text(r.read(r.int(text[b])))
    if b in (0xDC, 0xDD):
        count = r.int(2 if b == 0xDC else 4)
        _container(depth)
        return [_unpack(r, depth + 1) for _ in range(count)]
    if b in (0xDE, 0xDF):
        return _map(r, r.int(2 if b == 0xDE else 4), depth)
    raise Malformed


def _map(r: _Reader, count: int, depth: int) -> dict[Any, Any]:
    _container(depth)
    out: dict[Any, Any] = {}
    for _ in range(count):
        key = _unpack(r, depth + 1)
        if isinstance(key, bool) or not isinstance(key, (str, int, float, bytes)):
            raise Malformed
        out[key] = _unpack(r, depth + 1)
    return out


def unpack(data: bytes) -> Any:
    """One msgpack value that is the whole of data."""
    r = _Reader(data)
    value = _unpack(r, 0)
    if r.at != len(data):
        raise Malformed
    return value


# ── addresses ────────────────────────────────────────────────────────────────────────────────────────────────────


def encode_address(public_key: bytes) -> str:
    """Base32 of the 32-byte key and the last 4 bytes of its SHA-512/256, without padding."""
    return base64.b32encode(public_key + sha512_256(public_key)[-4:]).decode("ascii").rstrip("=")[:ADDRESS_LENGTH]


def decode_address(address: object) -> bytes | None:
    """The 32-byte key of a 58-character address whose checksum holds, or None."""
    if not isinstance(address, str) or len(address) != ADDRESS_LENGTH or _BASE32.fullmatch(address) is None:
        return None
    try:
        raw = base64.b32decode(address + "======")
    except binascii.Error:
        return None
    key, checksum = raw[:32], raw[32:36]
    return key if len(raw) == 36 and sha512_256(key)[-4:] == checksum else None


def is_address(value: object) -> bool:
    return decode_address(value) is not None


# ── transactions ─────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Params:
    """The rounds, the genesis, and the fee: flat, or per byte with a minimum."""

    first_valid: int
    last_valid: int
    genesis_id: str
    genesis_hash: bytes
    fee: int
    flat: bool
    min_fee: int


def _fields(common: dict[str, Any], specific: dict[str, Any]) -> dict[str, Any]:
    """The transaction's msgpack map: empty values omitted."""
    out: dict[str, Any] = {}
    for key, value in {**common, **specific}.items():
        if value is None or value == 0 or value == b"" or value == "" or value is False or value == bytes(32):
            continue
        out[key] = value
    return out


class Transaction:
    """A pay or axfer transaction with its fee set by the fee rule: flat, or the per-byte fee times the encoded length
    plus the signature's bytes, raised to the minimum."""

    def __init__(self, kind: str, sender: bytes, params: Params, note: bytes, specific: dict[str, Any]) -> None:
        self.kind = kind
        self.sender = sender
        self.params = params
        self.note = note
        self.specific = specific
        for value in (params.first_valid, params.last_valid, params.fee):
            if value >= 1 << 64:
                raise ValueError("above uint64")
        self.group: bytes | None = None
        self.fee = params.fee
        if not params.flat:
            self.fee = params.fee * (len(self.encoded()) + SIGNATURE_OVERHEAD)
            if self.fee < params.min_fee:
                self.fee = params.min_fee

    def fields(self) -> dict[str, Any]:
        common = {
            "type": self.kind,
            "fv": self.params.first_valid,
            "lv": self.params.last_valid,
            "snd": self.sender,
            "gen": self.params.genesis_id,
            "gh": self.params.genesis_hash,
            "fee": self.fee,
            "note": self.note,
            "grp": self.group,
        }
        return _fields(common, self.specific)

    def encoded(self) -> bytes:
        return pack(self.fields())

    def bytes_to_sign(self) -> bytes:
        return b"TX" + self.encoded()

    def raw_id(self) -> bytes:
        return sha512_256(self.bytes_to_sign())

    def signed(self, signature: bytes | None) -> bytes:
        """The msgpack SignedTxn: {sig, txn}, or {txn} unsigned."""
        wrapper: dict[str, Any] = {"txn": self.fields()}
        if signature is not None:
            wrapper["sig"] = signature
        return pack(wrapper)


def axfer(sender: bytes, receiver: bytes, asset: int, amount: int, note: bytes, params: Params) -> Transaction:
    """An asset transfer; asset 0 names no asset and raises ValueError."""
    if asset == 0:
        raise ValueError("no asset")
    return Transaction("axfer", sender, params, note, {"xaid": asset, "aamt": amount, "arcv": receiver})


def zero_pay(sender: bytes, params: Params) -> Transaction:
    """A payment of 0 from sender to itself."""
    return Transaction("pay", sender, params, b"", {"amt": 0, "rcv": sender})


def group_id(transactions: Sequence[Transaction]) -> bytes:
    """SHA-512/256 of TG and the msgpack {txlist: [each transaction's id]}."""
    return sha512_256(b"TG" + pack({"txlist": [t.raw_id() for t in transactions]}))


# ── reading a signed transaction ─────────────────────────────────────────────────────────────────────────────────

# A schema is a kind: "u64", "str", "bytes", "addr", "bool", ("fixed", n), ("opt", schema), ("list", schema),
# ("map", {key: schema}), or "any" for a value not checked here.
Schema = Any

_OPT_U64 = ("opt", "u64")
_OPT_ADDR = ("opt", "addr")
_OPT_FIXED32 = ("opt", ("fixed", 32))
_COUNTS = ("opt", ("map", {"nui": "u64", "nbs": "u64"}))
_BOX = ("map", {"i": "u64", "n": "bytes"})

# The transaction fields and their kinds; a key not named here is not read.
TXN_SCHEMA: dict[str, Schema] = {
    "type": "str", "snd": "addr", "lv": "u64", "gen": ("opt", "str"), "gh": _OPT_FIXED32, "fee": "u64",
    "fv": "u64", "note": "bytes", "lx": _OPT_FIXED32, "rekey": _OPT_ADDR, "grp": _OPT_FIXED32,
    "amt": _OPT_U64, "rcv": _OPT_ADDR, "close": _OPT_ADDR,
    "votekey": _OPT_FIXED32, "selkey": _OPT_FIXED32, "sprfkey": ("opt", ("fixed", 64)), "votefst": _OPT_U64,
    "votelst": _OPT_U64, "votekd": _OPT_U64, "nonpart": ("opt", "bool"),
    "caid": _OPT_U64,
    "apar": ("opt", ("map", {
        "t": "u64", "dc": "u64", "df": "bool", "m": _OPT_ADDR, "r": _OPT_ADDR, "f": _OPT_ADDR, "c": _OPT_ADDR,
        "un": ("opt", "str"), "an": ("opt", "str"), "au": ("opt", "str"), "am": _OPT_FIXED32,
    })),
    "xaid": _OPT_U64, "aamt": _OPT_U64, "arcv": _OPT_ADDR, "aclose": _OPT_ADDR, "asnd": _OPT_ADDR,
    "faid": _OPT_U64, "afrz": ("opt", "bool"), "fadd": _OPT_ADDR,
    "apid": _OPT_U64, "apan": _OPT_U64, "apaa": ("opt", ("list", "bytes")), "apat": ("opt", ("list", "addr")),
    "apas": ("opt", ("list", "u64")), "apfa": ("opt", ("list", "u64")), "apbx": ("opt", ("list", _BOX)),
    "al": ("opt", ("list", ("map", {
        "d": _OPT_ADDR, "s": _OPT_U64, "p": _OPT_U64,
        "h": ("opt", ("map", {"d": "u64", "s": "u64"})), "l": ("opt", ("map", {"d": "u64", "p": "u64"})),
        "b": ("opt", _BOX),
    }))),
    "apap": ("opt", "bytes"), "apsu": ("opt", "bytes"), "apls": _COUNTS, "apgs": _COUNTS, "apep": _OPT_U64,
    "aprv": _OPT_U64, "sptype": _OPT_U64, "sp": "any", "spmsg": "any", "hb": "any",
}  # fmt: skip


def _is_uint64(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, float):
        return value.is_integer() and 0 <= value <= 2**53 - 1
    return isinstance(value, int) and 0 <= value < 2**64


def _check(value: Any, schema: Schema) -> None:
    """Raises Malformed when value is not of the schema's kind."""
    if schema == "any":
        return
    if isinstance(schema, tuple) and schema[0] == "opt":
        if value is not None:
            _check(value, schema[1])
        return
    ok = (
        (schema == "u64" and _is_uint64(value))
        or (schema == "str" and isinstance(value, str))
        or (schema == "bytes" and isinstance(value, bytes))
        or (schema == "addr" and isinstance(value, bytes) and len(value) == 32)
        or (schema == "bool" and isinstance(value, bool))
        or (isinstance(schema, tuple) and schema[0] == "fixed" and isinstance(value, bytes) and len(value) == schema[1])
        or (isinstance(schema, tuple) and schema[0] == "list" and isinstance(value, list))
        or (isinstance(schema, tuple) and schema[0] == "map" and isinstance(value, dict))
    )
    if not ok:
        raise Malformed
    if isinstance(schema, tuple) and schema[0] == "list":
        for item in value:
            _check(item, schema[1])
    elif isinstance(schema, tuple) and schema[0] == "map":
        for key, inner in schema[1].items():
            if key in value:
                _check(value[key], inner)


@dataclass(frozen=True, slots=True)
class SignedRead:
    kind: str
    note: bytes


def read_signed(data: bytes) -> SignedRead:
    """The type and note of a msgpack SignedTxn: at most one of sig, msig, lsig and pqsig, and a transaction whose
    fields are of their schema's kinds. The multisig, logic-signature and state-proof values are not read. Raises
    Malformed for anything that does not decode as one."""
    top = unpack(data)
    if not isinstance(top, dict):
        raise Malformed
    sig = top.get("sig")
    if sig is not None and not (isinstance(sig, bytes) and len(sig) == 64):
        raise Malformed
    if sum(top.get(k) is not None for k in ("sig", "msig", "lsig", "pqsig")) > 1:
        raise Malformed
    sgnr = top.get("sgnr")
    if sgnr is not None and not (isinstance(sgnr, bytes) and len(sgnr) == 32):
        raise Malformed
    txn = top.get("txn")
    _check(txn, ("map", TXN_SCHEMA))
    assert isinstance(txn, dict)
    if txn.get("type") not in TRANSACTION_TYPES:
        raise Malformed
    note = txn.get("note", b"")
    return SignedRead(kind=txn["type"], note=note if isinstance(note, bytes) else b"")
