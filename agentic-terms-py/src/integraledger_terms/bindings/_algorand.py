"""Algorand encodings the buyer half writes and reads: canonical msgpack (keys sorted, empty values omitted, integers in
their smallest form), base32 addresses with their SHA-512/256 checksum, the fee rule, the group id, the bytes a
transaction is signed over, and a payment entry read as the x402 path reads it.

On the x402 path a payment entry has two readers. The x402 reference facilitator decodes it with algokit-utils'
decodeSignedTransaction, then submits the entry's own bytes, which algod decodes with go-codec and checks with
Transaction.WellFormed. read_signed follows both, from the same bytes, and reads the entry only when both accept it and
both read the same signed transaction.
"""

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

ADDRESS_LENGTH = 58
# msgpack arrays and maps nest at most MAX_DEPTH levels, the outermost container being level 1.
MAX_DEPTH = 32
# The bytes a signature and its key add to a transaction's encoded length.
SIGNATURE_OVERHEAD = 75
_BASE32 = re.compile(r"[A-Z2-7]*")


class Malformed(Exception):
    """The bytes are not one msgpack value within the caps, or not a payment entry both readers of the x402 path read
    as the same signed transaction."""


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


def _str(data: bytes) -> bytes:
    return _sized(len(data), (0xA0, 32), (0xD9, 0xDA, 0xDB)) + data


def _bin(data: bytes) -> bytes:
    return _sized(len(data), None, (0xC4, 0xC5, 0xC6)) + data


def _array_head(count: int) -> bytes:
    return _sized(count, (0x90, 16), (0, 0xDC, 0xDD))


def _map_head(count: int) -> bytes:
    return _sized(count, (0x80, 16), (0, 0xDE, 0xDF))


def pack(value: Any) -> bytes:
    """Canonical msgpack: map keys sorted, integers in their smallest form."""
    if isinstance(value, bool):
        return b"\xc3" if value else b"\xc2"
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negative")
        return _uint(value)
    if isinstance(value, (bytes, bytearray)):
        return _bin(bytes(value))
    if isinstance(value, str):
        return _str(value.encode("utf-8"))
    if isinstance(value, Mapping):
        keys = sorted(value)
        return _map_head(len(keys)) + b"".join(pack(k) + pack(value[k]) for k in keys)
    if isinstance(value, Sequence):
        return _array_head(len(value)) + b"".join(pack(v) for v in value)
    raise TypeError("not packable")


@dataclass(frozen=True, slots=True)
class Node:
    """One msgpack value as the specification's formats spell it. An integer keeps its value and its first byte, which
    tells a fixint and a 64-bit format apart; a bool's value is 1 or 0; a str and a bin keep their bytes; a map keeps
    its entries in the order written, a repeated key included."""

    kind: Literal["nil", "bool", "int", "float", "ext", "str", "bin", "array", "map"]
    value: int = 0
    head: int = 0
    data: bytes = b""
    items: tuple["Node", ...] = ()
    entries: tuple[tuple["Node", "Node"], ...] = ()


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


_STR = {0xD9: 1, 0xDA: 2, 0xDB: 4}
_BIN = {0xC4: 1, 0xC5: 2, 0xC6: 4}
_EXT = {0xC7: 1, 0xC8: 2, 0xC9: 4}
_FIXEXT = {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}
_UNSIGNED = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}
_SIGNED = {0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}


def _container(r: _Reader, kind: Literal["array", "map"], count: int, depth: int) -> Node:
    """An array or map inside depth others: it is level depth + 1, at most MAX_DEPTH, and declares no more items than
    the bytes left."""
    values = 2 * count if kind == "map" else count
    if depth + 1 > MAX_DEPTH or values > len(r.data) - r.at:
        raise Malformed
    items = tuple(_unpack(r, depth + 1) for _ in range(values))
    if kind == "array":
        return Node("array", items=items)
    return Node("map", entries=tuple(zip(items[0::2], items[1::2])))


def _unpack(r: _Reader, depth: int) -> Node:
    """One value inside depth arrays and maps."""
    b = r.int(1)
    if b < 0x80:
        return Node("int", b, b)
    if b >= 0xE0:
        return Node("int", b - 0x100, b)
    if b <= 0x8F:
        return _container(r, "map", b & 0x0F, depth)
    if b <= 0x9F:
        return _container(r, "array", b & 0x0F, depth)
    if b <= 0xBF:
        return Node("str", data=r.read(b & 0x1F))
    if b == 0xC0:
        return Node("nil")
    if b in (0xC2, 0xC3):
        return Node("bool", int(b == 0xC3))
    if b in _STR:
        return Node("str", data=r.read(r.int(_STR[b])))
    if b in _BIN:
        return Node("bin", data=r.read(r.int(_BIN[b])))
    if b in _EXT:
        r.read(r.int(_EXT[b]) + 1)
        return Node("ext")
    if b in _FIXEXT:
        r.read(_FIXEXT[b] + 1)
        return Node("ext")
    if b in (0xCA, 0xCB):
        r.read(4 if b == 0xCA else 8)
        return Node("float")
    if b in _UNSIGNED:
        return Node("int", r.int(_UNSIGNED[b]), b)
    if b in _SIGNED:
        return Node("int", r.int(_SIGNED[b], signed=True), b)
    if b in (0xDC, 0xDD):
        return _container(r, "array", r.int(2 if b == 0xDC else 4), depth)
    if b in (0xDE, 0xDF):
        return _container(r, "map", r.int(2 if b == 0xDE else 4), depth)
    raise Malformed


def unpack(data: bytes) -> Node:
    """data as exactly one msgpack value whose arrays and maps nest at most MAX_DEPTH deep and whose every declared
    length is no more than the bytes that remain; Malformed for any other input, the unused byte C1 included. A
    string's bytes, a key and a format are not judged here: read_signed reads each member as its type is read."""
    r = _Reader(data)
    value = _unpack(r, 0)
    if r.at != len(data):
        raise Malformed
    return value


# ── addresses ────────────────────────────────────────────────────────────────────────────────────────────────────


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


# ── algod's reader ───────────────────────────────────────────────────────────────────────────────────────────────
# go-codec v1.1.10 under go-algorand's CodecHandle (ErrorIfNoField, ErrorIfNoArrayExpand), over the SignedTxn type tree
# of go-algorand v5.0.3, and the type rules of Transaction.WellFormed.


@dataclass(frozen=True, slots=True)
class _Kind:
    """A member's Go type: uint (of bits), bool, string, bytes ([]byte), fixed ([n]byte), slice (of), uintmap (a map
    from uint64 to the struct of), ptr (to the struct of), or struct, whose fields are its members in source order,
    the order go-codec reads a struct written as an array."""

    t: Literal["uint", "bool", "string", "bytes", "fixed", "slice", "uintmap", "ptr", "struct"]
    bits: int = 0
    n: int = 0
    of: "_Kind | None" = None
    fields: tuple[tuple[str, "_Kind"], ...] = ()
    from_array: bool = True


_U8, _U16, _U32, _U64 = _Kind("uint", bits=8), _Kind("uint", bits=16), _Kind("uint", bits=32), _Kind("uint", bits=64)
_BOOL, _STRING, _BYTES = _Kind("bool"), _Kind("string"), _Kind("bytes")


def _fixed(n: int) -> _Kind:
    return _Kind("fixed", n=n)


def _slice(of: _Kind) -> _Kind:
    return _Kind("slice", of=of)


def _struct(*fields: tuple[str, _Kind], from_array: bool = True) -> _Kind:
    return _Kind("struct", fields=fields, from_array=from_array)


_ADDRESS = _fixed(32)
_MULTISIG = _struct(("v", _U8), ("thr", _U8), ("subsig", _slice(_struct(("pk", _fixed(32)), ("s", _fixed(64))))))
_PQSIG = _struct(("sch", _fixed(2)), ("slt", _U8), ("pk", _BYTES), ("sig", _BYTES))
_LOGICSIG = _struct(
    ("l", _BYTES), ("sig", _fixed(64)), ("msig", _MULTISIG), ("lmsig", _MULTISIG), ("pqsig", _PQSIG),
    ("arg", _slice(_BYTES)),
)  # fmt: skip
_STATE_SCHEMA = _struct(("nui", _U64), ("nbs", _U64))
_BOX_REF = _struct(("i", _U64), ("n", _BYTES))
_PROOF = _struct(("pth", _slice(_BYTES)), ("hsh", _struct(("t", _U16))), ("td", _U8))
_REVEAL = _struct(
    ("s", _struct(
        ("s", _struct(("sig", _BYTES), ("idx", _U64), ("prf", _PROOF), ("vkey", _struct(("k", _fixed(1793)))))),
        ("l", _U64),
    )),
    ("p", _struct(("p", _struct(("cmt", _fixed(64)), ("lf", _U64))), ("w", _U64))),
)  # fmt: skip
_HEARTBEAT = _struct(
    ("a", _ADDRESS),
    ("prf", _struct(
        ("s", _fixed(64)), ("p", _fixed(32)), ("p2", _fixed(32)), ("p1s", _fixed(64)), ("p2s", _fixed(64)),
    )),
    ("sd", _fixed(32)), ("vid", _fixed(32)), ("kd", _U64), ("c", _BOOL),
)  # fmt: skip

# Each transaction type's own members, as WellFormed groups them.
TYPE_FIELDS: dict[str, tuple[tuple[str, _Kind], ...]] = {
    "keyreg": (
        ("votekey", _fixed(32)), ("selkey", _fixed(32)), ("sprfkey", _fixed(64)), ("votefst", _U64),
        ("votelst", _U64), ("votekd", _U64), ("nonpart", _BOOL),
    ),
    "pay": (("rcv", _ADDRESS), ("amt", _U64), ("close", _ADDRESS)),
    "acfg": (
        ("caid", _U64),
        ("apar", _struct(
            ("t", _U64), ("dc", _U32), ("df", _BOOL), ("un", _STRING), ("an", _STRING), ("au", _STRING),
            ("am", _fixed(32)), ("m", _ADDRESS), ("r", _ADDRESS), ("f", _ADDRESS), ("c", _ADDRESS),
        )),
    ),
    "axfer": (("xaid", _U64), ("aamt", _U64), ("asnd", _ADDRESS), ("arcv", _ADDRESS), ("aclose", _ADDRESS)),
    "afrz": (("fadd", _ADDRESS), ("faid", _U64), ("afrz", _BOOL)),
    "appl": (
        ("apid", _U64), ("apan", _U64), ("apaa", _slice(_BYTES)), ("apat", _slice(_ADDRESS)), ("apas", _slice(_U64)),
        ("apfa", _slice(_U64)),
        ("al", _slice(_struct(
            ("d", _ADDRESS), ("s", _U64), ("p", _U64), ("h", _struct(("d", _U64), ("s", _U64))),
            ("l", _struct(("d", _U64), ("p", _U64))), ("b", _BOX_REF),
        ))),
        ("apbx", _slice(_BOX_REF)), ("apls", _STATE_SCHEMA), ("apgs", _STATE_SCHEMA), ("apap", _BYTES),
        ("apsu", _BYTES), ("apep", _U32), ("aprv", _U64),
    ),
    "stpf": (
        ("sptype", _U64),
        ("sp", _struct(
            ("c", _BYTES), ("w", _U64), ("S", _PROOF), ("P", _PROOF), ("v", _U8),
            ("r", _Kind("uintmap", of=_REVEAL)), ("pr", _slice(_U64)),
        )),
        ("spmsg", _struct(("b", _BYTES), ("v", _BYTES), ("P", _U64), ("f", _U64), ("l", _U64))),
    ),
    "hb": (("hb", _Kind("ptr", of=_HEARTBEAT)),),
}  # fmt: skip
_HEADER: tuple[tuple[str, _Kind], ...] = (
    ("type", _STRING), ("snd", _ADDRESS), ("fee", _U64), ("fv", _U64), ("lv", _U64), ("note", _BYTES),
    ("gen", _STRING), ("gh", _fixed(32)), ("grp", _fixed(32)), ("lx", _fixed(32)), ("rekey", _ADDRESS),
)  # fmt: skip
# The transaction, its embedded structs' members flattened into one map. Written as an array it is refused wherever it
# occurs: the facilitator's decoder reads a last txn written as an array as a transaction with no type and refuses it,
# and an earlier one, which both readers read under a later map, is refused too, so a transaction has one form.
TRANSACTION = _struct(*_HEADER, *(f for fields in TYPE_FIELDS.values() for f in fields), from_array=False)
# The signed transaction. Written as an array it is refused: the facilitator's decoder reads it with no transaction.
SIGNED_TXN = _struct(
    ("sig", _fixed(64)), ("msig", _MULTISIG), ("lsig", _LOGICSIG), ("pqsig", _PQSIG), ("txn", TRANSACTION),
    ("sgnr", _ADDRESS), from_array=False,
)  # fmt: skip


def _of(kind: _Kind) -> _Kind:
    assert kind.of is not None
    return kind.of


def _zero_of(kind: _Kind) -> Any:
    if kind.t == "uint":
        return 0
    if kind.t == "bool":
        return False
    if kind.t == "string":
        return b""
    if kind.t == "fixed":
        return bytes(kind.n)
    if kind.t == "struct":
        return {name: _zero_of(k) for name, k in kind.fields}
    return None


def _is_zero(kind: _Kind, v: Any) -> bool:
    """msgp's MsgIsZero: an empty slice, map or byte string is zero whether or not it is nil."""
    if kind.t in ("uint", "bool"):
        return not v
    if kind.t == "fixed":
        return not any(v)
    if kind.t in ("string", "bytes", "slice", "uintmap"):
        return v is None or len(v) == 0
    if kind.t == "ptr":
        return v is None
    return all(_is_zero(k, v[name]) for name, k in kind.fields)


def _uint_of(node: Node, bits: int) -> int:
    """A non-negative integer below 2^bits (go-codec's DecodeUint64 with its overflow check)."""
    if node.kind != "int" or node.value < 0 or node.value >= 1 << bits:
        raise Malformed
    return node.value


def _bytes_from_items(items: Sequence[Node]) -> bytes:
    """Bytes from an array of uint8 values (a map's keys and values in turn), each nil being 0."""
    return bytes(0 if x.kind == "nil" else _uint_of(x, 8) for x in items)


def _items_of(node: Node) -> tuple[Node, ...] | None:
    if node.kind == "array":
        return node.items
    if node.kind == "map":
        return tuple(x for entry in node.entries for x in entry)
    return None


class _Slice(list[Any]):
    """A decoded slice, with the array behind it up to its capacity: its elements, then any an earlier occurrence
    left."""

    __slots__ = ("backing",)
    backing: list[Any]


def _member(kind: _Kind, key: Node) -> tuple[str, _Kind]:
    """The struct member a key names. decStructFieldKey reads a key as DecodeStringAsBytes does, a str, a bin or an
    array of uint8 values; an empty key panics in indexForEncName. A key that is not exactly a member's name is
    refused: ErrorIfNoField refuses most, and a key for which indexForEncName's search of its names table finds a member
    is refused too, so a member has one key."""
    if key.kind in ("str", "bin"):
        name = key.data
    elif key.kind == "array":
        name = _bytes_from_items(key.items)
    else:
        raise Malformed
    for field in kind.fields:
        if name and name == field[0].encode("ascii"):
            return field
    raise Malformed


def _decode_into(kind: _Kind, node: Node, cur: Any) -> Any:
    """node decoded into cur, a value of kind (go-codec's decodeValue). A struct decodes into the struct it updates, so
    a repeated member merges; a fixed-length byte array has only the bytes written replaced; a slice keeps and updates
    the elements it already has. Raises Malformed where go-codec refuses."""
    if kind.t == "uint":
        return _uint_of(node, kind.bits)
    if kind.t == "bool":
        # DecodeBool: true, false, or the positive fixint 0 or 1.
        if node.kind == "bool":
            return node.value == 1
        if node.kind == "int" and node.head in (0x00, 0x01):
            return node.head == 0x01
        raise Malformed
    if kind.t == "string":
        # DecodeString: a str, a bin, or an array of uint8 values.
        if node.kind in ("str", "bin"):
            return node.data
        if node.kind == "array":
            return _bytes_from_items(node.items)
        raise Malformed
    if kind.t in ("bytes", "fixed"):
        written: bytes
        if node.kind in ("str", "bin"):
            written = node.data
        else:
            items = _items_of(node)
            if items is None or (kind.t == "fixed" and len(items) > kind.n):
                raise Malformed
            written = _bytes_from_items(items)
        if kind.t == "bytes":
            return written
        written = written[: kind.n]
        return written + cur[len(written) :]
    if kind.t == "slice":
        items = _items_of(node)
        if items is None:
            raise Malformed
        # kSlice keeps the slice's array: items that fit its capacity decode into the elements already there, those an
        # earlier, longer occurrence left past the slice's length included; more items take a new array holding only
        # the slice's elements.
        of, old = _of(kind), cur
        kept: list[Any] = [] if old is None else old.backing if len(items) <= len(old.backing) else list(old)
        out = _Slice(
            _zero_of(of) if item.kind == "nil" else _decode_into(of, item, kept[j] if j < len(kept) else _zero_of(of))
            for j, item in enumerate(items)
        )
        out.backing = [*out, *kept[len(out) :]]
        return out
    if kind.t == "uintmap":
        if node.kind != "map":
            raise Malformed
        of, reveals = _of(kind), dict(cur or {})
        for key, value in node.entries:
            at = _uint_of(key, 64)
            prior = reveals.get(at, _zero_of(of))
            reveals[at] = _zero_of(of) if value.kind == "nil" else _decode_into(of, value, prior)
        return reveals
    if kind.t == "ptr":
        return _decode_into(_of(kind), node, _zero_of(_of(kind)) if cur is None else cur)
    fields = dict(cur)

    def put(name: str, k: _Kind, x: Node) -> None:
        fields[name] = _zero_of(k) if x.kind == "nil" else _decode_into(k, x, fields[name])

    if node.kind == "map":
        for key, x in node.entries:
            put(*_member(kind, key), x)
        return fields
    if node.kind == "array" and kind.from_array and len(node.items) <= len(kind.fields):
        for (name, k), x in zip(kind.fields, node.items):
            put(name, k, x)
        return fields
    raise Malformed


def _well_typed(txn: dict[str, Any]) -> str:
    """WellFormed's type rules: a type algod knows, and no member of another type at a non-zero value. Gives the
    type."""
    names = [t for t in TYPE_FIELDS if txn["type"] == t.encode("ascii")]
    if not names:
        raise Malformed
    for t, fields in TYPE_FIELDS.items():
        if t == names[0]:
            continue
        for name, k in fields:
            # ApplicationCallTxnFields.Empty: a slice or byte string is a member once it is not nil, even when empty.
            set_ = txn[name] is not None if t == "appl" and k.t in ("slice", "bytes") else not _is_zero(k, txn[name])
            if set_:
                raise Malformed
    return names[0]


# ── the canonical encoding ───────────────────────────────────────────────────────────────────────────────────────
# As go-algorand's generated MarshalMsg writes it and algorand-msgpack writes algokit's: each struct a map of its
# non-zero members in sorted key order, integers, strings and byte strings in their shortest form.


def _map_of(members: list[tuple[str, bytes]]) -> bytes:
    """A map of the members given, keys in byte order."""
    members.sort(key=lambda m: m[0])
    return _map_head(len(members)) + b"".join(_str(name.encode("ascii")) + v for name, v in members)


def _marshal(kind: _Kind, v: Any) -> bytes:
    """MarshalMsg of v, a value of kind."""
    if kind.t == "uint":
        return _uint(v)
    if kind.t == "bool":
        return b"\xc3" if v else b"\xc2"
    if kind.t == "string":
        return _str(v)
    if kind.t in ("bytes", "fixed"):
        return _bin(v or b"")
    if kind.t == "slice":
        return _array_head(len(v or ())) + b"".join(_marshal(_of(kind), x) for x in v or ())
    if kind.t == "uintmap":
        reveals = sorted((v or {}).items())
        return _map_head(len(reveals)) + b"".join(_uint(k) + _marshal(_of(kind), x) for k, x in reveals)
    if kind.t == "ptr":
        return _marshal(_of(kind), v)
    return _map_of([(name, _marshal(k, v[name])) for name, k in kind.fields if not _is_zero(k, v[name])])


# ── the facilitator's reader ─────────────────────────────────────────────────────────────────────────────────────
# algokit-utils 10.0.0-alpha.46's decodeSignedTransaction, then its re-encoding (encodeSignedTransaction).
# algorand-msgpack 1.1.0 decodes the entry with every str read as raw bytes, a key as raw bytes too, and maps as Maps;
# each struct is read from its members by name, the last of a repeated key winning, and a value that is not a map read
# as a struct with no members. Only an entry algod accepts reaches this reader, so every key here is a str or bin
# spelling a member's name: an unknown key, a key of another msgpack type, or a transaction type other than axfer is
# refused by algod first.


def _members_of(node: Node | None) -> dict[bytes, Node]:
    """A struct's members by name, the last of a repeated key winning; a value that is not a map has none."""
    if node is None or node.kind != "map":
        return {}
    return {key.data: x for key, x in node.entries if key.kind in ("str", "bin")}


def _absent(node: Node | None) -> bool:
    return node is None or node.kind == "nil"


def _raw(node: Node) -> bytes:
    if node.kind not in ("str", "bin"):
        raise Malformed
    return node.data


def _fac_uint(node: Node | None) -> int:
    """BigIntCodec: an integer, absent or nil being 0."""
    if node is None or node.kind == "nil":
        return 0
    if node.kind != "int":
        raise Malformed
    return node.value


def _fac_number(name: str, node: Node | None, members: list[tuple[str, bytes]]) -> bool:
    """NumberCodec, which keeps the decoded value: an integer written in a 64-bit format is a bigint, which is written
    back even when it is 0; any other integer is a number, written back unless it is 0. True when it is left out."""
    if node is None or node.kind == "nil":
        return True
    if node.kind != "int":
        raise Malformed
    wide = node.head in (0xCF, 0xD3)
    if node.value != 0 or wide:
        members.append((name, _uint(node.value)))
    return node.value == 0 and not wide


def _fac_fixed(name: str, n: int, node: Node | None, members: list[tuple[str, bytes]]) -> bool:
    """FixedBytesCodec: raw bytes of any length, written back unless they are that length and all zero."""
    if node is None or node.kind == "nil":
        return True
    b = _raw(node)
    if len(b) == n and not any(b):
        return True
    members.append((name, _bin(b)))
    return False


def _fac_bytes(name: str, node: Node | None, members: list[tuple[str, bytes]]) -> bool:
    """BytesCodec: raw bytes, written back unless empty."""
    if node is None or node.kind == "nil":
        return True
    b = _raw(node)
    if b:
        members.append((name, _bin(b)))
    return not b


def _fac_address(name: str, node: Node | None, members: list[tuple[str, bytes]]) -> bool:
    """AddressCodec: 32 raw bytes, or 58 bytes read as an address's text whose checksum holds; written back unless all
    zero."""
    if node is None or node.kind == "nil":
        return True
    b = _raw(node)
    key = b if len(b) == 32 else decode_address(b.decode("latin-1")) if len(b) == ADDRESS_LENGTH else None
    if key is None:
        raise Malformed
    if not any(key):
        return True
    members.append((name, _bin(key)))
    return False


def _fac_string(name: str, node: Node | None, members: list[tuple[str, bytes]]) -> bool:
    """StringCodec: raw bytes read as text with Node's Buffer#toString("utf-8"), which keeps a leading mark and reads a
    sequence that is not UTF-8 as U+FFFD, written back unless empty. Bytes that are UTF-8 (RFC 3629) are written back as
    they are; any others the facilitator writes back as other bytes than algod reads, so the two read different
    transactions."""
    if node is None or node.kind == "nil":
        return True
    b = _raw(node)
    if not b:
        return True
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        raise Malformed from None
    members.append((name, _str(b)))
    return False


def _fac_multisig(node: Node) -> bytes | None:
    """The multisignature codec; None when every member is at its default and the struct is left out."""
    m = _members_of(node)
    members: list[tuple[str, bytes]] = []
    v = _fac_number("v", m.get(b"v"), members)
    zero = _fac_number("thr", m.get(b"thr"), members) and v
    subsig = m.get(b"subsig")
    if subsig is not None and subsig.kind != "nil":
        if subsig.kind != "array":
            raise Malformed
        if subsig.items:
            zero = False
            items = []
            for item in subsig.items:
                s = _members_of(None if _absent(item) else item)
                fields: list[tuple[str, bytes]] = []
                _fac_fixed("pk", 32, s.get(b"pk"), fields)
                _fac_fixed("s", 64, s.get(b"s"), fields)
                items.append(_map_of(fields))
            members.append(("subsig", _array_head(len(items)) + b"".join(items)))
    return None if zero else _map_of(members)


def _facilitator_encoding(root: Node) -> bytes:
    """The facilitator's re-encoding of the signed transaction it reads; Malformed where it refuses."""
    if root.kind == "nil":
        raise Malformed
    m = _members_of(root)
    members: list[tuple[str, bytes]] = []
    _fac_fixed("sig", 64, m.get(b"sig"), members)
    _fac_address("sgnr", m.get(b"sgnr"), members)
    msig = m.get(b"msig")
    if msig is not None and msig.kind != "nil":
        encoded = _fac_multisig(msig)
        if encoded is not None:
            members.append(("msig", encoded))
    lsig = m.get(b"lsig")
    if lsig is not None and lsig.kind != "nil":
        lm = _members_of(lsig)
        fields: list[tuple[str, bytes]] = []
        logic = _fac_bytes("l", lm.get(b"l"), fields)
        zero = _fac_fixed("sig", 64, lm.get(b"sig"), fields) and logic
        for name in ("msig", "lmsig"):
            inner = lm.get(name.encode("ascii"))
            if inner is None or inner.kind == "nil":
                continue
            encoded = _fac_multisig(inner)
            if encoded is not None:
                fields.append((name, encoded))
                zero = False
        arg = lm.get(b"arg")
        if arg is not None and arg.kind != "nil":
            if arg.kind != "array":
                raise Malformed
            if arg.items:
                zero = False
                args = b"".join(_bin(b"" if _absent(x) else _raw(x)) for x in arg.items)
                fields.append(("arg", _array_head(len(arg.items)) + args))
        if not zero:
            members.append(("lsig", _map_of(fields)))
    # The transaction: a map holding a type key, read as an asset transfer only when its type is the bytes "axfer".
    txn_node = m.get(b"txn")
    if txn_node is None or txn_node.kind != "map":
        raise Malformed
    t = _members_of(txn_node)
    kind = t.get(b"type")
    if kind is None or kind.kind not in ("str", "bin") or kind.data != b"axfer":
        raise Malformed
    txn: list[tuple[str, bytes]] = [("type", _str(b"axfer"))]
    for name in ("fee", "fv", "lv", "xaid", "aamt"):
        value = _fac_uint(t.get(name.encode("ascii")))
        if value != 0:
            txn.append((name, _uint(value)))
    for name in ("snd", "rekey", "arcv", "asnd", "aclose"):
        _fac_address(name, t.get(name.encode("ascii")), txn)
    # The facilitator computes the payment's id before it submits the group, and algokit's txId refuses a transaction
    # without a genesis hash.
    if _absent(t.get(b"gh")):
        raise Malformed
    for name in ("gh", "grp", "lx"):
        _fac_fixed(name, 32, t.get(name.encode("ascii")), txn)
    _fac_bytes("note", t.get(b"note"), txn)
    _fac_string("gen", t.get(b"gen"), txn)
    members.append(("txn", _map_of(txn)))
    return _map_of(members)


def _keys_readable(node: Node) -> bool:
    """algorand-msgpack 1.1.0 with useMap refuses a map key that is not a string, a number, a bigint or a byte string,
    at any depth: nil, a boolean, an array, a map or an extension."""
    if node.kind == "array":
        return all(_keys_readable(x) for x in node.items)
    if node.kind != "map":
        return True
    return all(k.kind in ("str", "bin", "int", "float") and _keys_readable(v) for k, v in node.entries)


# ── reading a payment entry ──────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class SignedRead:
    """A payment entry both readers read as one asset transfer: the transaction id algod computes, base32 of
    SHA-512/256 of TX and the transaction's canonical encoding, and the note."""

    txid: str
    note: bytes


def read_signed(data: bytes) -> SignedRead | Literal["not-axfer"]:
    """A payment entry read as the x402 path reads it. The entry must be one msgpack value within the caps (unpack).
    algod's reader must decode it as a signed transaction whose type algod knows, with no other type's member at a
    non-zero value; the facilitator's reader must decode it as one asset transfer; and the canonical encodings of the
    two signed transactions must be equal, so both read the same transaction. So a byte member written as a msgpack
    string is read as its bytes, whatever they are; a string member (type, gen) is refused when its bytes are not UTF-8;
    and a map key that does not spell a member's name exactly is refused. Gives "not-axfer" for an entry algod reads as
    a transaction of another type, and raises Malformed for every other entry either reader refuses or the two read
    differently. The signatures are not verified."""
    root = unpack(data)
    stxn = _zero_of(SIGNED_TXN) if root.kind == "nil" else _decode_into(SIGNED_TXN, root, _zero_of(SIGNED_TXN))
    txn = stxn["txn"]
    if _well_typed(txn) != "axfer":
        return "not-axfer"
    if not _keys_readable(root) or _marshal(SIGNED_TXN, stxn) != _facilitator_encoding(root):
        raise Malformed
    txid = base64.b32encode(sha512_256(b"TX" + _marshal(TRANSACTION, txn))).decode("ascii").rstrip("=")
    return SignedRead(txid=txid, note=txn["note"] or b"")
