"""The Stacks transaction the buyer half reads, by the rule lcp reads by: a transaction a Stacks node decodes and
serializes back to the same bytes (stacks-core 4.0.5). It is read field by field as stacks-core's
StacksTransaction::consensus_deserialize reads it, to find a contract call's function name and each argument's bytes;
any other bytes are malformed.

Among the node's rules: the bytes are one transaction's encoding, read to their end; the version byte is 0x00 or 0x80;
every address and principal has a version below 32; a multisig authorization holds exactly the signatures it requires,
an order-independent one at least that many, and a P2WSH one compressed keys only; a multisig key field holds a
compressed secp256k1 point (33 bytes) whether it marks the key compressed (0x00) or uncompressed (0x01), as SIP-005
encodes it. A contract name is a letter then letters, digits, - and _, or __transient: 1 to 40 characters where the
transaction names a contract, at most 128 in a value; a Clarity name is at most 128 characters of the name form. A
principal is any recipient: a token transfer's, a pay-to-alt coinbase's, and a Nakamoto coinbase's, which is none or
(some <principal>). A token transfer's memo is any 34 bytes. A smart contract's Clarity version is 1 to 7 and its code
printable ASCII, tab or newline. A poisoned microblock holds two signed headers that differ and share a sequence
number or a parent. A coinbase or a poisoned microblock is anchored on chain only, a Nakamoto coinbase's VRF proof
parses, and a tenure change's fields are whole.

A Clarity value nests at most 16 levels, the outermost counting 1, and is typed as the node types it: a tuple has
members, each named once, in name order as bytes; a list's items have a least common type; a value's type is at most
1,048,576 bytes; a string-ascii holds alphanumeric, punctuation and whitespace bytes; a string-utf8 is well-formed
UTF-8, a byte-order mark included.
"""

import re
from dataclasses import dataclass

from ._ed25519 import L, add, decode
from ._secp256k1 import N, point_of

# The most bytes a Clarity value's type admits, the most characters a string-utf8 holds, and the deepest a type nests
# (stacks-core 4.0.5, clarity-types/src/types/mod.rs).
_MAX_VALUE_SIZE = 1024 * 1024
_MAX_UTF8_CHARACTERS = _MAX_VALUE_SIZE // 4
_MAX_TYPE_DEPTH = 32
# The deepest a Clarity value nests, the outermost value counting 1: a Stacks node reads a transaction's Clarity values
# with this bound (stacks-core's UNSANITIZED_DEPTH_CHECK).
_MAX_DEPTH = 16
_CLARITY_NAME = re.compile(r"[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*|[-+=/*]|[<>]=?")
_CONTRACT_NAME = re.compile(r"[a-zA-Z]([a-zA-Z0-9]|[-_]){0,127}|__transient")
# The bytes a string-ascii holds: alphanumeric, punctuation and whitespace (space, tab, newline, form feed, carriage
# return); and the bytes a smart contract's code holds: printable ASCII, tab and newline.
_ASCII_TEXT = bytes([*range(0x20, 0x7F), 0x09, 0x0A, 0x0C, 0x0D])
_CODE_TEXT = bytes([*range(0x20, 0x7F), 0x09, 0x0A])


class Malformed(Exception):
    """The bytes are not a transaction a Stacks node decodes and serializes back to the same bytes."""


def _need(ok: bool) -> None:
    if not ok:
        raise Malformed


class _Reader:
    """Reads from bytes; a read past the end is malformed."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def read(self, n: int) -> bytes:
        _need(n <= len(self.data) - self.at)
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def byte(self) -> int:
        return self.read(1)[0]

    def number(self, n: int) -> int:
        """An n-byte big-endian integer."""
        return int.from_bytes(self.read(n), "big")

    def name(self, least: int, most: int, form: re.Pattern[str]) -> str:
        """A length byte from least to most, and that many ASCII bytes of the form."""
        n = self.byte()
        _need(least <= n <= most)
        text = self.read(n).decode("latin-1")
        _need(text.isascii() and form.fullmatch(text) is not None)
        return text

    def address(self) -> tuple[int, bytes]:
        """An address or a principal's: a version below 32 and a 20-byte hash."""
        version = self.byte()
        _need(version < 32)
        return version, self.read(20)


# ── Clarity types, as a node types a value it reads.


def _capped(n: int) -> int | None:
    return n if n <= _MAX_VALUE_SIZE else None


@dataclass(frozen=True, slots=True)
class _Type:
    """A Clarity type: its kind; a buffer's or string-ascii's bytes, a string-utf8's characters, or a list's most items;
    its parts (a list's item, an optional's value, a response's ok and err, a tuple's members) and a tuple's member
    names. Its depth, the most bytes a value of it serializes to (size) and the bytes the type itself takes (own) are
    computed once, from its parts; a size past _MAX_VALUE_SIZE is None."""

    kind: str
    length: int = 0
    parts: tuple["_Type", ...] = ()
    names: tuple[str, ...] = ()
    depth: int = 1
    size: int | None = 1
    own: int | None = 1


_NO_TYPE = _Type("none")
_BOOL = _Type("bool")
_INT = _Type("int", size=16)
_UINT = _Type("uint", size=16)
_PRINCIPAL = _Type("principal", size=148)
_EMPTY_LIST = _Type("list", 0, (_NO_TYPE,), depth=2, size=6, own=6)


def _sequence(kind: str, length: int) -> _Type:
    return _Type(kind, length, size=4 + (4 * length if kind == "utf8" else length), own=5)


def _list(item: _Type, most: int) -> _Type:
    own = None if item.own is None else _capped(item.own + 5)
    size = None if item.size is None or own is None else _capped(item.size * most + own)
    _need(1 + item.depth <= _MAX_TYPE_DEPTH and size is not None)
    return _Type("list", most, (item,), depth=1 + item.depth, size=size, own=own)


def _tuple(names: tuple[str, ...], parts: tuple[_Type, ...]) -> _Type:
    _need(len(parts) > 0 and all(1 + p.depth <= _MAX_TYPE_DEPTH for p in parts))
    own: int | None = 2 * len(parts)
    size: int | None = 2 * len(parts)
    for name, p in zip(names, parts, strict=True):
        own = None if own is None or p.own is None else own + p.own + len(name)
        size = None if size is None or p.size is None else size + p.size + len(name)
    own = None if own is None else _capped(own)
    size = None if size is None or own is None else _capped(size + own)
    _need(size is not None)
    return _Type("tuple", 0, parts, names, 1 + max(p.depth for p in parts), size, own)


def _optional(inner: _Type) -> _Type:
    _need(inner.size is not None and inner.size + 1 <= _MAX_VALUE_SIZE and 1 + inner.depth <= _MAX_TYPE_DEPTH)
    assert inner.size is not None
    own = None if inner.own is None else inner.own + 1
    return _Type("optional", 0, (inner,), depth=1 + inner.depth, size=inner.size + 1, own=own)


def _response(ok: _Type, err: _Type) -> _Type:
    _need(ok.size is not None and err.size is not None and max(ok.size, err.size) + 1 <= _MAX_VALUE_SIZE)
    _need(1 + max(ok.depth, err.depth) <= _MAX_TYPE_DEPTH)
    assert ok.size is not None and err.size is not None
    own = None if ok.own is None or err.own is None else ok.own + err.own + 1
    return _Type("response", 0, (ok, err), depth=1 + max(ok.depth, err.depth), size=max(ok.size, err.size) + 1, own=own)


def _join(a: _Type, b: _Type) -> _Type:
    """The least type both admit, as a node types a list's items: a tuple's members are the first's, each in the second
    too, each joined; two lists, two optionals and two responses join their parts, an empty list taking the other's
    items; buffers and strings of one kind the longer length; no type the other; any other pair only when equal."""
    if a.kind == "tuple" and b.kind == "tuple":
        members = dict(zip(b.names, b.parts, strict=True))
        _need(all(name in members for name in a.names))
        return _tuple(a.names, tuple(_join(p, members[name]) for name, p in zip(a.names, a.parts, strict=True)))
    if a.kind == "list" and b.kind == "list":
        item = b.parts[0] if a.length == 0 else a.parts[0] if b.length == 0 else _join(a.parts[0], b.parts[0])
        return _list(item, max(a.length, b.length))
    if a.kind == "response" and b.kind == "response":
        return _response(_join(a.parts[0], b.parts[0]), _join(a.parts[1], b.parts[1]))
    if a.kind == "optional" and b.kind == "optional":
        return _optional(_join(a.parts[0], b.parts[0]))
    if a.kind in ("buffer", "ascii", "utf8") and a.kind == b.kind:
        return _sequence(a.kind, max(a.length, b.length))
    if a.kind == "none":
        return b
    if b.kind == "none":
        return a
    _need(a == b)
    return a


def _value(r: _Reader, level: int) -> _Type:
    """One Clarity value at level, the outermost counting 1, as a node reads it unsanitized: its type."""
    _need(level <= _MAX_DEPTH)
    prefix = r.byte()
    if prefix in (0, 1):
        r.read(16)
        return _INT if prefix == 0 else _UINT
    if prefix in (2, 13, 14):
        n = r.number(4)
        _need(n <= _MAX_VALUE_SIZE)
        content = r.read(n)
        if prefix == 2:
            return _sequence("buffer", n)
        if prefix == 13:
            _need(not content.translate(None, _ASCII_TEXT))
            return _sequence("ascii", n)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            raise Malformed from None
        _need(len(text) <= _MAX_UTF8_CHARACTERS)
        return _sequence("utf8", len(text))
    if prefix in (3, 4):
        return _BOOL
    if prefix == 5:
        r.address()
        return _PRINCIPAL
    if prefix == 6:
        r.address()
        r.name(0, 128, _CONTRACT_NAME)
        return _PRINCIPAL
    if prefix == 7:
        return _response(_value(r, level + 1), _NO_TYPE)
    if prefix == 8:
        return _response(_NO_TYPE, _value(r, level + 1))
    if prefix == 9:
        return _optional(_NO_TYPE)
    if prefix == 10:
        return _optional(_value(r, level + 1))
    if prefix == 11:
        n = r.number(4)
        _need(n <= _MAX_VALUE_SIZE)
        if n == 0:
            return _EMPTY_LIST
        item = _value(r, level + 1)
        for _ in range(1, n):
            t = _value(r, level + 1)
            if t != item:
                item = _join(item, t)
        return _list(item, n)
    if prefix == 12:
        n = r.number(4)
        _need(0 < n <= _MAX_VALUE_SIZE)
        names: list[str] = []
        parts: list[_Type] = []
        for _ in range(n):
            name = r.name(0, 128, _CLARITY_NAME)
            _need(not names or name > names[-1])
            names.append(name)
            parts.append(_value(r, level + 1))
        return _tuple(tuple(names), tuple(parts))
    raise Malformed


# ── the transaction.


def _compressed_point(key: bytes) -> bool:
    """Whether key is a compressed secp256k1 point: 02 or 03, then an x below the field prime that has a point (SEC 1,
    2.3.4)."""
    if len(key) != 33 or key[0] not in (2, 3):
        return False
    return point_of(int.from_bytes(key[1:], "big"), key[0] == 3) is not None


def _spending_condition(r: _Reader) -> None:
    """A singlesig, multisig or order-independent multisig spending condition: a multisig one holds exactly the
    signatures it requires, an order-independent one at least that many, and a P2WSH one (hash mode 3 or 7) compressed
    keys and signatures only."""
    mode = r.byte()
    r.read(20 + 8 + 8)
    if mode in (0, 2):
        encoding = r.byte()
        _need(encoding in (0, 1) and (mode == 0 or encoding == 0))
        r.read(65)
        return
    _need(mode in (1, 3, 5, 7))
    signatures = 0
    uncompressed = False
    for _ in range(r.number(4)):
        field = r.byte()
        _need(field in (0, 1, 2, 3))
        if field in (0, 1):
            _need(_compressed_point(r.read(33)))
        else:
            r.read(65)
            signatures += 1
        uncompressed = uncompressed or field in (1, 3)
    required = r.number(2)
    _need(signatures <= 0xFFFF and (signatures == required if mode in (1, 3) else signatures >= required))
    _need(not uncompressed or mode in (1, 5))


def _post_condition(r: _Reader) -> None:
    """A post-condition: STX, fungible, non-fungible, Staking or Pox, its principal, its asset, and a condition code of
    its type."""
    kind = r.byte()
    _need(kind <= 4)
    principal = r.byte()
    _need(principal in (1, 2, 3))
    if principal in (2, 3):
        r.address()
    if principal == 3:
        r.name(1, 40, _CONTRACT_NAME)
    if kind in (1, 2):
        r.address()
        r.name(1, 40, _CONTRACT_NAME)
        r.name(0, 128, _CLARITY_NAME)
    if kind == 2:
        _value(r, 1)
        _need(0x10 <= r.byte() <= 0x12)
    elif kind == 4:
        _need(0x30 <= r.byte() <= 0x32)
    else:
        _need(1 <= r.byte() <= 5)
        r.read(8)


def _microblock_header(r: _Reader) -> bytes:
    """A microblock header, signed with a recoverable secp256k1 signature: a recovery id from 0 to 3, r and s below the
    group order."""
    header = r.read(1 + 2 + 32 + 32 + 65)
    signature = header[67:]
    _need(signature[0] <= 3)
    _need(int.from_bytes(signature[1:33], "big") < N and int.from_bytes(signature[33:], "big") < N)
    return header


def _vrf_proof(r: _Reader) -> None:
    """A Nakamoto coinbase's 80-byte VRF proof: Gamma, the canonical encoding of an Edwards25519 point (RFC 8032,
    5.1.3) not of small order, so that doubling it three times does not reach the neutral element (0, 1); c, 16 bytes;
    s, a scalar below the group order L."""
    proof = r.read(80)
    point = decode(proof[:32])
    if point is None:
        raise Malformed
    for _ in range(3):
        point = add(point, point)
    _need(point != (0, 1))
    _need(int.from_bytes(proof[48:], "little") < L)


@dataclass
class Call:
    """A contract call's function name, and each argument's bytes."""

    function: str
    args: list[bytes]


def _payload(r: _Reader) -> tuple[int, Call | None]:
    """The payload: its type, and a contract call's function and arguments."""
    kind = r.byte()
    if kind == 0:
        principal = r.byte()
        _need(principal in (5, 6))
        r.address()
        if principal == 6:
            r.name(0, 128, _CONTRACT_NAME)
        r.read(8 + 34)
    elif kind == 2:
        r.address()
        r.name(1, 40, _CONTRACT_NAME)
        call = Call(r.name(0, 128, _CLARITY_NAME), [])
        for _ in range(r.number(4)):
            at = r.at
            _value(r, 1)
            call.args.append(r.data[at : r.at])
        return kind, call
    elif kind in (1, 6):
        if kind == 6:
            _need(1 <= r.byte() <= 7)
        r.name(1, 40, _CONTRACT_NAME)
        _need(not r.read(r.number(4)).translate(None, _CODE_TEXT))
    elif kind == 3:
        a, b = _microblock_header(r), _microblock_header(r)
        _need(a != b and (a[1:3] == b[1:3] or a[3:35] == b[3:35]))
    elif kind == 4:
        r.read(32)
    elif kind == 5:
        r.read(32)
        _need(_value(r, 1) == _PRINCIPAL)
    elif kind == 8:
        r.read(32)
        recipient = _value(r, 1)
        _need(recipient.kind == "optional" and recipient.parts[0] in (_NO_TYPE, _PRINCIPAL))
        _vrf_proof(r)
    elif kind == 7:
        r.read(20 + 20 + 20 + 32 + 4)
        _need(r.byte() <= 6)
        r.read(20)
    else:
        raise Malformed
    return kind, None


def contract_call(data: bytes) -> Call | None:
    """The contract call a transaction's payload makes, or None for any other payload. Raises Malformed for bytes
    that are not a transaction a Stacks node decodes and serializes back to the same bytes."""
    r = _Reader(data)
    _need(r.byte() in (0x00, 0x80))
    r.read(4)
    auth = r.byte()
    _need(auth in (4, 5))
    _spending_condition(r)
    if auth == 5:
        _spending_condition(r)
    anchor = r.byte()
    _need(anchor in (1, 2, 3) and r.byte() in (1, 2, 3))
    for _ in range(r.number(4)):
        _post_condition(r)
    kind, call = _payload(r)
    _need(anchor == 1 or kind not in (3, 4, 5, 8))
    _need(r.at == len(data))
    return call
