"""The Stacks transaction the buyer half reads: a signed transaction's consensus bytes decoded field by field (version,
chain id, authorization with its spending conditions, anchor and post-condition modes, post-conditions, payload and
Clarity values), to find a contract call's function name and each argument's bytes. The bytes must be exactly one
transaction's encoding: a read past the end, or bytes after the payload, makes them malformed.

Clarity values are read as a Stacks node reads them (stacks-core 4.0.5). A value nests at most 16 levels, the outermost
counting 1, and is typed as the node types it: a tuple has members, each named once by a Clarity name, in name order
as bytes; a list's items have a least common type; a value's type is at most 1,048,576 bytes; a string-ascii holds
alphanumeric, punctuation and whitespace bytes; a string-utf8 is well-formed UTF-8, a byte-order mark included; a
principal has a version below 32, and a contract principal's name is a letter then letters, digits, - and _, or
__transient, of at most 128 characters. A function name and an asset name are Clarity names of at most 128 characters,
a smart contract's Clarity version is 1 to 7, and a token transfer's memo is any 34 bytes.

Enumerations, signature and coinbase lengths and public keys are checked, and anything else is accepted as read. A
multisig key field holds a compressed secp256k1 point (33 bytes) whether it marks the key compressed (0x00) or
uncompressed (0x01), as SIP-005 encodes it. A contract name the transaction names is well-formed UTF-8 of at most 128
bytes that does not begin with a byte-order mark. Payload types 7 and 8 are read as @stacks/transactions 7.6.0 reads
and writes them back: a tenure change's last field, the 20-byte public key hash, is the bytes that remain of it, so a
transaction that ends within it is one; a Nakamoto coinbase's recipient is none or (some <value>), which is all that is
written back, and counts from the value inside its (some ...).
"""

import re
from dataclasses import dataclass

_TX_VERSIONS = frozenset({0, 128})
_HASH_MODES = frozenset({0, 1, 2, 3, 5, 7})
_KEY_ENCODINGS = frozenset({0, 1})
_AUTH_TYPES = frozenset({4, 5})
_ANCHOR_MODES = frozenset({1, 2, 3})
_POST_CONDITION_MODES = frozenset({1, 2, 3})
_POST_CONDITION_TYPES = frozenset({0, 1, 2, 3, 4})
_PRINCIPALS = frozenset({1, 2, 3})
_FUNGIBLE_CODES = frozenset({1, 2, 3, 4, 5})
_NFT_CODES = frozenset({16, 17, 18})
_POX_CODES = frozenset({48, 49, 50})
_AUTH_FIELDS = frozenset({0, 1, 2, 3})
_PAYLOADS = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8})
_CLARITY_VERSIONS = frozenset({1, 2, 3, 4, 5, 6, 7})
_TENURE_CAUSES = frozenset({0, 1, 2, 3, 4, 5, 6})
# The Clarity type ids of none and (some <value>).
_NONE = 9
_SOME = 10
_MAX_NAME = 128
_MAX_BODY = 100_000
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
# return).
_ASCII_TEXT = bytes([*range(0x20, 0x7F), 0x09, 0x0A, 0x0C, 0x0D])
_P = 2**256 - 2**32 - 977


class Malformed(Exception):
    """The bytes do not decode as a Stacks transaction."""


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

    def enum(self, members: frozenset[int]) -> int:
        value = self.byte()
        _need(value in members)
        return value

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

    def remaining(self) -> int:
        return len(self.data) - self.at

    def principal(self) -> None:
        """A principal's address: a version below 32 and a 20-byte hash."""
        _need(self.byte() < 32)
        self.read(20)


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
        r.principal()
        return _PRINCIPAL
    if prefix == 6:
        r.principal()
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


def _text(data: bytes) -> str:
    """Well-formed UTF-8 text that does not begin with a byte-order mark."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Malformed from None
    _need(not text.startswith("\ufeff"))
    return text


def _lp_string(r: _Reader, prefix: int = 1, maximum: int = _MAX_NAME) -> str:
    content = _text(r.read(r.number(prefix)))
    _need(len(content.encode("utf-8")) <= maximum)
    return content


def _address(r: _Reader) -> None:
    r.read(1 + 20)


def _compressed_point(key: bytes) -> bool:
    """Whether key is a compressed secp256k1 point: 02 or 03, then an x below the field prime that has a point (SEC 1,
    2.3.4)."""
    if len(key) != 33 or key[0] not in (2, 3):
        return False
    x = int.from_bytes(key[1:], "big")
    if x >= _P:
        return False
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    return y * y % _P == y2


def _spending_condition(r: _Reader) -> None:
    mode = r.enum(_HASH_MODES)
    r.read(20 + 8 + 8)
    if mode in (0, 2):
        encoding = r.enum(_KEY_ENCODINGS)
        _need(mode == 0 or encoding == 0)
        r.read(65)
        return
    uncompressed = False
    for _ in range(r.number(4)):
        field = r.enum(_AUTH_FIELDS)
        if field in (0, 1):
            _need(_compressed_point(r.read(33)))
        else:
            r.read(65)
        uncompressed = uncompressed or field in (1, 3)
    r.read(2)
    _need(not uncompressed or mode not in (3, 7))


def _post_condition(r: _Reader) -> None:
    kind = r.enum(_POST_CONDITION_TYPES)
    principal = r.enum(_PRINCIPALS)
    if principal in (2, 3):
        _address(r)
    if principal == 3:
        _lp_string(r)
    if kind in (1, 2):
        _address(r)
        _lp_string(r)
        r.name(0, 128, _CLARITY_NAME)
    if kind == 2:
        _value(r, 1)
        r.enum(_NFT_CODES)
    elif kind == 4:
        r.enum(_POX_CODES)
    else:
        r.enum(_FUNGIBLE_CODES)
        r.read(8)


@dataclass
class Call:
    """A contract call's function name, and each argument's bytes."""

    function: str
    args: list[bytes]


def _payload(r: _Reader) -> Call | None:
    kind = r.enum(_PAYLOADS)
    if kind == 0:
        _value(r, 1)
        r.read(8 + 34)
    elif kind == 1:
        _lp_string(r)
        _lp_string(r, 4, _MAX_BODY)
    elif kind == 2:
        _address(r)
        _lp_string(r)
        call = Call(r.name(0, 128, _CLARITY_NAME), [])
        for _ in range(r.number(4)):
            at = r.at
            _value(r, 1)
            call.args.append(r.data[at : r.at])
        return call
    elif kind in (4, 5, 8):
        r.read(32)
        if kind == 8:
            _need(r.remaining() > 0 and r.data[r.at] in (_NONE, _SOME))
        if kind != 4:
            # @stacks/transactions 7.6.0 holds a Nakamoto coinbase's recipient as the value inside its (some ...), and
            # its levels count from that value.
            _value(r, 0 if kind == 8 else 1)
        if kind == 8:
            r.read(80)
    elif kind == 6:
        r.enum(_CLARITY_VERSIONS)
        _lp_string(r)
        _lp_string(r, 4, 2**32)
    elif kind == 7:
        r.read(92)
        r.number(4)
        r.enum(_TENURE_CAUSES)
        r.read(min(20, r.remaining()))
    return None


def contract_call(data: bytes) -> Call | None:
    """The contract call a transaction's payload makes, or None for any other payload. Raises Malformed for bytes
    that are not exactly one transaction's encoding."""
    r = _Reader(data)
    r.enum(_TX_VERSIONS)
    r.read(4)
    auth = r.enum(_AUTH_TYPES)
    _spending_condition(r)
    if auth == 5:
        _spending_condition(r)
    r.enum(_ANCHOR_MODES)
    r.enum(_POST_CONDITION_MODES)
    for _ in range(r.number(4)):
        _post_condition(r)
    call = _payload(r)
    _need(r.at == len(data))
    return call
