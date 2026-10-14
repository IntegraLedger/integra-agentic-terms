"""The Stacks transaction the buyer half reads: a signed transaction's consensus bytes decoded field by field (version,
chain id, authorization with its spending conditions, anchor and post-condition modes, post-conditions, payload and
Clarity values), to find a contract call's function name and the bytes of its fourth argument. Every Clarity value the
transaction carries nests at most 16 levels, the outermost counting 1, the depth a Stacks node reads; a deeper one is
malformed. A Nakamoto coinbase's recipient counts from the value inside its (some ...), as @stacks/transactions 7.6.0
holds it.

A read past the end gives what bytes remain: an integer read short is not a number, a length that is not a number
reads nothing, and every later read past the end reads nothing. Enumerations, signature and coinbase lengths, Clarity
names, contract-name lengths, principal versions and public keys are checked, and anything else is accepted as read. A
multisig key field holds a compressed secp256k1 point (33 bytes) whether it marks the key compressed (0x00) or
uncompressed (0x01), as SIP-005 encodes it.
The bytes must be exactly one transaction's encoding: a read past the end, bytes after the payload, text (a
length-prefixed string, a string-utf8 value or a token transfer's memo) that is not well-formed UTF-8 or that begins
with a byte-order mark, or a tuple whose member names are not in ascending order under the Unicode Collation
Algorithm's root order (UTS #10) makes them malformed. Payload types 7 and 8 are read as @stacks/transactions 7.6.0
reads and writes them back: a tenure change's last field, the 20-byte public key hash, is the bytes that remain of it,
so a transaction that ends within it is one; a Nakamoto coinbase's recipient is none or (some <value>), which is all
that is written back.
"""

import re
from dataclasses import dataclass, field

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
_CLARITY_VERSIONS = frozenset({1, 2, 3, 4, 5, 6})
_TENURE_CAUSES = frozenset({0, 1, 2, 3, 4, 5, 6})
_CLARITY_TYPES = range(0, 15)
CONTRACT_CALL = 2
# The Clarity type ids of none and (some <value>).
_NONE = 9
_SOME = 10
_MAX_NAME = 128
_MAX_BODY = 100_000
# The deepest a Clarity value nests, the outermost value counting 1: a Stacks node reads a transaction's Clarity values
# with this bound (stacks-core's UNSANITIZED_DEPTH_CHECK).
_MAX_DEPTH = 16
_P = 2**256 - 2**32 - 977
# The characters of a Clarity name in the root collation's primary order; a letter's two cases share a weight, and the
# lower case sorts first when the weights are equal.
_PRIMARY = {c: i for i, c in enumerate("_-!?*/+<=>0123456789abcdefghijklmnopqrstuvwxyz")}
_CLARITY_NAME = re.compile(r"[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*|[-+=/*]|[<>]=?")


class Malformed(Exception):
    """The bytes do not decode as a Stacks transaction."""


class _Reader:
    """Reads from bytes; at is None once a length that is not a number has been read."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at: int | None = 0

    def read(self, n: int | None) -> bytes:
        if self.at is None or n is None:
            self.at = None
            return b""
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def byte(self) -> int | None:
        b = self.read(1)
        return b[0] if b else None

    def peek(self) -> int | None:
        """The next byte, not read; None when none remains."""
        return self.data[self.at] if self.at is not None and self.at < len(self.data) else None

    def remaining(self) -> int:
        return max(0, len(self.data) - self.at) if self.at is not None else 0

    def enum(self, members: frozenset[int] | range) -> int:
        value = self.byte()
        if value is None or value not in members:
            raise Malformed
        return value

    def u32(self) -> int | None:
        b = self.read(4)
        return int.from_bytes(b, "big") if len(b) == 4 else None

    def prefix(self, n: int) -> int | None:
        """A length written in n bytes, read from the bytes that remain; not a number when none remain."""
        b = self.read(n)
        return int.from_bytes(b, "big") if b else None

    def big(self, n: int) -> int:
        """An n-byte integer from the bytes that remain; none remaining raises."""
        b = self.read(n)
        if not b:
            raise Malformed
        return int.from_bytes(b, "big")


def _text(data: bytes) -> str:
    """Well-formed UTF-8 text that does not begin with a byte-order mark."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Malformed from None
    if text.startswith("\ufeff"):
        raise Malformed
    return text


def _collation_key(name: str) -> tuple[list[int], list[bool]]:
    """A Clarity name's sort key: its primary weights, then its letters' cases."""
    return [_PRIMARY.get(c.lower(), len(_PRIMARY) + ord(c)) for c in name], [c.isupper() for c in name]


def _lp_string(r: _Reader, prefix: int = 1, maximum: int = _MAX_NAME) -> str:
    content = _text(r.read(r.prefix(prefix)))
    if len(content.encode("utf-8")) > maximum:
        raise Malformed
    return content


def _address(r: _Reader) -> tuple[int | None, bytes]:
    version = r.prefix(1)
    return version, r.read(20)


def _principal_address(version: int | None, hash160: bytes) -> None:
    """The checks writing a principal's c32 address makes: a 20-byte hash and a version below 32."""
    if len(hash160) != 20 or (version is not None and not 0 <= version < 32):
        raise Malformed


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


def _public_key(r: _Reader) -> None:
    if not _compressed_point(r.read(33)):
        raise Malformed


def _signature(r: _Reader) -> None:
    if len(r.read(65)) != 65:
        raise Malformed


def _spending_condition(r: _Reader) -> None:
    mode = r.enum(_HASH_MODES)
    r.read(20)
    r.big(8)
    r.big(8)
    if mode in (0, 2):
        encoding = r.enum(_KEY_ENCODINGS)
        if mode == 2 and encoding != 0:
            raise Malformed
        _signature(r)
        return
    uncompressed = False
    for _ in range(r.prefix(4) or 0):
        field = r.enum(_AUTH_FIELDS)
        if field in (0, 1):
            _public_key(r)
        else:
            _signature(r)
        uncompressed = uncompressed or field in (1, 3)
    r.read(2)
    if uncompressed and mode in (3, 7):
        raise Malformed


@dataclass
class _Frame:
    """Clarity values still to read at one level, whether each is preceded by a tuple member's name, and the names
    read."""

    pending: int
    named: bool = False
    names: list[str] = field(default_factory=list)


def clarity_value(r: _Reader, level: int = 1) -> bytes | None:
    """One Clarity value, read with an explicit stack; tuple member names are checked once the value is read. The value
    counts level, and each value inside an optional, a response, a list or a tuple one more than its container; a value
    past _MAX_DEPTH is malformed. For (some <buffer>) it returns the value's serialization from the bytes read, and None
    for any other value."""
    stack = [_Frame(1)]
    names: list[str] = []
    kinds: list[int] = []
    content = b""
    while stack:
        frame = stack[-1]
        if frame.pending == 0:
            keys = [_collation_key(n) for n in frame.names]
            if any(a >= b for a, b in zip(keys, keys[1:], strict=False)):
                raise Malformed
            stack.pop()
            continue
        frame.pending -= 1
        if level + len(stack) - 1 > _MAX_DEPTH:
            raise Malformed
        if frame.named:
            name = _lp_string(r)
            names.append(name)
            frame.names.append(name)
        kind = r.enum(_CLARITY_TYPES)
        kinds.append(kind)
        if kind in (0, 1):
            r.big(16)
        elif kind in (2, 13, 14):
            content = r.read(r.u32())
            if kind == 14:
                _text(content)
        elif kind == 5:
            _principal_address(*_address(r))
        elif kind == 6:
            version, hash160 = _address(r)
            if len(_lp_string(r).encode("utf-8")) >= _MAX_NAME:
                raise Malformed
            _principal_address(version, hash160)
        elif kind in (7, 8, 10):
            stack.append(_Frame(1))
        elif kind in (11, 12):
            stack.append(_Frame(r.u32() or 0, kind == 12))
    if not all(_CLARITY_NAME.fullmatch(n) is not None and len(n) < _MAX_NAME for n in names):
        raise Malformed
    if kinds != [10, 2]:
        return None
    return bytes([10, 2]) + len(content).to_bytes(4, "big") + content


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
        _lp_string(r)
    if kind == 2:
        clarity_value(r)
        r.enum(_NFT_CODES)
    elif kind == 4:
        r.enum(_POX_CODES)
    else:
        r.enum(_FUNGIBLE_CODES)
        r.big(8)


@dataclass
class Call:
    """A contract call's function name, its argument count, and its fourth argument's serialization when that is
    (some <buffer>)."""

    function: str
    args: int = 0
    fourth: bytes | None = None


def _payload(r: _Reader) -> Call | None:
    kind = r.enum(_PAYLOADS)
    if kind == 0:
        clarity_value(r)
        r.big(8)
        _text(r.read(34))
    elif kind == 1:
        _lp_string(r)
        _lp_string(r, 4, _MAX_BODY)
    elif kind == CONTRACT_CALL:
        _address(r)
        _lp_string(r)
        call = Call(_lp_string(r))
        call.args = r.u32() or 0
        for i in range(call.args):
            value = clarity_value(r)
            if i == 3:
                call.fourth = value
        return call
    elif kind in (4, 5, 8):
        if len(r.read(32)) != 32:
            raise Malformed
        if kind == 8 and r.peek() not in (_NONE, _SOME):
            raise Malformed
        if kind != 4:
            # @stacks/transactions 7.6.0 holds a Nakamoto coinbase's recipient as the value inside its (some ...), and
            # its levels count from that value.
            clarity_value(r, 0 if kind == 8 else 1)
        if kind == 8 and len(r.read(80)) != 80:
            raise Malformed
    elif kind == 6:
        r.enum(_CLARITY_VERSIONS)
        _lp_string(r)
        _lp_string(r, 4, 2**32)
    elif kind == 7:
        r.read(92)
        r.u32()
        r.enum(_TENURE_CAUSES)
        r.read(min(20, r.remaining()))
    return None


def contract_call(data: bytes) -> Call | None:
    """The contract call a transaction's payload makes, or None for any other payload. Raises Malformed for bytes
    that are not exactly one transaction's encoding."""
    r = _Reader(data)
    r.enum(_TX_VERSIONS)
    r.u32()
    auth = r.enum(_AUTH_TYPES)
    _spending_condition(r)
    if auth == 5:
        _spending_condition(r)
    r.enum(_ANCHOR_MODES)
    r.enum(_POST_CONDITION_MODES)
    for _ in range(r.prefix(4) or 0):
        _post_condition(r)
    call = _payload(r)
    if r.at != len(data):
        raise Malformed
    return call
