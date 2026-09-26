"""The Stacks transaction the buyer half reads: a signed transaction's consensus bytes decoded field by field (version,
chain id, authorization with its spending conditions, anchor and post-condition modes, post-conditions, payload and
Clarity values), to find a contract call's function name and the bytes of its fourth argument.

A read past the end gives what bytes remain: an integer read short is not a number, a length that is not a number
reads nothing, and every later read past the end reads nothing. Enumerations, signature and coinbase lengths, Clarity
names, contract-name lengths, principal versions and public keys are checked, and anything else is accepted as read.
The bytes must be exactly one transaction's encoding: a read past the end, bytes after the payload, text (a
length-prefixed string, a string-utf8 value or a token transfer's memo) that is not well-formed UTF-8 or that begins
with a byte-order mark, or a tuple whose member names are not in ascending order under the Unicode Collation
Algorithm's root order (UTS #10) makes them malformed.
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
_MAX_NAME = 128
_MAX_BODY = 100_000
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


def _on_curve(key: bytes) -> bool:
    """Whether key is a secp256k1 point, compressed (02 or 03) or uncompressed (04)."""
    if len(key) == 33 and key[0] in (2, 3):
        x = int.from_bytes(key[1:], "big")
        if x >= _P:
            return False
        y2 = (pow(x, 3, _P) + 7) % _P
        y = pow(y2, (_P + 1) // 4, _P)
        return y * y % _P == y2
    if len(key) == 65 and key[0] == 4:
        x, y = int.from_bytes(key[1:33], "big"), int.from_bytes(key[33:], "big")
        return x < _P and y < _P and (y * y - x * x * x - 7) % _P == 0
    return False


def _public_key(r: _Reader) -> bytes:
    field_id = r.byte()
    if field_id is None:
        raise Malformed
    return bytes([field_id]) + r.read(64 if field_id == 4 else 32)


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
            key = _public_key(r)
            if field == 1:
                if not _on_curve(key):
                    raise Malformed
                uncompressed = True
            elif key[0] == 4:
                uncompressed = True
        else:
            _signature(r)
            uncompressed = uncompressed or field == 3
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


def clarity_value(r: _Reader) -> bytes | None:
    """One Clarity value, read with an explicit stack; tuple member names are checked once the value is read. For
    (some <buffer>) it returns the value's serialization from the bytes read, and None for any other value."""
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
        if kind != 4:
            clarity_value(r)
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
        r.read(20)
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
