"""A bounded reader of one CBOR data item (RFC 8949): definite lengths only, at most 8 levels of nesting and 256
items. Integers are ints, floats are floats, byte strings are bytes, text is checked UTF-8 with every character kept (a
leading U+FEFF included), arrays are lists, maps keep their pairs in order and a map with two equal keys is malformed,
tags are kept as CborTag, and a simple value other than false, true, null and undefined is kept as CborSimple."""

import math
import struct
from dataclasses import dataclass
from typing import Any

MAX_DEPTH = 8
MAX_ITEMS = 256


class _Undefined:
    """CBOR's undefined, and what map_get gives for an absent key."""


UNDEFINED = _Undefined()


@dataclass(frozen=True, slots=True)
class CborMap:
    pairs: tuple[tuple[Any, Any], ...]


@dataclass(frozen=True, slots=True)
class CborTag:
    tag: int
    value: Any


@dataclass(frozen=True, slots=True)
class CborSimple:
    simple: int


class _Malformed(Exception):
    pass


class _State:
    def __init__(self) -> None:
        self.at = 0
        self.items = 0


def decode_cbor(b: bytes) -> Any:
    """The one data item b holds, with nothing after it, or None when b is anything else. CBOR null is None too."""
    s = _State()
    try:
        v = _item(b, s, 0)
    except _Malformed:
        return None
    return v if s.at == len(b) else None


def is_tag(v: Any, tag: int) -> bool:
    return isinstance(v, CborTag) and v.tag == tag


def map_get(m: CborMap, key: str | int) -> Any:
    """The value under key, a text or integer key compared by type and value, or UNDEFINED when the key is absent."""
    for k, v in m.pairs:
        if type(k) is type(key) and k == key:
            return v
    return UNDEFINED


def _byte(b: bytes, s: _State) -> int:
    if s.at >= len(b):
        raise _Malformed()
    s.at += 1
    return b[s.at - 1]


def _take(b: bytes, s: _State, n: int) -> bytes:
    if n > len(b) - s.at:
        raise _Malformed()
    out = b[s.at : s.at + n]
    s.at += n
    return out


def _argument(b: bytes, s: _State, info: int) -> int:
    if info < 24:
        return info
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
    if width is None:
        raise _Malformed()
    return int.from_bytes(_take(b, s, width), "big")


def _simple(b: bytes, s: _State, info: int) -> Any:
    if info == 20:
        return False
    if info == 21:
        return True
    if info == 22:
        return None
    if info == 23:
        return UNDEFINED
    if info < 20:
        return CborSimple(info)
    if info == 24:
        v = _byte(b, s)
        if v < 32:
            raise _Malformed()
        return CborSimple(v)
    if info == 25:
        return float(struct.unpack(">e", _take(b, s, 2))[0])
    if info == 26:
        return float(struct.unpack(">f", _take(b, s, 4))[0])
    if info == 27:
        return float(struct.unpack(">d", _take(b, s, 8))[0])
    raise _Malformed()


def _item(b: bytes, s: _State, depth: int) -> Any:
    if depth > MAX_DEPTH:
        raise _Malformed()
    s.items += 1
    if s.items > MAX_ITEMS:
        raise _Malformed()
    head = _byte(b, s)
    major, info = head >> 5, head & 0x1F
    if major == 7:
        return _simple(b, s, info)
    arg = _argument(b, s, info)
    if major == 0:
        return arg
    if major == 1:
        return -1 - arg
    if major == 2:
        return _take(b, s, arg)
    if major == 3:
        try:
            return _take(b, s, arg).decode("utf-8")
        except UnicodeDecodeError as e:
            raise _Malformed() from e
    if major == 4:
        out: list[Any] = []
        for _ in range(min(arg, MAX_ITEMS + 1)):
            out.append(_item(b, s, depth + 1))
        return out
    if major == 5:
        pairs: list[tuple[Any, Any]] = []
        for _ in range(min(arg, MAX_ITEMS + 1)):
            k = _item(b, s, depth + 1)
            if any(_same(key, k) for key, _ in pairs):
                raise _Malformed()
            pairs.append((k, _item(b, s, depth + 1)))
        return CborMap(tuple(pairs))
    return CborTag(arg, _item(b, s, depth + 1))


def _same(a: Any, b: Any) -> bool:
    """Whether two decoded items are the same value in CBOR's data model."""
    if type(a) is not type(b):
        return False
    if isinstance(a, float):
        if math.isnan(a) or math.isnan(b):
            return math.isnan(a) and math.isnan(b)
        return a == b and math.copysign(1.0, a) == math.copysign(1.0, b)
    if isinstance(a, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, CborMap):
        return len(a.pairs) == len(b.pairs) and all(
            any(_same(k, k2) and _same(v, v2) for k2, v2 in b.pairs) for k, v in a.pairs
        )
    if isinstance(a, CborTag):
        return bool(a.tag == b.tag) and _same(a.value, b.value)
    return bool(a == b)
