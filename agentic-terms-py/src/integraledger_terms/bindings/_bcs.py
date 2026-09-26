"""BCS schema combinators with a reader and a writer: unsigned integers, bool, ULEB128 lengths, fixed and
length-prefixed bytes, UTF-8 strings, structs, enums, tuples, vectors, options, maps and transforms.

Values take one form each: u8 to u32 as ints, u64 to u256 as decimal strings, bytes as bytes, a struct as a dict of
its fields in order, an enum as {"$kind": name, name: value} (True for a variant with no value), an option as its
value or None, and a map as a dict. Reading accepts a ULEB128 in any length whose value is at most 2^53 - 1 and a
bool byte other than 1 as false; writing produces the one canonical encoding, so parsing and writing back gives the
same bytes only for canonical input. Every failure raises BcsError."""

import functools
from collections.abc import Callable, Sequence
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1


class BcsError(Exception):
    pass


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise BcsError("short")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def uleb(self) -> int:
        total, shift = 0, 0
        while True:
            if self.at >= len(self.data):
                raise BcsError("short")
            byte = self.data[self.at]
            self.at += 1
            total += (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                break
            shift += 7
        if total > MAX_SAFE_INTEGER:
            raise BcsError("uleb too large")
        return total


def uleb_encode(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


class Type:
    def read(self, r: Reader) -> Any:
        raise NotImplementedError

    def write(self, value: Any, w: bytearray) -> None:
        raise NotImplementedError

    def parse(self, data: bytes) -> Any:
        return self.read(Reader(data))

    def serialize(self, value: Any) -> bytes:
        w = bytearray()
        self.write(value, w)
        return bytes(w)


class UInt(Type):
    def __init__(self, size: int, as_string: bool) -> None:
        self.size = size
        self.as_string = as_string

    def read(self, r: Reader) -> Any:
        v = int.from_bytes(r.take(self.size), "little")
        return str(v) if self.as_string else v

    def write(self, value: Any, w: bytearray) -> None:
        if isinstance(value, bool):
            raise BcsError("not an integer")
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise BcsError("not an integer")
            v = int(value)
        else:
            v = int(value)
        if v < 0 or v >= 1 << (8 * self.size):
            raise BcsError("out of range")
        w += v.to_bytes(self.size, "little")


class Bool(Type):
    def read(self, r: Reader) -> Any:
        return r.take(1)[0] == 1

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, bool):
            raise BcsError("not a bool")
        w.append(1 if value else 0)


class FixedBytes(Type):
    def __init__(self, size: int) -> None:
        self.size = size

    def read(self, r: Reader) -> Any:
        return r.take(self.size)

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, bytes) or len(value) != self.size:
            raise BcsError("wrong length")
        w += value


class ByteVector(Type):
    def read(self, r: Reader) -> Any:
        return r.take(r.uleb())

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, bytes):
            raise BcsError("not bytes")
        w += uleb_encode(len(value)) + value


def utf8_decode(data: bytes) -> str:
    """UTF-8 as a WHATWG TextDecoder decodes it by default: malformed sequences replaced, a leading BOM removed."""
    text = data.decode("utf-8", errors="replace")
    return text[1:] if text.startswith("﻿") else text


def utf8_encode(text: str) -> bytes:
    """UTF-8 as a WHATWG TextEncoder encodes it: a lone surrogate as U+FFFD."""
    return "".join("\ufffd" if 0xD800 <= ord(c) <= 0xDFFF else c for c in text).encode("utf-8")


class String(Type):
    def read(self, r: Reader) -> Any:
        return utf8_decode(r.take(r.uleb()))

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, str):
            raise BcsError("not a string")
        data = utf8_encode(value)
        w += uleb_encode(len(data)) + data


class Struct(Type):
    def __init__(self, fields: Sequence[tuple[str, Type]]) -> None:
        self.fields = list(fields)

    def read(self, r: Reader) -> Any:
        return {name: t.read(r) for name, t in self.fields}

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, dict):
            raise BcsError("not a struct")
        for name, t in self.fields:
            t.write(value.get(name), w)


class Enum(Type):
    def __init__(self, variants: Sequence[tuple[str, Type | None]]) -> None:
        self.variants = list(variants)

    def read(self, r: Reader) -> Any:
        index = r.uleb()
        if index >= len(self.variants):
            raise BcsError("unknown variant")
        name, t = self.variants[index]
        value = t.read(r) if t is not None else None
        return {name: True if value is None else value, "$kind": name}

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, dict):
            raise BcsError("not an enum")
        names = [n for n, _ in self.variants]
        present = [k for k in value if k in names and value[k] is not None]
        if len(present) != 1:
            raise BcsError("not one variant")
        index = names.index(present[0])
        w += uleb_encode(index)
        t = self.variants[index][1]
        if t is not None:
            t.write(value[present[0]], w)


class Tuple(Type):
    def __init__(self, types: Sequence[Type]) -> None:
        self.types = list(types)

    def read(self, r: Reader) -> Any:
        return [t.read(r) for t in self.types]

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, list):
            raise BcsError("not a tuple")
        for i, t in enumerate(self.types):
            t.write(value[i] if i < len(value) else None, w)


class Vector(Type):
    def __init__(self, t: Type) -> None:
        self.t = t

    def read(self, r: Reader) -> Any:
        n = r.uleb()
        out = []
        for _ in range(n):
            out.append(self.t.read(r))
        return out

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, list):
            raise BcsError("not a vector")
        w += uleb_encode(len(value))
        for item in value:
            self.t.write(item, w)


class Transform(Type):
    """inner read then output; validate, input, then inner write."""

    def __init__(
        self,
        inner: Type,
        output: Callable[[Any], Any] | None = None,
        input: Callable[[Any], Any] | None = None,
        validate: Callable[[Any], None] | None = None,
    ) -> None:
        self.inner = inner
        self.output = output
        self.input = input
        self.validate = validate

    def read(self, r: Reader) -> Any:
        v = self.inner.read(r)
        return self.output(v) if self.output is not None else v

    def write(self, value: Any, w: bytearray) -> None:
        if self.validate is not None:
            self.validate(value)
        self.inner.write(self.input(value) if self.input is not None else value, w)


class Lazy(Type):
    def __init__(self, get: Callable[[], Type]) -> None:
        self.get = get

    def read(self, r: Reader) -> Any:
        return self.get().read(r)

    def write(self, value: Any, w: bytearray) -> None:
        self.get().write(value, w)


def option(t: Type) -> Type:
    """An Option enum whose value is the Some value, or None."""
    return Transform(
        Enum([("None", None), ("Some", t)]),
        output=lambda v: v["Some"] if v["$kind"] == "Some" else None,
        input=lambda v: {"None": True} if v is None else {"Some": v},
    )


def _compare_bytes(a: bytes, b: bytes) -> int:
    for x, y in zip(a, b):
        if x != y:
            return x - y
    return len(a) - len(b)


def _compare_entries(a: tuple[bytes, Any], b: tuple[bytes, Any]) -> int:
    return _compare_bytes(a[0], b[0])


class Map(Type):
    """A map read into a dict, a repeated key keeping its first position and its last value; written with its keys in
    the order of their encoded bytes."""

    def __init__(self, key: Type, value: Type) -> None:
        self.key = key
        self.value = value

    def read(self, r: Reader) -> Any:
        n = r.uleb()
        out: dict[Any, Any] = {}
        for _ in range(n):
            k = self.key.read(r)
            out[k] = self.value.read(r)
        return out

    def write(self, value: Any, w: bytearray) -> None:
        if not isinstance(value, dict):
            raise BcsError("not a map")
        entries = [(self.key.serialize(k), v) for k, v in value.items()]
        entries.sort(key=functools.cmp_to_key(_compare_entries))
        w += uleb_encode(len(entries))
        for kb, v in entries:
            w += kb
            self.value.write(v, w)


U8 = UInt(1, False)
U16 = UInt(2, False)
U32 = UInt(4, False)
U64 = UInt(8, True)
U128 = UInt(16, True)
U256 = UInt(32, True)
BOOL = Bool()
BYTE_VECTOR = ByteVector()
STRING = String()
