"""Byte encodings the bindings read and write: strict unpadded base64url (RFC 4648 §5), base64, base58 (the Bitcoin
alphabet), 0x hex, and the JSON forms the TypeScript bindings compare with."""

import base64
import binascii
import json
import math
import re
from typing import Any

_B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64U_INDEX = {c: i for i, c in enumerate(_B64U)}
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: object, max_bytes: int | None = None) -> bytes | None:
    """Strict base64url without padding: only the alphabet, canonical (zero) trailing bits, and at most max_bytes
    decoded. None for anything else."""
    if not isinstance(text, str) or len(text) % 4 == 1:
        return None
    if max_bytes is not None and len(text) > math.ceil(max_bytes * 4 / 3):
        return None
    out = bytearray()
    acc = 0
    bits = 0
    for c in text:
        v = _B64U_INDEX.get(c)
        if v is None:
            return None
        acc = ((acc << 6) | v) & 0xFFFFFF
        bits += 6
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if acc & ((1 << bits) - 1):
        return None
    return bytes(out)


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: object) -> bytes | None:
    """Standard padded base64, alphabet enforced; None for anything else."""
    if not isinstance(text, str):
        return None
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def b58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = _B58[rest] + out
    zeros = len(data) - len(data.lstrip(b"\0"))
    return "1" * zeros + out


def b58_decode(text: object) -> bytes | None:
    """The bytes of a base58 string, or None when it holds a character outside the alphabet."""
    if not isinstance(text, str):
        return None
    number = 0
    for c in text:
        v = _B58_INDEX.get(c)
        if v is None:
            return None
        number = number * 58 + v
    zeros = len(text) - len(text.lstrip("1"))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * zeros + body


def is_hex(value: object) -> bool:
    """0x followed by an even number of hex digits."""
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def hex_bytes(value: object) -> bytes | None:
    return bytes.fromhex(value[2:]) if isinstance(value, str) and is_hex(value) else None


def to_hex(data: bytes) -> str:
    return "0x" + data.hex()


MAX_JSON_DEPTH = 64


def es_number(value: int | float) -> str:
    """A number as JSON.stringify writes it (ECMAScript Number::toString)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("not a number")
    if isinstance(value, int):
        value = float(value) if abs(value) > 2**53 else value
        if isinstance(value, int):
            return str(value)
    if not math.isfinite(value):
        raise ValueError("not finite")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 2**53:
        return str(int(value))
    text = repr(value)
    mantissa, _, exponent = text.partition("e")
    if not exponent:
        return text[:-2] if text.endswith(".0") else text
    digits = mantissa.replace(".", "").lstrip("-")
    sign = "-" if value < 0 else ""
    power = int(exponent)
    n = power + 1
    k = len(digits.rstrip("0")) or 1
    digits = digits[:k]
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    tail = ("." + digits[1:]) if k > 1 else ""
    return sign + digits[0] + tail + "e" + ("+" if n - 1 >= 0 else "-") + str(abs(n - 1))


def _string(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def js_json(value: Any, depth: int = 0) -> str:
    """The text JSON.stringify writes for plain JSON data: compact, members in their order, non-ASCII kept."""
    if depth > MAX_JSON_DEPTH:
        raise ValueError("too deep")
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return es_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(js_json(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(_string(k) + ":" + js_json(v, depth + 1) for k, v in value.items()) + "}"
    raise TypeError("not JSON data")


def _utf16_key(text: str) -> bytes:
    return text.encode("utf-16-be", "surrogatepass")


def canonical_json(value: Any, depth: int = 0) -> str:
    """The RFC 8785 form of value: object members sorted by the UTF-16 code units of their names, recursively, and
    every primitive written as JSON.stringify writes it. Raises for what is not JSON data, for a string that is not
    well formed, and past 64 levels of nesting."""
    if depth >= MAX_JSON_DEPTH and isinstance(value, (list, tuple, dict)):
        raise ValueError("too deep")
    if isinstance(value, str):
        value.encode("utf-8")
        return _string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(v, depth + 1) for v in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("not JSON data")
        keys = sorted(value, key=_utf16_key)
        for key in keys:
            key.encode("utf-8")
        return "{" + ",".join(_string(k) + ":" + canonical_json(value[k], depth + 1) for k in keys) + "}"
    return js_json(value)


def canonical_or_none(value: Any) -> str | None:
    try:
        return canonical_json(value)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None


def utf8_json_length(value: Any) -> int | None:
    """The UTF-8 length of value's compact JSON text, or None when value has none."""
    try:
        return len(js_json(value).encode("utf-8"))
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None



def _json_string_length(text: str, utf8: bool) -> int:
    """The length, in UTF-16 code units or in UTF-8 bytes, of the JSON string JSON.stringify writes for text: quoted,
    with the short escapes, \\u00XX for other control characters and \\uXXXX for a lone surrogate."""
    n = 2
    for c in text:
        o = ord(c)
        if c in '"\\\b\f\n\r\t':
            n += 2
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            n += 6
        elif utf8:
            n += 1 if o < 0x80 else 2 if o < 0x800 else 3 if o <= 0xFFFF else 4
        else:
            n += 2 if o > 0xFFFF else 1
    return n


def js_json_length(value: Any, limit: int, utf8: bool = False) -> int | None:
    """The length of the text JSON.stringify writes for plain JSON data (a non-finite number as null), in UTF-16 code
    units or, with utf8, in UTF-8 bytes; None once it exceeds limit or for what is not JSON data. The walk is iterative
    and stops at the limit."""
    total = 0
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            total += _json_string_length(item, utf8)
        elif item is None or isinstance(item, bool):
            total += 4 if item is None or item is True else 5
        elif isinstance(item, float) and not math.isfinite(item):
            total += 4
        elif isinstance(item, (int, float)):
            total += len(es_number(item))
        elif isinstance(item, (list, tuple)):
            total += 2 + max(len(item) - 1, 0)
            if total > limit:
                return None
            stack.extend(item)
        elif isinstance(item, dict):
            total += 2 + max(len(item) - 1, 0)
            if total > limit:
                return None
            for k, v in item.items():
                if not isinstance(k, str):
                    return None
                total += _json_string_length(k, utf8) + 1
                stack.append(v)
        else:
            return None
        if total > limit:
            return None
    return total
