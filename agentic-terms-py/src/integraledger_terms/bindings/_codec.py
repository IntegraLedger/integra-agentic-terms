"""Byte encodings the bindings read and write: base64url without padding (RFC 4648 §5) and padded standard base64
(§4), each read in its canonical form (§3.5), base58 (the Bitcoin alphabet), 0x hex, UTF-8 as TextEncoder writes it,
and the JSON forms the TypeScript bindings compare with."""

import base64
import binascii
import json
import math
import re
from typing import Any

_B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64U_INDEX = {c: i for i, c in enumerate(_B64U)}
_B64U_TEXT = re.compile(r"[A-Za-z0-9_-]*")
# The bits of the last character past the last whole byte, by the text's length mod 4.
_B64U_SPARE = (0, 0, 0x0F, 0x03)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def is_b64u(text: object) -> bool:
    """True when text is base64url without padding in its canonical form (RFC 4648 §3.5): the URL-safe alphabet alone, a
    length that is not 1 mod 4, and zero bits past the last whole byte in the last character."""
    if not isinstance(text, str) or len(text) % 4 == 1 or _B64U_TEXT.fullmatch(text) is None:
        return False
    return text == "" or _B64U_INDEX[text[-1]] & _B64U_SPARE[len(text) % 4] == 0


def b64u_decode(text: object, max_bytes: int | None = None) -> bytes | None:
    """The bytes of base64url without padding in its canonical form (is_b64u), when they number at most max_bytes: the
    length is checked before anything is decoded. None for anything else."""
    if not isinstance(text, str):
        return None
    if max_bytes is not None and len(text) > math.ceil(max_bytes * 4 / 3):
        return None
    if not is_b64u(text):
        return None
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(text: object) -> bytes | None:
    """Standard padded base64 (RFC 4648 §4) in its canonical form (RFC 4648 §3.5); None for anything else. A text whose
    last character before the padding has a bit set past the last byte is not that form. Every rail's standard base64
    is read here."""
    if not isinstance(text, str):
        return None
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return data if base64.b64encode(data).decode("ascii") == text else None


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


def text_encode(text: str) -> bytes:
    """The UTF-8 bytes TextEncoder writes for text as a JavaScript string of its UTF-16 code units (WHATWG Encoding,
    UTF-8 encode): a surrogate pair is the one four-byte character it forms, held as one code point or as two, and each
    lone surrogate is U+FFFD."""
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace").encode("utf-8")


MAX_JSON_DEPTH = 64


def es_number(value: int | float) -> str:
    """A number as JSON.stringify writes it (ECMAScript Number::toString). An int past 2^53 is the double JSON.parse
    reads for it, and one outside the double range is the infinity JSON.parse reads: like any non-finite number, it
    raises ValueError."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("not a number")
    if isinstance(value, int):
        if abs(value) <= 2**53:
            return str(value)
        try:
            value = float(value)
        except OverflowError:
            raise ValueError("not finite") from None
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


# A surrogate pair, whose two code points JSON.stringify writes as the one character they form, or a lone surrogate,
# which it writes as a lower-case \uXXXX escape.
_SURROGATES = re.compile("[\ud800-\udbff][\udc00-\udfff]|[\ud800-\udfff]")


def _surrogate(match: re.Match[str]) -> str:
    s = match.group()
    if len(s) == 2:
        return chr(0x10000 + ((ord(s[0]) - 0xD800) << 10) + (ord(s[1]) - 0xDC00))
    return f"\\u{ord(s):04x}"


def _string(text: str) -> str:
    """A string as JSON.stringify writes it: quoted, with its short escapes, and each lone surrogate escaped."""
    return _SURROGATES.sub(_surrogate, json.dumps(text, ensure_ascii=False))


def js_json(value: Any, depth: int = 0, *, null_non_finite: bool = False) -> str:
    """The text JSON.stringify writes for plain JSON data: compact, members in their order, non-ASCII kept. A number
    that is not finite (es_number) raises ValueError, or, with null_non_finite, is written null, as JSON.stringify
    writes it (ECMA-262 SerializeJSONProperty). Arrays and objects nested more than MAX_JSON_DEPTH levels, the value
    itself being level 1, raise ValueError, as the protocol package writes no deeper JSON."""
    if depth >= MAX_JSON_DEPTH and isinstance(value, (list, tuple, dict)):
        raise ValueError("too deep")
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        try:
            return es_number(value)
        except ValueError:
            if null_non_finite:
                return "null"
            raise
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(js_json(v, depth + 1, null_non_finite=null_non_finite) for v in value) + "]"
    if isinstance(value, dict):
        members = (_string(k) + ":" + js_json(v, depth + 1, null_non_finite=null_non_finite) for k, v in value.items())
        return "{" + ",".join(members) + "}"
    raise TypeError("not JSON data")


def utf16_key(text: str) -> bytes:
    """The sort key of a string by its UTF-16 code units, which is RFC 8785's member order; a lone surrogate is its own
    code unit."""
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
        keys = sorted(value, key=utf16_key)
        for key in keys:
            key.encode("utf-8")
        return "{" + ",".join(_string(k) + ":" + canonical_json(value[k], depth + 1) for k in keys) + "}"
    return js_json(value)


def canonical_or_none(value: Any) -> str | None:
    try:
        return canonical_json(value)
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        return None
