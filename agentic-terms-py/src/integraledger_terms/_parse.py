"""The parse of terms' profile buyer-gate.md (rule 5): the ATR's bytes as they were fetched, the bytes the gate hashed,
read as exactly what the protocol package's assemble takes as a party's bytes (its check 8), so that the TypeScript and
the Python gate read one text alike. json.loads alone is not the parse: it takes NaN, Infinity and -Infinity, reads a
number past the largest double as infinity, keeps an integer past 2^53 - 1 exactly (and raises past 4,300 digits)
and keeps the last of a repeated name. The text is scanned here first, and only bytes the scan takes are loaded."""

import json
import math
import re
from typing import Any

from ._types import Declined

# lcp's MAX_JSON_DEPTH: arrays and objects nest at most this many levels, the outermost counting 1.
MAX_JSON_DEPTH = 64
MAX_SAFE_INTEGER = 2**53 - 1

_BOM = b"\xef\xbb\xbf"
_WS = re.compile(r"[ \t\n\r]*")
_STRING = re.compile(r'"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"')
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")
_LITERALS = ("true", "false", "null")


def _skip(text: str, at: int) -> int:
    """The index after the whitespace at at."""
    m = _WS.match(text, at)
    return at if m is None else m.end()


def _number_ok(token: str, fraction: str | None, exponent: str | None) -> bool:
    """An integer, a number with neither fraction nor exponent, within -(2^53 - 1) to 2^53 - 1; any other number
    finite as an IEEE 754 double (RFC 7493, section 2.2). The integer is decided by its digits before it is converted:
    the grammar admits no leading zero, so one of more than 16 digits lies outside, and int() refuses a string of more
    than 4,300 digits (CPython 3.11 and later) where the text must be declined instead. float() has no such limit."""
    if fraction is None and exponent is None:
        digits = token.lstrip("-")
        return len(digits) <= len(str(MAX_SAFE_INTEGER)) and int(digits) <= MAX_SAFE_INTEGER
    return math.isfinite(float(token))


def is_one_json_text(b: bytes) -> bool:
    """Whether b is what the protocol package's assemble takes as a party's bytes (its check 8): well-formed UTF-8 with
    no leading byte-order mark, holding exactly one RFC 8259 JSON value with optional surrounding whitespace, nested at
    most MAX_JSON_DEPTH levels, in which no object repeats a member name (names compared after their escapes are
    decoded), no number overflows a double, and no integer lies beyond 2^53 - 1 either way."""
    if b.startswith(_BOM):
        return False
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    n = len(text)
    stack: list[str] = []
    names: list[set[str]] = []
    i = _skip(text, 0)

    def member(at: int) -> int:
        """The index after a member name, its colon and the whitespace after it, or -1."""
        m = _STRING.match(text, at)
        if m is None:
            return -1
        name: str = json.loads(m.group())
        seen = names[-1]
        if name in seen:
            return -1
        seen.add(name)
        at = _skip(text, m.end())
        if text[at : at + 1] != ":":
            return -1
        return _skip(text, at + 1)

    while True:
        # A value starts at i.
        c = text[i : i + 1]
        if c in ("{", "["):
            if len(stack) >= MAX_JSON_DEPTH:
                return False
            stack.append(c)
            if c == "{":
                names.append(set())
            i = _skip(text, i + 1)
            close = "}" if c == "{" else "]"
            if text[i : i + 1] == close:
                i += 1
                if stack.pop() == "{":
                    names.pop()
            else:
                if c == "{":
                    i = member(i)
                    if i < 0:
                        return False
                continue
        elif c == '"':
            m = _STRING.match(text, i)
            if m is None:
                return False
            i = m.end()
        elif c == "-" or "0" <= c <= "9":
            m = _NUMBER.match(text, i)
            if m is None or not _number_ok(m.group(), m.group(1), m.group(2)):
                return False
            i = m.end()
        else:
            word = next((w for w in _LITERALS if text.startswith(w, i)), None)
            if word is None:
                return False
            i += len(word)

        # A value ended before i: close containers until another value is due.
        while True:
            i = _skip(text, i)
            if not stack:
                return i == n
            top = stack[-1]
            d = text[i : i + 1]
            if d == ",":
                i = _skip(text, i + 1)
                if top == "{":
                    i = member(i)
                    if i < 0:
                        return False
                break
            if (top == "[" and d == "]") or (top == "{" and d == "}"):
                i += 1
                if stack.pop() == "{":
                    names.pop()
                continue
            return False


class _Parsed:
    """The value the ATR's bytes hold."""

    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value


def parse_atr(atr_bytes: bytes) -> _Parsed | Declined:
    """The ATR's bytes parsed as they were fetched: the value they hold, or atr-malformed where they are not one JSON
    text as is_one_json_text takes it."""
    if not is_one_json_text(atr_bytes):
        return Declined("atr-malformed", "The ATR's bytes are not one JSON text both languages read alike.")
    return _Parsed(json.loads(atr_bytes.decode("utf-8")))
