"""JSON and compact-JWS reading as the bindings do it: JSON.parse's result (members in ECMAScript property order),
JSON.stringify's UTF-8 length, string lengths in UTF-16 code units, base64url without padding read in its canonical
form, the three segments of a compact JWS, and the SD-JWT reader of RFC 9901 §7.1 steps 1 and 3-5, without step 2's
signature check. Nothing here verifies a signature.

Every read of JSON text by a binding goes through parse_json or decode_json_segment, which parse only text whose
arrays and objects nest at most MAX_JSON_DEPTH levels deep, counted over the text's brackets outside strings."""

import hashlib
import json
import math
import re
from collections.abc import Generator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._types import Refusal
from . import _codec
from ._codec import b64u_decode, b64u_encode, es_number

MAX_JSON_DEPTH = 64
RESOLUTION_DEPTH = 16
MIB = 1_048_576

_PRESENTATION = re.compile(r"[A-Za-z0-9_.~-]*")
_ARRAY_INDEX = re.compile(r"0|[1-9][0-9]*")
_LONE_SURROGATE = re.compile(r"[\ud800-\udfff]")
_ARRAY_INDEX_LIMIT = 2**32 - 1


def js_length(text: str) -> int:
    """The string's length in UTF-16 code units, as String.prototype.length counts it."""
    return len(text) + sum(1 for c in text if ord(c) > 0xFFFF)


def text_encode(text: str) -> bytes:
    """The UTF-8 bytes TextEncoder writes: a lone surrogate becomes U+FFFD."""
    return _LONE_SURROGATE.sub("�", text).encode("utf-8")


def _is_array_index(key: str) -> bool:
    return _ARRAY_INDEX.fullmatch(key) is not None and int(key) < _ARRAY_INDEX_LIMIT


def _js_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """An object's members in ECMAScript property order: array-index names ascending, then the rest as first written;
    a repeated name keeps its last value."""
    merged: dict[str, Any] = {}
    for key, value in pairs:
        merged[key] = value
    indices = sorted((k for k in merged if _is_array_index(k)), key=int)
    if not indices:
        return merged
    ordered = {k: merged[k] for k in indices}
    ordered.update((k, v) for k, v in merged.items() if not _is_array_index(k))
    return ordered


def _no_constant(name: str) -> Any:
    raise ValueError(name)


def _js_integer(text: str) -> int | float:
    """An integer literal as JSON.parse reads it, whatever its digits: infinity when it is outside the double range,
    and the integer otherwise."""
    value = float(text)
    return value if math.isinf(value) else int(text)


class _Unparsed:
    """The text is not JSON."""


UNPARSED = _Unparsed()


def json_within_depth(text: str) -> bool:
    """True when no array or object in JSON text is nested more than MAX_JSON_DEPTH deep. Brackets inside strings are
    skipped; nothing else about the text is checked."""
    depth = 0
    in_string = False
    i = 0
    while i < len(text):
        c = text[i]
        if in_string:
            if c == "\\":
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
        elif c in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif c in "]}":
            depth -= 1
        i += 1
    return True


def _json_parse(text: str) -> Any:
    """JSON.parse of text within the nesting cap, with objects as dicts in ECMAScript property order; UNPARSED when
    it is not JSON."""
    try:
        return json.loads(text, object_pairs_hook=_js_object, parse_int=_js_integer, parse_constant=_no_constant)
    except ValueError:
        return UNPARSED


def parse_json(text: str) -> Any:
    """The value of JSON text nested at most MAX_JSON_DEPTH deep; UNPARSED for text that is deeper or is not JSON."""
    if not json_within_depth(text):
        return UNPARSED
    return _json_parse(text)


def member_names(text: str) -> list[str]:
    """The member names of the JSON object text holds, decoded, in the order written, a repeated name each time it is
    written. text is one JSON object that parse_json has read; the root object's members are the last ones the parser
    hands over."""
    names: list[str] = []

    def record(pairs: list[tuple[str, Any]]) -> None:
        names[:] = [k for k, _ in pairs]

    json.loads(text, object_pairs_hook=record, parse_int=_js_integer, parse_constant=_no_constant)
    return names


_JSON_TOKEN = re.compile(
    r'[ \t\n\r]*(?:([][{}:,])|("(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*")'
    r"|(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null))"
)
_JSON_SPACE = re.compile(r"[ \t\n\r]*")


def _is_json_text(text: str) -> bool:
    """True when text is one RFC 8259 JSON value with optional surrounding whitespace; read with an explicit stack,
    so any depth is read."""
    stack: list[str] = []
    state = "value"
    at = 0
    while True:
        if state == "after" and not stack:
            space = _JSON_SPACE.match(text, at)
            return space is not None and space.end() == len(text)
        m = _JSON_TOKEN.match(text, at)
        if m is None:
            return False
        at = m.end()
        punct, string, scalar = m.group(1), m.group(2), m.group(3)
        if state in ("value", "value-or-end"):
            if punct == "]" and state == "value-or-end":
                stack.pop()
                state = "after"
            elif punct in ("{", "["):
                stack.append(punct)
                state = "key-or-end" if punct == "{" else "value-or-end"
            elif string is not None or scalar is not None:
                state = "after"
            else:
                return False
        elif state in ("key", "key-or-end"):
            if punct == "}" and state == "key-or-end":
                stack.pop()
                state = "after"
            elif string is not None:
                state = "colon"
            else:
                return False
        elif state == "colon":
            if punct != ":":
                return False
            state = "value"
        elif punct == ",":
            state = "key" if stack[-1] == "{" else "value"
        elif punct == ("}" if stack[-1] == "{" else "]"):
            stack.pop()
        else:
            return False


def _deeper_than_the_cap(text: str) -> Any:
    """For JSON text nested past the cap: a value of the same top-level kind nested one level past it, which every
    depth check refuses; UNPARSED when the text is not JSON."""
    if not _is_json_text(text):
        return UNPARSED
    inner: Any = []
    for _ in range(MAX_JSON_DEPTH - 1):
        inner = [inner]
    return {"": inner} if text.lstrip(" \t\n\r").startswith("{") else [inner]


def _string_bytes(text: str) -> int:
    n = 2
    for c in text:
        o = ord(c)
        if c in '"\\' or c in "\b\f\n\r\t":
            n += 2
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            n += 6
        elif o < 0x80:
            n += 1
        elif o < 0x800:
            n += 2
        elif o < 0x10000:
            n += 3
        else:
            n += 4
    return n


def _number_bytes(value: int | float) -> int:
    """The length of a number as JSON.stringify writes it. A number outside the double range is the infinity JSON.parse
    reads for it, and JSON.stringify writes every infinity as null."""
    if isinstance(value, int) and abs(value) > 2**53:
        try:
            value = float(value)
        except OverflowError:
            return 4
    if not math.isfinite(value):
        return 4
    return len(es_number(value))


def json_bytes(value: Any) -> float | None:
    """The UTF-8 length of JSON.stringify(value), or None when the value cannot be written as JSON. A value in which
    arrays and objects nest more than MAX_JSON_DEPTH levels, the value itself being level 1, measures infinity, over
    every size limit: the walk stops at the first level past the bound, so the answer never depends on the
    interpreter's stack."""
    total = 0
    path: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(value, 1, False)]
    while stack:
        item, level, leaving = stack.pop()
        if leaving:
            path.discard(id(item))
        elif item is None or item is True:
            total += 4
        elif item is False:
            total += 5
        elif isinstance(item, str):
            total += _string_bytes(item)
        elif isinstance(item, (int, float)):
            total += _number_bytes(item)
        elif isinstance(item, Mapping) or (isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray))):
            if level > MAX_JSON_DEPTH:
                return math.inf
            if id(item) in path:
                return None
            path.add(id(item))
            stack.append((item, level, True))
            if isinstance(item, Mapping):
                members = list(item.items())
                if any(not isinstance(key, str) for key, _ in members):
                    return None
                total += 2 + max(0, len(members) - 1) + sum(_string_bytes(key) + 1 for key, _ in members)
                children = [member for _, member in members]
            else:
                children = list(item)
                total += 2 + max(0, len(children) - 1)
            stack.extend((child, level + 1, False) for child in reversed(children))
        else:
            return None
    return total


def disclosure_digest(text: str) -> str:
    """Unpadded base64url of SHA-256 over the string's UTF-8 bytes (RFC 9901 §4.2.3)."""
    return b64u_encode(hashlib.sha256(text_encode(text)).digest())


def decode_json_segment(text: str) -> Any:
    """The JSON value that base64url text without padding, in its canonical form, decodes to as UTF-8, or UNPARSED.
    JSON nested past the cap comes back as a value that within_depth refuses."""
    data = b64u_decode(text)
    if data is None:
        return UNPARSED
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return UNPARSED
    if json_within_depth(decoded):
        return _json_parse(decoded)
    return _deeper_than_the_cap(decoded)


def jws_segments(text: object) -> tuple[str, str, str] | None:
    """The three segments of a compact JWS, each base64url without padding in its canonical form (RFC 7515 §2, RFC 4648
    §3.5), or None. A segment whose last character carries a bit past its last byte is None, the signature's
    included."""
    if not isinstance(text, str):
        return None
    parts = text.split(".")
    if len(parts) != 3:
        return None
    for part in parts:
        if not _codec.is_b64u(part):
            return None
    return parts[0], parts[1], parts[2]


def is_json_array(value: object) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def within_depth(value: Any, limit: int = MAX_JSON_DEPTH) -> bool:
    """True when the value nests no deeper than limit levels of arrays and objects."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, Mapping):
            children: Sequence[Any] = list(item.values())
        elif is_json_array(item):
            children = item
        else:
            continue
        if depth >= limit:
            return False
        stack.extend((child, depth + 1) for child in children)
    return True


@dataclass(frozen=True, slots=True)
class SdJwtCodes:
    malformed: str
    sd_alg_unsupported: str
    unreferenced: str
    too_large: str


@dataclass(frozen=True, slots=True)
class SdJwtBounds:
    max_bytes: int
    max_disclosures: int


DEFAULT_BOUNDS = SdJwtBounds(max_bytes=MIB, max_disclosures=128)


@dataclass(frozen=True, slots=True)
class SdJwt:
    jwt: str
    header: dict[str, Any]
    payload: dict[str, Any]
    resolved: dict[str, Any]
    disclosures: tuple[str, ...]
    key_binding: str | None


@dataclass(slots=True)
class _Disclosure:
    name: str | None
    value: Any
    used: bool = False


@dataclass(frozen=True, slots=True)
class _Fail:
    code: str


_Outcome = Any
_Step = Generator[tuple[Any, int, int], _Outcome, _Outcome]


class _Resolver:
    """Resolves disclosures into a payload by digest, one nesting level per generator frame, so the depth of the
    payload never reaches the interpreter's stack. A disclosed value takes the place of the element or member that
    references it, and the resolved payload, itself level 1, nests at most MAX_JSON_DEPTH levels."""

    def __init__(self, by_digest: dict[str, _Disclosure], codes: SdJwtCodes) -> None:
        self.by_digest = by_digest
        self.codes = codes
        self.referenced: set[str] = set()
        self.listed_ignored: set[str] = set()

    def run(self, value: Any) -> _Outcome:
        frames: list[_Step] = [self.resolve(value, 0, 1)]
        sent: _Outcome = None
        while frames:
            try:
                child, level, depth = frames[-1].send(sent)
            except StopIteration as done:
                frames.pop()
                sent = done.value
                continue
            frames.append(self.resolve(child, level, depth))
            sent = None
        return sent

    def resolve(self, value: Any, level: int, depth: int) -> _Step:
        codes = self.codes
        if isinstance(value, (list, dict)) and depth > MAX_JSON_DEPTH:
            return _Fail(codes.too_large)
        if isinstance(value, list):
            out: list[Any] = []
            for element in value:
                if isinstance(element, dict) and len(element) == 1 and "..." in element:
                    digest = element["..."]
                    if not isinstance(digest, str) or digest in self.referenced:
                        return _Fail(codes.malformed)
                    self.referenced.add(digest)
                    found = self.by_digest.get(digest)
                    if found is None:
                        continue
                    if found.name is not None:
                        return _Fail(codes.malformed)
                    found.used = True
                    if level + 1 > RESOLUTION_DEPTH:
                        return _Fail(codes.too_large)
                    r = yield (found.value, level + 1, depth + 1)
                else:
                    r = yield (element, level, depth + 1)
                if isinstance(r, _Fail):
                    return r
                out.append(r)
            return out
        if not isinstance(value, dict):
            return value

        obj: dict[str, Any] = {}
        for key, member in value.items():
            if key == "_sd":
                continue
            r = yield (member, level, depth + 1)
            if isinstance(r, _Fail):
                return r
            obj[key] = r
        if "_sd" not in value:
            return obj
        sd = value["_sd"]
        if not isinstance(sd, list):
            return _Fail(codes.malformed)
        for digest in sd:
            if not isinstance(digest, str):
                return _Fail(codes.malformed)
            found = self.by_digest.get(digest)
            if found is None or found.name is None:
                if digest in self.listed_ignored:
                    return _Fail(codes.malformed)
                self.listed_ignored.add(digest)
                continue
            if digest in self.referenced:
                return _Fail(codes.malformed)
            self.referenced.add(digest)
            name = found.name
            if name in ("_sd", "...") or name in obj:
                return _Fail(codes.malformed)
            found.used = True
            if level + 1 > RESOLUTION_DEPTH:
                return _Fail(codes.too_large)
            r = yield (found.value, level + 1, depth + 1)
            if isinstance(r, _Fail):
                return r
            obj[name] = r
        return obj


def read_sd_jwt(token: object, codes: SdJwtCodes, bounds: SdJwtBounds = DEFAULT_BOUNDS) -> SdJwt | Refusal:
    """Reads an SD-JWT presentation and resolves its disclosures: every disclosure must be referenced and no digest
    referenced twice; a digest in an object's _sd that does not name a three-element disclosure, whether it names a
    two-element disclosure or none, is ignored at its first _sd listing, and a second _sd listing of it is malformed
    (RFC 9901 section 7.1 step 4). A resolved payload that, with each disclosed value where its reference sits, nests
    more than MAX_JSON_DEPTH levels is too_large. Each JWS segment and each disclosure is base64url without padding in
    its canonical form (RFC 7515 §2, RFC 4648 §3.5): one whose last character carries a bit past its last byte is
    malformed. No signature is verified."""
    malformed = Refusal(codes.malformed)
    if not isinstance(token, str):
        return malformed
    if js_length(token) > bounds.max_bytes:
        return Refusal(codes.too_large)
    if _PRESENTATION.fullmatch(token) is None:
        return malformed

    parts = token.split("~")
    if len(parts) < 2:
        return malformed
    jwt = parts[0]
    last = parts[-1]
    if last == "":
        key_binding: str | None = None
    elif "." in last:
        key_binding = last
    else:
        return malformed
    disclosures = parts[1:-1]
    if len(disclosures) > bounds.max_disclosures:
        return Refusal(codes.too_large)

    segments = jws_segments(jwt)
    if segments is None:
        return malformed
    header = decode_json_segment(segments[0])
    payload = decode_json_segment(segments[1])
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return malformed
    if not within_depth(header) or not within_depth(payload):
        return Refusal(codes.too_large)

    if "_sd_alg" in payload and payload["_sd_alg"] != "sha-256":
        return Refusal(codes.sd_alg_unsupported)

    by_digest: dict[str, _Disclosure] = {}
    for d in disclosures:
        if d == "":
            return malformed
        decoded = decode_json_segment(d)
        if not isinstance(decoded, list):
            return malformed
        if not within_depth(decoded):
            return Refusal(codes.too_large)
        if len(decoded) == 3 and isinstance(decoded[0], str) and isinstance(decoded[1], str):
            disclosure = _Disclosure(decoded[1], decoded[2])
        elif len(decoded) == 2 and isinstance(decoded[0], str):
            disclosure = _Disclosure(None, decoded[1])
        else:
            return malformed
        digest = disclosure_digest(d)
        if digest in by_digest:
            return malformed
        by_digest[digest] = disclosure

    outcome = _Resolver(by_digest, codes).run(payload)
    if isinstance(outcome, _Fail):
        return Refusal(outcome.code)
    for disclosure in by_digest.values():
        if not disclosure.used:
            return Refusal(codes.unreferenced)
    assert isinstance(outcome, dict)
    outcome.pop("_sd_alg", None)
    return SdJwt(jwt, header, payload, outcome, tuple(disclosures), key_binding)
