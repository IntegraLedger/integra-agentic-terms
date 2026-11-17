"""What the gate compares with the ATR's binding slot, in the forms the protocol package writes them: the commitment to
the buyer's request over HTTP and over MCP (lcp profile x402-request-commitment.md), an x402 option as its pairing's
unplaced gives it, and an MPP challenge by its bound members as lcp's issuedDigest reads them. Each is held by lcp's own
vectors (x402-request-commitment.json, mpp-server-checks.json)."""

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ._types import Refusal
from .bindings._codec import b64u_encode, canonical_or_none
from .bindings._jose import js_length
from .bindings._lcp import is_object
from .bindings._mpp import challenge_id_h, is_challenge_shape, same_bytes
from .bindings._mpp_checks import decode_object, decode_string_map

# lcp's MAX_REQUEST_BYTES: a body, the RFC 8785 form of a tool call's arguments, and a named header field's value, its
# lines joined, each at most this many bytes.
MAX_REQUEST_BYTES = 1_048_576
MAX_TARGET = 8192
MAX_DECODED = 8192

# RFC 9110 section 5.6.2: a token, 1*tchar, as a method (section 9.1) and a field name (section 5.1) are.
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def _digest(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def _ascii_lower(s: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def _is_visible_ascii(s: str) -> bool:
    return all(0x21 <= ord(c) <= 0x7E for c in s)


def _field_text(s: str) -> bool:
    """Every character visible ASCII, the space or the tab."""
    return all(c == "\t" or 0x20 <= ord(c) <= 0x7E for c in s)


def _header_digests(names: object, record: object) -> list[dict[str, Any]] | str:
    """The named fields' digests, in the order named, as lcp's headerDigests gives them: "invalid" or "too-large" for
    what it refuses. Only the named fields are read; a field's lines are joined by a comma and a space, cookie's by a
    semicolon and a space; a field with no line, or none in the record, has digest None."""
    if not isinstance(names, list):
        return "invalid"
    lower: list[str] = []
    for n in names:
        if not isinstance(n, str) or _TOKEN.fullmatch(n) is None:
            return "invalid"
        low = _ascii_lower(n)
        if low in lower:
            return "invalid"
        lower.append(low)
    if not isinstance(record, Mapping):
        return "invalid"
    keys = list(record.keys())
    lines: list[list[str] | None] = []
    for name in lower:
        matching = [k for k in keys if isinstance(k, str) and _ascii_lower(k) == name]
        if len(matching) > 1:
            return "invalid"
        if not matching:
            lines.append(None)
            continue
        v = record[matching[0]]
        given = [v] if isinstance(v, str) else list(v) if isinstance(v, (list, tuple)) else None
        if given is None or not all(isinstance(x, str) for x in given):
            return "invalid"
        if not given:
            lines.append(None)
            continue
        if sum(js_length(x) for x in given) + (len(given) - 1) * 2 > MAX_REQUEST_BYTES:
            return "too-large"
        if not all(_field_text(x) for x in given):
            return "invalid"
        lines.append([x.strip(" \t") for x in given])
    out: list[dict[str, Any]] = []
    for name, joined in zip(lower, lines):
        digest = None if joined is None else _digest(("; " if name == "cookie" else ", ").join(joined).encode("utf-8"))
        out.append({"name": name, "digest": digest})
    return out


def request_commitment(r: object, fields: Sequence[str] | None = None) -> dict[str, Any] | Refusal:
    """lcp's requestCommitment: {method, path, query, bodyDigest} of an HTTP request, the method a token, the target
    split at its first "?", SHA-256 over the body's bytes as received; and, where fields names header fields, headers:
    each named field's lower-cased name and the digest of its value. The refusals are lcp's codes."""
    if not isinstance(r, Mapping) or not isinstance(r.get("method"), str) or _TOKEN.fullmatch(r["method"]) is None:
        return Refusal("x402/request-target-invalid")
    target, body = r.get("target"), r.get("body")
    if not isinstance(target, str) or not isinstance(body, (bytes, bytearray)):
        return Refusal("x402/request-target-invalid")
    if js_length(target) > MAX_TARGET or len(body) > MAX_REQUEST_BYTES:
        return Refusal("x402/request-too-large")
    if not target.startswith("/") or not _is_visible_ascii(target):
        return Refusal("x402/request-target-invalid")
    path, _, query = target.partition("?")
    commitment: dict[str, Any] = {"method": r["method"], "path": path, "query": query, "bodyDigest": _digest(bytes(body))}
    if fields is None or (isinstance(fields, list) and not fields):
        return commitment
    headers = _header_digests(fields, r.get("headers"))
    if headers == "too-large":
        return Refusal("x402/request-too-large")
    if isinstance(headers, str):
        return Refusal("x402/request-header-invalid")
    return {**commitment, "headers": headers}


def _is_well_formed(s: str) -> bool:
    return not any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def tool_call_commitment(call: object) -> dict[str, Any] | Refusal:
    """lcp's toolCallCommitment: {tool, argumentsDigest}, the tool's name as received and SHA-256 over the UTF-8 of the
    RFC 8785 form of its arguments, absent read as {}. The refusals are lcp's codes."""
    if not isinstance(call, Mapping) or "refused" in call:
        return Refusal("x402/tool-call-malformed")
    name = call.get("name")
    if not isinstance(name, str) or not name or js_length(name) > MAX_TARGET or not _is_well_formed(name):
        return Refusal("x402/tool-call-malformed")
    args = call["arguments"] if "arguments" in call else {}
    if not isinstance(args, Mapping):
        return Refusal("x402/tool-call-malformed")
    text = canonical_or_none(dict(args))
    if text is None:
        return Refusal("x402/tool-call-malformed")
    data = text.encode("utf-8")
    if len(data) > MAX_REQUEST_BYTES:
        return Refusal("x402/request-too-large")
    return {"tool": name, "argumentsDigest": _digest(data)}


# ── An x402 option as its pairing's unplaced gives it.


def _without_extra(option: Mapping[str, Any], key: str, keep_empty: bool) -> Mapping[str, Any]:
    extra = option.get("extra")
    if not isinstance(extra, Mapping) or key not in extra:
        return option
    rest = {k: v for k, v in extra.items() if k != key}
    base = {k: v for k, v in option.items() if k != "extra"}
    return {**base, "extra": rest} if rest or keep_empty else base


def x402_unplaced(pairing: str, option: object) -> object:
    """The option as lcp's unplaced for the pairing gives it, for a binding that carries no unplaced of its own (the
    protocol package: src/x402-exact-solana.ts:134, src/x402-upto-solana.ts:144 and
    src/x402-batch-settlement.ts:1706 drop extra.memo, src/x402-exact-xrpl.ts:154 drops extra.invoiceId, each through
    src/internal/x402.ts:308's withoutExtra, which removes an extra the removal empties; src/tvm.ts:1937 drops
    extra.forwardPayload and keeps the extra; every other x402 pairing's leaves the option, src/x402.ts:513), an option
    that carries a refused member being x402/option-malformed."""
    if not isinstance(option, Mapping):
        return option
    if "refused" in option:
        return Refusal("x402/option-malformed")
    if pairing in ("x402/exact/solana", "x402/upto/solana", "x402/batch-settlement/solana"):
        return _without_extra(option, "memo", keep_empty=False)
    if pairing == "x402/exact/xrpl":
        return _without_extra(option, "invoiceId", keep_empty=False)
    if pairing == "x402/exact/tvm":
        return _without_extra(option, "forwardPayload", keep_empty=True)
    return option


# ── An MPP challenge by its bound members.

_LCP_KEYS = ("legalContext", "legalContextUrl", "legalContextAgreementUrl")

# The request member each intent and method carries H in, from lcp's MPP data (each pairing's carrier.member); usdc's
# by its methodDetails.type. A Tempo charge's carrier is the split whose memo is H.
_CARRIER: Mapping[tuple[str, str], tuple[str, ...]] = {
    ("charge", "solana"): ("externalId",),
    ("subscription", "solana"): ("externalId",),
    ("charge", "xrpl"): ("methodDetails", "invoiceId"),
    ("charge", "nearintents"): ("externalId",),
    ("charge", "card"): ("externalId",),
    ("charge", "stripe"): ("methodDetails", "metadata", "legal_context"),
    ("subscription", "stripe"): ("methodDetails", "metadata", "legal_context"),
    ("charge", "lightning"): ("methodDetails", "invoice"),
    ("session", "lightning"): ("depositInvoice",),
}
_USDC_CARRIER: Mapping[str, tuple[str, ...]] = {"solana": ("externalId",)}

# The request members of a NEAR Intents charge written after H, at the quote.
_NEARINTENTS_QUOTE: tuple[tuple[str, ...], ...] = (
    ("externalId",),
    ("recipient",),
    ("amount",),
    ("methodDetails", "minAmountIn"),
    ("methodDetails", "depositMemo"),
    ("methodDetails", "timeEstimate"),
    ("methodDetails", "refundTo"),
)


def _without(o: Mapping[str, Any], path: Sequence[str]) -> Mapping[str, Any]:
    """o without the member at path; a metadata object that removal leaves empty is removed too."""
    if not path or path[0] not in o:
        return o
    head, rest = path[0], path[1:]
    if not rest:
        return {k: v for k, v in o.items() if k != head}
    inner = o[head]
    if not is_object(inner):
        return o
    reduced = _without(inner, rest)
    if head == "metadata" and not reduced and inner:
        return {k: v for k, v in o.items() if k != head}
    return {**o, head: reduced}


def _member_at(o: Mapping[str, Any], path: Sequence[str]) -> bool:
    at: Any = o
    for k in path:
        if not is_object(at) or k not in at:
            return False
        at = at[k]
    return True


def _as_issued(c: Mapping[str, Any], request: Mapping[str, Any]) -> Mapping[str, Any]:
    """A decoded request as the seller issued it: lcp's asIssued, the carrier removed."""
    intent, method = c["intent"], c["method"]
    if intent == "charge" and method == "tempo":
        h = challenge_id_h(c) if isinstance(c.get("id"), str) else None
        md = request.get("methodDetails")
        if not isinstance(h, str) or not is_object(md) or not isinstance(md.get("splits"), list):
            return request
        splits = md["splits"]
        kept = [s for s in splits if not (is_object(s) and isinstance(s.get("memo"), str) and same_bytes(s["memo"], h))]
        if len(kept) == len(splits):
            return request
        rest = {k: v for k, v in md.items() if k != "splits"}
        return {**request, "methodDetails": rest if not kept else {**rest, "splits": kept}}
    if intent == "charge" and method == "usdc":
        md = request.get("methodDetails")
        kind = md.get("type") if is_object(md) else None
        path = _USDC_CARRIER.get(kind) if isinstance(kind, str) else None
    else:
        path = _CARRIER.get((intent, method))
    if path is None or not _member_at(request, path):
        return request
    return _without(request, path)


def _opaque_members(v: object) -> dict[str, str] | None:
    """lcp's opaqueMembers: the flat string map an opaque string decodes to, or an object of string members whose RFC
    8785 form is at most 8 KiB, as a credential may echo it."""
    if isinstance(v, str):
        return decode_string_map(v)
    if not is_object(v) or not all(isinstance(x, str) for x in v.values()):
        return None
    text = canonical_or_none(dict(v))
    if text is None or len(text.encode("utf-8")) > MAX_DECODED:
        return None
    return dict(v)


def _is_echoed_shape(c: object) -> bool:
    if not is_object(c):
        return False
    opaque = c.get("opaque")
    if opaque is None and "opaque" not in c or isinstance(opaque, str):
        return is_challenge_shape(c)
    return is_object(opaque) and is_challenge_shape({k: v for k, v in c.items() if k != "opaque"})


def issued_form(given: object) -> str | None:
    """The RFC 8785 text lcp's issuedDigest hashes for an MPP challenge: realm, method and intent; request decoded as the
    seller issued it, written after H removed for the pairings whose seller writes it (a NEAR Intents charge's quote and
    expires); expires, digest and header; and opaque without the LCP members, omitted when that leaves it empty. A value
    that does not decode is its string. None where the challenge is not of an echoed challenge's shape or the members are
    not JSON."""
    if not _is_echoed_shape(given):
        return None
    assert is_object(given)
    c: dict[str, Any] = dict(given)
    if is_object(c.get("opaque")):
        members = _opaque_members(c["opaque"])
        text = None if members is None else canonical_or_none(members)
        if text is not None:
            c["opaque"] = b64u_encode(text.encode("utf-8"))
    key = (c["intent"], c["method"])
    # unplacedChallenge reads only a challenge of the wire's shape, its opaque a string.
    nearintents = key == ("charge", "nearintents") and is_challenge_shape(c)
    out: dict[str, Any] = {"realm": c["realm"], "method": c["method"], "intent": c["intent"]}
    request = decode_object(c["request"])
    if request is None:
        out["request"] = c["request"]
    else:
        reduced: Mapping[str, Any] = request
        if nearintents:
            for path in _NEARINTENTS_QUOTE:
                reduced = _without(reduced, path)
        out["request"] = dict(_as_issued(c, reduced))
    for k in ("expires", "digest", "header"):
        if k in c and not (k == "expires" and nearintents):
            out[k] = c[k]
    if "opaque" in c:
        members = _opaque_members(c["opaque"])
        if members is None:
            out["opaque"] = c["opaque"]
        else:
            seller = {k: v for k, v in members.items() if k not in _LCP_KEYS}
            if seller:
                out["opaque"] = seller
    return canonical_or_none(out)


def issued_digest(given: object) -> str | None:
    """lcp's issuedDigest: SHA-256 of issued_form as 0x lowercase hex, or None."""
    text = issued_form(given)
    return None if text is None else _digest(text.encode("utf-8"))
