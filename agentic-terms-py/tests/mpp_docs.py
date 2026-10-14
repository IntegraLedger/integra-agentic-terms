"""The seller's MPP challenge list, built from vector data as the seller's placement writes it: an issued challenge
from a request's JSON text, and the placement of H, the link and the agreement URL in the chosen challenge's id and
opaque, with the request member the pairing carries H in re-encoded where it has one."""

import copy
import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from integraledger_terms import Refusal
from integraledger_terms.bindings._codec import b64u_encode, canonical_json
from integraledger_terms.bindings._lcp import from_lcp_string, is_object, normal_hash, to_lcp_string
from integraledger_terms.bindings._mpp import LCP_KEYS, MAX_CHALLENGES, check_challenge, is_challenge_shape, is_link
from integraledger_terms.bindings._mpp_checks import MAX_DECODED, decode_object, decode_string_map

from support import load

MC = load("mpp-challenge.json")
REALM: str = MC["fixed"]["realm"]
EXPIRES: str = MC["fixed"]["expires"]
# The challenge's members MPP binds.
BOUND = ("realm", "method", "intent", "request", "expires", "digest", "header", "opaque")

# The request member a pairing writes H into, by intent and method; None where no request member carries it. usdc
# carries H in a request member only on its Solana profile (USDC_CARRIER).
CARRIER: Mapping[str, Mapping[str, tuple[str, ...] | None]] = {
    "charge": {
        "card": ("externalId",),
        "stripe": ("methodDetails", "metadata", "legal_context"),
        "usdc": None,
        "evm": None,
        "tempo": None,
        "solana": ("externalId",),
        "stellar": ("recipient",),
        "xrpl": ("methodDetails", "invoiceId"),
        "hedera": None,
        "lightning": ("methodDetails", "invoice"),
        "nearintents": ("externalId",),
    },
    "session": {"lightning": ("depositInvoice",), "hedera": None, "solana": None, "xrpl": None, "evm": None, "tempo": None},
    "subscription": {"tempo": None, "stripe": ("methodDetails", "metadata", "legal_context")},
}

# The request member usdc writes H into, by methodDetails.type; None where no request member carries it.
USDC_CARRIER: Mapping[str, tuple[str, ...] | None] = {"evm": None, "solana": ("externalId",), "stacks": None, "gateway": None}


def carrier_of(c: Mapping[str, Any], request: Mapping[str, Any]) -> tuple[str, ...] | None:
    """The request member a challenge's intent and method carry H in, or None; for usdc, the member its request's
    methodDetails.type names."""
    if c.get("intent") == "charge" and c.get("method") == "usdc":
        md = request.get("methodDetails")
        kind = md.get("type") if is_object(md) else None
        return USDC_CARRIER.get(kind) if isinstance(kind, str) else None
    intent, method = c.get("intent"), c.get("method")
    by_method = CARRIER.get(intent) if isinstance(intent, str) else None
    return by_method.get(method) if by_method is not None and isinstance(method, str) else None


def member_at(o: Mapping[str, Any], path: Sequence[str]) -> Any:
    """The value at path in a decoded request, or None when a step is missing."""
    at: Any = o
    for k in path:
        if not is_object(at) or k not in at:
            return None
        at = at[k]
    return at


def b64u(text: str) -> str:
    return b64u_encode(text.encode("utf-8"))


def issued(method: str, intent: str, request_json: str, realm: str = REALM, expires: str = EXPIRES) -> dict[str, Any]:
    """An issued challenge: realm, method, intent, the request's JSON text as base64url, and the expiry."""
    return {"realm": realm, "method": method, "intent": intent, "request": b64u(request_json), "expires": expires}


def _seller_map(m: Mapping[str, str]) -> dict[str, str]:
    return {k: v for k, v in m.items() if k not in LCP_KEYS}


def _same_bound(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    for k in BOUND:
        if k != "opaque" and a.get(k) != b.get(k):
            return False
    if "opaque" not in a and "opaque" not in b:
        return True
    x = decode_string_map(a["opaque"]) if "opaque" in a else {}
    y = decode_string_map(b["opaque"]) if "opaque" in b else {}
    if x is None or y is None:
        return False
    return canonical_json(_seller_map(x)) == canonical_json(_seller_map(y))


def place(
    doc: Sequence[Mapping[str, Any]], h: str, link: str, option: Mapping[str, Any], agreement_url: str | None = None
) -> list[dict[str, Any]] | Refusal:
    """A copy of doc in which the challenge whose bound members equal option carries the id derived from h (the bare
    base64url of h for a Tempo subscription) and an opaque holding the seller's map plus legalContext,
    legalContextUrl and, when given, legalContextAgreementUrl, as base64url of the RFC 8785 JSON. A doc holding a
    challenge that carries a refused member is mpp/challenge-malformed, as one holding a challenge without the
    required members is."""
    if len(doc) > MAX_CHALLENGES or not all(is_challenge_shape(c) for c in doc) or any("refused" in c for c in doc):
        return Refusal("mpp/challenge-malformed")
    hash_ = normal_hash(h)
    if hash_ is None:
        return Refusal("mpp/challenge-malformed")
    if not is_link(link) or (agreement_url is not None and not is_link(agreement_url)):
        return Refusal("mpp/link-not-https")
    checked = check_challenge(option, False)
    if isinstance(checked, Refusal):
        return checked
    i = next((k for k, c in enumerate(doc) if _same_bound(c, option)), -1)
    if i == -1:
        return Refusal("mpp/not-this-pairing")
    target = doc[i]
    subscription = option["intent"] == "subscription" and option["method"] == "tempo"
    if subscription and any(
        j != i and c["intent"] == "subscription" and c["method"] == "tempo" for j, c in enumerate(doc)
    ):
        return Refusal("mpp/witness-taken")
    present = decode_string_map(target["opaque"]) if "opaque" in target else {}
    if present is None:
        return Refusal("mpp/opaque-malformed")
    lcp = {"legalContext": to_lcp_string(hash_), "legalContextUrl": link}
    if agreement_url is not None:
        lcp["legalContextAgreementUrl"] = agreement_url
    for k in LCP_KEYS:
        if k not in present:
            continue
        same = from_lcp_string(present[k]) == hash_ if k == "legalContext" else present[k] == lcp.get(k)
        if not same:
            return Refusal("mpp/legal-context-conflict")
    text = canonical_json({**_seller_map(present), **lcp})
    if len(text.encode("utf-8")) > MAX_DECODED:
        return Refusal("mpp/opaque-malformed")
    raw = bytes.fromhex(hash_[2:])
    id_ = b64u_encode(raw) if subscription else f"{b64u_encode(raw)}.{i}"
    out = [dict(copy.deepcopy(c)) for c in doc]
    out[i] = {**out[i], "id": id_, "opaque": b64u(text)}
    return out


def _with_member(o: Mapping[str, Any], path: Sequence[str], value: str) -> dict[str, Any]:
    head, rest = path[0], path[1:]
    if not rest:
        return {**o, head: value}
    inner = o.get(head)
    return {**o, head: _with_member(inner if isinstance(inner, Mapping) else {}, rest, value)}


def place_carrier(
    doc: Sequence[Mapping[str, Any]],
    h: str,
    link: str,
    option: Mapping[str, Any],
    carrier: Callable[[Any], str | Refusal],
    agreement_url: str | None = None,
) -> list[dict[str, Any]] | Refusal:
    """place, then the request member the challenge's intent and method carry H in set to what carrier computes from
    the member as issued (None when absent), with the request re-encoded as base64url of its RFC 8785 JSON."""
    placed = place(doc, h, link, option, agreement_url)
    if isinstance(placed, Refusal):
        return placed
    i = next(k for k, c in enumerate(doc) if _same_bound(c, option))
    request = decode_object(placed[i]["request"])
    if request is None:
        return Refusal("mpp/request-malformed")
    path = carrier_of(option, request)
    if path is None:
        return Refusal("mpp/not-this-pairing")
    value = carrier(member_at(request, path))
    if isinstance(value, Refusal):
        return value
    text = canonical_json(_with_member(request, path, value))
    if len(text.encode("utf-8")) > MAX_DECODED:
        return Refusal("mpp/request-malformed")
    placed[i] = {**placed[i], "request": b64u(text)}
    return placed


def placed_doc(option: Mapping[str, Any], h: str, link: str, agreement_url: str | None = None) -> list[dict[str, Any]]:
    """The one-challenge list of option with h and link placed; raises when the placement refuses."""
    out = place([option], h, link, option, agreement_url)
    if isinstance(out, Refusal):
        raise AssertionError(out.code)
    return out


def lcp_carrier(h: str, occupied: str) -> Callable[[Any], str | Refusal]:
    """The carrier that writes h's LCP string where the member is absent or already holds it, and refuses occupied
    otherwise."""
    value = to_lcp_string(h)
    return lambda issued_value: value if issued_value is None or issued_value == value else Refusal(occupied)


def http_doc(doc: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """doc with each challenge's legalContextUrl moved from https to http."""
    out = []
    for c in doc:
        present = decode_string_map(c["opaque"])
        assert present is not None
        http = {**present, "legalContextUrl": present["legalContextUrl"].replace("https://", "http://")}
        out.append({**c, "opaque": b64u(json.dumps(http))})
    return out
