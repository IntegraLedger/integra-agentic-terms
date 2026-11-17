"""The buyer halves of the UCP pairings ucp/checkout/ap2-mandate, ucp/checkout/unsigned, ucp/checkout/agent-signed,
ucp/booking/ap2-mandate and ucp/booking/unsigned: read, build with complete, and bound.

The ATR hash and link ride as one links[] entry of type legal_context in the checkout response. The ap2-mandate
pairings read the hash from the checkout JWT presented beside the buyer's checkout mandate, after AP2's checkout_hash
check, the mandate presented alone or last in AP2's chain; the agent-signed pairing reads it from the legal_context
member of the platform's signed request that completes the checkout; the unsigned pairings have nothing signed to read.
Nothing here takes a key, signs or verifies a signature.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, atr_hash, hash_equals
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._codec import b64_encode, b64u_encode, canonical_or_none, text_encode
from ._jose import MIB, UNPARSED, js_length, json_bytes, parse_json, within_depth
from ._lcp import (
    agreement_fault,
    from_lcp_string,
    is_agreement_url,
    is_https_link,
    is_list,
    is_object,
    is_other_scheme_link,
    normal_hash,
)
from .ap2_checkout_mandate import CHECKOUT_VCT, checkout_binding, checkout_hash_of

CHECKOUT_AP2_MANDATE = "ucp/checkout/ap2-mandate"
CHECKOUT_UNSIGNED = "ucp/checkout/unsigned"
CHECKOUT_AGENT_SIGNED = "ucp/checkout/agent-signed"
BOOKING_AP2_MANDATE = "ucp/booking/ap2-mandate"
BOOKING_UNSIGNED = "ucp/booking/unsigned"

LINK_TYPE = "legal_context"
AGREEMENT_LINK_TYPE = "legal_context_agreement"
MAX_LINKS = 64
MAX_ID = 256
MAX_LINK = 2048
_MERCHANT_AUTHORIZATION = re.compile(r"[A-Za-z0-9_-]+\.\.[A-Za-z0-9_-]+")


def legal_context_link(c: object) -> tuple[AtrHash, str] | Refusal:
    """The hash and link of the checkout's one legal_context link. Nothing else of the checkout is read."""
    if not is_object(c):
        return Refusal("ucp/checkout-malformed")
    if "links" not in c:
        return Refusal("ucp/no-legal-context")
    links = c["links"]
    if not is_list(links):
        return Refusal("ucp/checkout-malformed")
    if len(links) > MAX_LINKS:
        return Refusal("ucp/too-large")
    entries = [entry for entry in links if is_object(entry) and entry.get("type") == LINK_TYPE]
    if not entries:
        return Refusal("ucp/no-legal-context")
    if len(entries) > 1:
        return Refusal("ucp/legal-context-conflict")
    entry = entries[0]
    title = entry.get("title")
    h = from_lcp_string(title) if isinstance(title, str) else None
    if h is None:
        return Refusal("ucp/legal-context-malformed")
    url = entry.get("url")
    if not is_https_link(url):
        return Refusal("ucp/link-not-https" if is_other_scheme_link(url) else "ucp/legal-context-malformed")
    if js_length(url) > MAX_LINK:
        return Refusal("ucp/too-large")
    return h, url


def _agreement_link(c: Mapping[str, Any]) -> str | None | Refusal:
    """The url of the checkout's one legal_context_agreement link, None when it has none."""
    links = c.get("links")
    if not is_list(links):
        return None
    entries = [entry for entry in links if is_object(entry) and entry.get("type") == AGREEMENT_LINK_TYPE]
    if not entries:
        return None
    if len(entries) > 1:
        return Refusal("ucp/legal-context-conflict")
    url = entries[0].get("url")
    return url if is_agreement_url(url) else Refusal(f"ucp/{agreement_fault(url).fault}")


def _checkout_of(doc: object) -> Mapping[str, Any] | Refusal:
    """The checkout's shape as the pairings read it: an object of at most 1 MiB as JSON, nested at most 64 levels, with
    an id of 1-256."""
    if not is_object(doc):
        return Refusal("ucp/checkout-malformed")
    size = json_bytes(doc)
    if size is None:
        return Refusal("ucp/checkout-malformed")
    if size > MIB:
        return Refusal("ucp/too-large")
    checkout_id = doc.get("id")
    if not isinstance(checkout_id, str) or checkout_id == "":
        return Refusal("ucp/checkout-malformed")
    if js_length(checkout_id) > MAX_ID:
        return Refusal("ucp/too-large")
    return doc


def _read(doc: object, require_ap2: bool) -> Advertised | Refusal:
    c = _checkout_of(doc)
    if isinstance(c, Refusal):
        return c
    lc = legal_context_link(c)
    if isinstance(lc, Refusal):
        return lc
    if require_ap2:
        ap2 = c.get("ap2")
        auth = ap2.get("merchant_authorization") if is_object(ap2) else None
        if not isinstance(auth, str) or _MERCHANT_AUTHORIZATION.fullmatch(auth) is None:
            return Refusal("ucp/ap2-not-active")
    return Advertised(h=lc[0], link=lc[1], offer={"checkout": c})


def _read_shown(doc: object, require_ap2: bool) -> Advertised | Refusal:
    """The read, with the url of the checkout's legal_context_agreement link as the agreement when it has one."""
    r = _read(doc, require_ap2)
    if isinstance(r, Refusal):
        return r
    agreement = _agreement_link(r.offer["checkout"])
    if isinstance(agreement, Refusal):
        return agreement
    return r if agreement is None else Advertised(h=r.h, link=r.link, offer=r.offer, agreement=agreement)


def checkout_jwt(c: object) -> str | Refusal:
    """The checkout JWT a buyer's checkout mandate commits to, for a checkout the business signed: its detached
    ap2.merchant_authorization with the payload reinserted, header.payload.signature, the payload being the base64url of
    the RFC 8785 form of the checkout without its ap2 member, the bytes that signature covers (UCP 2026-08-25, the AP2
    Mandates extension, Business Authorization). UCP does not say which bytes are the checkout JWT; this is the second
    of the two readings its open issue 905 sets out, as the protocol package reads it. A checkout with no
    ap2.merchant_authorization of the form header..signature is ucp/ap2-not-active; one with no RFC 8785 form is
    ucp/checkout-malformed. No signature is verified."""
    checkout = _checkout_of(c)
    if isinstance(checkout, Refusal):
        return checkout
    ap2 = checkout.get("ap2")
    auth = ap2.get("merchant_authorization") if is_object(ap2) else None
    if not isinstance(auth, str) or _MERCHANT_AUTHORIZATION.fullmatch(auth) is None:
        return Refusal("ucp/ap2-not-active")
    payload = canonical_or_none({k: v for k, v in checkout.items() if k != "ap2"})
    if payload is None:
        return Refusal("ucp/checkout-malformed")
    header, _, signature = auth.split(".")
    return f"{header}.{b64u_encode(text_encode(payload))}.{signature}"


@dataclass(frozen=True, slots=True)
class UcpUnsigned:
    """The checkout unchanged, for the buyer's mandate issuer, and the claims its checkout mandate carries: the
    checkout JWT checkout_jwt gives, and its hash."""

    checkout: Mapping[str, Any]
    content: Mapping[str, str]

    def complete(self, checkout_mandate: str) -> dict[str, Any] | Refusal:
        """The signed mandate beside the checkout JWT; a mandate that commits to another JWT is refused as bound would
        refuse it, so complete never hands back a presentation bound refuses for that."""
        presented = {"checkout_mandate": checkout_mandate, "checkout_jwt": self.content["checkout_jwt"]}
        bound = checkout_binding(presented)
        return bound if isinstance(bound, Refusal) else presented


def _build_ap2(offer: object, h: AtrHash) -> UcpUnsigned | Refusal:
    """The claims the buyer's checkout mandate carries for a checkout the business signed, once its link carries h: the
    checkout JWT checkout_jwt gives, and its hash."""
    if not is_object(offer):
        return Refusal("ucp/checkout-malformed")
    checkout = offer.get("checkout")
    r = _read(checkout, True)
    if isinstance(r, Refusal):
        return r
    if not hash_equals(r.h, h):
        return Refusal("ucp/hash-not-in-checkout")
    assert is_object(checkout)
    jwt = checkout_jwt(checkout)
    if isinstance(jwt, Refusal):
        return jwt
    return UcpUnsigned(checkout, {"vct": CHECKOUT_VCT, "checkout_jwt": jwt, "checkout_hash": checkout_hash_of(jwt)})


def _bound_ap2(presented: object) -> AtrHash | Refusal:
    """The hash in the checkout inside the buyer's mandate, after AP2's checkout_hash check. No signature is
    verified."""
    payload = checkout_binding(presented)
    if isinstance(payload, Refusal):
        return payload
    lc = legal_context_link(payload)
    return lc if isinstance(lc, Refusal) else lc[0]


@dataclass(frozen=True, slots=True)
class UcpAp2Mandate:
    id: str
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "any"

    def read(self, doc: Json) -> Advertised | Refusal:
        return _read_shown(doc, True)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> UcpUnsigned | Refusal:
        return _build_ap2(choice, h)

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        return _bound_ap2(presented)

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the business's payment handler executes the payment the buyer's checkout mandate
        authorizes. A value that is not a JSON object gets ap2/mandate-malformed, as bound refuses it."""
        return "payee" if is_object(presented) else Refusal("ap2/mandate-malformed")


@dataclass(frozen=True, slots=True)
class UcpUnsignedPairing:
    id: str
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "any"

    def read(self, doc: Json) -> Advertised | Refusal:
        return _read_shown(doc, False)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> Refusal:
        return Refusal("ucp/nothing-to-sign")

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> Refusal:
        return Refusal("ucp/not-buyer-signed")

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the business's payment handler executes the payment the checkout or booking completed.
        bound applies no shape gate, so it answers whatever is presented."""
        return "payee"


# ucp/checkout/agent-signed: H in a member of the platform's signed request.

REQUEST_MEMBER = "legal_context"


def _bound_agent_signed(presented: object) -> AtrHash | Refusal:
    """The hash in the platform's signed request: the body's one legal_context member, once the Content-Digest value is
    exactly sha-256=: and the standard base64 of the SHA-256 of the body's UTF-8 bytes and :, the comparison UCP's
    request verification makes. No signature is verified and no key is read: the business verifies the platform's
    signature, which covers content-digest, as UCP defines."""
    if not is_object(presented):
        return Refusal("ucp/request-malformed")
    body = presented.get("body")
    content_digest = presented.get("contentDigest")
    if not isinstance(body, str) or not isinstance(content_digest, str):
        return Refusal("ucp/request-malformed")
    if js_length(body) > MIB or js_length(content_digest) > MAX_LINK:
        return Refusal("ucp/too-large")
    data = text_encode(body)
    if len(data) > MIB:
        return Refusal("ucp/too-large")
    digest = bytes.fromhex(atr_hash(data)[2:])
    if content_digest != f"sha-256=:{b64_encode(digest)}:":
        return Refusal("ucp/content-digest-mismatch")
    parsed = parse_json(body)
    if parsed is UNPARSED or not isinstance(parsed, dict) or not within_depth(parsed):
        return Refusal("ucp/request-malformed")
    if REQUEST_MEMBER not in parsed:
        return Refusal("ucp/no-legal-context")
    lc = parsed[REQUEST_MEMBER]
    if not isinstance(lc, dict) or len(lc) != 2 or lc.get("type") != "sha256":
        return Refusal("ucp/legal-context-malformed")
    h = normal_hash(lc.get("value"))
    return h if h is not None else Refusal("ucp/legal-context-malformed")


@dataclass(frozen=True, slots=True)
class UcpAgentSigned:
    id: str = CHECKOUT_AGENT_SIGNED
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "any"

    def read(self, doc: Json) -> Advertised | Refusal:
        return _read_shown(doc, False)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> dict[str, Any] | Refusal:
        """The member for the platform to write into its request body, once the checkout's link carries h."""
        if not is_object(choice):
            return Refusal("ucp/checkout-malformed")
        r = _read(choice.get("checkout"), False)
        if isinstance(r, Refusal):
            return r
        if not hash_equals(r.h, h):
            return Refusal("ucp/hash-not-in-checkout")
        return {REQUEST_MEMBER: {"type": "sha256", "value": r.h}}

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        return _bound_agent_signed(presented)

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the business's payment handler executes the payment the signed request completes. A
        value that is not a JSON object gets ucp/request-malformed, as bound refuses it."""
        return "payee" if is_object(presented) else Refusal("ucp/request-malformed")
