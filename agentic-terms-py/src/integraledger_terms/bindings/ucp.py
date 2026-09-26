"""The buyer halves of the UCP pairings ucp/checkout/ap2-mandate, ucp/checkout/unsigned, ucp/booking/ap2-mandate and
ucp/booking/unsigned: read, build with complete, and bound.

The ATR hash and link ride as one links[] entry of type legal_context in the checkout response. The ap2-mandate
pairings read the hash from the checkout inside the buyer's checkout mandate, after AP2's checkout_hash check; the
unsigned pairings have nothing signed to read. Nothing here takes a key, signs or verifies a signature.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Json, Refusal
from ._jose import MIB, js_length, json_bytes
from ._lcp import agreement_fault, from_lcp_string, is_agreement_url, is_https_link, is_list, is_object, is_other_scheme_link
from .ap2_checkout_mandate import checkout_binding, checkout_jwt_of

CHECKOUT_AP2_MANDATE = "ucp/checkout/ap2-mandate"
CHECKOUT_UNSIGNED = "ucp/checkout/unsigned"
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
        return Refusal("ucp/legal-context-malformed")
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
    """The checkout's shape as the pairings read it: an object of at most 1 MiB as JSON, with an id of 1-256."""
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


@dataclass(frozen=True, slots=True)
class UcpUnsigned:
    """The checkout unchanged, for the buyer's mandate issuer."""

    checkout: Mapping[str, Any]

    def complete(self, checkout_mandate: str) -> dict[str, Any] | Refusal:
        """The mandate as issued, with the checkout_jwt it discloses."""
        checkout_jwt = checkout_jwt_of(checkout_mandate)
        if isinstance(checkout_jwt, Refusal):
            return checkout_jwt
        return {"checkout_mandate": checkout_mandate, "checkout_jwt": checkout_jwt}


def _build_ap2(offer: object, h: AtrHash) -> UcpUnsigned | Refusal:
    """The checkout unchanged, once its link carries h."""
    if not is_object(offer):
        return Refusal("ucp/checkout-malformed")
    checkout = offer.get("checkout")
    r = _read(checkout, True)
    if isinstance(r, Refusal):
        return r
    if not hash_equals(r.h, h):
        return Refusal("ucp/hash-not-in-checkout")
    assert is_object(checkout)
    return UcpUnsigned(checkout)


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
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return _read_shown(doc, True)

    def build(self, choice: Json, h: AtrHash) -> UcpUnsigned | Refusal:
        return _build_ap2(choice, h)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        return _bound_ap2(presented)


@dataclass(frozen=True, slots=True)
class UcpUnsignedPairing:
    id: str
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return _read_shown(doc, False)

    def build(self, choice: Json, h: AtrHash) -> Refusal:
        return Refusal("ucp/nothing-to-sign")

    def bound(self, presented: Json) -> Refusal:
        return Refusal("ucp/not-buyer-signed")
