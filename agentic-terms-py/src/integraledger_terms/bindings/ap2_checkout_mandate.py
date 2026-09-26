"""The buyer half of the pairing ap2/checkout-mandate: read, build with complete, and bound.

The ATR hash is the legalContext member of the merchant-signed checkout_jwt payload, committed to by the buyer's closed
Checkout Mandate through checkout_hash, and read back from inside the mandate. Nothing here verifies a signature.
"""

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Json, Refusal
from ._jose import (
    MIB,
    SdJwtCodes,
    b64u_encode,
    decode_json_segment,
    js_length,
    jws_segments,
    read_sd_jwt,
    text_encode,
    within_depth,
)
from ._lcp import AgreementFault, agreement_in, is_hash_with_non_https_link, is_object, legal_context_info

ID = "ap2/checkout-mandate"
CHECKOUT_VCT = "mandate.checkout.1"
MAX_ID = 256
MAX_LINK = 2048
_CHECKOUT_HASH = re.compile(r"[A-Za-z0-9_-]{43}")
MANDATE_CODES = SdJwtCodes(
    malformed="ap2/mandate-malformed",
    sd_alg_unsupported="ap2/sd-alg-unsupported",
    unreferenced="ap2/disclosure-unreferenced",
    too_large="ap2/too-large",
)


def jws_payload(jwt: object) -> dict[str, Any] | Refusal:
    """The payload of a compact JWS, decoded as one JSON object. The signature is never verified."""
    if not isinstance(jwt, str):
        return Refusal("ap2/jws-malformed")
    if js_length(jwt) > MIB:
        return Refusal("ap2/too-large")
    segments = jws_segments(jwt)
    if segments is None:
        return Refusal("ap2/jws-malformed")
    payload = decode_json_segment(segments[1])
    if not isinstance(payload, dict):
        return Refusal("ap2/jws-malformed")
    if not within_depth(payload):
        return Refusal("ap2/too-large")
    return payload


def checkout_hash_of(jwt: str) -> str:
    """Unpadded base64url of SHA-256 over the JWT's characters."""
    return b64u_encode(hashlib.sha256(text_encode(jwt)).digest())


@dataclass(frozen=True, slots=True)
class MandateContent:
    checkout_hash: str
    checkout_jwt: str | None


def read_mandate(m: object) -> MandateContent | Refusal:
    """The closed Checkout Mandate inside an SD-JWT: exactly one resolved object whose vct is mandate.checkout.1, its
    checkout_hash, and its checkout_jwt when disclosed."""
    sd = read_sd_jwt(m, MANDATE_CODES)
    if isinstance(sd, Refusal):
        return sd
    found: list[dict[str, Any]] = []
    stack: list[Any] = [sd.resolved]
    while stack:
        v = stack.pop()
        if isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            if v.get("vct") == CHECKOUT_VCT:
                found.append(v)
            stack.extend(v.values())
    if not found:
        return Refusal("ap2/no-checkout-mandate")
    if len(found) > 1:
        return Refusal("ap2/mandate-ambiguous")
    mandate = found[0]
    checkout_hash = mandate.get("checkout_hash")
    if not isinstance(checkout_hash, str) or _CHECKOUT_HASH.fullmatch(checkout_hash) is None:
        return Refusal("ap2/mandate-malformed")
    if "checkout_jwt" in mandate and not isinstance(mandate["checkout_jwt"], str):
        return Refusal("ap2/mandate-malformed")
    return MandateContent(checkout_hash, mandate.get("checkout_jwt"))


def checkout_binding(p: object) -> dict[str, Any] | Refusal:
    """AP2's merchant check: the mandate's checkout_hash is the hash of the presenter's latest checkout_jwt, and a
    disclosed checkout_jwt is that JWT. Returns that JWT's payload."""
    if not is_object(p):
        return Refusal("ap2/mandate-malformed")
    mandate = read_mandate(p.get("checkout_mandate"))
    if isinstance(mandate, Refusal):
        return mandate
    jwt = p.get("checkout_jwt")
    if not isinstance(jwt, str):
        return Refusal("ap2/jws-malformed")
    if js_length(jwt) > MIB:
        return Refusal("ap2/too-large")
    if checkout_hash_of(jwt) != mandate.checkout_hash:
        return Refusal("ap2/checkout-not-latest")
    if mandate.checkout_jwt is not None and mandate.checkout_jwt != jwt:
        return Refusal("ap2/checkout-hash-mismatch")
    return jws_payload(jwt)


def checkout_jwt_of(m: object) -> str | Refusal:
    """The checkout_jwt the mandate discloses."""
    mandate = read_mandate(m)
    if isinstance(mandate, Refusal):
        return mandate
    if mandate.checkout_jwt is None:
        return Refusal("ap2/mandate-malformed")
    return mandate.checkout_jwt


def _read_checkout(doc: object) -> tuple[AtrHash, str, dict[str, Any]] | Refusal:
    """The hash and link from the checkout_jwt's legalContext, and the checkout."""
    payload = jws_payload(doc)
    if isinstance(payload, Refusal):
        return payload
    checkout = payload.get("id")
    if not isinstance(checkout, str) or checkout == "":
        return Refusal("ap2/checkout-id-missing")
    if js_length(checkout) > MAX_ID:
        return Refusal("ap2/too-large")
    if "legalContext" not in payload:
        return Refusal("ap2/no-legal-context")
    lc = payload["legalContext"]
    decoded = legal_context_info(lc)
    if decoded is None:
        return Refusal("ap2/link-not-https" if is_hash_with_non_https_link(lc) else "ap2/legal-context-malformed")
    if js_length(decoded[1]) > MAX_LINK:
        return Refusal("ap2/legal-context-malformed")
    assert isinstance(doc, str)
    return decoded[0], decoded[1], {"checkoutJwt": doc, "payload": payload, "checkout": checkout}


@dataclass(frozen=True, slots=True)
class Ap2Unsigned:
    """The closed Checkout Mandate's required claims, for the buyer's mandate signer."""

    content: dict[str, Any]

    def complete(self, checkout_mandate: str) -> dict[str, Any]:
        return {"checkout_mandate": checkout_mandate, "checkout_jwt": self.content["checkout_jwt"]}


@dataclass(frozen=True, slots=True)
class Ap2CheckoutMandate:
    id: str = ID
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        """The hash, the link and, when present, the agreement URL from the checkout_jwt's legalContext, and the
        checkout."""
        r = _read_checkout(doc)
        if isinstance(r, Refusal):
            return r
        h, link, offer = r
        agreement = agreement_in(offer["payload"].get("legalContext"))
        if isinstance(agreement, AgreementFault):
            return Refusal(f"ap2/{agreement.fault}")
        return Advertised(h=h, link=link, offer=offer, agreement=agreement if isinstance(agreement, str) else None)

    def build(self, choice: Json, h: AtrHash) -> Ap2Unsigned | Refusal:
        """The closed Checkout Mandate's claims over the offer's checkout_jwt, whose hash must be h."""
        if not is_object(choice):
            return Refusal("ap2/jws-malformed")
        checkout_jwt = choice.get("checkoutJwt")
        r = _read_checkout(checkout_jwt)
        if isinstance(r, Refusal):
            return r
        if not hash_equals(r[0], h):
            return Refusal("ap2/hash-not-in-checkout")
        assert isinstance(checkout_jwt, str)
        return Ap2Unsigned(
            {"vct": CHECKOUT_VCT, "checkout_jwt": checkout_jwt, "checkout_hash": checkout_hash_of(checkout_jwt)}
        )

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the checkout the buyer's mandate commits to, lowercase. No signature is verified."""
        payload = checkout_binding(presented)
        if isinstance(payload, Refusal):
            return payload
        if "legalContext" not in payload:
            return Refusal("ap2/no-legal-context")
        lc = payload["legalContext"]
        decoded = legal_context_info(lc)
        if decoded is None:
            return Refusal("ap2/link-not-https" if is_hash_with_non_https_link(lc) else "ap2/legal-context-malformed")
        if js_length(decoded[1]) > MAX_LINK:
            return Refusal("ap2/legal-context-malformed")
        return decoded[0]
