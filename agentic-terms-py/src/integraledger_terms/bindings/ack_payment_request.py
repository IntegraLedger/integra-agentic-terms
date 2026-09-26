"""The buyer half of the pairing ack/payment-request: read, build and bound.

The ATR hash is the id of the seller-signed ACK Payment Request, in LCP's string form, with the link beside the
request in the 402 body. ACK defines no payer signature, so build and bound always refuse. No token signature is
verified here.
"""

from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Json, Refusal
from ._jose import decode_json_segment, js_length, json_bytes, jws_segments, within_depth
from ._lcp import (
    AgreementFault,
    agreement_in,
    from_lcp_string,
    is_hash_with_non_https_link,
    is_list,
    is_object,
    legal_context_info,
)

ID = "ack/payment-request"
MAX_BODY_BYTES = 65_536
MAX_TOKEN = 16_384
MAX_OPTIONS = 16
MAX_LINK = 2048


def token_payload(token: object) -> dict[str, Any] | None:
    """The JSON object in a compact JWS's second segment, decoded as unpadded base64url, strict UTF-8 and JSON and
    nested at most 64 levels deep, or None. The signature is not checked."""
    if not isinstance(token, str) or js_length(token) > MAX_TOKEN:
        return None
    segments = jws_segments(token)
    if segments is None:
        return None
    value = decode_json_segment(segments[1])
    return value if isinstance(value, dict) and within_depth(value) else None


@dataclass(frozen=True, slots=True)
class AckPaymentRequest:
    id: str = ID
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        """The hash from the signed token's id, which the body's legalContext must match; the link and, when present,
        the agreement URL from legalContext; and the token's payment options. The unsigned paymentRequest copy is
        never read."""
        if not is_object(doc):
            return Refusal("ack/token-malformed")
        size = json_bytes(doc)
        if size is None:
            return Refusal("ack/token-malformed")
        if size > MAX_BODY_BYTES:
            return Refusal("ack/too-large")
        token = doc.get("paymentRequestToken")
        if isinstance(token, str) and js_length(token) > MAX_TOKEN:
            return Refusal("ack/too-large")
        payload = token_payload(token)
        if payload is None:
            return Refusal("ack/token-malformed")
        token_id = payload.get("id")
        signed = from_lcp_string(token_id) if isinstance(token_id, str) else None
        if signed is None:
            return Refusal("ack/id-not-lcp")
        if "legalContext" not in doc:
            return Refusal("ack/no-legal-context")
        lc = doc["legalContext"]
        decoded = legal_context_info(lc)
        if decoded is None:
            return Refusal("ack/link-not-https" if is_hash_with_non_https_link(lc) else "ack/legal-context-malformed")
        h, link = decoded
        if js_length(link) > MAX_LINK:
            return Refusal("ack/legal-context-malformed")
        if not hash_equals(signed, h):
            return Refusal("ack/legal-context-conflict")
        agreement = agreement_in(lc)
        if isinstance(agreement, AgreementFault):
            return Refusal(f"ack/{agreement.fault}")
        options = payload.get("paymentOptions")
        if not is_list(options):
            return Refusal("ack/token-malformed")
        if len(options) > MAX_OPTIONS:
            return Refusal("ack/too-large")
        return Advertised(
            h=signed,
            link=link,
            offer={"options": list(options)},
            agreement=agreement if isinstance(agreement, str) else None,
        )

    def build(self, choice: Json, h: AtrHash) -> Refusal:
        return Refusal("ack/no-signed-place")

    def bound(self, presented: Json) -> AtrHash | Refusal:
        return Refusal("ack/no-signed-place")
