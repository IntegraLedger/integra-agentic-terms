"""The buyer halves of the card pairings card/visa-tap, card/mastercard-vi/immediate, card/mastercard-vi/autonomous and
card/seller-reference: read, build and bound.

- Visa TAP: the agent sends the hash in an lcp-hash field and lists that field among the covered components of its
  agent-payer-auth message signature.
- Mastercard Verifiable Intent, Immediate mode: the hash rides in the merchant's checkout_jwt, whose SHA-256 the
  user's L2 mandate signs as checkout_hash.
- Mastercard Verifiable Intent, Autonomous mode: the hash rides in the checkout_jwt of the agent's L3b checkout
  mandate, signed under the key the user's L2 delegates, with L2 signed under L1's key; bound verifies both ES256
  signatures.
- The plain card checkout: nothing the buyer signs carries the hash.

Only the Autonomous mode's bound verifies a signature.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .._core import AtrHash, hash_equals
from .._types import Advertised, Json, Refusal
from ._jose import (
    SdJwt,
    SdJwtBounds,
    SdJwtCodes,
    b64u_decode,
    decode_json_segment,
    disclosure_digest,
    js_length,
    jws_segments,
    read_sd_jwt,
    text_encode,
    within_depth,
)
from ._lcp import (
    AgreementFault,
    agreement_in,
    is_hash_with_non_https_link,
    is_list,
    is_object,
    legal_context_info,
    normal_hash,
)
from ._sfv import TOO_LARGE, InnerList, Item, Member, parse_dictionary

VISA_TAP = "card/visa-tap"
VI_IMMEDIATE = "card/mastercard-vi/immediate"
VI_AUTONOMOUS = "card/mastercard-vi/autonomous"
SELLER_REFERENCE = "card/seller-reference"

TAP_FIELD = "lcp-hash"
MAX_LINK = 2048
MAX_TAP_FIELD = 8192
MAX_TAP_MEMBERS = 16
MAX_TAP_COMPONENTS = 32
MAX_TAP_HASH_LINE = 256
MAX_VI_LAYER = 65_536
MAX_CHECKOUT_JWT = 16_384
MAX_VI_DISCLOSURES = 32
PAYER_TAG = "agent-payer-auth"
CHECKOUT_VCT = "mandate.checkout.1"
PAYMENT_VCT = "mandate.payment.1"
OPEN_CHECKOUT_VCT = "mandate.checkout.open.1"
SD_JWT_CODES = SdJwtCodes(
    malformed="card/vi-malformed",
    sd_alg_unsupported="card/vi-malformed",
    unreferenced="card/vi-disclosure-unreferenced",
    too_large="card/too-large",
)
SD_JWT_BOUNDS = SdJwtBounds(max_bytes=MAX_VI_LAYER, max_disclosures=MAX_VI_DISCLOSURES)


# ── read ──


def _legal_context_of(o: Mapping[str, Any]) -> tuple[AtrHash, str] | Refusal:
    lc = o.get("legalContext")
    decoded = legal_context_info(lc)
    if decoded is None:
        return Refusal("card/link-not-https" if is_hash_with_non_https_link(lc) else "card/legal-context-malformed")
    if js_length(decoded[1]) > MAX_LINK:
        return Refusal("card/legal-context-malformed")
    return decoded


def _with_agreement(o: Mapping[str, Any], r: tuple[AtrHash, str] | Refusal) -> Advertised | Refusal:
    """The hash and link, with the agreement URL from o.legalContext when one is present."""
    if isinstance(r, Refusal):
        return r
    agreement = agreement_in(o.get("legalContext"))
    if isinstance(agreement, AgreementFault):
        return Refusal(f"card/{agreement.fault}")
    return Advertised(h=r[0], link=r[1], offer={}, agreement=agreement if isinstance(agreement, str) else None)


def read_shown(doc: object) -> Advertised | Refusal:
    """The hash, the link and, when present, the agreement URL from the JSON the seller showed."""
    if not is_object(doc) or "legalContext" not in doc:
        return Refusal("card/no-legal-context")
    return _with_agreement(doc, _legal_context_of(doc))


def _checkout_payload(doc: object) -> dict[str, Any] | Refusal:
    """The payload of a checkout_jwt, its second segment base64url-decoded and JSON-parsed, with a legalContext."""
    if not isinstance(doc, str):
        return Refusal("card/vi-malformed")
    if js_length(doc) > MAX_CHECKOUT_JWT:
        return Refusal("card/too-large")
    parts = jws_segments(doc)
    if parts is None:
        return Refusal("card/vi-malformed")
    payload = decode_json_segment(parts[1])
    if not isinstance(payload, dict):
        return Refusal("card/vi-malformed")
    if not within_depth(payload):
        return Refusal("card/too-large")
    if "legalContext" not in payload:
        return Refusal("card/no-legal-context")
    return payload


def read_checkout(doc: object) -> tuple[AtrHash, str] | Refusal:
    """The hash and link from the payload of a checkout_jwt."""
    payload = _checkout_payload(doc)
    if isinstance(payload, Refusal):
        return payload
    return _legal_context_of(payload)


def read_checkout_shown(doc: object) -> Advertised | Refusal:
    payload = _checkout_payload(doc)
    if isinstance(payload, Refusal):
        return payload
    return _with_agreement(payload, _legal_context_of(payload))


# ── TAP ──


def _plain_params(params: Mapping[str, Any]) -> bool:
    return all(v.t != "bytes" for v in params.values())


def _is_signature_input(d: Mapping[str, Member]) -> bool:
    """Every member an Inner List of Strings; every parameter an Integer, String, Token or Boolean."""
    for m in d.values():
        if not isinstance(m, InnerList) or not _plain_params(m.params):
            return False
        for it in m.list:
            if it.item.t != "string" or not _plain_params(it.params):
                return False
    return True


def _is_signature_set(d: Mapping[str, Member]) -> bool:
    """Every member a Byte Sequence."""
    return all(isinstance(m, Item) and m.item.t == "bytes" for m in d.values())


def _is_payer(m: Member) -> bool:
    tag = m.params.get("tag")
    return tag is not None and tag.t == "string" and tag.v == PAYER_TAG


def _is_bare_hash_component(it: Item) -> bool:
    """The String lcp-hash with no parameters."""
    return it.item.t == "string" and it.item.v == TAP_FIELD and len(it.params) == 0


def _trim_sp_htab(text: str) -> str:
    return text.strip(" \t")


def tap_bound(presented: object) -> AtrHash | Refusal:
    """The hash from a TAP payment request: the one lcp-hash line, when every agent-payer-auth signature lists
    "lcp-hash" without parameters and one of them has its Signature member, so whichever payer signature the seller's
    recognition verifies covers the hash. No signature, key, window or nonce is verified."""
    if not is_object(presented):
        return Refusal("card/tap-signature-input-malformed")
    signature_input = presented.get("signatureInput")
    signature = presented.get("signature")
    lcp_hash = presented.get("lcpHash")

    if not isinstance(signature_input, str):
        return Refusal("card/tap-signature-input-malformed")
    if js_length(signature_input) > MAX_TAP_FIELD:
        return Refusal("card/too-large")
    inputs = parse_dictionary(signature_input, MAX_TAP_MEMBERS, MAX_TAP_COMPONENTS)
    if inputs is TOO_LARGE:
        return Refusal("card/too-large")
    if not isinstance(inputs, dict) or not _is_signature_input(inputs):
        return Refusal("card/tap-signature-input-malformed")

    if not isinstance(signature, str):
        return Refusal("card/tap-signature-malformed")
    if js_length(signature) > MAX_TAP_FIELD:
        return Refusal("card/too-large")
    signatures = parse_dictionary(signature, MAX_TAP_MEMBERS, MAX_TAP_COMPONENTS)
    if signatures is TOO_LARGE:
        return Refusal("card/too-large")
    if not isinstance(signatures, dict) or not _is_signature_set(signatures):
        return Refusal("card/tap-signature-malformed")

    payers = [(label, m) for label, m in inputs.items() if _is_payer(m)]
    if not payers:
        return Refusal("card/tap-no-payer-signature")
    if not all(isinstance(m, InnerList) and any(map(_is_bare_hash_component, m.list)) for _, m in payers):
        return Refusal("card/tap-hash-not-covered")
    if not any(label in signatures for label, _ in payers):
        return Refusal("card/tap-signature-missing")

    if not is_list(lcp_hash):
        return Refusal("card/tap-field-malformed")
    if len(lcp_hash) == 0:
        return Refusal("card/tap-field-missing")
    if len(lcp_hash) > 1:
        return Refusal("card/tap-field-repeated")
    line = lcp_hash[0]
    if not isinstance(line, str):
        return Refusal("card/tap-field-malformed")
    if js_length(line) > MAX_TAP_HASH_LINE:
        return Refusal("card/too-large")
    h = normal_hash(_trim_sp_htab(line))
    return h if h is not None else Refusal("card/tap-field-malformed")


# ── Verifiable Intent ──


def read_layer(value: object, typ: str) -> SdJwt | Refusal:
    """One Verifiable Intent L2 or L3 layer: a JWS, one or more disclosures and an empty last part, read through the
    SD-JWT reader, with header alg ES256 and the given typ, _sd_alg sha-256, and a delegate_payload array of
    {"...": digest} entries."""
    if not isinstance(value, str):
        return Refusal("card/vi-malformed")
    if js_length(value) > MAX_VI_LAYER:
        return Refusal("card/too-large")
    parts = value.split("~")
    if len(parts) < 3 or parts[-1] != "":
        return Refusal("card/vi-malformed")
    if len(parts) - 2 > MAX_VI_DISCLOSURES:
        return Refusal("card/too-large")
    layer = read_sd_jwt(value, SD_JWT_CODES, SD_JWT_BOUNDS)
    if isinstance(layer, Refusal):
        return layer
    if layer.header.get("alg") != "ES256" or layer.header.get("typ") != typ:
        return Refusal("card/vi-typ")
    delegated = layer.payload.get("delegate_payload")
    if layer.payload.get("_sd_alg") != "sha-256" or not isinstance(delegated, list):
        return Refusal("card/vi-malformed")
    for d in delegated:
        if not isinstance(d, dict) or len(d) != 1 or not isinstance(d.get("..."), str):
            return Refusal("card/vi-malformed")
    return layer


def _mandates(layer: SdJwt) -> list[dict[str, Any]]:
    """The mandate objects a layer's delegate_payload resolves to: only disclosures its signed payload references."""
    resolved = layer.resolved.get("delegate_payload")
    return [m for m in resolved if isinstance(m, dict)] if isinstance(resolved, list) else []


def checkout_hash(layer: SdJwt) -> AtrHash | Refusal:
    """The hash from a layer's one referenced mandate.checkout.1, after its binding checks."""
    every = _mandates(layer)
    checkouts = [m for m in every if m.get("vct") == CHECKOUT_VCT]
    if len(checkouts) != 1:
        return Refusal("card/vi-no-checkout-mandate")
    mandate = checkouts[0]
    checkout_jwt = mandate.get("checkout_jwt")
    r = read_checkout(checkout_jwt)
    if isinstance(r, Refusal):
        return r
    assert isinstance(checkout_jwt, str)
    digest = disclosure_digest(checkout_jwt)
    if mandate.get("checkout_hash") != digest:
        return Refusal("card/vi-checkout-hash-mismatch")
    for m in every:
        if m.get("vct") == PAYMENT_VCT and m.get("transaction_id") != digest:
            return Refusal("card/vi-transaction-id-mismatch")
    return r[0]


def vi_build(doc: object, h: AtrHash) -> dict[str, Any] | Refusal:
    """The checkout mandate over checkout_jwt, whose legalContext.value must be h by decoded bytes. checkout_hash and
    transactionId are both disclosure_digest(checkout_jwt)."""
    r = read_checkout(doc)
    if isinstance(r, Refusal):
        return r
    if not hash_equals(r[0], h):
        return Refusal("card/vi-legal-context-conflict")
    assert isinstance(doc, str)
    digest = disclosure_digest(doc)
    return {
        "checkoutMandate": {"vct": CHECKOUT_VCT, "checkout_jwt": doc, "checkout_hash": digest},
        "transactionId": digest,
    }


def _jwk_of(cnf: object) -> Mapping[str, Any] | None:
    """An EC P-256 public JWK from cnf's jwk member, or None."""
    k = cnf.get("jwk") if is_object(cnf) else None
    if not is_object(k) or k.get("kty") != "EC" or k.get("crv") != "P-256":
        return None
    if not isinstance(k.get("x"), str) or not isinstance(k.get("y"), str):
        return None
    return k


def verify_es256(jws: str, jwk: Mapping[str, Any]) -> bool | Refusal:
    """ES256 over the ASCII header.payload of a compact JWS, with a 64-byte r||s signature, under an EC P-256 public
    JWK. A key that is not a point of P-256 given as two 32-byte coordinates is card/vi-key-malformed; any other
    failure is card/vi-signature-invalid."""
    x, y = b64u_decode(jwk["x"]), b64u_decode(jwk["y"])
    if x is None or y is None or len(x) != 32 or len(y) != 32:
        return Refusal("card/vi-key-malformed")
    try:
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError:
        return Refusal("card/vi-key-malformed")
    cut = jws.rfind(".")
    signature = b64u_decode(jws[cut + 1 :])
    if cut < 0 or signature is None or len(signature) != 64:
        return Refusal("card/vi-signature-invalid")
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        key.verify(der, text_encode(jws[:cut]), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return Refusal("card/vi-signature-invalid")
    return True


def vi_autonomous_bound(presented: object) -> AtrHash | Refusal:
    """The hash in L3b's checkout mandate, with L3b bound to L2 by sd_hash and signed under the key L2's open checkout
    mandate delegates, and L2 bound to L1 by sd_hash and signed under L1's cnf.jwk. L1's issuer signature is not
    verified."""
    if not is_object(presented):
        return Refusal("card/vi-malformed")
    l1, l2, l3b = presented.get("l1"), presented.get("l2"), presented.get("l3b")

    agent = read_layer(l3b, "kb-sd-jwt")
    if isinstance(agent, Refusal):
        return agent
    kid = agent.header.get("kid")
    if not isinstance(kid, str):
        return Refusal("card/vi-typ")
    h = checkout_hash(agent)
    if isinstance(h, Refusal):
        return h

    if not isinstance(l2, str):
        return Refusal("card/vi-malformed")
    if js_length(l2) > MAX_VI_LAYER:
        return Refusal("card/too-large")
    if agent.payload.get("sd_hash") != disclosure_digest(l2):
        return Refusal("card/vi-sd-hash-mismatch")
    user = read_layer(l2, "kb-sd-jwt+kb")
    if isinstance(user, Refusal):
        return user
    opened = [m for m in _mandates(user) if m.get("vct") == OPEN_CHECKOUT_VCT]
    agent_key = _jwk_of(opened[0].get("cnf")) if len(opened) == 1 else None
    if agent_key is None or not isinstance(agent_key.get("kid"), str):
        return Refusal("card/vi-key-malformed")
    if agent_key["kid"] != kid:
        return Refusal("card/vi-kid-mismatch")
    agent_signed = verify_es256(agent.jwt, agent_key)
    if agent_signed is not True:
        return agent_signed if isinstance(agent_signed, Refusal) else Refusal("card/vi-signature-invalid")

    if not isinstance(l1, str):
        return Refusal("card/vi-malformed")
    if js_length(l1) > MAX_VI_LAYER:
        return Refusal("card/too-large")
    if user.payload.get("sd_hash") != disclosure_digest(l1):
        return Refusal("card/vi-sd-hash-mismatch")
    issued = read_sd_jwt(l1, SD_JWT_CODES, SD_JWT_BOUNDS)
    if isinstance(issued, Refusal):
        return issued
    user_key = _jwk_of(issued.payload.get("cnf"))
    if user_key is None:
        return Refusal("card/vi-key-malformed")
    user_signed = verify_es256(user.jwt, user_key)
    if user_signed is not True:
        return user_signed if isinstance(user_signed, Refusal) else Refusal("card/vi-signature-invalid")
    return h


# ── The pairings ──


@dataclass(frozen=True, slots=True)
class CardVisaTap:
    id: str = VISA_TAP
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_shown(doc)

    def build(self, choice: Any, h: AtrHash) -> dict[str, Any] | Refusal:
        """The field for the agent's signer to add and list in its agent-payer-auth signature."""
        value = normal_hash(h)
        if value is None:
            return Refusal("card/legal-context-malformed")
        return {"field": TAP_FIELD, "value": value, "component": TAP_FIELD}

    def bound(self, presented: Json) -> AtrHash | Refusal:
        return tap_bound(presented)


@dataclass(frozen=True, slots=True)
class CardMastercardViImmediate:
    id: str = VI_IMMEDIATE
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_checkout_shown(doc)

    def build(self, choice: Any, h: AtrHash) -> dict[str, Any] | Refusal:
        return vi_build(choice, h)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the checkout_jwt of the one checkout mandate the user's L2 references. Its checkout_hash, and
        a referenced payment mandate's transaction_id, must be that checkout_jwt's digest. No signature is
        verified."""
        if not is_object(presented):
            return Refusal("card/vi-malformed")
        user = read_layer(presented.get("l2"), "kb-sd-jwt")
        if isinstance(user, Refusal):
            return user
        return checkout_hash(user)


@dataclass(frozen=True, slots=True)
class CardMastercardViAutonomous:
    id: str = VI_AUTONOMOUS
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_checkout_shown(doc)

    def build(self, choice: Any, h: AtrHash) -> dict[str, Any] | Refusal:
        return vi_build(choice, h)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        return vi_autonomous_bound(presented)


@dataclass(frozen=True, slots=True)
class CardSellerReference:
    id: str = SELLER_REFERENCE
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_shown(doc)

    def build(self, choice: Any, h: AtrHash) -> Refusal:
        return Refusal("card/no-signed-place")

    def bound(self, presented: Json) -> Refusal:
        return Refusal("card/no-signed-place")
