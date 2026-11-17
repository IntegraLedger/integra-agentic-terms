"""The buyer halves of the pairings ap2/checkout-mandate and ap2/checkout-mandate/x402: read, build with complete, and
bound.

The ATR hash is the legalContext member of the merchant-signed checkout_jwt payload, committed to by the buyer's closed
Checkout Mandate through checkout_hash, and read back from the checkout JWT presented beside the mandate. The mandate is
presented alone, or last in AP2's chain after the open mandate. On ap2/checkout-mandate/x402 the payment is AP2's x402
credential, bound to the checkout through its payment mandate chain. Nothing here verifies a signature, a cnf delegation
or a link between hops.
"""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._keccak import keccak256
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._codec import b64u_encode, text_encode
from ._jose import (
    MIB,
    SdJwt,
    SdJwtCodes,
    decode_json_segment,
    js_length,
    jws_segments,
    read_sd_jwt,
    within_depth,
)
from ._lcp import AgreementFault, agreement_in, is_object, legal_context_info

ID = "ap2/checkout-mandate"
X402_ID = "ap2/checkout-mandate/x402"
CHECKOUT_VCT = "mandate.checkout.1"
PAYMENT_VCT = "mandate.payment.1"
MAX_HOPS = 2
MAX_ID = 256
MAX_LINK = 2048
_CHECKOUT_HASH = re.compile(r"[A-Za-z0-9_-]{43}")
MANDATE_CODES = SdJwtCodes(
    malformed="ap2/mandate-malformed",
    sd_alg_unsupported="ap2/sd-alg-unsupported",
    unreferenced="ap2/disclosure-unreferenced",
    too_large="ap2/too-large",
)
PAYMENT_CODES = SdJwtCodes(
    malformed="ap2/payment-malformed",
    sd_alg_unsupported="ap2/sd-alg-unsupported",
    unreferenced="ap2/disclosure-unreferenced",
    too_large="ap2/too-large",
)


def jws_payload(jwt: object) -> dict[str, Any] | Refusal:
    """The payload of a compact JWS, decoded as one JSON object. Each segment is base64url without padding in its
    canonical form (RFC 7515 §2, RFC 4648 §3.5); a JWS with a segment in another form is ap2/jws-malformed. The
    signature is never verified."""
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


def _closed_hop(m: object, codes: SdJwtCodes = MANDATE_CODES) -> SdJwt | Refusal:
    """The SD-JWT that holds the closed Checkout Mandate. A presentation without ~~ is that SD-JWT. AP2's chained
    presentation joins the open mandate's SD-JWT and the closed mandate's with ~~, in the compact serialization of the
    Delegate SD-JWT draft: every hop before the last is an SD-JWT written without its trailing ~, and the hop after it
    stands in its Key Binding JWT's place. A chain has at most two hops, as AP2's checkout chain does. Every hop must
    read as an SD-JWT presentation; only the last is returned. No hop's signature, cnf key, sd_hash or issuer_jwt_hash
    is verified."""
    if not isinstance(m, str):
        return Refusal(codes.malformed)
    if js_length(m) > MIB:
        return Refusal("ap2/too-large")
    hops = m.split("~~", MAX_HOPS)
    if len(hops) > MAX_HOPS:
        return Refusal(codes.malformed)
    for hop in hops[:-1]:
        opened = read_sd_jwt(f"{hop}~", codes)
        if isinstance(opened, Refusal):
            return opened
    return read_sd_jwt(hops[-1], codes)


def _objects_of(resolved: Any, vct: str) -> list[dict[str, Any]]:
    """Every object, at any depth of a resolved SD-JWT payload, whose vct is the one given."""
    found: list[dict[str, Any]] = []
    stack: list[Any] = [resolved]
    while stack:
        v = stack.pop()
        if isinstance(v, list):
            stack.extend(v)
        elif isinstance(v, dict):
            if v.get("vct") == vct:
                found.append(v)
            stack.extend(v.values())
    return found


def read_mandate(m: object) -> MandateContent | Refusal:
    """The closed Checkout Mandate in a presentation, one SD-JWT or AP2's chain of the open and closed mandates joined
    by ~~ (at most these two hops, each an SD-JWT): exactly one resolved object of the last SD-JWT whose vct is
    mandate.checkout.1, its checkout_hash, and its checkout_jwt when disclosed. No signature is verified, nor the open
    mandate's cnf delegation to the closed mandate's signer, nor the closed mandate's sd_hash or issuer_jwt_hash link
    to the open one; the open mandate's constraints are not read. Each JWS segment and disclosure is base64url without
    padding in its canonical form (RFC 4648 §3.5), or the mandate is ap2/mandate-malformed. A hop whose payload, with
    each disclosed value where its reference sits, nests more than 64 levels is ap2/too-large."""
    sd = _closed_hop(m)
    if isinstance(sd, Refusal):
        return sd
    found = _objects_of(sd.resolved, CHECKOUT_VCT)
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
    """AP2's merchant check: the mandate's checkout_hash is the hash of the presented checkout_jwt, and a disclosed
    checkout_jwt is that JWT. Returns that JWT's payload. It checks that the mandate commits to the latest checkout when
    the seller presents the checkout_jwt it last sent for this checkout; with the buyer's copy, it checks only that the
    mandate and that JWT agree."""
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


def mandate_shape(p: object) -> Refusal | None:
    """The shape gate bound applies first: a JSON object, else ap2/mandate-malformed; and a payment_receipt, where
    present, a JSON object, else ap2/receipt-malformed. None for a presentation within it."""
    if not is_object(p):
        return Refusal("ap2/mandate-malformed")
    return None if "payment_receipt" not in p or is_object(p["payment_receipt"]) else Refusal("ap2/receipt-malformed")


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
        return Refusal("ap2/legal-context-malformed")
    if js_length(decoded[1]) > MAX_LINK:
        return Refusal("ap2/too-large")
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
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "any"

    def read(self, doc: Json) -> Advertised | Refusal:
        """The hash, the link and, when present, the agreement URL from the checkout_jwt's legalContext, and the
        checkout."""
        r = _read_checkout(doc)
        if isinstance(r, Refusal):
            return r
        h, link, offer = r
        agreement = agreement_in(offer["payload"].get("legalContext"))
        if isinstance(agreement, AgreementFault):
            return Refusal("ap2/legal-context-malformed")
        return Advertised(h=h, link=link, offer=offer, agreement=agreement if isinstance(agreement, str) else None)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> Ap2Unsigned | Refusal:
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

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """The hash in the checkout the buyer's closed mandate commits to, lowercase, the mandate presented alone or last
        in AP2's chain. No signature, cnf delegation or link between hops is verified."""
        shaped = mandate_shape(presented)
        if shaped is not None:
            return shaped
        payload = checkout_binding(presented)
        if isinstance(payload, Refusal):
            return payload
        if "legalContext" not in payload:
            return Refusal("ap2/no-legal-context")
        lc = payload["legalContext"]
        decoded = legal_context_info(lc)
        if decoded is None:
            return Refusal("ap2/legal-context-malformed")
        if js_length(decoded[1]) > MAX_LINK:
            return Refusal("ap2/too-large")
        return decoded[0]

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """Where the merchant initiates the charge, the payee broadcasts: the seller's payment processor executes the
        payment the closed Checkout Mandate authorizes. In AP2's push funding the presentation carries payment_receipt
        and the payer broadcasts: its side sent the funds before the merchant saw them. A value outside bound's shape
        gate gets the refusal bound gives it."""
        shaped = mandate_shape(presented)
        if shaped is not None:
            return shaped
        return "payer" if is_object(presented) and "payment_receipt" in presented else "payee"


# ap2/checkout-mandate/x402: the checkout paid with AP2's x402 payment credential.

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_NONCE = re.compile(r"(0x)?[0-9a-fA-F]{64}")
_UINT = re.compile(r"0|[1-9][0-9]{0,77}")
_HEX = re.compile(r"(0x)?[0-9a-fA-F]*")
MAX_SIGNATURE = 8192
AUTHORIZATION_MEMBERS = ("from", "to", "value", "validAfter", "validBefore", "nonce")


def _bundle_of(b: object) -> Mapping[str, Any] | Refusal:
    """AP2's x402 credential, as its reference credential provider writes it: a payment mandate chain of at most 1 MiB,
    a payment nonce, and an EIP-3009 authorization of exactly six members, two addresses, three decimal integers and a
    32-byte nonce, with a hex signature."""
    if not is_object(b):
        return Refusal("ap2/payment-malformed")
    chain = b.get("payment_mandate_chain")
    if isinstance(chain, str) and js_length(chain) > MIB:
        return Refusal("ap2/too-large")
    if not isinstance(chain, str) or chain == "" or not isinstance(b.get("payment_nonce"), str):
        return Refusal("ap2/payment-malformed")
    eip = b.get("eip_3009_payload")
    if not is_object(eip):
        return Refusal("ap2/payment-malformed")
    signature = eip.get("signature")
    a = eip.get("authorization")
    if not isinstance(signature, str) or js_length(signature) > MAX_SIGNATURE or _HEX.fullmatch(signature) is None:
        return Refusal("ap2/payment-malformed")
    if not is_object(a) or len(a) != len(AUTHORIZATION_MEMBERS):
        return Refusal("ap2/payment-malformed")
    if not all(isinstance(a.get(k), str) for k in AUTHORIZATION_MEMBERS):
        return Refusal("ap2/payment-malformed")
    if any(_ADDRESS.fullmatch(a[k]) is None for k in ("from", "to")) or _NONCE.fullmatch(a["nonce"]) is None:
        return Refusal("ap2/payment-malformed")
    if any(_UINT.fullmatch(a[k]) is None for k in ("value", "validAfter", "validBefore")):
        return Refusal("ap2/payment-malformed")
    return b


def _transaction_id_of(chain: str) -> str | Refusal:
    """The transaction_id of the closed Payment Mandate in AP2's payment mandate chain, read as the checkout mandate is
    (the chain's last hop, its disclosures resolved): exactly one object whose vct is mandate.payment.1. A chain that is
    not an SD-JWT presentation of at most two hops is ap2/payment-malformed, as is one with two such objects; one with
    none, or whose closed mandate names no transaction_id string, binds no checkout, ap2/payment-not-bound."""
    sd = _closed_hop(chain, PAYMENT_CODES)
    if isinstance(sd, Refusal):
        return sd
    found = _objects_of(sd.resolved, PAYMENT_VCT)
    if len(found) > 1:
        return Refusal("ap2/payment-malformed")
    transaction_id = found[0].get("transaction_id") if found else None
    return transaction_id if isinstance(transaction_id, str) else Refusal("ap2/payment-not-bound")


@dataclass(frozen=True, slots=True)
class Ap2CheckoutMandateX402(Ap2CheckoutMandate):
    """ap2/checkout-mandate/x402: ap2/checkout-mandate's read and build, the payment being AP2's x402 credential from
    the buyer's credential provider, whose EIP-3009 authorization's nonce is keccak-256 of the payment mandate chain and
    carries no hash of the ATR."""

    id: str = X402_ID

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """The hash in the checkout the buyer's closed mandate commits to, as ap2/checkout-mandate reads it, once the x402
        credential is bound to this checkout: the authorization's nonce is keccak-256 of the payment mandate chain's
        UTF-8 text, compared as 32 bytes, as AP2's payment processor checks it; and the chain's closed Payment Mandate
        names this checkout, its transaction_id equal to the checkout mandate's checkout_hash. Either failing is
        ap2/payment-not-bound. No signature is verified."""
        h = Ap2CheckoutMandate.bound(self, presented)
        if isinstance(h, Refusal):
            return h
        assert is_object(presented)
        b = _bundle_of(presented.get("payment"))
        if isinstance(b, Refusal):
            return b
        chain: str = b["payment_mandate_chain"]
        nonce: str = b["eip_3009_payload"]["authorization"]["nonce"]
        if keccak256(text_encode(chain)) != bytes.fromhex(nonce.removeprefix("0x")):
            return Refusal("ap2/payment-not-bound")
        transaction_id = _transaction_id_of(chain)
        if isinstance(transaction_id, Refusal):
            return transaction_id
        mandate = read_mandate(presented.get("checkout_mandate"))
        if isinstance(mandate, Refusal):
            return mandate
        return h if transaction_id == mandate.checkout_hash else Refusal("ap2/payment-not-bound")

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the merchant forwards AP2's x402 credential to its payment processor, which submits the
        authorization. A value outside bound's shape gate gets the refusal bound gives it."""
        shaped = mandate_shape(presented)
        return shaped if shaped is not None else "payee"
