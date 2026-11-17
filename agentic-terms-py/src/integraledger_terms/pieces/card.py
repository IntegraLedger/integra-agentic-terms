"""The buyer pieces of the card pairings. The build input is the seller's document itself (the shown JSON for TAP, Agent
Pay, Visa Intelligent Commerce and the plain checkout, the checkout_jwt for Verifiable Intent), kept in Chosen as
{"doc": ...}. TAP's and Agent Pay's nonce goes to the agent's RFC 9421 signer, which places it in every message signature
of its checkout request and answers {"signatureInput", "signature"}, from which bound reads the hash the nonce carries.
The Visa Intelligent Commerce transaction reference goes to the agent's credential client, which writes it into its
credential request and answers {"transactionReferenceId"} as the credential payload Visa signs returns it. The checkout
mandate goes to the wallet (L2, answering {"l2"}) or the agent (L3b, answering {"l1", "l2", "l3b"}). In Immediate mode
the agent may create the checkout_jwt itself: given the JSON the seller showed and the agent's checkout payload, as the
input checkout, the agent first signs the payload with the seller's legalContext written into it, answering
{"checkout_jwt"}, and the wallet then signs the checkout mandate over that checkout_jwt."""

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Binding, Chosen, Inputs, Json, Refusal, Signature, Step
from ..bindings._codec import b64_decode, b64u_encode
from ..bindings._lcp import is_object
from ..bindings.card import (
    AGENT_PAY,
    NONCE_BYTES,
    SELLER_REFERENCE,
    VI_AUTONOMOUS,
    VI_IMMEDIATE,
    VISA_TAP,
    VISA_VIC,
    vi_build,
    vi_json,
)
from ._base import BasePiece
from .protocol_groups import ConfirmOnlyPiece, object_choice, unnamed_buyer

_NS = "card"


def choose_doc(read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> dict[str, Any] | Refusal:
    """{"doc": doc} for a named buyer; the document is the one the binding's read was given."""
    unnamed = unnamed_buyer(account, _NS)
    if unnamed is not None:
        return unnamed
    return {"doc": doc}


def doc_of(chosen: Chosen) -> Any:
    c = object_choice(chosen, _NS)
    if isinstance(c, Refusal):
        return c
    return c["doc"] if "doc" in c else Refusal("card/choice-malformed")


def strings(signature: Signature, keys: Sequence[str]) -> dict[str, str] | None:
    """The named members of the signer's answer, each a non-empty string, or None."""
    if not isinstance(signature, Mapping):
        return None
    out: dict[str, str] = {}
    for k in keys:
        v = signature.get(k)
        if not isinstance(v, str) or v == "":
            return None
        out[k] = v
    return out


class _SignedCardPiece(BasePiece):
    pairing: str

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        choice = choose_doc(read, account, inputs, now, ref, doc)
        if isinstance(choice, Refusal):
            return choice
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return doc_of(chosen)


def _carries_hash(nonce: str, h: AtrHash) -> bool:
    """Whether nonce is the padded base64 of 64 bytes whose first 32 are the hash's."""
    data = b64_decode(nonce)
    return data is not None and len(data) == NONCE_BYTES and data[:32].hex() == h[2:].lower()


class CardVisaTapPiece(_SignedCardPiece):
    """TAP's nonce exactly as built, for the agent's signer to place in every message signature of its checkout
    request. The build draws the nonce's random half, so the piece keeps the built nonce in chosen (kept), and a rebuild
    from that chosen gives the nonce the signer was handed, once it is found to carry the hash."""

    pairing = VISA_TAP

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = object_choice(chosen, _NS)
        if isinstance(c, Refusal):
            return c
        if "doc" not in c:
            return Refusal("card/choice-malformed")
        nonce = c.get("nonce")
        if nonce is not None and not isinstance(nonce, str):
            return Refusal("card/choice-malformed")
        return {"doc": c["doc"]} if nonce is None else {"doc": c["doc"], "nonce": nonce}

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        nonce = choice.get("nonce")
        if nonce is None:
            return binding.build(choice["doc"], h)
        return {"nonce": nonce} if _carries_hash(nonce, h) else Refusal("card/choice-malformed")

    def kept(self, chosen: Chosen, unsigned: Any) -> Chosen:
        c = object_choice(chosen, _NS)
        nonce = unsigned.get("nonce") if isinstance(unsigned, Mapping) else None
        if isinstance(c, Refusal) or not isinstance(nonce, str):
            return chosen
        return replace(chosen, choice={**c, "nonce": nonce})

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "tap-field", **unsigned}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        s = strings(signature, ("signatureInput", "signature"))
        if s is None:
            return Refusal("card/signature-malformed")
        return {"signatureInput": s["signatureInput"], "signature": s["signature"]}


class CardMastercardAgentPayPiece(CardVisaTapPiece):
    """TAP's piece for Agent Pay's nonce: the build is Agent Pay's, its answer TAP's."""

    pairing = AGENT_PAY


class CardVisaVicPiece(_SignedCardPiece):
    """The transaction reference exactly as built, for the agent to write into its credential request."""

    pairing = VISA_VIC

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "vic-reference", **unsigned}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        s = strings(signature, ("transactionReferenceId",))
        return Refusal("card/signature-malformed") if s is None else {"transactionReferenceId": s["transactionReferenceId"]}


def _l2(signature: Signature) -> dict[str, Any] | Refusal:
    s = strings(signature, ("l2",))
    return Refusal("card/signature-malformed") if s is None else {"l2": s["l2"]}


def _mandate_over(unsigned: Mapping[str, Any], answer: Signature) -> dict[str, Any] | Refusal:
    """The checkout mandate over the agent's checkout_jwt, once its payload is found to be the payload handed as
    vi_json writes it, whose legalContext the build wrote with the hash it was given."""
    s = strings(answer, ("checkout_jwt",))
    encoded = vi_json(unsigned["checkout"])
    lc = unsigned["checkout"].get("legalContext")
    h = lc.get("value") if is_object(lc) else None
    if s is None or encoded is None or not isinstance(h, str):
        return Refusal("card/signature-malformed")
    parts = s["checkout_jwt"].split(".")
    if len(parts) != 3 or parts[1] != b64u_encode(encoded.encode("ascii")):
        return Refusal("card/signature-malformed")
    return vi_build(s["checkout_jwt"], h)


class CardMastercardViImmediatePiece(_SignedCardPiece):
    """Immediate mode. On a checkout_jwt the seller wrote, the checkout mandate exactly as built, for the user's wallet
    to sign as L2, answering {"l2"}. On the JSON the seller showed, with the agent's checkout payload as the input
    checkout, two signings: the payload with the seller's legalContext written into it, exactly as built, for the agent
    to sign as its checkout_jwt, answering {"checkout_jwt"}, whose payload must be that payload as vi_json writes it;
    then the checkout mandate over that checkout_jwt, for the wallet's L2."""

    pairing = VI_IMMEDIATE

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        choice = choose_doc(read, account, inputs, now, ref, doc)
        if isinstance(choice, Refusal):
            return choice
        if isinstance(doc, str):
            return Chosen(pairing=self.pairing, choice=choice, ref=ref)
        checkout = inputs.get("checkout")
        if not is_object(checkout):
            return Refusal("card/input-missing")
        return Chosen(pairing=self.pairing, choice={**choice, "checkout": checkout}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = object_choice(chosen, _NS)
        if isinstance(c, Refusal):
            return c
        if "doc" not in c:
            return Refusal("card/choice-malformed")
        if "checkout" not in c:
            return c["doc"]
        return {"checkout": c["checkout"], "shown": c["doc"]} if is_object(c["checkout"]) else Refusal("card/choice-malformed")

    def request(self, unsigned: Any) -> dict[str, Any]:
        if "checkoutMandate" in unsigned:
            return {"kind": "vi-checkout-mandate", **unsigned}
        return {"kind": "vi-checkout", **unsigned}

    def steps(self, unsigned: Any) -> int:
        """One signing on a mandate the seller's checkout_jwt names; two on the agent's payload, then the mandate over
        it."""
        return 1 if "checkoutMandate" in unsigned else 2

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        if "checkoutMandate" in unsigned:
            return _l2(signature)
        if not isinstance(signature, list):
            mandate = _mandate_over(unsigned, signature)
            return mandate if isinstance(mandate, Refusal) else Step(next={"kind": "vi-checkout-mandate", **mandate})
        if len(signature) != 2:
            return Refusal("card/signature-malformed")
        mandate = _mandate_over(unsigned, signature[0])
        return mandate if isinstance(mandate, Refusal) else _l2(signature[1])


class CardMastercardViAutonomousPiece(_SignedCardPiece):
    """The checkout mandate exactly as built, for the agent to sign as L3b."""

    pairing = VI_AUTONOMOUS

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "vi-checkout-mandate", **unsigned}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        s = strings(signature, ("l1", "l2", "l3b"))
        return Refusal("card/signature-malformed") if s is None else {"l1": s["l1"], "l2": s["l2"], "l3b": s["l3b"]}


VISA_TAP_PIECE = CardVisaTapPiece()
AGENT_PAY_PIECE = CardMastercardAgentPayPiece()
VISA_VIC_PIECE = CardVisaVicPiece()
VI_IMMEDIATE_PIECE = CardMastercardViImmediatePiece()
VI_AUTONOMOUS_PIECE = CardMastercardViAutonomousPiece()
# The plain card checkout: the gate confirms only.
SELLER_REFERENCE_PIECE = ConfirmOnlyPiece(SELLER_REFERENCE, choose_doc)
