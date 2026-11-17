"""The buyer pieces of the card pairings. The build input is the seller's document itself (the shown JSON for TAP and
the plain checkout, the checkout_jwt for Verifiable Intent), kept in Chosen as {"doc": ...}. TAP's nonce goes to the
agent's RFC 9421 signer, which places it in every message signature of its checkout request and answers
{"signatureInput", "signature"}, from which bound reads the hash the nonce carries. The checkout mandate goes to the
wallet (L2, answering {"l2"}) or the agent (L3b, answering {"l1", "l2", "l3b"})."""

from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Binding, Chosen, Inputs, Json, Refusal, Signature
from ..bindings._codec import b64_decode
from ..bindings.card import NONCE_BYTES, SELLER_REFERENCE, VI_AUTONOMOUS, VI_IMMEDIATE, VISA_TAP
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


class CardMastercardViImmediatePiece(_SignedCardPiece):
    """The checkout mandate exactly as built, for the user's wallet to sign as L2."""

    pairing = VI_IMMEDIATE

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "vi-checkout-mandate", **unsigned}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        s = strings(signature, ("l2",))
        return Refusal("card/signature-malformed") if s is None else {"l2": s["l2"]}


class CardMastercardViAutonomousPiece(_SignedCardPiece):
    """The checkout mandate exactly as built, for the agent to sign as L3b."""

    pairing = VI_AUTONOMOUS

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "vi-checkout-mandate", **unsigned}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        s = strings(signature, ("l1", "l2", "l3b"))
        return Refusal("card/signature-malformed") if s is None else {"l1": s["l1"], "l2": s["l2"], "l3b": s["l3b"]}


VISA_TAP_PIECE = CardVisaTapPiece()
VI_IMMEDIATE_PIECE = CardMastercardViImmediatePiece()
VI_AUTONOMOUS_PIECE = CardMastercardViAutonomousPiece()
# The plain card checkout: the gate confirms only.
SELLER_REFERENCE_PIECE = ConfirmOnlyPiece(SELLER_REFERENCE, choose_doc)
