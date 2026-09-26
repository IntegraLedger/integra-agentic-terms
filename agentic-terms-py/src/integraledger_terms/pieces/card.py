"""The buyer pieces of the card pairings. The build input is the seller's document itself (the shown JSON for TAP and
the plain checkout, the checkout_jwt for Verifiable Intent), kept in Chosen as {"doc": ...}. The TAP field goes to the
agent's RFC 9421 signer, which answers {"signatureInput", "signature", "lcpHash"}, lcpHash being every lcp-hash field
line it sent, in order, which bound reads. The checkout mandate goes to the user's wallet, which answers {"l2"}."""

from collections.abc import Mapping, Sequence
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.card import SELLER_REFERENCE, VI_AUTONOMOUS, VI_IMMEDIATE, VISA_TAP
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


class CardVisaTapPiece(_SignedCardPiece):
    """The TAP field exactly as built, for the agent's signer to add and list in its agent-payer-auth signature."""

    pairing = VISA_TAP

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "tap-field", **unsigned}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        s = strings(signature, ("signatureInput", "signature"))
        lines = signature.get("lcpHash") if isinstance(signature, Mapping) else None
        if s is None or not isinstance(lines, list):
            return Refusal("card/signature-malformed")
        return {"signatureInput": s["signatureInput"], "signature": s["signature"], "lcpHash": list(lines)}


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
