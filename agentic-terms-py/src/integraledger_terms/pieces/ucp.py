"""The buyer pieces of the UCP pairings. The build input is the offer read gives, {"checkout": ...}. Under the AP2
Mandates extension the checkout goes, unchanged, to the buyer's mandate issuer, which answers the checkout mandate as
issued, an SD-JWT string. Without it the gate confirms only."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.ucp import BOOKING_AP2_MANDATE, BOOKING_UNSIGNED, CHECKOUT_AP2_MANDATE, CHECKOUT_UNSIGNED
from ._base import BasePiece
from .protocol_groups import ConfirmOnlyPiece, object_choice, unnamed_buyer


def choose_checkout(read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> dict[str, Any] | Refusal:
    unnamed = unnamed_buyer(account, "ucp")
    if unnamed is not None:
        return unnamed
    if not isinstance(read.offer, Mapping):
        return Refusal("ucp/no-payable-option")
    return dict(read.offer)


class UcpMandatePiece(BasePiece):
    """The piece of a UCP pairing under the AP2 Mandates extension."""

    def __init__(self, pairing: str) -> None:
        self.pairing = pairing

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        choice = choose_checkout(read, account, inputs, now, ref, doc)
        if isinstance(choice, Refusal):
            return choice
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return object_choice(chosen, "ucp")

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "ucp-checkout", "checkout": unsigned.checkout}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, str) or signature == "":
            return Refusal("ucp/signature-malformed")
        signed: dict[str, Any] | Refusal = unsigned.complete(signature)
        return signed


CHECKOUT_AP2_MANDATE_PIECE = UcpMandatePiece(CHECKOUT_AP2_MANDATE)
BOOKING_AP2_MANDATE_PIECE = UcpMandatePiece(BOOKING_AP2_MANDATE)
CHECKOUT_UNSIGNED_PIECE = ConfirmOnlyPiece(CHECKOUT_UNSIGNED, choose_checkout)
BOOKING_UNSIGNED_PIECE = ConfirmOnlyPiece(BOOKING_UNSIGNED, choose_checkout)
