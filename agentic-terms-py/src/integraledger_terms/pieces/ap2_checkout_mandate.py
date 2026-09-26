"""The buyer piece for ap2/checkout-mandate: the build input is the offer read gives (the merchant's checkout_jwt and
its payload); the closed Checkout Mandate's claims go to the buyer's mandate signer, which answers the mandate as
issued, an SD-JWT string."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.ap2_checkout_mandate import ID
from ._base import BasePiece
from .protocol_groups import object_choice, unnamed_buyer


class Ap2CheckoutMandatePiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        unnamed = unnamed_buyer(account, "ap2")
        if unnamed is not None:
            return unnamed
        if not isinstance(read.offer, Mapping):
            return Refusal("ap2/no-payable-option")
        return Chosen(pairing=self.pairing, choice=dict(read.offer), ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return object_choice(chosen, "ap2")

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "ap2-checkout-mandate", "content": unsigned.content}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, str) or signature == "":
            return Refusal("ap2/signature-malformed")
        signed: dict[str, Any] = unsigned.complete(signature)
        return signed


PIECE = Ap2CheckoutMandatePiece()
