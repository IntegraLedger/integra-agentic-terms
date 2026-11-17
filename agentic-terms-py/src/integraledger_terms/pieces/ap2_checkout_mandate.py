"""The buyer pieces for ap2/checkout-mandate and ap2/checkout-mandate/x402: the build input is the offer read gives (the
merchant's checkout_jwt and its payload); the closed Checkout Mandate's claims go to the buyer's mandate signer, which
answers the mandate as issued, an SD-JWT string, or AP2's chained presentation of the open and closed mandates joined by
~~. In AP2's push funding, where the payer's side sends the funds itself, the signer answers {"checkout_mandate",
"payment_receipt"}: the mandate and AP2's Payment Receipt, the confirmation of the funds it sent, which the presentation
carries; such a payment has moved once the signer answers, so a decline after it keeps it. On ap2/checkout-mandate/x402
the signer answers {"checkout_mandate", "payment"}: the mandate and AP2's x402 bundle from the buyer's credential
provider, whose EIP-3009 authorization's nonce is keccak-256 of the payment mandate chain, so it carries no hash of the
ATR and nothing builds it here."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.ap2_checkout_mandate import ID, X402_ID
from ._base import BasePiece
from .protocol_groups import object_choice, unnamed_buyer


def _pushed(signature: Signature) -> bool:
    """Whether the signer's answer is a push funding's: the mandate with the Payment Receipt of the funds its side
    sent."""
    return isinstance(signature, Mapping) and isinstance(signature.get("payment_receipt"), Mapping)


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
        if _pushed(signature):
            assert isinstance(signature, Mapping)
            mandate = signature.get("checkout_mandate")
            if not isinstance(mandate, str) or mandate == "" or len(signature) != 2:
                return Refusal("ap2/signature-malformed")
            pushed: dict[str, Any] = unsigned.complete(mandate)
            return {**pushed, "payment_receipt": signature["payment_receipt"]}
        if not isinstance(signature, str) or signature == "":
            return Refusal("ap2/signature-malformed")
        signed: dict[str, Any] = unsigned.complete(signature)
        return signed

    def moved_by(self, signature: Signature) -> bool:
        """True where the answer is a push funding's: the payer's side has sent the funds."""
        return _pushed(signature)


class Ap2CheckoutMandateX402Piece(Ap2CheckoutMandatePiece):
    pairing = X402_ID

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, Mapping) or len(signature) != 2:
            return Refusal("ap2/signature-malformed")
        mandate = signature.get("checkout_mandate")
        payment = signature.get("payment")
        if not isinstance(mandate, str) or mandate == "" or not isinstance(payment, Mapping):
            return Refusal("ap2/signature-malformed")
        signed: dict[str, Any] = unsigned.complete(mandate)
        return {**signed, "payment": payment}

    def moved_by(self, signature: Signature) -> bool:
        return False


PIECE = Ap2CheckoutMandatePiece()
X402_PIECE = Ap2CheckoutMandateX402Piece()
