"""The gate's buyer piece for x402/exact/eip155/gateway-batched: Circle Gateway's batched payment, an EIP-3009
TransferWithAuthorization in the Gateway Wallet's GatewayWalletBatched domain with the ATR hash as its nonce. The first
option on the signer's chain; the choice carries minValiditySeconds, the minimum validity Circle Gateway's /supported
serves for the network, which the caller gives in inputs (the gate declines floor-missing before it reads the offer
where inputs lacks it). The typed data is handed to the signer exactly as built, and the signature completes the
payment, with the payment identifier where the challenge advertises it. The pairing is at coverage none: its payment is
taken only after an agreement on the same network."""

import re
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_exact_eip155_gateway_batched import ID
from ._base import BasePiece
from ._common import choice_of, first_option, with_payment_identifier

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


class X402ExactEip155GatewayBatchedPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        """The first option, in document order, on the chain of the signer's CAIP-10 account, with the served minimum
        validity the caller gives."""
        option = first_option(read, account, "eip155", self.pairing, _EVM_ADDRESS)
        if isinstance(option, Refusal):
            return Refusal("x402/no-payable-option")
        choice: dict[str, Any] = {"required": option.required, "accepted": option.accepted, "from": option.address, "now": now}
        if "minValiditySeconds" in inputs:
            choice["minValiditySeconds"] = inputs["minValiditySeconds"]
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        found = choice_of(chosen)
        return found if found is not None else Refusal("x402/choice-malformed")

    def request(self, unsigned: Any) -> dict[str, Any]:
        """The signing request: the EIP-712 typed data exactly as built."""
        return {"kind": "eip712", "typedData": unsigned.typed_data}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        """The signed payment, with the payment identifier where the challenge advertises it."""
        if not isinstance(signature, str):
            return Refusal("x402/signature-malformed")
        signed = unsigned.complete(signature)
        if isinstance(signed, Refusal):
            return signed
        return with_payment_identifier(signed, chosen.choice.get("required"), chosen.ref)


PIECE = X402ExactEip155GatewayBatchedPiece()
