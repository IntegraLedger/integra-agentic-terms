"""The buyer piece shared by the x402 pairings on EVM: the first option on the signer's chain, the typed data or
delegation request exactly as built, and the payment the answer completes, with the payment identifier appended where
the challenge advertises it."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_evm import Unsigned
from ._base import BasePiece
from ._common import choice_of, first_option, with_payment_identifier

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_DELEGATION = ("delegationManager", "permissionContext", "delegator")


class EvmX402Piece(BasePiece):
    def __init__(self, pairing: str) -> None:
        self.pairing = pairing

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        """The first option, in document order, on the chain of the signer's CAIP-10 account."""
        option = first_option(read, account, "eip155", self.pairing, _EVM_ADDRESS)
        if isinstance(option, Refusal):
            return Refusal("x402/no-payable-option")
        choice = {"required": option.required, "accepted": option.accepted, "from": option.address, "now": now}
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        found = choice_of(chosen)
        return found if found is not None else Refusal("x402/choice-malformed")

    def request(self, unsigned: Any) -> dict[str, Any]:
        """The request exactly as built: EIP-712 typed data, or the delegation request."""
        assert isinstance(unsigned, Unsigned)
        return unsigned.request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        """The signed payment, with the payment identifier where the challenge advertises it. An EIP-712 request takes
        a hex signature; a delegation request takes the delegation manager, the permission context and the
        delegator."""
        assert isinstance(unsigned, Unsigned)
        if unsigned.request.get("kind") == "eip712":
            if not isinstance(signature, str):
                return Refusal("x402/signature-malformed")
            signed = unsigned.complete(signature)
        else:
            if not isinstance(signature, Mapping) or not all(isinstance(signature.get(k), str) for k in _DELEGATION):
                return Refusal("x402/signature-malformed")
            signed = unsigned.complete({k: signature[k] for k in _DELEGATION})
        if isinstance(signed, Refusal):
            return signed
        return with_payment_identifier(signed, chosen.choice.get("required"), chosen.ref)
