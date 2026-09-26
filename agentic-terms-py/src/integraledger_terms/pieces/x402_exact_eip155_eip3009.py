"""The gate's buyer piece for x402/exact/eip155/eip3009: which option to pay, what the signer is handed, and the
payment identifier."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_exact_eip155_eip3009 import ID
from ._base import BasePiece

_ACCOUNT = re.compile(r"eip155:([0-9]+):(0x[0-9a-fA-F]{40})")


def with_payment_identifier(signed: dict[str, Any], chosen: Chosen) -> dict[str, Any] | Refusal:
    """Where the challenge advertises payment-identifier, its echoed info gains id = ref; the echo is never
    overwritten."""
    required = chosen.choice.get("required")
    advertised = required.get("extensions") if isinstance(required, Mapping) else None
    if not isinstance(advertised, Mapping) or "payment-identifier" not in advertised:
        return signed
    extensions = signed.get("extensions")
    if not isinstance(extensions, Mapping):
        return Refusal("x402/payment-identifier-unwritable")
    extension = extensions.get("payment-identifier")
    info = extension.get("info") if isinstance(extension, Mapping) else None
    if not isinstance(extension, Mapping) or not isinstance(info, Mapping) or "id" in info:
        return Refusal("x402/payment-identifier-unwritable")
    return {**signed, "extensions": {**extensions, "payment-identifier": {**extension, "info": {**info, "id": chosen.ref}}}}


class X402ExactEip155Eip3009Piece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        """The first option, in document order, on the chain of the signer's CAIP-10 account."""
        match = _ACCOUNT.fullmatch(account) if isinstance(account, str) else None
        if match is None:
            return Refusal("x402/no-payable-option")
        network = "eip155:" + match.group(1)
        options = read.offer.get("options")
        if not isinstance(options, Sequence):
            return Refusal("x402/no-payable-option")
        for option in options:
            if isinstance(option, Mapping) and option.get("network") == network:
                choice = {"required": read.offer.get("required"), "accepted": option, "from": match.group(2), "now": now}
                return Chosen(pairing=self.pairing, choice=choice, ref=ref)
        return Refusal("x402/no-payable-option")

    def request(self, unsigned: Any) -> dict[str, Any]:
        """The signing request: the EIP-712 typed data exactly as built."""
        return {"kind": "eip712", "typedData": unsigned.typed_data}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        """The signed payment, with the payment identifier where the challenge advertises it."""
        signed = unsigned.complete(signature)
        if isinstance(signed, Refusal):
            return signed
        return with_payment_identifier(signed, chosen)


PIECE = X402ExactEip155Eip3009Piece()
