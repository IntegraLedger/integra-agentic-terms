"""The buyer piece for x402/upto/xrpl: the first option, in document order, that the pairing's read offers. The
payer's own client opens the payment channel to the option's payTo and signs one claim over the channel's id and the
maximum, and neither carries the hash, so nothing is handed to the signer: the proof of the hash is the agreement
payment, on the option's own network, paid before the client opens the channel, from the account that opens it. The
option stays in the choice as accepted, so the agreement is paid on its network."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_upto_xrpl import ID
from ._base import BasePiece
from ._common import x402_offer_of


class UptoXrplPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        offer = x402_offer_of(read)
        accepted = offer[1][0] if offer is not None and len(offer[1]) > 0 else None
        if not isinstance(accepted, Mapping):
            return Refusal("x402/no-payable-option")
        return Chosen(pairing=ID, choice={"accepted": accepted}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = chosen.choice if isinstance(chosen, Chosen) and isinstance(chosen.choice, dict) else None
        return Refusal("x402/choice-malformed") if c is None or not isinstance(c.get("accepted"), Mapping) else c

    def request(self, unsigned: Any) -> Refusal:
        return Refusal("x402/nothing-to-sign")

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> Refusal:
        return Refusal("x402/nothing-to-sign")


PIECE = UptoXrplPiece()
