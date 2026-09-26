"""The gate's buyer piece for x402/exact/starknet: the request is SNIP-9's outside execution as SNIP-12 typed data for
the payer's account, whose nonce the build takes from the ATR hash; the account answers its signature as a list of
felts."""

import re
from typing import Any

from .._types import Advertised, Chosen, Inputs, Refusal, Signature
from ..bindings.x402_exact_starknet import ID
from ._base import BasePiece
from ._x402_account_rails import chosen_choice, identified, rail_option

_FELT = re.compile(r"0x[0-9a-fA-F]{1,64}")


class X402ExactStarknetPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Any) -> Chosen | Refusal:
        o = rail_option(read, account, ("starknet",), ID, lambda a: _FELT.fullmatch(a) is not None)
        if isinstance(o, Refusal):
            return o
        return Chosen(pairing=ID, choice={"required": o.required, "accepted": o.accepted, "from": o.address, "now": now}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return chosen_choice(chosen)

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, list) or not all(isinstance(s, str) for s in signature):
            return Refusal("x402/signature-malformed")
        return identified(unsigned.complete(signature), chosen)


PIECE = X402ExactStarknetPiece()
