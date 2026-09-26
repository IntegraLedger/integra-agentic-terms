"""The gate's buyer piece for x402/exact/casper: the CEP-3009 typed data with the hash as its nonce, signed by the
account's key; the answer is {publicKey, signature}, each hex with its one-byte algorithm tag."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Refusal, Signature
from ..bindings.x402_exact_casper import ID
from ._base import BasePiece
from ._common import first_option
from ._x402_account_rails import chosen_choice, identified


class X402ExactCasperPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Any) -> Chosen | Refusal:
        o = first_option(read, account, "casper", ID)
        if isinstance(o, Refusal):
            return Refusal("x402/no-payable-option")
        return Chosen(pairing=ID, choice={"required": o.required, "accepted": o.accepted, "from": o.address, "now": now}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return chosen_choice(chosen)

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, Mapping):
            return Refusal("x402/signature-malformed")
        public_key, value = signature.get("publicKey"), signature.get("signature")
        if not isinstance(public_key, str) or not isinstance(value, str):
            return Refusal("x402/signature-malformed")
        return identified(unsigned.complete(public_key, value), chosen)


PIECE = X402ExactCasperPiece()
