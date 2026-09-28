"""The gate's buyer piece for x402/exact/ccd: the transfer the wallet assembles, with the hash in its memo; the answer
is the sender-signed V1 sponsored transaction in x402's wire form, the JSON-serialized transaction: with
@concordium/web-sdk, JSON.parse(Transaction.toJSONString(tx)). Any other value is ccd/transaction-malformed."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Refusal, Signature
from ..bindings.x402_exact_ccd import ID
from ._base import BasePiece
from ._common import first_option
from ._x402_account_rails import chosen_choice, identified


class X402ExactCcdPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Any) -> Chosen | Refusal:
        o = first_option(read, account, "ccd", ID)
        if isinstance(o, Refusal):
            return Refusal("x402/no-payable-option")
        return Chosen(pairing=ID, choice={"required": o.required, "accepted": o.accepted, "now": now}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return chosen_choice(chosen)

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, Mapping):
            return Refusal("x402/signature-malformed")
        return identified(unsigned.complete(signature), chosen)


PIECE = X402ExactCcdPiece()
