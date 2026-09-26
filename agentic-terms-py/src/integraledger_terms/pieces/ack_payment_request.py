"""The buyer piece for ack/payment-request: ACK defines no payer signature, so the gate confirms only. The option to
pay is the first of the signed request's payment options, in order, whose network is the account's CAIP-2."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Inputs, Json, Refusal
from ..bindings.ack_payment_request import ID
from ._common import account_of
from .protocol_groups import ConfirmOnlyPiece


def _choose(read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> dict[str, Any] | Refusal:
    a = account_of(account)
    options = read.offer.get("options") if isinstance(read.offer, Mapping) else None
    if a is None or not isinstance(options, list):
        return Refusal("ack/no-payable-option")
    for option in options:
        if isinstance(option, Mapping) and option.get("network") == a.network:
            return {"option": option}
    return Refusal("ack/no-payable-option")


PIECE = ConfirmOnlyPiece(ID, _choose)
