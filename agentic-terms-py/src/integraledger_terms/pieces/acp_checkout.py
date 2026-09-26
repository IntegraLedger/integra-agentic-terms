"""The buyer pieces of the ACP pairings. For acp/checkout/delegated the build input is the session read gives and the
buyer's own allowance values, as inputs: max_amount (minor units), currency, merchant_id and expires_at. The allowance
goes to the agent, which answers the delegate_payment request it signed, as an object. For
acp/checkout/undelegated the handler does not delegate, so the gate confirms only."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.acp_checkout import DELEGATED, UNDELEGATED
from ._base import BasePiece
from ._common import InputKind, inputs_of
from .protocol_groups import ConfirmOnlyPiece, object_choice, unnamed_buyer

ALLOWANCE_INPUTS: Mapping[str, InputKind] = {
    "max_amount": "uint",
    "currency": "string",
    "merchant_id": "string",
    "expires_at": "string",
}


def _session_of(read: Advertised) -> Any:
    return read.offer.get("session") if isinstance(read.offer, Mapping) else None


class AcpCheckoutDelegatedPiece(BasePiece):
    pairing = DELEGATED

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        unnamed = unnamed_buyer(account, "acp")
        if unnamed is not None:
            return unnamed
        session = _session_of(read)
        if not isinstance(session, Mapping):
            return Refusal("acp/no-payable-option")
        values = inputs_of(inputs, self.pairing, ALLOWANCE_INPUTS)
        if isinstance(values, Refusal):
            return values
        return Chosen(pairing=self.pairing, choice={"session": session, **values}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return object_choice(chosen, "acp")

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "acp-allowance", "allowance": unsigned.allowance}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, Mapping):
            return Refusal("acp/signature-malformed")
        signed: dict[str, Any] | Refusal = unsigned.complete(signature)
        return signed


def _choose_undelegated(
    read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json
) -> dict[str, Any] | Refusal:
    unnamed = unnamed_buyer(account, "acp")
    if unnamed is not None:
        return unnamed
    session = _session_of(read)
    if not isinstance(session, Mapping):
        return Refusal("acp/no-payable-option")
    return {"session": session}


DELEGATED_PIECE = AcpCheckoutDelegatedPiece()
UNDELEGATED_PIECE = ConfirmOnlyPiece(UNDELEGATED, _choose_undelegated)
