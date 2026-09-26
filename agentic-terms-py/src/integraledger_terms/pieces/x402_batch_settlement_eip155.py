"""The gate's buyer piece for x402/batch-settlement/eip155: the first option on the signer's chain; the opening's
token authorization and first voucher, signed in order; the deposit from extra.minDeposit or the buyer's input,
within the buyer's maximum; and the authorization salt, drawn once and kept in chosen."""

import re
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_batch_settlement_eip155 import ID
from ._base import BasePiece
from ._batch import batch_complete, batch_request, deposit_of, optional_inputs, random_salt32, revive_decimals
from ._common import first_option

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH32 = re.compile(r"0x[0-9a-fA-F]{64}")


class X402BatchSettlementEip155Piece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        option = first_option(read, account, "eip155", self.pairing, _EVM_ADDRESS)
        if isinstance(option, Refusal):
            return Refusal("x402/no-payable-option")
        given = optional_inputs(inputs, "x402", {"payerAuthorizer": _EVM_ADDRESS, "authSalt": _HASH32})
        if isinstance(given, Refusal):
            return given
        if "payerAuthorizer" not in given:
            return Refusal("x402/input-missing")
        deposit = deposit_of(option.accepted, inputs)
        if isinstance(deposit, Refusal):
            return deposit
        choice = {
            "required": option.required,
            "accepted": option.accepted,
            "from": option.address,
            "now": now,
            "payerAuthorizer": given["payerAuthorizer"],
            "deposit": deposit,
            "authSalt": given["authSalt"] if "authSalt" in given else random_salt32(),
        }
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return revive_decimals(chosen, ["deposit"])

    def request(self, unsigned: Any) -> dict[str, Any]:
        return batch_request(unsigned)

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        return batch_complete(unsigned, signature, chosen)


PIECE = X402BatchSettlementEip155Piece()
