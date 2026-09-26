"""The buyer piece for x402/batch-settlement/solana: the first option on the signer's cluster; the opening's
transaction message and first voucher, signed in order, each answered in base58; the deposit from extra.minDeposit or
the buyer's input, within the buyer's maximum; the recent blockhash from extra.recentBlockhash when the offer carries
one; and the channel salt, drawn once and kept in chosen."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_batch_settlement_solana import ID
from ._base import BasePiece
from ._batch import batch_complete, batch_request, deposit_of, optional_inputs, random_u64, revive_decimals
from ._common import first_option, inputs_of

KEY = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")
U64 = re.compile(r"[0-9]{1,20}")
U64_LIMIT = 1 << 64


def _is_u64(value: object) -> bool:
    return isinstance(value, str) and U64.fullmatch(value) is not None and int(value) < U64_LIMIT


class X402BatchSettlementSolanaPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        """The first option on the signer's cluster, with the buyer's inputs, the deposit and a salt."""
        o = first_option(read, account, "solana", ID, KEY)
        if isinstance(o, Refusal):
            return Refusal("x402/no-payable-option")
        extra = o.accepted.get("extra")
        extra = extra if isinstance(extra, Mapping) else {}
        offered = extra.get("recentBlockhash")
        spec: dict[str, Any] = {"payerAuthorizer": "string", "openSlot": "decimal", "tokenProgram": "string"}
        if "recentBlockhash" not in extra:
            spec["recentBlockhash"] = "string"
        spec["computeUnitLimit"] = "optional-uint"
        spec["computeUnitPrice"] = "optional-decimal"
        required = inputs_of(inputs, ID, spec)
        if isinstance(required, Refusal):
            return required
        optional = optional_inputs(inputs, "x402", {"salt": U64})
        if isinstance(optional, Refusal):
            return optional
        has_salt = "salt" in optional
        salt = optional.get("salt")
        blockhash = offered if offered is not None else required.get("recentBlockhash")
        if not isinstance(blockhash, str) or KEY.fullmatch(blockhash) is None:
            return Refusal("x402/input-missing")
        if KEY.fullmatch(str(required["payerAuthorizer"])) is None or not _is_u64(required["openSlot"]):
            return Refusal("x402/input-missing")
        if has_salt and not _is_u64(salt):
            return Refusal("x402/input-missing")
        deposit = deposit_of(o.accepted, inputs)
        if isinstance(deposit, Refusal):
            return deposit
        choice: dict[str, Any] = {
            "required": o.required,
            "accepted": o.accepted,
            "payer": o.address,
            "now": now,
            **required,
            "recentBlockhash": blockhash,
            "deposit": deposit,
            "salt": salt if has_salt else random_u64(),
        }
        return Chosen(pairing=ID, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return revive_decimals(chosen, ("deposit", "salt", "openSlot", "computeUnitPrice"))

    def request(self, unsigned: Any) -> dict[str, Any]:
        return batch_request(unsigned)

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        return batch_complete(unsigned, signature, chosen)


PIECE = X402BatchSettlementSolanaPiece()
