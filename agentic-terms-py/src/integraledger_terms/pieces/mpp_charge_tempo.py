"""The buyer pieces for mpp/charge/tempo/memo and mpp/charge/tempo/push: the first challenge offering the pairing on
the signer's chain, with clientId optional. With splits, the transaction carries one call per recipient: the primary,
carrying the attribution memo, for amount less the splits, then each split in array order. memo's answer is the signed
0x76 transaction; push's is the hash the signer broadcast with its landed receipt, which bound reads for the memo, and
the payment sent is the credential without the landed receipt."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Binding, Chosen, Refusal, Signature, Step
from ..bindings._lcp import is_address, is_list
from ..bindings._mpp import MppUnsigned
from ..bindings._mpp_evm import transfer_calldata
from ..bindings._tempo import memo_calldata
from ..bindings.mpp_charge_tempo import MEMO, PUSH
from ._common import bigint_of
from ._mpp import MppChargePiece, request_of

_MAX_SPLITS = 10
_DECIMAL = re.compile(r"[0-9]{1,78}")
_WORD = re.compile(r"0x[0-9a-fA-F]{64}")


@dataclass(frozen=True, slots=True)
class Split:
    recipient: str
    amount: int
    memo: str | None


def tempo_splits(c: Mapping[str, Any]) -> list[Split] | Refusal:
    """A Tempo challenge's methodDetails.splits: none, or 1 to 10 entries, each with a recipient address, an amount
    above zero and an optional 32-byte memo."""
    request = request_of(c) or {}
    details = request.get("methodDetails")
    splits = details.get("splits") if isinstance(details, Mapping) else None
    if splits is None:
        return []
    if not is_list(splits) or not 1 <= len(splits) <= _MAX_SPLITS:
        return Refusal("mpp/splits-malformed")
    out: list[Split] = []
    for s in splits:
        if not isinstance(s, Mapping):
            return Refusal("mpp/splits-malformed")
        recipient, amount, memo = s.get("recipient"), s.get("amount"), s.get("memo")
        if not isinstance(recipient, str) or not is_address(recipient):
            return Refusal("mpp/splits-malformed")
        if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None or int(amount) == 0:
            return Refusal("mpp/splits-malformed")
        if "memo" in s and (not isinstance(memo, str) or _WORD.fullmatch(memo) is None):
            return Refusal("mpp/splits-malformed")
        out.append(Split(recipient, int(amount), memo if isinstance(memo, str) else None))
    return out


def primary_amount(c: Mapping[str, Any], splits: list[Split]) -> int | Refusal:
    """What the primary recipient receives: amount less the splits, which must leave more than zero."""
    amount = (request_of(c) or {}).get("amount")
    if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None:
        return Refusal("mpp/request-malformed")
    primary = int(amount) - sum(s.amount for s in splits)
    return primary if primary > 0 else Refusal("mpp/input-malformed")


def accept_splits(c: Mapping[str, Any]) -> Refusal | None:
    """Accepts a Tempo challenge whose splits are well formed and leave the primary recipient more than zero."""
    splits = tempo_splits(c)
    if isinstance(splits, Refusal):
        return splits
    primary = primary_amount(c, splits)
    return primary if isinstance(primary, Refusal) else None


def tempo_build(binding: Binding, choice: Any, h: AtrHash) -> Any:
    """Without splits, the binding's own tempo-call. With splits, tempo-calls: the binding's primary call, carrying
    its attribution memo, for amount less the splits, then one call per split in array order, transferWithMemo where
    the split names a memo and transfer otherwise, all on currency."""
    unsigned = binding.build(choice, h)
    if isinstance(unsigned, Refusal):
        return unsigned
    challenge = choice["challenge"]
    splits = tempo_splits(challenge)
    if isinstance(splits, Refusal) or not splits:
        return splits if isinstance(splits, Refusal) else unsigned
    primary = primary_amount(challenge, splits)
    if isinstance(primary, Refusal):
        return primary
    request = unsigned.request
    if request.get("kind") != "tempo-call":
        return Refusal("mpp/request-malformed")
    recipient = (request_of(challenge) or {}).get("recipient")
    memo = "0x" + request["call"]["data"][-64:]
    primary_call = memo_calldata(recipient, primary, memo)
    if isinstance(primary_call, Refusal):
        return primary_call
    currency = request["call"]["to"]
    calls = [{"to": currency, "data": primary_call}]
    for s in splits:
        data = memo_calldata(s.recipient, s.amount, s.memo) if s.memo is not None else transfer_calldata(s.recipient, s.amount)
        if isinstance(data, Refusal):
            return data
        calls.append({"to": currency, "data": data})
    tempo_calls = {
        "kind": "tempo-calls",
        "chainId": request["chainId"],
        "calls": calls,
        "validBefore": request["validBefore"],
        "broadcast": request["broadcast"],
    }
    return MppUnsigned(tempo_calls, unsigned.complete)


class MppChargeTempoMemoPiece(MppChargePiece):
    def __init__(self) -> None:
        super().__init__(MEMO, {"clientId": "optional-string"}, accept_splits)

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        return tempo_build(binding, choice, h)


class MppChargeTempoPushPiece(MppChargePiece):
    def __init__(self) -> None:
        super().__init__(PUSH, {"clientId": "optional-string"}, accept_splits)

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        return tempo_build(binding, choice, h)

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        """The credential for a pushed transfer: the answer is {hash, landed?: {transaction, blockNumber, logs}}, the
        hash the signer broadcast and, where the signer gives it, its landed receipt, which carries the memo bound
        reads."""
        if not isinstance(signature, Mapping) or not isinstance(signature.get("hash"), str):
            return Refusal("mpp/credential-malformed")
        credential: dict[str, Any] | Refusal = unsigned.complete(signature["hash"])
        if isinstance(credential, Refusal):
            return credential
        landed = signature.get("landed")
        if landed is None:
            return credential
        if not isinstance(landed, Mapping) or not isinstance(landed.get("transaction"), str) or not is_list(landed.get("logs")):
            return Refusal("mpp/credential-malformed")
        block_number = bigint_of(landed.get("blockNumber"))
        if block_number is None:
            return Refusal("mpp/credential-malformed")
        return {
            **credential,
            "landed": {"transaction": landed["transaction"], "blockNumber": str(block_number), "logs": list(landed["logs"])},
        }

    def sent(self, signed: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in signed.items() if k != "landed"}


MEMO_PIECE = MppChargeTempoMemoPiece()
PUSH_PIECE = MppChargeTempoPushPiece()
