"""The buyer pieces for mpp/charge/tempo/memo and mpp/charge/tempo/push: the first challenge offering the pairing on
the signer's chain, with clientId optional, and the binding's own build, whose tempo-calls request carries one call per
recipient where the challenge names splits. memo's answer is the signed 0x76 transaction; push's is the hash the signer
broadcast with its landed receipt, held in Held, as @integraledger/lcp holds it under the payment's own FETCHED
member, where bound reads it for the memo; the payment sent is the credential without it."""

from collections.abc import Mapping
from typing import Any

from .._types import Chosen, Refusal, Signature, Step
from ..bindings._lcp import is_list
from ..bindings._mpp import Held
from ..bindings.mpp_charge_tempo import MEMO, PUSH
from ._common import bigint_of
from ._mpp import MppChargePiece


class MppChargeTempoPushPiece(MppChargePiece):
    def __init__(self) -> None:
        super().__init__(PUSH, {"clientId": "optional-string"})

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        """The credential for a pushed transfer: the answer is {hash, landed?: {transaction, blockNumber, logs}}, the
        hash the signer broadcast and, where the signer gives it, its landed receipt, which carries the memo bound
        reads, held in Held, as @integraledger/lcp holds it under the payment's own FETCHED member."""
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
        read = {"transaction": landed["transaction"], "blockNumber": str(block_number), "logs": list(landed["logs"])}
        return Held(credential, read)

    def sent(self, signed: dict[str, Any]) -> dict[str, Any]:
        return dict(signed)


MEMO_PIECE = MppChargePiece(MEMO, {"clientId": "optional-string"})
PUSH_PIECE = MppChargeTempoPushPiece()
