"""The buyer piece for mpp/session/hedera: the opening handed to the signer as the build's hedera-session-open request,
exactly as built. The signer broadcasts the two calls in order, signs the zero voucher, and answers {openTx,
signature}, the opening's hash and the voucher signature, with, where it has it, landed: {transaction, blockNumber,
logs}, the opening's landed receipt, whose escrow log carries the channel's salt that bound reads. The payment sent is
the credential without the landed receipt. The signer moves the deposit, so a decline keeps it."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Chosen, Inputs, Json, Refusal, Signature, Step
from ..bindings.mpp_session_hedera import ID
from ._common import bigint_of, inputs_of
from ._mpp import MppRail, MppRailPiece, session_revive

HEDERA_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")


def _complete(unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
    if not isinstance(signature, Mapping) or not isinstance(signature.get("openTx"), str):
        return Refusal("mpp/credential-malformed")
    if not isinstance(signature.get("signature"), str):
        return Refusal("mpp/credential-malformed")
    credential = unsigned.complete({"openTx": signature["openTx"], "signature": signature["signature"]})
    if isinstance(credential, Refusal):
        return credential
    landed = signature.get("landed")
    if landed is None:
        return dict(credential)
    if not isinstance(landed, Mapping) or not isinstance(landed.get("transaction"), str):
        return Refusal("mpp/credential-malformed")
    if not isinstance(landed.get("logs"), list):
        return Refusal("mpp/credential-malformed")
    block_number = bigint_of(landed.get("blockNumber"))
    if block_number is None:
        return Refusal("mpp/credential-malformed")
    return {**credential, "landed": {"transaction": landed["transaction"], "blockNumber": str(block_number), "logs": landed["logs"]}}


def _inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    return inputs_of(given, ID, {"deposit": "decimal"})


class MppSessionHederaPiece(MppRailPiece):
    def moves(self, request: Json) -> bool:
        return True

    def sent(self, signed: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in signed.items() if k != "landed"}


PIECE = MppSessionHederaPiece(
    MppRail(
        pairing=ID,
        namespace="hedera",
        address=HEDERA_EVM_ADDRESS,
        payer="from",
        now=True,
        inputs=_inputs,
        revive=session_revive,
        complete=_complete,
    )
)
