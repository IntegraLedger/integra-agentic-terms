"""The buyer piece for x402/exact/hedera/transfer-executor: the offered executors, asset, payee, amount and
validBefore, handed to the buyer's wallet or executor tooling as hedera-executor, which answers
{payer, executor, authorization}."""

from collections.abc import Mapping
from typing import Any

from .._types import Refusal, Signature
from ..bindings.x402_exact_hedera import EXECUTOR
from ._x402_rail import Rail, RailPiece
from .x402_exact_hedera import HEDERA_ENTITY


def _answer(signature: Signature) -> dict[str, str] | Refusal:
    """The wallet's answer, its three members as strings."""
    if not isinstance(signature, Mapping):
        return Refusal("x402/signature-malformed")
    payer, executor, authorization = signature.get("payer"), signature.get("executor"), signature.get("authorization")
    if not isinstance(payer, str) or not isinstance(executor, str) or not isinstance(authorization, str):
        return Refusal("x402/signature-malformed")
    return {"payer": payer, "executor": executor, "authorization": authorization}


def _none(accepted: Mapping[str, Any], given: Any) -> dict[str, Any]:
    return {}


PIECE = RailPiece(
    Rail(
        pairing=EXECUTOR,
        namespace="hedera",
        address=HEDERA_ENTITY,
        payer=None,
        now=True,
        inputs=_none,
        revive=lambda c: c,
        answer=_answer,
    )
)
