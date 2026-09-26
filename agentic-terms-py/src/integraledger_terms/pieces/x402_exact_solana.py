"""The buyer piece for x402/exact/solana: the v0 message whose one memo is the option's extra.memo, signed by the payer
as solana-message. The recent blockhash is the option's extra.recentBlockhash when it names one, else the buyer's; the
mint's decimals and token program are the buyer's reads."""

from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal
from ..bindings.x402_exact_solana import ID
from ._common import bigint_of, inputs_of
from ._sol_rail import SOLANA_ADDRESS, signature64
from ._x402_rail import Rail, RailPiece


def with_unit_price(c: dict[str, Any]) -> dict[str, Any] | Refusal:
    """computeUnitPrice as the build's int, where the choice carries one."""
    if "computeUnitPrice" not in c:
        return c
    price = bigint_of(c["computeUnitPrice"])
    return Refusal("x402/choice-malformed") if price is None else {**c, "computeUnitPrice": price}


def _inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    extra = accepted.get("extra")
    offered = extra.get("recentBlockhash") if isinstance(extra, Mapping) else None
    from_offer = isinstance(offered, str) and offered != ""
    spec: dict[str, Any] = {"decimals": "uint", "tokenProgram": "string"}
    if not from_offer:
        spec["recentBlockhash"] = "string"
    spec["computeUnitLimit"] = "optional-uint"
    spec["computeUnitPrice"] = "optional-decimal"
    read = inputs_of(given, ID, spec)
    if isinstance(read, Refusal):
        return read
    return {**read, "recentBlockhash": offered} if from_offer else read


PIECE = RailPiece(Rail(pairing=ID, namespace="solana", address=SOLANA_ADDRESS, payer="payer", now=False, inputs=_inputs, revive=with_unit_price, answer=signature64))
