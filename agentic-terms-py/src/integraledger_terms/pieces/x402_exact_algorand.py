"""The buyer piece for x402/exact/algorand: the asset transfer whose note is the hash's LCP string, signed by the payer
as algorand-txn. params is the buyer's read of algod's transaction parameters."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal, Signature
from ..bindings.x402_exact_algorand import ID
from ._common import bigint_of, bytes_of, inputs_of
from ._x402_rail import Rail, RailPiece


def signature64(signature: Signature) -> bytes | Refusal:
    """A 64-byte signature given as 0x hex, as bytes."""
    out = bytes_of(signature, 64)
    return Refusal("x402/signature-malformed") if out is None else out


def _inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    read = inputs_of(given, ID, {"params": "object"})
    if isinstance(read, Refusal):
        return read
    params = inputs_of(
        read["params"],
        ID,
        {"firstValid": "decimal", "genesisHash": "string", "genesisId": "string", "minFee": "decimal", "feePerByte": "decimal"},
    )
    return params if isinstance(params, Refusal) else {"params": params}


def _revive(c: dict[str, Any]) -> dict[str, Any] | Refusal:
    p = c.get("params")
    if not isinstance(p, Mapping):
        return Refusal("x402/choice-malformed")
    first, min_fee, per_byte = bigint_of(p.get("firstValid")), bigint_of(p.get("minFee")), bigint_of(p.get("feePerByte"))
    if first is None or min_fee is None or per_byte is None:
        return Refusal("x402/choice-malformed")
    return {**c, "params": {**p, "firstValid": first, "minFee": min_fee, "feePerByte": per_byte}}


PIECE = RailPiece(
    Rail(
        pairing=ID,
        namespace="algorand",
        address=re.compile(r"[A-Z2-7]{58}"),
        payer="payer",
        now=False,
        inputs=_inputs,
        revive=_revive,
        answer=signature64,
    )
)
