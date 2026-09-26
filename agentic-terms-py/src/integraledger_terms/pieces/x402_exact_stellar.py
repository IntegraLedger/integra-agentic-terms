"""The buyer piece for x402/exact/stellar: the Soroban authorization preimage for the buyer's simulated transfer,
signed by the payer as stellar-auth, and the payment whose payload.transaction is the signed transaction's XDR."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal
from ..bindings.x402_exact_stellar import ID
from ._common import inputs_of
from ._x402_rail import Rail, RailPiece
from .x402_exact_algorand import signature64


def _inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    return inputs_of(given, ID, {"simulatedXdr": "string", "currentLedger": "uint"})


PIECE = RailPiece(
    Rail(
        pairing=ID,
        namespace="stellar",
        address=re.compile(r"G[A-Z2-7]{55}"),
        payer=None,
        now=False,
        inputs=_inputs,
        revive=lambda c: c,
        answer=signature64,
        payload=lambda transaction: {"transaction": transaction},
    )
)
