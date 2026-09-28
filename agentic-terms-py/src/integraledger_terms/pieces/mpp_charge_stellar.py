"""The buyer piece for mpp/charge/stellar: the Soroban authorization preimage for the buyer's simulated transfer to the
request's muxed recipient, signed by the payer as stellar-auth; the credential is the build's own. The simulated
transaction and the current ledger are the buyer's reads."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal
from ..bindings.mpp_charge_stellar import ID
from ._common import inputs_of
from ._mpp import MppRail, MppRailPiece, complete_with, signature64

STELLAR_ACCOUNT = re.compile(r"G[A-Z2-7]{55}")


def _inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    return inputs_of(given, ID, {"simulatedXdr": "string", "currentLedger": "uint"})


PIECE = MppRailPiece(
    MppRail(
        pairing=ID,
        namespace="stellar",
        address=STELLAR_ACCOUNT,
        payer="payer",
        now=True,
        inputs=_inputs,
        revive=lambda c: c,
        complete=complete_with(signature64),
    )
)
