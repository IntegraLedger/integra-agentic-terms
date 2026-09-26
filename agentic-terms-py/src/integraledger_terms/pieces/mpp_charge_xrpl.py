"""The buyer piece for mpp/charge/xrpl: the Payment whose InvoiceID is the request's methodDetails.invoiceId, handed to
the wallet as xrpl-tx. The wallet's signed blob, as 0x hex, completes the build's own credential. Fee, Sequence and
LastLedgerSequence are the buyer's reads."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal, Signature
from ..bindings.mpp_charge_xrpl import ID
from ._common import inputs_of
from ._mpp import MppRail, MppRailPiece, complete_with, hex_digits

XRPL_ADDRESS = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")


def _inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    return inputs_of(given, ID, {"fee": "decimal", "sequence": "uint", "lastLedgerSequence": "uint"})


def _blob(signature: Signature) -> str | Refusal:
    """The signed blob's hex digits, from 0x hex."""
    digits = hex_digits(signature)
    return Refusal("mpp/credential-malformed") if digits is None else digits


PIECE = MppRailPiece(
    MppRail(
        pairing=ID,
        namespace="xrpl",
        address=XRPL_ADDRESS,
        payer="account",
        now=False,
        inputs=_inputs,
        revive=lambda c: c,
        complete=complete_with(_blob),
    )
)
