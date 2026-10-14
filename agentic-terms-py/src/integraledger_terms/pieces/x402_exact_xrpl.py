"""The buyer piece for x402/exact/xrpl: the Payment whose InvoiceID is the SHA-256 of the option's extra.invoiceId,
handed to the wallet as xrpl-tx. The wallet's signed blob, as hex digits without 0x, completes the payment. Fee,
Sequence (or TicketSequence) and LastLedgerSequence are the buyer's reads."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal, Signature
from ..bindings.x402_exact_xrpl import ID
from ._common import InputKind, inputs_of
from ._x402_rail import Rail, RailPiece


def _inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    extra = accepted.get("extra")
    ticket = isinstance(extra, Mapping) and extra.get("assetTransferMethod") == "ticketSequence"
    spec: dict[str, InputKind] = {"fee": "decimal"}
    spec["ticketSequence" if ticket else "sequence"] = "uint"
    spec["lastLedgerSequence"] = "uint"
    return inputs_of(given, ID, spec)


def _blob(signature: Signature) -> str | Refusal:
    """The signed blob as given: the build's complete reads it as hex digits without 0x."""
    return signature if isinstance(signature, str) else Refusal("x402/signature-malformed")


PIECE = RailPiece(
    Rail(
        pairing=ID,
        namespace="xrpl",
        address=re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}"),
        payer="account",
        now=False,
        inputs=_inputs,
        revive=lambda c: c,
        answer=_blob,
    )
)
