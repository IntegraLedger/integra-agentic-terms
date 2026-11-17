"""The buyer piece for x402/exact/stellar/precondition, the agreement on Stellar, never a charge: the buyer's simulated
transfer(buyer, payTo, amount) with the authorization entry's expiration set and one signed-payload precondition of H
and the entry's nonce, handed to the signer as stellar-precondition, its preimage (whose SHA-256 the buyer's key signs)
and its 40-byte payload (which the key signs raw). The signer answers {entry, payload}, each a 64-byte Ed25519
signature as 0x hex; the payment's payload.transaction is the envelope with both written. simulatedXdr and
currentLedger are the buyer's reads."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal, Signature
from ..bindings.x402_exact_stellar_precondition import ID
from ._common import bytes_of, inputs_of
from ._x402_rail import Rail, RailPiece


def _inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    return inputs_of(given, ID, {"simulatedXdr": "string", "currentLedger": "uint"})


def _answer(signature: Signature) -> Any:
    """{entry, payload}, each a 64-byte signature as 0x hex, as the bytes the build's complete takes."""
    if not isinstance(signature, Mapping):
        return Refusal("x402/signature-malformed")
    entry, payload = bytes_of(signature.get("entry"), 64), bytes_of(signature.get("payload"), 64)
    if entry is None or payload is None:
        return Refusal("x402/signature-malformed")
    return {"entry": entry, "payload": payload}


PIECE = RailPiece(
    Rail(
        pairing=ID,
        namespace="stellar",
        address=re.compile(r"G[A-Z2-7]{55}"),
        payer="payer",
        now=False,
        inputs=_inputs,
        revive=lambda c: c,
        answer=_answer,
    )
)
