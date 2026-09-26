"""The buyer piece for x402/upto/solana: the open message of a one-request payment channel whose one memo is the
option's extra.memo, signed by the payer as solana-message. The channel's nonce is the buyer's when given, else a random
u64; the open slot, recent blockhash and the mint's token program are the buyer's reads."""

import secrets
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal
from ..bindings.x402_upto_solana import ID
from ._common import bigint_of, inputs_of
from ._sol_rail import SOLANA_ADDRESS, signature64
from ._x402_rail import Rail, RailPiece
from .x402_exact_solana import with_unit_price

U64_LIMIT = 1 << 64


def random_u64() -> str:
    """A u64 from the platform's CSPRNG, in decimal."""
    return str(secrets.randbits(64))


def _inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    read = inputs_of(
        given,
        ID,
        {
            "nonce": "optional-decimal",
            "openSlot": "decimal",
            "tokenProgram": "string",
            "recentBlockhash": "string",
            "computeUnitLimit": "optional-uint",
            "computeUnitPrice": "optional-decimal",
        },
    )
    if isinstance(read, Refusal):
        return read
    nonce = read.get("nonce", random_u64())
    if int(nonce) >= U64_LIMIT or int(read["openSlot"]) >= U64_LIMIT:
        return Refusal("x402/input-missing")
    return {**read, "nonce": nonce}


def _revive(c: dict[str, Any]) -> dict[str, Any] | Refusal:
    nonce, open_slot = bigint_of(c.get("nonce")), bigint_of(c.get("openSlot"))
    if nonce is None or open_slot is None:
        return Refusal("x402/choice-malformed")
    return with_unit_price({**c, "nonce": nonce, "openSlot": open_slot})


PIECE = RailPiece(Rail(pairing=ID, namespace="solana", address=SOLANA_ADDRESS, payer="payer", now=True, inputs=_inputs, revive=_revive, answer=signature64))
