"""The buyer pieces for mpp/charge/solana and mpp/charge/usdc/solana: the v0 message whose one LCP memo is the
request's externalId, signed by the payer as solana-message; the credential is the build's own. The request's
decimals, tokenProgram and recentBlockhash are taken first (from methodDetails, or methodDetails.solana for usdc), and
the buyer's reads fill what the request leaves out."""

from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal
from ..bindings.mpp_charge_solana import SOLANA_ID, USDC_SOLANA_ID
from ._common import InputKind, inputs_of
from ._mpp import MppRail, MppRailPiece, complete_with, signature64
from ._sol_rail import SOLANA_ADDRESS
from .x402_exact_solana import with_unit_price


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _spec(d: Mapping[str, Any], native: bool) -> dict[str, InputKind]:
    spec: dict[str, InputKind] = {}
    if not native and not _is_number(d.get("decimals")):
        spec["decimals"] = "uint"
    if not native and not isinstance(d.get("tokenProgram"), str):
        spec["tokenProgram"] = "string"
    if not isinstance(d.get("recentBlockhash"), str):
        spec["recentBlockhash"] = "string"
    spec["computeUnitLimit"] = "optional-uint"
    spec["computeUnitPrice"] = "optional-decimal"
    return spec


def _solana_inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    md = request.get("methodDetails")
    d = md if isinstance(md, Mapping) else {}
    return inputs_of(given, SOLANA_ID, _spec(d, request.get("currency") == "sol"))


def _usdc_inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    md = request.get("methodDetails")
    md = md if isinstance(md, Mapping) else {}
    d = md.get("solana")
    return inputs_of(given, USDC_SOLANA_ID, _spec(d if isinstance(d, Mapping) else {}, False))


def _rail(pairing: str, inputs: Any) -> MppRailPiece:
    return MppRailPiece(
        MppRail(
            pairing=pairing,
            namespace="solana",
            address=SOLANA_ADDRESS,
            payer="payer",
            now=False,
            inputs=inputs,
            revive=with_unit_price,
            complete=complete_with(signature64),
        )
    )


SOLANA_PIECE = _rail(SOLANA_ID, _solana_inputs)
USDC_SOLANA_PIECE = _rail(USDC_SOLANA_ID, _usdc_inputs)
