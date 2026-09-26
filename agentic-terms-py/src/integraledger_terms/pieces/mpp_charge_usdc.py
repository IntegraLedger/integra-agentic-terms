"""The buyer pieces for mpp/charge/usdc/evm and mpp/charge/usdc/gateway. On EVM, the first challenge offering the
pairing on the signer's chain, with the token's EIP-712 name and version as the buyer's input. On Gateway, the first
challenge offering the pairing that accepts the account's network as a Gateway source: the request hands the buyer's
Gateway client the salt's preimage; the client adds its own values, computes usdc_gateway_salt and sets the result as
spec.salt before signing, then answers {source, sourceNetwork, destinationNetwork, maxFee, burnIntent, signature}."""

from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature, Step
from ..bindings.mpp_charge_usdc import EVM, GATEWAY
from ._base import BasePiece
from ._common import account_of
from ._mpp import MppChargePiece, built_request, challenges_of, pairings_of_placed, request_of

EVM_PIECE = MppChargePiece(EVM, {"tokenDomain": "object"})


def _accepted_sources(c: Mapping[str, Any]) -> list[Any]:
    """The Gateway source networks a challenge accepts."""
    md = (request_of(c) or {}).get("methodDetails")
    g = md.get("gateway") if isinstance(md, Mapping) else None
    sources = g.get("acceptedSources") if isinstance(g, Mapping) else None
    return sources if isinstance(sources, list) else []


class MppChargeUsdcGatewayPiece(BasePiece):
    pairing = GATEWAY

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        a = account_of(account)
        if a is None:
            return Refusal("mpp/no-payable-option")
        challenge = next(
            (c for c in challenges_of(read) if GATEWAY in pairings_of_placed(c) and a.network in _accepted_sources(c)),
            None,
        )
        if challenge is None:
            return Refusal("mpp/no-payable-option")
        return Chosen(pairing=GATEWAY, choice={"challenge": challenge, "from": a.address, "now": now}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = chosen.choice if isinstance(chosen, Chosen) and isinstance(chosen.choice, dict) else None
        return Refusal("mpp/choice-malformed") if c is None or not isinstance(c.get("challenge"), Mapping) else c

    def request(self, unsigned: Any) -> dict[str, Any] | Refusal:
        return built_request(unsigned)

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        if not isinstance(signature, Mapping):
            return Refusal("mpp/credential-malformed")
        out: dict[str, Any] | Refusal = unsigned.complete(signature)
        return out


GATEWAY_PIECE = MppChargeUsdcGatewayPiece()
