"""The gate's buyer piece for x402/batch-settlement/cloudflare: the first option on cloudflare:402 for the account's
agent. The build is itself the payment, echoing the challenge's extensions; the agent's HTTP message signature stack
signs the request that carries it, so the gate calls no signer."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_batch_settlement_cloudflare import ID, NETWORK
from ._base import BasePiece
from ._common import choice_of, with_payment_identifier, x402_offer_of

# cloudflare:402: and a CAIP-10 account reference naming the agent.
_ACCOUNT = re.compile(r"cloudflare:402:[-.%a-zA-Z0-9]{1,128}")


class X402BatchSettlementCloudflarePiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        offer = x402_offer_of(read)
        if not isinstance(account, str) or _ACCOUNT.fullmatch(account) is None or offer is None:
            return Refusal("x402/no-payable-option")
        required, options = offer
        for option in options:
            if isinstance(option, Mapping) and option.get("network") == NETWORK:
                return Chosen(pairing=self.pairing, choice={"required": required, "accepted": option}, ref=ref)
        return Refusal("x402/no-payable-option")

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        found = choice_of(chosen)
        return found if found is not None else Refusal("x402/choice-malformed")

    def request(self, unsigned: Any) -> None:
        return None

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        return with_payment_identifier(unsigned, chosen.choice.get("required"), chosen.ref)


PIECE = X402BatchSettlementCloudflarePiece()
