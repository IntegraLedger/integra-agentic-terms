"""The buyer half of mpp/charge/card, mpp/charge/stripe and mpp/subscription/stripe: the ATR hash rides in the MPP
challenge the seller's server binds and in the method's reference field. Nothing the buyer's card or Stripe token
signs carries the hash, so build and bound refuse mpp/no-signed-place."""

from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Refusal
from ._mpp import credential_of, echoed_for, read

CHARGE_CARD = "mpp/charge/card"
CHARGE_STRIPE = "mpp/charge/stripe"
SUBSCRIPTION_STRIPE = "mpp/subscription/stripe"


def _bound(pairing: str, presented: Any) -> AtrHash | Refusal:
    """The echoed challenge is checked as this pairing's; nothing the buyer signed carries H."""
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    e = echoed_for(c, pairing)
    return e if isinstance(e, Refusal) else Refusal("mpp/no-signed-place")


@dataclass(frozen=True, slots=True)
class _ConfirmOnly:
    id: str
    public_proof: bool = False

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> Refusal:
        """Nothing the buyer signs has a place for H."""
        return Refusal("mpp/no-signed-place")

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _bound(self.id, presented)


def charge_card() -> _ConfirmOnly:
    return _ConfirmOnly(CHARGE_CARD)


def charge_stripe() -> _ConfirmOnly:
    return _ConfirmOnly(CHARGE_STRIPE)


def subscription_stripe() -> _ConfirmOnly:
    return _ConfirmOnly(SUBSCRIPTION_STRIPE)
