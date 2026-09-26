"""The buyer pieces for mpp/charge/card, mpp/charge/stripe and mpp/subscription/stripe: the first challenge, in
document order, that offers the pairing. Nothing the buyer's card or Stripe token signs carries the hash, so the gate's
comparison is the whole of the buyer's step."""

from ..bindings.mpp_card_stripe import CHARGE_CARD, CHARGE_STRIPE, SUBSCRIPTION_STRIPE
from ._mpp import MppConfirmOnlyPiece

CHARGE_CARD_PIECE = MppConfirmOnlyPiece(CHARGE_CARD)
CHARGE_STRIPE_PIECE = MppConfirmOnlyPiece(CHARGE_STRIPE)
SUBSCRIPTION_STRIPE_PIECE = MppConfirmOnlyPiece(SUBSCRIPTION_STRIPE)
