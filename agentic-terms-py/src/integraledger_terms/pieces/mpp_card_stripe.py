"""The buyer pieces for mpp/charge/card, mpp/charge/stripe and mpp/subscription/stripe: the first challenge, in
document order, that offers the pairing. Nothing in the card or Stripe payment carries the hash, and the binding builds
nothing for the buyer to sign: the proof of the hash is the agreement payment the offer's agreement URL asks for, whose
signed payload carries it."""

from ..bindings.mpp_card_stripe import CHARGE_CARD, CHARGE_STRIPE, SUBSCRIPTION_STRIPE
from ._mpp import MppConfirmOnlyPiece

CHARGE_CARD_PIECE = MppConfirmOnlyPiece(CHARGE_CARD)
CHARGE_STRIPE_PIECE = MppConfirmOnlyPiece(CHARGE_STRIPE)
SUBSCRIPTION_STRIPE_PIECE = MppConfirmOnlyPiece(SUBSCRIPTION_STRIPE)
