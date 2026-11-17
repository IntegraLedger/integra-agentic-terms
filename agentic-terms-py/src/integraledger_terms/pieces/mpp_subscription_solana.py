"""The buyer piece for mpp/subscription/solana: the first challenge, in document order, that offers the pairing. The
buyer's stock @solana/mpp client composes and signs the activation, writing the request's externalId, H's LCP string, as
its Memo instruction; the activation's transfer_subscription also takes the challenge's puller, the seller's key, as a
signer, so the seller's server co-signs and submits it. The binding builds nothing and nothing is handed to the signer:
the gate compares the ATR, and check reads H from the activation the buyer's client signed."""

from ..bindings.mpp_subscription_solana import ID
from ._mpp import MppConfirmOnlyPiece

PIECE = MppConfirmOnlyPiece(ID)
