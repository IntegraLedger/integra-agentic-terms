"""The buyer pieces of MPP's pairings, keyed by the pairing's id."""

from .._types import Piece
from . import mpp_card_stripe, mpp_charge_evm, mpp_charge_nearintents, mpp_charge_tempo, mpp_charge_usdc, mpp_session

FAMILY: dict[str, Piece] = {
    p.pairing: p
    for p in (
        mpp_charge_evm.AUTHORIZATION_PIECE,
        mpp_charge_evm.PERMIT2_PIECE,
        mpp_charge_evm.TRANSACTION_PIECE,
        mpp_charge_evm.HASH_PIECE,
        mpp_card_stripe.CHARGE_CARD_PIECE,
        mpp_card_stripe.CHARGE_STRIPE_PIECE,
        mpp_card_stripe.SUBSCRIPTION_STRIPE_PIECE,
        mpp_charge_nearintents.PIECE,
        mpp_charge_tempo.MEMO_PIECE,
        mpp_charge_tempo.PUSH_PIECE,
        mpp_charge_usdc.EVM_PIECE,
        mpp_charge_usdc.GATEWAY_PIECE,
        mpp_session.SESSION_EVM_PIECE,
        mpp_session.SESSION_TEMPO_PIECE,
        mpp_session.SUBSCRIPTION_PIECE,
    )
}
