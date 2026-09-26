"""The buyer pieces of the protocol-group and Lightning pairings, keyed by the pairing's id."""

from .._types import Piece
from . import acp_checkout, ack_payment_request, ap2_checkout_mandate, card, lightning, ucp

FAMILY: dict[str, Piece] = {
    acp_checkout.DELEGATED_PIECE.pairing: acp_checkout.DELEGATED_PIECE,
    acp_checkout.UNDELEGATED_PIECE.pairing: acp_checkout.UNDELEGATED_PIECE,
    ack_payment_request.PIECE.pairing: ack_payment_request.PIECE,
    ap2_checkout_mandate.PIECE.pairing: ap2_checkout_mandate.PIECE,
    card.VISA_TAP_PIECE.pairing: card.VISA_TAP_PIECE,
    card.VI_IMMEDIATE_PIECE.pairing: card.VI_IMMEDIATE_PIECE,
    card.VI_AUTONOMOUS_PIECE.pairing: card.VI_AUTONOMOUS_PIECE,
    card.SELLER_REFERENCE_PIECE.pairing: card.SELLER_REFERENCE_PIECE,
    lightning.LNBTC_PIECE.pairing: lightning.LNBTC_PIECE,
    lightning.NAMED_PIECE.pairing: lightning.NAMED_PIECE,
    lightning.MPP_CHARGE_PIECE.pairing: lightning.MPP_CHARGE_PIECE,
    lightning.MPP_SESSION_PIECE.pairing: lightning.MPP_SESSION_PIECE,
    ucp.CHECKOUT_AP2_MANDATE_PIECE.pairing: ucp.CHECKOUT_AP2_MANDATE_PIECE,
    ucp.CHECKOUT_UNSIGNED_PIECE.pairing: ucp.CHECKOUT_UNSIGNED_PIECE,
    ucp.BOOKING_AP2_MANDATE_PIECE.pairing: ucp.BOOKING_AP2_MANDATE_PIECE,
    ucp.BOOKING_UNSIGNED_PIECE.pairing: ucp.BOOKING_UNSIGNED_PIECE,
}
