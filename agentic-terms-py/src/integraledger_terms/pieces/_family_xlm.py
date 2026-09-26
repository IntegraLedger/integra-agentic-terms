"""The buyer pieces of the XRPL, Algorand, Stellar and Stacks pairings, keyed by pairing id."""

from .._types import Piece
from . import mpp_charge_stellar, mpp_charge_usdc_stacks, mpp_charge_xrpl, mpp_session_xrpl, x402_exact_algorand, x402_exact_stellar, x402_exact_xrpl

FAMILY: dict[str, Piece] = {
    x402_exact_xrpl.PIECE.pairing: x402_exact_xrpl.PIECE,
    x402_exact_algorand.PIECE.pairing: x402_exact_algorand.PIECE,
    x402_exact_stellar.PIECE.pairing: x402_exact_stellar.PIECE,
    mpp_charge_xrpl.PIECE.pairing: mpp_charge_xrpl.PIECE,
    mpp_charge_stellar.PIECE.pairing: mpp_charge_stellar.PIECE,
    mpp_charge_usdc_stacks.PIECE.pairing: mpp_charge_usdc_stacks.PIECE,
    mpp_session_xrpl.PIECE.pairing: mpp_session_xrpl.PIECE,
}
