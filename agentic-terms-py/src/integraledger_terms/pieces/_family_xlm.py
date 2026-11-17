"""The buyer pieces of the XRPL, Algorand and Stacks pairings, keyed by pairing id."""

from .._types import Piece
from . import (
    mpp_charge_usdc_stacks,
    mpp_charge_xrpl,
    mpp_session_xrpl,
    mpp_session_xrpl_stock,
    x402_exact_algorand,
    x402_exact_xrpl,
    x402_upto_xrpl,
)

FAMILY: dict[str, Piece] = {
    x402_exact_xrpl.PIECE.pairing: x402_exact_xrpl.PIECE,
    x402_exact_algorand.PIECE.pairing: x402_exact_algorand.PIECE,
    mpp_charge_xrpl.PIECE.pairing: mpp_charge_xrpl.PIECE,
    mpp_charge_usdc_stacks.PIECE.pairing: mpp_charge_usdc_stacks.PIECE,
    mpp_session_xrpl.PIECE.pairing: mpp_session_xrpl.PIECE,
    mpp_session_xrpl_stock.PIECE.pairing: mpp_session_xrpl_stock.PIECE,
    x402_upto_xrpl.PIECE.pairing: x402_upto_xrpl.PIECE,
}
