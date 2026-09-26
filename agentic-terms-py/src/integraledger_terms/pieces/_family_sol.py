"""The Solana family's buyer pieces, keyed by the pairing's id."""

from .._types import Piece
from . import mpp_charge_solana, mpp_session_solana, x402_batch_settlement_solana, x402_exact_solana, x402_upto_solana

FAMILY: dict[str, Piece] = {
    x402_exact_solana.PIECE.pairing: x402_exact_solana.PIECE,
    x402_upto_solana.PIECE.pairing: x402_upto_solana.PIECE,
    x402_batch_settlement_solana.PIECE.pairing: x402_batch_settlement_solana.PIECE,
    mpp_charge_solana.SOLANA_PIECE.pairing: mpp_charge_solana.SOLANA_PIECE,
    mpp_charge_solana.USDC_SOLANA_PIECE.pairing: mpp_charge_solana.USDC_SOLANA_PIECE,
    mpp_session_solana.PIECE.pairing: mpp_session_solana.PIECE,
}
