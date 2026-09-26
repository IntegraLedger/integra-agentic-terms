"""The buyer pieces of the account-rail x402 pairings, keyed by the pairing's id."""

from .._types import Piece
from . import x402_exact_starknet
from . import x402_exact_casper
from . import x402_exact_aptos
from . import x402_exact_polkadot_lcp_assets_remark
from . import x402_exact_ccd
from . import x402_exact_cardano
from . import x402_exact_sui

FAMILY: dict[str, Piece] = {
    x402_exact_starknet.PIECE.pairing: x402_exact_starknet.PIECE,
    x402_exact_casper.PIECE.pairing: x402_exact_casper.PIECE,
    x402_exact_aptos.PIECE.pairing: x402_exact_aptos.PIECE,
    x402_exact_polkadot_lcp_assets_remark.PIECE.pairing: x402_exact_polkadot_lcp_assets_remark.PIECE,
    x402_exact_ccd.PIECE.pairing: x402_exact_ccd.PIECE,
    x402_exact_cardano.PIECE.pairing: x402_exact_cardano.PIECE,
    x402_exact_sui.PIECE.pairing: x402_exact_sui.PIECE,
}
