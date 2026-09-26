"""The gate's buyer pieces, one per pairing, keyed by the pairing's id."""

from collections.abc import Mapping

from .._types import Piece
from . import _family_evm, _family_hbar, _family_mpp, _family_proto, _family_rails, _family_sol, _family_xlm, x402_exact_eip155_eip3009

PIECES: Mapping[str, Piece] = {
    x402_exact_eip155_eip3009.PIECE.pairing: x402_exact_eip155_eip3009.PIECE,
    **_family_evm.FAMILY,
    **_family_hbar.FAMILY,
    **_family_mpp.FAMILY,
    **_family_proto.FAMILY,
    **_family_rails.FAMILY,
    **_family_sol.FAMILY,
    **_family_xlm.FAMILY,
}
