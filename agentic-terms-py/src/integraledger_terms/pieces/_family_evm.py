"""The EVM family's buyer pieces, keyed by pairing id."""

from .._types import Piece
from ..bindings.x402_evm import (
    AUTH_CAPTURE_EIP3009,
    AUTH_CAPTURE_PERMIT2,
    EXACT_ERC7710,
    EXACT_ERC7710_SALT,
    EXACT_PERMIT2,
    UPTO_PERMIT2,
)
from . import x402_batch_settlement_cloudflare, x402_batch_settlement_eip155
from .evm_x402 import EvmX402Piece

FAMILY: dict[str, Piece] = {
    **{
        pairing: EvmX402Piece(pairing)
        for pairing in (
            EXACT_PERMIT2,
            UPTO_PERMIT2,
            EXACT_ERC7710,
            EXACT_ERC7710_SALT,
            AUTH_CAPTURE_EIP3009,
            AUTH_CAPTURE_PERMIT2,
        )
    },
    x402_batch_settlement_eip155.PIECE.pairing: x402_batch_settlement_eip155.PIECE,
    x402_batch_settlement_cloudflare.PIECE.pairing: x402_batch_settlement_cloudflare.PIECE,
}
