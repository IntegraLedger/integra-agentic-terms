"""The buyer pieces of the Hedera, NEAR, Tron and TON pairings, keyed by the pairing's id."""

from .._types import Piece
from . import (
    mpp_charge_hedera,
    mpp_session_hedera,
    x402_exact_hedera,
    x402_exact_hedera_transfer_executor,
    x402_exact_near,
    x402_exact_tron_lcp_trc20_memo,
    x402_exact_tvm,
)

FAMILY: dict[str, Piece] = {
    x402_exact_hedera.PIECE.pairing: x402_exact_hedera.PIECE,
    x402_exact_hedera_transfer_executor.PIECE.pairing: x402_exact_hedera_transfer_executor.PIECE,
    x402_exact_near.PIECE.pairing: x402_exact_near.PIECE,
    x402_exact_tron_lcp_trc20_memo.PIECE.pairing: x402_exact_tron_lcp_trc20_memo.PIECE,
    x402_exact_tvm.PIECE.pairing: x402_exact_tvm.PIECE,
    mpp_charge_hedera.PIECE.pairing: mpp_charge_hedera.PIECE,
    mpp_session_hedera.PIECE.pairing: mpp_session_hedera.PIECE,
}
