"""The gate's buyer piece for x402/exact/cardano/lock, x402's two Cardano lock methods ("masumi" or "script"): a
deposit into an escrow or a contract the seller defines, which is a charge and never an agreement. The wallet builds
the scheme's lock for the request's option with a TTL, which a lock must carry, attaches the request's auxiliaryData
and its hash, signs without broadcasting, and answers {transaction, nonce}."""

import re

from ..bindings.x402_exact_cardano import LOCK_ID
from ._x402_account_rails import WalletBuiltPiece

_BECH32_ADDRESS = re.compile(r"[a-z_]{1,83}1[02-9ac-hj-np-z]{6,}")

PIECE = WalletBuiltPiece(
    LOCK_ID, ("cardano", "cip34"), lambda a: _BECH32_ADDRESS.fullmatch(a) is not None, ("transaction", "nonce")
)
