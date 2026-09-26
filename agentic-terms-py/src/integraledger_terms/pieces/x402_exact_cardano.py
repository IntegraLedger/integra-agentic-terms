"""The gate's buyer piece for x402/exact/cardano: the wallet builds the scheme's payment with a TTL, attaches the
request's auxiliaryData and its hash, signs without broadcasting, and answers {transaction, nonce}."""

import re

from ..bindings.x402_exact_cardano import ID
from ._x402_account_rails import WalletBuiltPiece

_BECH32_ADDRESS = re.compile(r"[a-z_]{1,83}1[02-9ac-hj-np-z]{6,}")

PIECE = WalletBuiltPiece(
    ID, ("cardano", "cip34"), lambda a: _BECH32_ADDRESS.fullmatch(a) is not None, ("transaction", "nonce")
)
