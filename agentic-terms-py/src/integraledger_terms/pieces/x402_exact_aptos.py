"""The gate's buyer piece for x402/exact/aptos: the wallet builds and signs the scheme's own payment for the request's
option and answers {transaction}."""

import re

from ..bindings.x402_exact_aptos import ID
from ._x402_account_rails import WalletBuiltPiece

_APTOS_ADDRESS = re.compile(r"0x[0-9a-fA-F]{1,64}")

PIECE = WalletBuiltPiece(ID, ("aptos",), lambda a: _APTOS_ADDRESS.fullmatch(a) is not None, ("transaction",))
