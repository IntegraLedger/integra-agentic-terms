"""The gate's buyer piece for x402/exact/sui: the wallet builds the scheme's payment, adds the request's pureInput as
the one unused Pure input, bounds the expiration by epoch, signs, and answers {signature, transaction}."""

import re

from ..bindings.x402_exact_sui import ID
from ._x402_account_rails import WalletBuiltPiece

_SUI_ADDRESS = re.compile(r"0x[0-9a-fA-F]{64}")

PIECE = WalletBuiltPiece(ID, ("sui",), lambda a: _SUI_ADDRESS.fullmatch(a) is not None, ("signature", "transaction"))
