"""The gate's buyer piece for x402/exact/sui: the wallet builds the scheme's payment, adds the request's pureInput as
the one unused Pure input, bounds the expiration by epoch as the request asks, signs, and answers {signature,
transaction}, with sent, the transaction it sent to the option's gas station, on the sponsored path (extra.gasStation).
The epoch bound is this piece's choice, not a condition of the record: a signed transaction without one that carries
the hash completes, and is recorded."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Chosen, Refusal, Signature
from ..bindings.x402_exact_sui import ID
from ._x402_account_rails import WalletBuiltPiece, identified

_SUI_ADDRESS = re.compile(r"0x[0-9a-fA-F]{64}")


class SuiPiece(WalletBuiltPiece):
    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        """The wallet's signature and transaction completed as every wallet-built payment is; where the answer holds
        sent, the build's complete holds the signed transaction to it in everything but the gas data."""
        sent = signature.get("sent") if isinstance(signature, Mapping) else None
        if sent is None:
            return super().complete(unsigned, signature, chosen)
        if not isinstance(sent, str) or not isinstance(signature.get("signature"), str) or not isinstance(signature.get("transaction"), str):
            return Refusal("x402/signature-malformed")
        signed = {"signature": signature["signature"], "transaction": signature["transaction"]}
        return identified(unsigned.complete(signed, sent), chosen)


PIECE = SuiPiece(ID, ("sui",), lambda a: _SUI_ADDRESS.fullmatch(a) is not None, ("signature", "transaction"))
