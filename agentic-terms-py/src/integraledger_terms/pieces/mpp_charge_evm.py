"""The buyer pieces for MPP's EVM charges: the first challenge offering the pairing on the signer's chain. The
authorization's token EIP-712 name and version, and the Permit2 spender, are the buyer's inputs; the transaction's
answer is the signed EIP-1559 transaction of the call, and the hash's the hash of the call the signer broadcast."""

from ..bindings.mpp_charge_evm import AUTHORIZATION, HASH, PERMIT2_ID, TRANSACTION
from ._mpp import MppChargePiece

AUTHORIZATION_PIECE = MppChargePiece(AUTHORIZATION, {"tokenDomain": "object"})
PERMIT2_PIECE = MppChargePiece(PERMIT2_ID, {"spender": "string"})
TRANSACTION_PIECE = MppChargePiece(TRANSACTION, {})
HASH_PIECE = MppChargePiece(HASH, {})
