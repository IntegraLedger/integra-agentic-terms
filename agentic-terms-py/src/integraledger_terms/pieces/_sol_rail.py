"""What the Solana buyer pieces share: the form of a Solana address, and the signer's 64-byte signature."""

import re
from .._types import Refusal, Signature
from ._common import bytes_of

# A Solana address: base58 of 32 bytes.
SOLANA_ADDRESS = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")


def signature64(signature: Signature) -> bytes | Refusal:
    """A 64-byte signature given as 0x hex, as bytes."""
    out = bytes_of(signature, 64)
    return out if out is not None else Refusal("x402/signature-malformed")
