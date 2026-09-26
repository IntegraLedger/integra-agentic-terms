"""The buyer piece for mpp/charge/usdc/stacks: the SIP-010 transfer whose memo argument is (some H), handed to the
buyer's Stacks wallet as stacks-contract-call; the wallet answers the signed transaction's consensus bytes as 0x
hex."""

import re

from .._types import Refusal, Signature
from ..bindings.mpp_charge_usdc_stacks import ID
from ._common import bytes_of
from ._mpp import MppRail, MppRailPiece, complete_with


def _transaction_bytes(signature: Signature) -> bytes | Refusal:
    out = bytes_of(signature)
    return Refusal("mpp/credential-malformed") if out is None else out


PIECE = MppRailPiece(
    MppRail(
        pairing=ID,
        namespace="stacks",
        address=re.compile(r"S[0-9A-HJKMNP-TV-Z]{38,40}"),
        payer="from",
        now=False,
        inputs=lambda request, given: {},
        revive=lambda c: c,
        complete=complete_with(_transaction_bytes),
    )
)
