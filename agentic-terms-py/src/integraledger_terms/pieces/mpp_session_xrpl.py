"""The buyer piece for mpp/session/xrpl: the PaymentChannelCreate and the first claim handed to the wallet as the
build's xrpl-session-open request, exactly as built. The wallet answers {signedBlob, claimSignature} as 0x hex, which
completes the build's own credential. The deposit and the channel's terms are the buyer's."""

from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal, Signature
from ..bindings.mpp_session_xrpl import ID
from ._common import inputs_of
from ._mpp import MppRail, MppRailPiece, complete_with, hex_digits, session_revive
from .mpp_charge_xrpl import XRPL_ADDRESS


def _inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    read = inputs_of(given, ID, {"deposit": "decimal", "xrpl": "object"})
    if isinstance(read, Refusal):
        return read
    x = inputs_of(
        read["xrpl"],
        ID,
        {
            "publicKey": "hex",
            "settleDelay": "uint",
            "fee": "decimal",
            "sequence": "uint",
            "lastLedgerSequence": "uint",
            "cancelAfter": "optional-uint",
        },
    )
    if isinstance(x, Refusal):
        return x
    public_key = hex_digits(x["publicKey"])
    if public_key is None:
        return Refusal("mpp/input-missing")
    return {**read, "xrpl": {**x, "publicKey": public_key}}


def _answer(signature: Signature) -> dict[str, str] | Refusal:
    """{signedBlob, claimSignature} as the build's hex digits, from 0x hex."""
    if not isinstance(signature, Mapping):
        return Refusal("mpp/credential-malformed")
    blob, claim = hex_digits(signature.get("signedBlob")), hex_digits(signature.get("claimSignature"))
    if blob is None or claim is None:
        return Refusal("mpp/credential-malformed")
    return {"signedBlob": blob, "claimSignature": claim}


PIECE = MppRailPiece(
    MppRail(
        pairing=ID,
        namespace="xrpl",
        address=XRPL_ADDRESS,
        payer="from",
        now=True,
        inputs=_inputs,
        revive=session_revive,
        complete=complete_with(_answer),
    )
)
