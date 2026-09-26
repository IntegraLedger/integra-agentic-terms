"""The buyer piece for mpp/session/solana: the opening's values handed to the signer as the build's
solana-session-open request, exactly as built. The buyer's channel client composes and signs the open from them and
answers the open payload, which completes the build's own credential. When the challenge's voucherSigner is operator,
the payer then signs the session proof over the channel, the payer and the challenge id as ed25519-raw, answered in
base58, and the open payload carries it as authentication."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Chosen, Inputs, Refusal, Signature, Step
from ..bindings.mpp_session_solana import ID, session_proof
from ._common import choice_of, inputs_of
from ._mpp import MppRail, MppRailPiece, complete_with, request_of, session_revive
from ._sol_rail import SOLANA_ADDRESS

# Base58 of a 64-byte Ed25519 signature.
SIGNATURE_BASE58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]{64,88}")

_complete_open = complete_with(lambda s: s if isinstance(s, Mapping) else Refusal("mpp/credential-malformed"))


def _operator_mode(chosen: Chosen) -> tuple[Mapping[str, Any], str] | None | Refusal:
    """The challenge and payer of the choice, when its challenge asks for the operator mode's session proof."""
    c = choice_of(chosen)
    challenge = c.get("challenge") if c is not None else None
    if not isinstance(challenge, Mapping):
        return Refusal("mpp/choice-malformed")
    request = request_of(challenge)
    details = request.get("methodDetails") if request is not None else None
    if not isinstance(details, Mapping) or details.get("voucherSigner") != "operator":
        return None
    payer = c.get("from") if c is not None else None
    if not isinstance(challenge.get("id"), str) or not isinstance(payer, str):
        return Refusal("mpp/choice-malformed")
    return challenge, payer


def _complete(unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
    """The open payload alone completes the credential, unless the challenge asks for the operator mode's session
    proof: then the open payload asks for the proof's signature next, and [open, proofSignature] completes the
    credential with authentication = {type: "proof", challengeId, payer, signature}."""
    mode = _operator_mode(chosen)
    if mode is None:
        return _complete_open(unsigned, signature, chosen)
    if isinstance(mode, Refusal):
        return mode
    challenge, payer = mode
    if isinstance(signature, Mapping):
        channel_id = signature.get("channelId")
        if not isinstance(channel_id, str) or SOLANA_ADDRESS.fullmatch(channel_id) is None:
            return Refusal("mpp/credential-malformed")
        message = session_proof(channel_id, payer, challenge["id"])
        return Step(next={"kind": "ed25519-raw", "message": message, "signer": payer})
    if not isinstance(signature, list) or len(signature) != 2:
        return Refusal("mpp/credential-malformed")
    opened, proof = signature
    if not isinstance(opened, Mapping) or not isinstance(proof, str) or SIGNATURE_BASE58.fullmatch(proof) is None:
        return Refusal("mpp/credential-malformed")
    authentication = {"type": "proof", "challengeId": challenge["id"], "payer": payer, "signature": proof}
    return _complete_open(unsigned, {**opened, "authentication": authentication}, chosen)


def _inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    return inputs_of(given, ID, {"deposit": "optional-decimal"})


PIECE = MppRailPiece(
    MppRail(
        pairing=ID,
        namespace="solana",
        address=SOLANA_ADDRESS,
        payer="from",
        now=True,
        inputs=_inputs,
        revive=session_revive,
        complete=_complete,
    )
)
