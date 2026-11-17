"""The buyer pieces for MPP's session intent under the stock solana method.

mpp/session/solana/memo: the first challenge, in document order, that offers the pairing on the account's network. The
protocol package's build composes the stock open of a payment channel, its fee payer and rent payer the challenge's
operator, with one Memo instruction carrying H's LCP string, and hands the payer its message as the
solana-session-open request, exactly as built; the payer signs the message once, and its 64-byte Ed25519 signature,
as 0x hex, completes the build's own open credential, which the seller's server co-signs and submits. The channel's
salt is the buyer's when given, else a random u64, as the stock client draws one; the session key that signs vouchers
(authorizedSigner) is the buyer's when given, else the payer's own key. The deposit (the request's cap where absent),
the grace period, and the open slot, blockhash, mint and token program the request leaves out are the buyer's.

mpp/session/solana/stock, at coverage none: the first challenge, in document order, that offers the pairing. The
buyer's stock client composes, signs and broadcasts the open itself, so nothing is handed to the signer: the proof of
the hash is the agreement payment, on the session's own network, paid before the stock client opens the channel, from
the account that opens it, the open's payer. The challenge stays in the choice, so the agreement is paid on its
network."""

import secrets
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal
from ..bindings.mpp_session_solana import MEMO_ID, STOCK_ID
from ._common import bigint_of, inputs_of
from ._mpp import MppConfirmOnlyPiece, MppRail, MppRailPiece, complete_with, signature64
from ._sol_rail import SOLANA_ADDRESS

_U64_LIMIT = 1 << 64


def _inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    read = inputs_of(
        given,
        MEMO_ID,
        {
            "salt": "optional-decimal",
            "authorizedSigner": "optional-string",
            "deposit": "optional-decimal",
            "gracePeriod": "optional-uint",
            "openSlot": "optional-decimal",
            "recentBlockhash": "optional-string",
            "mint": "optional-string",
            "tokenProgram": "optional-string",
        },
    )
    if isinstance(read, Refusal):
        return read
    salt = read.get("salt", str(secrets.randbits(64)))
    signer = read.get("authorizedSigner")
    salt_value = bigint_of(salt)
    if salt_value is None or salt_value >= _U64_LIMIT or (signer is not None and SOLANA_ADDRESS.fullmatch(signer) is None):
        return Refusal("mpp/input-missing")
    return {**read, "salt": salt}


def _revive(c: dict[str, Any]) -> dict[str, Any] | Refusal:
    """The choice as the build takes it: the salt, deposit and open slot as ints, the voucher key the payer's by
    default."""
    out = dict(c)
    for key in ("salt", "deposit", "openSlot"):
        if key not in c and key != "salt":
            continue
        value = bigint_of(c.get(key))
        if value is None:
            return Refusal("mpp/choice-malformed")
        out[key] = value
    out["authorizedSigner"] = c.get("authorizedSigner", c.get("payer"))
    return out


MEMO_PIECE = MppRailPiece(
    MppRail(
        pairing=MEMO_ID,
        namespace="solana",
        address=SOLANA_ADDRESS,
        payer="payer",
        now=False,
        inputs=_inputs,
        revive=_revive,
        complete=complete_with(signature64),
    )
)

STOCK_PIECE = MppConfirmOnlyPiece(STOCK_ID)
