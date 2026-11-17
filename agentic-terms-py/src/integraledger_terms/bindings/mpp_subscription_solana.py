"""The buyer half of the pairing mpp/subscription/solana: read and bound. MPP's subscription intent under the stock
solana method (@solana/mpp 0.7.0, src/Methods.ts:129-201). The sale is the activation, the transaction that subscribes
the payer to the plan and collects the first period. The stock client writes the request's externalId, H's LCP string,
as the activation's Memo instruction (src/client/Subscription.ts:240-242) and the stock server never reads it, so bound
checks it. The protocol package builds nothing for this pairing: the buyer's stock client composes and signs the
activation. Nothing here fetches, hashes an ATR or signs.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._mpp import by_type, credential_of, echoed_for, mpp_broadcaster, read
from ._svm import SvmTx, decode_svm_tx, static_nonce, wire_of
from .mpp_charge_solana import mpp_svm_carrier

ID = "mpp/subscription/solana"
# The activation's transfer_subscription takes the challenge's puller, the seller's key, as a signer
# (src/client/Subscription.ts:230), so the seller's server co-signs and submits it.
_TYPES: Mapping[str, Broadcaster] = {"transaction": "payee"}


def _activation(payload: Mapping[str, Any]) -> SvmTx | Refusal:
    """The activation a type=transaction credential presents; any other type is mpp/credential-type."""
    if payload.get("type") != "transaction":
        return Refusal("mpp/credential-type")
    wire = wire_of(payload.get("transaction"))
    return wire if isinstance(wire, Refusal) else decode_svm_tx(wire)


@dataclass(frozen=True, slots=True)
class MppSubscriptionSolana:
    """mpp/subscription/solana: never an agreement option."""

    id: str = ID
    agreement: AgreementData | None = None
    coverage: Coverage = "full"

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> Refusal:
        """Nothing: the buyer's stock client composes and signs the activation."""
        return Refusal("mpp/nothing-to-sign")

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H from the echoed challenge, once the activation's one LCP memo, spelled exactly as H's LCP string, equals
        the request's externalId and names that H. None is svm/no-carrier, more than one svm/memo-count. No signature
        is verified here."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        e = echoed_for(credential, self.id)
        if isinstance(e, Refusal):
            return e
        tx = _activation(e.payload)
        if isinstance(tx, Refusal):
            return tx
        from_table = static_nonce(tx)
        if from_table is not None:
            return from_table
        carrier = mpp_svm_carrier(tx)
        if isinstance(carrier, Refusal):
            return carrier
        if carrier.memo != e.checked.request.get("externalId"):
            return Refusal("svm/carrier-mismatch")
        if not hash_equals(carrier.h, e.h):
            return Refusal("mpp/carrier-not-challenge")
        return e.h

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """"payee" for the activation: its transfer_subscription needs the signature of the challenge's puller, the
        seller's key, which the payer's client does not hold. A credential of any other type gets mpp/credential-type,
        as bound refuses it."""
        return mpp_broadcaster(presented, by_type(_TYPES))
