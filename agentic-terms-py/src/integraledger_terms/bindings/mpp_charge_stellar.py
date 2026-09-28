"""The buyer half of mpp/charge/stellar: the request's recipient placed as the seller's muxed address whose 8-byte id
is the ATR hash's first 8 bytes, which the payer signs as the Soroban transfer's to. The full hash rides in the
challenge. Nothing here fetches or signs."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Refusal
from . import _stellar
from ._lcp import is_object, safe_int
from ._mpp import chosen_for, credential_of, echoed_for, read

ID = "mpp/charge/stellar"


def _presented_xdr(payload: Mapping[str, Any]) -> str | Refusal:
    """The signed transfer a credential presents: its transaction, or for type "hash" none until one is fetched."""
    kind = payload.get("type")
    if kind not in ("transaction", "hash"):
        return Refusal("mpp/credential-type")
    if "transaction" not in payload:
        return Refusal("stellar/read-first" if kind == "hash" else "stellar/tx-malformed")
    xdr = payload["transaction"]
    return xdr if isinstance(xdr, str) else Refusal("stellar/tx-malformed")


@dataclass(frozen=True, slots=True)
class StellarChargeUnsigned:
    """The preimage the payer signs, and how the signature completes the credential."""

    request: dict[str, object]
    _unsigned: _stellar.StellarUnsigned
    _challenge: Mapping[str, Any]

    def complete(self, signature: object) -> dict[str, Any] | Refusal:
        xdr = self._unsigned.complete(signature)
        if isinstance(xdr, Refusal):
            return xdr
        return {"challenge": self._challenge, "payload": {"type": "transaction", "transaction": xdr}}


@dataclass(frozen=True, slots=True)
class MppChargeStellar:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> StellarChargeUnsigned | Refusal:
        """The authorization preimage from the buyer's simulated transaction, with the entry's expiration at
        currentLedger + ceil((expires - now) / 5). The request's recipient must carry muxed_id(h) and equal the to of
        the invocation the payer's entry signs, and the operation must invoke exactly that. That invocation's token
        contract must then be the request's currency, its amount the request's amount exactly, and its from the
        choice's payer. Nothing reaches the signer unless every one holds. With feePayer true the source is the
        all-zeros account."""
        if not is_object(choice):
            return Refusal("stellar/tx-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        recipient = checked.request.get("recipient")
        m = _stellar.unmux(recipient)
        if m is None or m.id != _stellar.muxed_id(h):
            return Refusal("stellar/carrier-mismatch")
        ledger, now = safe_int(choice.get("currentLedger")), safe_int(choice.get("now"))
        if ledger is None or ledger < 0 or now is None:
            return Refusal("stellar/tx-malformed")
        expiration = ledger + max(0, -(-(checked.expires - now) // 5))
        fee_payer = checked.details.get("feePayer") is True
        s = _stellar.signing_for(choice.get("simulatedXdr"), checked.details.get("network"), expiration, fee_payer)
        if isinstance(s, Refusal):
            return s
        if s.payment.to != recipient:
            return Refusal("stellar/carrier-mismatch")
        if not s.agrees:
            return Refusal("stellar/not-one-transfer")
        if s.payment.asset != checked.request.get("currency"):
            return Refusal("stellar/asset-mismatch")
        if s.payment.amount != int(checked.request["amount"]):
            return Refusal("stellar/amount-mismatch")
        if s.payment.source != choice.get("payer"):
            return Refusal("stellar/payer-mismatch")
        return StellarChargeUnsigned(request=s.unsigned.request, _unsigned=s.unsigned, _challenge=choice["challenge"])

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """H from the echoed challenge, once the to of the invocation the payer's entry signs is the request's muxed
        recipient whose id is H's first 8 bytes, and the operation invokes exactly that. The authorization's signature
        is not verified here."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        e = echoed_for(presented, ID)
        if isinstance(e, Refusal):
            return e
        xdr = _presented_xdr(e.payload)
        if isinstance(xdr, Refusal):
            return xdr
        signed = _stellar.read_signed_transfer(xdr, e.checked.details.get("network"))
        if isinstance(signed, Refusal):
            return signed
        payment = signed.payment
        if payment.to_id is None:
            return Refusal("stellar/no-carrier")
        if payment.to != e.checked.request.get("recipient") or payment.to_id != _stellar.muxed_id(e.h):
            return Refusal("stellar/carrier-mismatch")
        if not signed.agrees:
            return Refusal("stellar/not-one-transfer")
        return e.h
