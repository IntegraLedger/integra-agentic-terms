"""The buyer half of mpp/charge/stellar: the request's recipient placed as the seller's muxed address whose 8-byte id
is the ATR hash's first 8 bytes, which the payer signs as the Soroban transfer's to. The full hash rides in the
challenge. Nothing here fetches or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Refusal
from . import _stellar
from ._lcp import is_object, safe_int
from ._mpp import chosen_for, credential_of, echoed_for, expires_of, fetched_of, mpp_broadcaster, read
from ._mpp_checks import decode_object, is_fee_payer, is_stellar_recipient

ID = "mpp/charge/stellar"
_HASH = re.compile(r"[0-9a-fA-F]{64}")


def _presented_xdr(credential: Mapping[str, Any], payload: Mapping[str, Any]) -> str | Refusal:
    """The signed transfer a credential presents: its transaction for type "transaction", or for type "hash" the
    envelope read by that hash and held in Held, as @integraledger/lcp holds it under the payment's own FETCHED member
    (fetched_of), else stellar/read-first. A hash credential's own transaction member is not read."""
    kind = payload.get("type")
    if kind not in ("transaction", "hash"):
        return Refusal("mpp/credential-type")
    if kind == "hash":
        read = fetched_of(credential)
        landed = read.get("transaction") if is_object(read) else None
        return landed if isinstance(landed, str) else Refusal("stellar/read-first")
    xdr = payload.get("transaction")
    return xdr if isinstance(xdr, str) else Refusal("stellar/tx-malformed")


def _broadcaster_for(credential: Mapping[str, Any]) -> Broadcaster | Refusal:
    """Who broadcasts a Stellar charge credential, by its type: a transaction, which the seller's server submits, and,
    where the echoed request's feePayer is not true, a hash, which the payer broadcast. Under feePayer true MPP's
    Stellar charge forbids push mode, so a hash credential there is mpp/credential-type, as bound refuses it, and so is
    a credential of any other type."""
    kind = credential["payload"].get("type")
    if kind == "transaction":
        return "payee"
    if kind != "hash":
        return Refusal("mpp/credential-type")
    request = decode_object(credential["challenge"].get("request"))
    details = request.get("methodDetails") if request is not None else None
    return Refusal("mpp/credential-type") if is_object(details) and details.get("feePayer") is True else "payer"


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
        expires = expires_of(checked)
        if isinstance(expires, Refusal):
            return expires
        expiration = ledger + max(0, -(-(expires - now) // 5))
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
        recipient whose id is H's first 8 bytes, and the operation invokes exactly that. The challenge's network and
        its request's recipient, an account or its muxed form, are read as pairings_of reads them, else
        stellar/option-malformed. For a transaction credential, not yet submitted, the operation carries exactly one
        address-credential entry of the payer. For a hash credential, whose transaction landed, the entry is the
        payer's first address-credential entry whose root invocation is the operation's transfer, byte for byte; other
        entries of the payer are not read. Under a request with feePayer true, a hash credential is
        mpp/credential-type, fetched or not, whatever its entries: MPP's Stellar charge forbids push mode when the
        server sponsors the fee. A hash credential whose transaction carries no address entry of the payer, under a
        request with feePayer false or absent, binds H when the payer is the source account of the transaction
        and of its operation and an entry with source-account credentials is that transfer: the payer signed the whole
        transaction, to included. That transaction is the instrument, so the credential's hash must name it: 64 hex
        digits, else mpp/credential-malformed. There feePayer is read as pairings_of reads it: one that is present and
        not a boolean is stellar/option-malformed. For a transaction credential such a payment is
        stellar/no-address-auth. The authorization's signature is not verified here; the network verifies it when the
        entry is used."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        e = echoed_for(presented, ID)
        if isinstance(e, Refusal):
            return e
        network = e.checked.details.get("network")
        if network not in ("stellar:pubnet", "stellar:testnet"):
            return Refusal("stellar/option-malformed")
        if not is_stellar_recipient(e.checked.request.get("recipient")):
            return Refusal("stellar/option-malformed")
        if e.payload.get("type") == "hash" and e.checked.details.get("feePayer") is True:
            return Refusal("mpp/credential-type")
        xdr = _presented_xdr(presented, e.payload)
        if isinstance(xdr, Refusal):
            return xdr
        landed = e.payload.get("type") == "hash"
        signed = _stellar.read_signed_transfer(xdr, network, landed)
        read: tuple[_stellar.Payment | _stellar.SourcePayment, bool] | Refusal
        read = signed if isinstance(signed, Refusal) else (signed.payment, signed.agrees)
        if isinstance(read, Refusal) and read.code == "stellar/no-address-auth" and landed:
            if not is_fee_payer(e.checked.details):
                return Refusal("stellar/option-malformed")
            source = _stellar.read_source_transfer(xdr, network)
            if not isinstance(source, Refusal):
                hash_ = e.payload.get("hash")
                if not isinstance(hash_, str) or _HASH.fullmatch(hash_) is None:
                    return Refusal("mpp/credential-malformed")
                read = (source, True)
        if isinstance(read, Refusal):
            return read
        payment, agrees = read
        if payment.to_id is None:
            return Refusal("stellar/no-carrier")
        if payment.to != e.checked.request.get("recipient") or payment.to_id != _stellar.muxed_id(e.h):
            return Refusal("stellar/carrier-mismatch")
        if not agrees:
            return Refusal("stellar/not-one-transfer")
        return e.h

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """By the credential's type (_broadcaster_for): transaction, "payee", a signed transaction the seller's server
        submits; hash, where the request's feePayer is not true, "payer", a transaction the payer broadcast. A hash
        credential under feePayer true, and a credential of any other type, get mpp/credential-type, as bound refuses
        them."""
        return mpp_broadcaster(presented, _broadcaster_for)
