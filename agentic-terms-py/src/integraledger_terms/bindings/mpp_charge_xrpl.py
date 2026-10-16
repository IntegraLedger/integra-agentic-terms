"""The buyer half of mpp/charge/xrpl: the ATR hash itself, as 64 upper-case hex digits, placed as the request's
methodDetails.invoiceId, which the payer signs as the Payment's InvoiceID. Nothing here fetches or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Broadcaster, Refusal
from ._lcp import is_object
from ._mpp import by_type, chosen_for, credential_of, echoed_for, fetched_of, measured, mpp_broadcaster, read
from ._mpp_checks import is_xrpl_invoice_id, xrpl_network_of
from ._xrpl import decode_presented, is_blob_hex, mpp_invoice_id, network_id_held, same_invoice

ID = "mpp/charge/xrpl"

_DROPS = re.compile(r"0|[1-9][0-9]{0,18}")
_ABSENT = object()


def _u32(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return 0 <= value <= 0xFFFFFFFF


def _presented_blob(credential: Mapping[str, Any], payload: Mapping[str, Any]) -> str | Refusal:
    """The signed blob a credential presents: its blob for type "transaction", or for type "hash" the blob read by
    that hash and held in Held, as @integraledger/lcp holds it under the payment's own FETCHED member (fetched_of),
    else xrpl/read-first. A hash credential's own blob member is not read."""
    kind = payload.get("type")
    if kind not in ("transaction", "hash"):
        return Refusal("mpp/credential-type")
    if kind == "hash":
        read = fetched_of(credential)
        landed = read.get("blob") if is_object(read) else None
        return landed if isinstance(landed, str) else Refusal("xrpl/read-first")
    blob = payload.get("blob")
    return blob if isinstance(blob, str) else Refusal("xrpl/blob-malformed")


@dataclass(frozen=True, slots=True)
class XrplChargeUnsigned:
    """The Payment for the wallet to sign, and how its signed blob completes the credential."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]
    _network: str

    def complete(self, signed_blob: object) -> dict[str, Any] | Refusal:
        """The credential of the wallet's signed blob, hex, read in bound's order: the credential measured first
        (measured), then the blob as bound reads it: a blob that does not decode, or is multi-signed, gets the refusal
        bound gives it, and one whose NetworkID the challenge's network does not take (network_id_held) is
        xrpl/network-mismatch."""
        credential = measured({"challenge": self._challenge, "payload": {"type": "transaction", "blob": signed_blob}})
        if isinstance(credential, Refusal):
            return credential
        if not is_blob_hex(signed_blob):
            return Refusal("xrpl/blob-malformed")
        assert isinstance(signed_blob, str)
        decoded = decode_presented(signed_blob)
        if isinstance(decoded, Refusal):
            return decoded
        if not network_id_held(decoded.tx, self._network):
            return Refusal("xrpl/network-mismatch")
        return credential


@dataclass(frozen=True, slots=True)
class MppChargeXrpl:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> XrplChargeUnsigned | Refusal:
        """The Payment: Destination the request's recipient, Amount from its currency (drops, an issued amount with
        SendMax equal to it, or an MPT amount), InvoiceID the request's invoiceId, which must be this H, and the
        request's tags, with no NetworkID: each network the challenge can name has an id of at most 1024. The pairing's
        filter refuses a request with memos (xrpl/memos-not-carried)."""
        if not is_object(choice):
            return Refusal("mpp/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        r, d = checked.request, checked.details
        if not same_invoice(d.get("invoiceId"), mpp_invoice_id(h)):
            return Refusal("xrpl/carrier-mismatch")
        network = xrpl_network_of(d)
        if isinstance(network, Refusal):
            return network
        account, fee = choice.get("account"), choice.get("fee")
        sequence, last = choice.get("sequence"), choice.get("lastLedgerSequence")
        if not isinstance(account, str) or not isinstance(fee, str) or _DROPS.fullmatch(fee) is None:
            return Refusal("mpp/input-malformed")
        if not _u32(sequence) or not _u32(last):
            return Refusal("mpp/input-malformed")
        currency, value = r.get("currency"), r.get("amount")
        send_max = False
        amount: Any
        if currency == "XRP":
            amount = value
        elif is_object(currency) and isinstance(currency.get("mpt_issuance_id"), str):
            amount = {"mpt_issuance_id": currency["mpt_issuance_id"], "value": value}
        else:
            c: Mapping[str, Any] = currency if is_object(currency) else {}
            amount = {"currency": c.get("currency"), "issuer": c.get("issuer"), "value": value}
            send_max = True
        tx: dict[str, Any] = {
            "TransactionType": "Payment",
            "Flags": 0,
            "Account": account,
            "Destination": r.get("recipient"),
            "Amount": amount,
        }
        if send_max:
            tx["SendMax"] = amount
        if "destinationTag" in d:
            tx["DestinationTag"] = d["destinationTag"]
        if "sourceTag" in d:
            tx["SourceTag"] = d["sourceTag"]
        tx["InvoiceID"] = mpp_invoice_id(h)
        tx["Fee"] = fee
        tx["Sequence"] = sequence
        tx["LastLedgerSequence"] = last
        return XrplChargeUnsigned(
            request={"kind": "xrpl-tx", "txJson": tx}, _challenge=dict(checked.challenge), _network=network
        )

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """H from the echoed challenge, once the signed Payment's InvoiceID is the request's invoiceId and equals
        that H. The invoiceId is read as pairings_of reads it: absent, or 64 hex digits, else mpp/request-malformed.
        A multi-signed blob is xrpl/multisigned: the payer signs with a single key. The blob's NetworkID is read first,
        as rippled reads it (network_id_held), else xrpl/network-mismatch. The signature is not verified here."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        e = echoed_for(presented, ID)
        if isinstance(e, Refusal):
            return e
        if not is_xrpl_invoice_id(e.checked.details):
            return Refusal("mpp/request-malformed")
        blob = _presented_blob(presented, e.payload)
        if isinstance(blob, Refusal):
            return blob
        decoded = decode_presented(blob)
        if isinstance(decoded, Refusal):
            return decoded
        tx = decoded.tx
        network = xrpl_network_of(e.checked.details)
        if isinstance(network, Refusal):
            return network
        if not network_id_held(tx, network):
            return Refusal("xrpl/network-mismatch")
        if tx.get("TransactionType") != "Payment":
            return Refusal("xrpl/not-payment")
        invoice = tx.get("InvoiceID")
        if not isinstance(invoice, str):
            return Refusal("xrpl/no-invoice-id")
        if not same_invoice(invoice, e.checked.details.get("invoiceId")):
            return Refusal("xrpl/carrier-mismatch")
        if not hash_equals("0x" + invoice.lower(), e.h):
            return Refusal("mpp/carrier-not-challenge")
        return e.h

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """By the credential's type: transaction, "payee", a signed blob the seller's server submits; hash, "payer", a
        transaction the payer broadcast. A credential of any other type gets mpp/credential-type, as bound refuses
        it."""
        return mpp_broadcaster(presented, by_type({"transaction": "payee", "hash": "payer"}))
