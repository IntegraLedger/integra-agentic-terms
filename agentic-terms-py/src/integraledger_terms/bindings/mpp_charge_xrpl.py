"""The buyer half of mpp/charge/xrpl: the ATR hash itself, as 64 upper-case hex digits, placed as the request's
methodDetails.invoiceId, which the payer signs as the Payment's InvoiceID. Nothing here fetches or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Refusal
from ._lcp import is_object
from ._mpp import chosen_for, credential_of, echoed_for, read
from ._xrpl import decode_blob, is_blob_hex, mpp_invoice_id, same_invoice

ID = "mpp/charge/xrpl"

_DROPS = re.compile(r"0|[1-9][0-9]{0,18}")
_ABSENT = object()


def _u32(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return 0 <= value <= 0xFFFFFFFF


def _presented_blob(payload: Mapping[str, Any]) -> str | Refusal:
    """The signed blob a credential presents: its blob, or for type "hash" none until one is fetched by that hash."""
    kind = payload.get("type")
    if kind not in ("transaction", "hash"):
        return Refusal("mpp/credential-type")
    if "blob" not in payload:
        return Refusal("xrpl/read-first" if kind == "hash" else "xrpl/blob-malformed")
    blob = payload["blob"]
    return blob if isinstance(blob, str) else Refusal("xrpl/blob-malformed")


@dataclass(frozen=True, slots=True)
class XrplChargeUnsigned:
    """The Payment for the wallet to sign, and how its signed blob completes the credential."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]

    def complete(self, signed_blob: object) -> dict[str, Any] | Refusal:
        if not is_blob_hex(signed_blob):
            return Refusal("xrpl/blob-malformed")
        return {"challenge": self._challenge, "payload": {"type": "transaction", "blob": signed_blob}}


@dataclass(frozen=True, slots=True)
class MppChargeXrpl:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> XrplChargeUnsigned | Refusal:
        """The Payment: Destination the request's recipient, Amount from its currency (drops, an issued amount with
        SendMax equal to it, or an MPT amount), InvoiceID the request's invoiceId, which must be this H, and the
        request's tags. A request with memos is refused."""
        if not is_object(choice):
            return Refusal("mpp/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        r, d = checked.request, checked.details
        if not same_invoice(d.get("invoiceId"), mpp_invoice_id(h)):
            return Refusal("xrpl/carrier-mismatch")
        if "memos" in d:
            return Refusal("xrpl/memos-not-carried")
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
        return XrplChargeUnsigned(request={"kind": "xrpl-tx", "txJson": tx}, _challenge=choice["challenge"])

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """H from the echoed challenge, once the signed Payment's InvoiceID is the request's invoiceId and equals
        that H. The signature is not verified here."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        e = echoed_for(presented, ID)
        if isinstance(e, Refusal):
            return e
        blob = _presented_blob(e.payload)
        if isinstance(blob, Refusal):
            return blob
        decoded = decode_blob(blob)
        if isinstance(decoded, Refusal):
            return decoded
        tx = decoded.tx
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
