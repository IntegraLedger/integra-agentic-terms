"""The buyer half of the pairing x402/exact/xrpl: read, build with complete, and bound.

The option's extra.invoiceId holds the ATR hash's LCP string, and the payer signs a Payment whose InvoiceID is its
SHA-256. Nothing here fetches or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._lcp import from_lcp_string, is_object, to_lcp_string
from ._x402 import chosen, filter_of, payment_with, read_for
from ._xrpl import Blob, decode_presented, is_blob_hex, is_xrpl_network, network_id, same_invoice, x402_invoice_id

ID = "x402/exact/xrpl"

_AMOUNT = re.compile(r"[0-9]+(\.[0-9]+)?")
_DROPS = re.compile(r"[1-9][0-9]{0,16}")
_ABSENT = object()


def pairing_of(option: object) -> str | None:
    """This pairing's id for an option it can pay: scheme exact, an xrpl network, fees not sponsored, a sequence or
    ticket sequence transfer, and extra.invoiceId absent or a string."""
    if not is_object(option) or option.get("scheme") != "exact" or not is_xrpl_network(option.get("network")):
        return None
    extra = option.get("extra")
    if not is_object(extra) or extra.get("areFeesSponsored", _ABSENT) is not False:
        return None
    method = extra.get("assetTransferMethod", _ABSENT)
    if method is not _ABSENT and method not in ("sequence", "ticketSequence"):
        return None
    invoice_id = extra.get("invoiceId", _ABSENT)
    if invoice_id is not _ABSENT and not isinstance(invoice_id, str):
        return None
    return ID


def _is_this(option: Mapping[str, Any]) -> bool:
    return pairing_of(option) is not None


_THIS = filter_of(_is_this)


def _payable(option: Mapping[str, Any]) -> bool:
    """True when build can write the Payment's Amount: XRP drops, or an issued amount with extra.issuer."""
    amount, asset = option.get("amount"), option.get("asset")
    if not isinstance(amount, str) or not isinstance(asset, str) or not isinstance(option.get("payTo"), str):
        return False
    if asset == "XRP":
        return _DROPS.fullmatch(amount) is not None
    extra = option.get("extra")
    return _AMOUNT.fullmatch(amount) is not None and is_object(extra) and isinstance(extra.get("issuer"), str)


def _u32(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return 0 <= value <= 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class XrplUnsigned:
    """What the wallet signs, and how its signed blob completes the payment."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signed_blob: object) -> dict[str, Any] | Refusal:
        if not is_blob_hex(signed_blob):
            return Refusal("xrpl/blob-malformed")
        return payment_with(self._required, self._accepted, {"signedTxBlob": signed_blob})


def _presented(presented: object) -> tuple[Mapping[str, Any], Blob, AtrHash] | Refusal:
    """The option, the decoded blob and the hash of a payment, or the refusal that names what is wrong."""
    if not is_object(presented) or presented.get("x402Version") != 2 or isinstance(presented.get("x402Version"), bool):
        return Refusal("x402/not-v2")
    accepted = presented.get("accepted")
    if not is_object(accepted) or not _is_this(accepted):
        return Refusal("x402/option-not-this-pairing")
    payload = presented.get("payload")
    if not is_object(payload):
        return Refusal("x402/payload-malformed")
    blob = decode_presented(payload.get("signedTxBlob"))
    if isinstance(blob, Refusal):
        return blob
    if blob.tx.get("TransactionType") != "Payment":
        return Refusal("xrpl/not-payment")
    invoice = blob.tx.get("InvoiceID")
    if not isinstance(invoice, str):
        return Refusal("xrpl/no-invoice-id")
    extra = accepted.get("extra")
    h = from_lcp_string(extra.get("invoiceId") if is_object(extra) else None)
    if h is None:
        return Refusal("xrpl/carrier-not-lcp")
    if not same_invoice(invoice, x402_invoice_id(h)):
        return Refusal("xrpl/carrier-mismatch")
    return accepted, blob, h


@dataclass(frozen=True, slots=True)
class X402ExactXrpl:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(_THIS)(doc)

    def build(self, choice: Json, h: AtrHash) -> XrplUnsigned | Refusal:
        """The Payment for the wallet to sign, with InvoiceID = SHA-256 of the option's extra.invoiceId."""
        c: Mapping[str, Any] = choice if is_object(choice) else {}
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        if not _payable(accepted):
            return Refusal("x402/option-malformed")
        extra = accepted["extra"]
        if extra.get("invoiceId") != to_lcp_string(h):
            return Refusal("xrpl/carrier-mismatch")
        ticket = extra.get("assetTransferMethod") == "ticketSequence"
        account, fee, last = c.get("account"), c.get("fee"), c.get("lastLedgerSequence")
        if not isinstance(account, str) or not isinstance(fee, str) or _DROPS.fullmatch(fee) is None or not _u32(last):
            return Refusal("x402/option-malformed")
        if not _u32(c.get("ticketSequence") if ticket else c.get("sequence")):
            return Refusal("x402/option-malformed")
        amount: Any = (
            accepted["amount"]
            if accepted["asset"] == "XRP"
            else {"currency": accepted["asset"], "issuer": extra["issuer"], "value": accepted["amount"]}
        )
        tx: dict[str, Any] = {
            "TransactionType": "Payment",
            "Flags": 0,
            "Account": account,
            "Destination": accepted["payTo"],
            "Amount": amount,
        }
        if accepted["asset"] != "XRP":
            tx["SendMax"] = amount
        if "destinationTag" in extra:
            tx["DestinationTag"] = extra["destinationTag"]
        tx["InvoiceID"] = x402_invoice_id(h)
        tx["Fee"] = fee
        tx["Sequence"] = 0 if ticket else c["sequence"]
        if ticket:
            tx["TicketSequence"] = c["ticketSequence"]
        tx["LastLedgerSequence"] = last
        chain = network_id(accepted["network"])
        if chain > 1024:
            tx["NetworkID"] = chain
        return XrplUnsigned(request={"kind": "xrpl-tx", "txJson": tx}, _required=required, _accepted=accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash whose LCP string's SHA-256 is the signed InvoiceID. A multi-signed blob is xrpl/multisigned: the
        payer signs with a single key. The signature is not verified here."""
        p = _presented(presented)
        return p if isinstance(p, Refusal) else p[2]
