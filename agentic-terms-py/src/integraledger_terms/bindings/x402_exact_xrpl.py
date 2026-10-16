"""The buyer half of the pairing x402/exact/xrpl: read, build with complete, and bound.

The option's extra.invoiceId holds the ATR hash's LCP string, and the payer signs a Payment whose InvoiceID is its
SHA-256. Nothing here fetches or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._lcp import from_lcp_string, is_object, normal_hash, to_lcp_string
from ._x402 import accepted_by, chosen, filter_of, is_amount, payment_with, read_for, timeout_seconds, x402_broadcaster
from ._xrpl import (
    Blob,
    decode_presented,
    is_blob_hex,
    is_xrpl_network,
    network_id,
    network_id_held,
    same_invoice,
    x402_invoice_id,
)
from ._xrpl_codec import account_id_of

ID = "x402/exact/xrpl"

# A decimal with no sign, exponent or leading zero, whose fraction, if any, ends in a digit other than 0.
_ISSUED = re.compile(r"(0|[1-9][0-9]*)(\.[0-9]*[1-9])?")
_DROPS = re.compile(r"[1-9][0-9]{0,16}")
_I64_LIMIT = 2**63
# AccountID 1, rippled's noAccount() (XRPLF/rippled 00e64075, src/libxrpl/protocol/AccountID.cpp:165-170).
_NO_ACCOUNT = 1
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


def _account(value: object) -> int:
    """The AccountID of a classic address whose checksum holds, as a number, else -1: base58 with the XRPL alphabet of
    version 0, a 20-byte AccountID and a 4-byte checksum, the first 4 bytes of the double SHA-256 of the two, the form
    the XRPL exact scheme gives payTo and extra.issuer."""
    account_id = account_id_of(value)
    return -1 if account_id is None else int.from_bytes(account_id, "big")


def _is_issued_value(s: str) -> bool:
    """True when s is the canonical decimal of a positive STAmount value, which rippled 3.4.1 (XRPLF/rippled
    00e64075) reads exactly. An STAmount value is a mantissa of 10^15 to 10^16 - 1 at an offset of -96 to 80
    (include/xrpl/protocol/STAmount.h:35-40,61-68): IOUAmount rounds a value of more than 16 significant digits and
    reads one below 10^-81 as zero (src/libxrpl/protocol/IOUAmount.cpp:29-36,58-68). partsFromString
    (src/libxrpl/protocol/STNumber.cpp:159-216) refuses a leading zero, and reads the digits with the point removed as
    a uint64 (:192, :198) that STAmount::iou casts to int64 (src/libxrpl/protocol/STAmount.cpp:291), so they are below
    2^63; that also holds the value below the largest offset. So: no sign, exponent or leading zero, a fraction that
    ends in a digit other than 0, at most 16 significant digits, at least 10^-81, and digits below 2^63. More than 19
    digits, leading zeros aside, the width of 2^63, are refused before any further step reads them, so each step takes
    time linear in the length of s."""
    m = _ISSUED.fullmatch(s)
    if m is None:
        return False
    fraction = (m.group(2) or "")[1:]
    digits = (m.group(1) + fraction).lstrip("0")
    if digits == "" or len(digits) > 19:
        return False
    significant = len(digits)
    while digits[significant - 1] == "0":
        significant -= 1
    return significant <= 16 and int(digits) < _I64_LIMIT and len(digits) - 1 - len(fraction) - 15 >= -96


def _payable(option: Mapping[str, Any]) -> bool:
    """True when build can write the Payment's Destination and Amount, and the timeout is a positive safe integer. payTo
    is a classic address whose checksum holds (_account), and its AccountID is not 0, which rippled 3.4.1 (XRPLF/rippled
    00e64075) refuses as any Payment's Destination (src/libxrpl/tx/transactors/payment/Payment.cpp:178-184). XRP is a
    positive amount of drops (is_amount) below 10^17. An issued currency's amount is the canonical decimal of a positive
    STAmount value, which rippled reads exactly (_is_issued_value), the form the XRPL exact scheme gives that amount,
    and its extra.issuer is a classic address whose checksum holds. On an issued currency neither payTo nor the issuer
    is AccountID 0 or 1: rippled does not read an issued amount whose issuer is 0
    (src/libxrpl/protocol/STAmount.cpp:155-158), and the payment engine that every issued-currency Payment runs through
    (Payment.cpp:611-613, :638) refuses 1, noAccount(), as the destination or the issuer
    (src/libxrpl/tx/paths/PaySteps.cpp:188-190). The XRP Payment build writes, with no SendMax or paths, does not run
    through that engine (Payment.cpp:611, :756-758), so an XRP payTo may be 1."""
    amount, asset = option.get("amount"), option.get("asset")
    if not isinstance(amount, str) or not isinstance(asset, str):
        return False
    if timeout_seconds(option.get("maxTimeoutSeconds")) is None:
        return False
    if asset == "XRP":
        return _account(option.get("payTo")) > 0 and is_amount(amount) and _DROPS.fullmatch(amount) is not None
    extra = option.get("extra")
    issuer = extra.get("issuer") if is_object(extra) else None
    return _account(option.get("payTo")) > _NO_ACCOUNT and _account(issuer) > _NO_ACCOUNT and _is_issued_value(amount)


# The pairing's one option filter, which read, build and bound apply: an option of this pairing whose Destination and
# Amount build can write and whose timeout is a positive safe integer (_payable), else x402/option-malformed.
_THIS = filter_of(_is_this, _payable)


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
        """The payment of the wallet's signed blob, hex, read as bound reads it: a blob that does not decode, or is
        multi-signed, gets the refusal bound gives it, and one whose NetworkID a node of the option's network does not
        take (network_id_held) is xrpl/network-mismatch."""
        if not is_blob_hex(signed_blob):
            return Refusal("xrpl/blob-malformed")
        payment = payment_with(self._required, self._accepted, {"signedTxBlob": signed_blob})
        blob = decode_presented(signed_blob)
        if isinstance(blob, Refusal):
            return blob
        return payment if network_id_held(blob.tx, self._accepted["network"]) else Refusal("xrpl/network-mismatch")


def _presented(presented: object) -> tuple[Mapping[str, Any], Blob, AtrHash] | Refusal:
    """The option, the decoded blob and the hash of a payment, or the refusal that names what is wrong. The option's
    invoiceId is read before the blob, so one that is not an LCP string is xrpl/carrier-not-lcp whatever the blob
    holds. Of the blob, its NetworkID is read first, as rippled 3.4.1 reads it (network_id_held): none on a network
    whose id is at most 1024, the network's own id above that, else xrpl/network-mismatch."""
    if not is_object(presented) or presented.get("x402Version") != 2 or isinstance(presented.get("x402Version"), bool):
        return Refusal("x402/not-v2")
    accepted = accepted_by(presented.get("accepted"), _THIS)
    if isinstance(accepted, Refusal):
        return accepted
    payload = presented.get("payload")
    if not is_object(payload):
        return Refusal("x402/payload-malformed")
    extra = accepted.get("extra")
    h = from_lcp_string(extra.get("invoiceId") if is_object(extra) else None)
    if h is None:
        return Refusal("xrpl/carrier-not-lcp")
    blob = decode_presented(payload.get("signedTxBlob"))
    if isinstance(blob, Refusal):
        return blob
    if not network_id_held(blob.tx, accepted["network"]):
        return Refusal("xrpl/network-mismatch")
    if blob.tx.get("TransactionType") != "Payment":
        return Refusal("xrpl/not-payment")
    invoice = blob.tx.get("InvoiceID")
    if not isinstance(invoice, str):
        return Refusal("xrpl/no-invoice-id")
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
        """The Payment for the wallet to sign, with InvoiceID = SHA-256 of the option's extra.invoiceId, and NetworkID
        the network's id where it is above 1024. complete reads the signed blob's NetworkID as bound does. H is checked
        first, then the form of the choice's account, fee and last ledger sequence, then its document and option, then
        the sequence or ticket the option's transfer method names."""
        if normal_hash(h) is None:
            return Refusal("x402/payload-malformed")
        if not is_object(choice):
            return Refusal("x402/not-v2")
        c: Mapping[str, Any] = choice
        account, fee, last = c.get("account"), c.get("fee"), c.get("lastLedgerSequence")
        if not isinstance(account, str) or not isinstance(fee, str) or _DROPS.fullmatch(fee) is None or not _u32(last):
            return Refusal("x402/option-malformed")
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        extra = accepted["extra"]
        if extra.get("invoiceId") != to_lcp_string(h):
            return Refusal("xrpl/carrier-mismatch")
        ticket = extra.get("assetTransferMethod") == "ticketSequence"
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
        """The hash whose LCP string's SHA-256 is the signed InvoiceID. The blob's NetworkID is read as rippled reads
        it (network_id_held): none on a network whose id is at most 1024, the network's own id above that, else
        xrpl/network-mismatch. A multi-signed blob is xrpl/multisigned: the payer signs with a single key. The
        signature is not verified here."""
        p = _presented(presented)
        return p if isinstance(p, Refusal) else p[2]

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's facilitator submits the signed Payment blob. The payment is held to
        x402_shape's gate, the one bound applies first; any other gets its refusal."""
        return x402_broadcaster(presented, "payee")
