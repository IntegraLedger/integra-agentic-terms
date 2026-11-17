"""The buyer half of mpp/charge/xrpl: the ATR hash itself, as 64 upper-case hex digits, placed as the request's
methodDetails.invoiceId, which the payer signs as the Payment's InvoiceID. Nothing here fetches or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Refusal
from ._lcp import is_object
from ._mpp import by_type, chosen_for, credential_of, echoed_for, fetched_of, measured, mpp_broadcaster, read
from ._mpp_checks import is_xrpl_invoice_id, xrpl_currency_of, xrpl_network_of
from ._xrpl import decode_presented, is_blob_hex, mpp_invoice_id, network_id_held, same_invoice

ID = "mpp/charge/xrpl"
# The SourceTag a stock client writes where the challenge names none: xrpl-mpp-sdk 0.1.0-beta.4's MPP_SOURCE_TAG
# (dist/chunk-JQG7ATQA.js:39), written by its charge client as methodDetails.sourceTag ?? MPP_SOURCE_TAG
# (dist/client/index.js:344).
MPP_SOURCE_TAG = 593_184_257
# The most hex digits of a transaction credential's blob the stock server's schema takes: 8,192, 4,096 bytes
# (xrpl-mpp-sdk 0.1.0-beta.4, dist/chunk-L6LVAN2P.js:16, :24). A longer blob is xrpl/blob-too-large before anything moves.
CHARGE_BLOB_HEX = 8192

_DROPS = re.compile(r"0|[1-9][0-9]{0,18}")
_ABSENT = object()


def _u32(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return 0 <= value <= 0xFFFFFFFF


def _hex_of(text: str) -> str:
    """A memo member's UTF-8 bytes in upper-case hex, as the stock utf8ToHex writes them."""
    return text.encode("utf-8").hex().upper()


def _presented_blob(credential: Mapping[str, Any], payload: Mapping[str, Any]) -> str | Refusal:
    """The signed blob a credential presents: its blob for type "transaction", of at most 8,192 hex digits, the stock
    server's bound, else xrpl/blob-too-large; or for type "hash" the blob read by that hash and held in Held, as
    @integraledger/lcp holds it under the payment's own FETCHED member (fetched_of), else xrpl/read-first. A hash
    credential's own blob member is not read."""
    kind = payload.get("type")
    if kind not in ("transaction", "hash"):
        return Refusal("mpp/credential-type")
    if kind == "hash":
        read = fetched_of(credential)
        landed = read.get("blob") if is_object(read) else None
        return landed if isinstance(landed, str) else Refusal("xrpl/read-first")
    blob = payload.get("blob")
    if not isinstance(blob, str):
        return Refusal("xrpl/blob-malformed")
    return Refusal("xrpl/blob-too-large") if len(blob) > CHARGE_BLOB_HEX else blob


@dataclass(frozen=True, slots=True)
class XrplChargeUnsigned:
    """The Payment for the wallet to sign, and how its signed blob completes the credential."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]
    _network: str
    _source: str

    def complete(self, signed_blob: object) -> dict[str, Any] | Refusal:
        """The credential of the wallet's signed blob, hex, naming its payer by source,
        did:pkh:xrpl:{network}:{account}, the challenge's network name and the account build was given, as the stock
        client writes it and the stock server reads it first (xrpl-mpp-sdk 0.1.0-beta.4, dist/client/index.js:376-385).
        It is read in bound's order: the credential measured first (measured), its source included; then a blob over
        8,192 hex digits, the stock server's bound, is xrpl/blob-too-large; then the blob as bound reads it: a blob that
        does not decode gets the refusal bound gives it, and one whose NetworkID the challenge's network does not take
        (network_id_held) is xrpl/network-mismatch."""
        payload = {"type": "transaction", "blob": signed_blob}
        credential = measured({"challenge": self._challenge, "payload": payload, "source": self._source})
        if isinstance(credential, Refusal):
            return credential
        if isinstance(signed_blob, str) and len(signed_blob) > CHARGE_BLOB_HEX:
            return Refusal("xrpl/blob-too-large")
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
    coverage: Coverage = "full"
    agreement: AgreementData | None = None

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash, act: Act | None = None) -> XrplChargeUnsigned | Refusal:
        """The Payment for the wallet to sign, as the stock client writes it (xrpl-mpp-sdk 0.1.0-beta.4,
        dist/client/index.js:333-346): Destination the request's recipient; Amount from its currency string
        (xrpl_currency_of) as the stock buildAmount writes it, drops, an issued amount, or an MPT amount; an issued
        amount's SendMax equal to it, where the stock client computes SendMax from the issuer's transfer rate and its
        slippage, so that this build fails with a tec result where the issuer charges a transfer fee; InvoiceID the
        request's invoiceId, which must be this H; the request's destinationTag; SourceTag the request's sourceTag, or
        MPP_SOURCE_TAG; and Memos from the request's memos where it holds any, each member's UTF-8 in upper-case hex, as
        the stock encodeMemos writes them (dist/client/index.js:391-399). No NetworkID: each network the challenge can
        name has an id of at most 1024. complete writes the credential's source."""
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
        currency = xrpl_currency_of(r.get("currency"))
        if currency is None:
            return Refusal("mpp/request-malformed")
        value = r.get("amount")
        send_max = False
        amount: Any
        if currency == "XRP":
            amount = value
        elif isinstance(currency, dict) and "mpt_issuance_id" in currency:
            amount = {"mpt_issuance_id": currency["mpt_issuance_id"], "value": value}
        else:
            assert isinstance(currency, dict)
            amount = {"currency": currency["currency"], "issuer": currency["issuer"], "value": value}
            send_max = True
        memos = d.get("memos") if isinstance(d.get("memos"), list) else []
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
        tx["SourceTag"] = d["sourceTag"] if "sourceTag" in d else MPP_SOURCE_TAG
        if memos:
            tx["Memos"] = [
                {
                    "Memo": {
                        name: _hex_of(m[member])
                        for member, name in (("type", "MemoType"), ("format", "MemoFormat"), ("data", "MemoData"))
                        if m.get(member)
                    }
                }
                for m in memos
            ]
        tx["InvoiceID"] = mpp_invoice_id(h)
        tx["Fee"] = fee
        tx["Sequence"] = sequence
        tx["LastLedgerSequence"] = last
        return XrplChargeUnsigned(
            request={"kind": "xrpl-tx", "txJson": tx},
            _challenge=dict(checked.challenge),
            _network=network,
            _source=f"did:pkh:xrpl:{d['network']}:{account}",
        )

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H from the echoed challenge, once the signed Payment's InvoiceID is the request's invoiceId and equals
        that H. The invoiceId is read as pairings_of reads it: absent, or 64 hex digits, else mpp/request-malformed.
        A multisigned blob is admitted: the payment is found by the payer's instrument. The blob's NetworkID is read
        first, as rippled reads it (network_id_held), else xrpl/network-mismatch. The signature is not verified here."""
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
