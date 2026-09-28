"""The buyer halves of the Lightning pairings on x402 and MPP: read, build with complete, and bound.

On x402/exact/lnbtc the seller's node writes the ATR hash as the invoice's m field and signs it; on
x402/exact/lnbtc/invoice-named the invoice carries no hash and the ATR's x402 slot names the invoice instead. On MPP the
seller's node writes the ATR hash as the invoice's description hash h. The payer signs nothing; it pays the invoice. No
signature is verified here.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .._core import MAX_ATR_BYTES, AtrHash
from .._types import Advertised, Json, Refusal
from ._bolt11 import FIELD, Bolt11, Currency, decode, invoice_h
from ._channel import ChannelKind, ChannelRef
from ._jose import member_names, parse_json
from ._mpp import challenge_bound, check_challenge, credential_of
from ._mpp import read as mpp_read
from ._mpp_checks import decode_object
from ._lcp import is_object, legal_context_info, normal_hash, safe_int
from ._x402 import chosen, filter_of, is_v2, payment_with, read_for

LNBTC = "x402/exact/lnbtc"
NAMED = "x402/exact/lnbtc/invoice-named"

MAX_ACCEPTS_READ = 32
NETWORKS: Mapping[str, Currency] = {
    "lnbtc:000000000019d6689c085ae165831e93": "bc",
    "lnbtc:000000000933ea01ad0ee984209779ba": "tb",
}
_PAY_TO = re.compile(r"[0-9a-f]{66}")
_REQUEST_HASH = re.compile(r"[0-9a-f]{64}")
PREIMAGE = re.compile(r"[0-9a-f]{64}")
_POSITIVE = re.compile(r"[1-9][0-9]{0,77}")


def is_ln_option(o: object) -> bool:
    """An exact option on a Lightning network with an invoice string: the part of the filter both pairings share."""
    if not is_object(o) or o.get("scheme") != "exact":
        return False
    network = o.get("network")
    if not isinstance(network, str) or network not in NETWORKS:
        return False
    extra = o.get("extra")
    return is_object(extra) and isinstance(extra.get("invoice"), str)


def _with_metadata(want: bool) -> Callable[[Mapping[str, Any]], bool]:
    """An option whose invoice decodes with an m field, or without one."""

    def pairs(o: Mapping[str, Any]) -> bool:
        if not is_ln_option(o):
            return False
        b = decode(o["extra"]["invoice"])
        return not isinstance(b, Refusal) and (FIELD["m"] in b.tags) == want

    return pairs


def check_option(o: Mapping[str, Any], h: AtrHash | None) -> Bolt11 | Refusal:
    """The x402 option checks both Lightning pairings make on the invoice and the option. h is the ATR hash the
    invoice's m must carry, or None where m must be absent."""
    extra = o["extra"]
    b = decode(extra["invoice"])
    if isinstance(b, Refusal):
        return b
    if h is not None:
        m = invoice_h(b, "m")
        if isinstance(m, Refusal):
            return m
        if m != normal_hash(h):
            return Refusal("ln/no-metadata")
    elif FIELD["m"] in b.tags:
        return Refusal("ln/not-this-pairing")
    d = invoice_h(b, "h")
    if isinstance(d, Refusal):
        return d
    request_hash = extra.get("requestHash")
    if not isinstance(request_hash, str) or _REQUEST_HASH.fullmatch(request_hash) is None or d != "0x" + request_hash:
        return Refusal("ln/request-hash-mismatch")
    if NETWORKS[o["network"]] != b.currency:
        return Refusal("ln/currency-network")
    pay_to = o.get("payTo")
    amount = o.get("amount")
    max_timeout = safe_int(o.get("maxTimeoutSeconds"))
    if (
        extra.get("paymentFlow") != "upfront"
        or o.get("asset") != "BTC"
        or not isinstance(pay_to, str)
        or _PAY_TO.fullmatch(pay_to) is None
        or not isinstance(amount, str)
        or _POSITIVE.fullmatch(amount) is None
        or max_timeout is None
        or max_timeout <= 0
    ):
        return Refusal("x402/option-malformed")
    return b


def atr_names_invoice(atr: object, invoice: object) -> bool:
    """True when the ATR's bytes are one JSON object in the core's layout whose x402 slot's accepts holds, among its
    first 32 entries, an option whose extra.invoice is exactly the invoice. The object's first members are atrVersion,
    id and x402, in that order, and no member name appears twice, so every JSON reader finds the same x402 slot. The
    text is strict UTF-8 with a leading byte-order mark kept, so an ATR that begins with one is not one JSON object.
    Only that slot is read."""
    if not isinstance(atr, (bytes, bytearray)) or len(atr) > MAX_ATR_BYTES or not isinstance(invoice, str):
        return False
    try:
        text = bytes(atr).decode("utf-8")
    except UnicodeDecodeError:
        return False
    parsed = parse_json(text)
    if not isinstance(parsed, dict):
        return False
    names = member_names(text)
    if names[:3] != ["atrVersion", "id", "x402"] or len(set(names)) != len(names):
        return False
    slot = parsed.get("x402")
    accepts = slot.get("accepts") if isinstance(slot, dict) else None
    if not isinstance(accepts, list):
        return False
    for o in accepts[:MAX_ACCEPTS_READ]:
        extra = o.get("extra") if isinstance(o, dict) else None
        if isinstance(extra, dict) and extra.get("invoice") == invoice:
            return True
    return False


@dataclass(frozen=True, slots=True)
class LnUnsigned:
    """The invoice the payer's node pays exactly, and the payment its preimage completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, preimage: object) -> dict[str, Any] | Refusal:
        if not isinstance(preimage, str) or PREIMAGE.fullmatch(preimage) is None:
            return Refusal("ln/preimage-malformed")
        return payment_with(self._required, self._accepted, {"preimage": preimage})


_IS_LN = filter_of(is_ln_option)


def _choice(c: object) -> tuple[Mapping[str, Any], Mapping[str, Any]] | Refusal:
    """The chosen option, after the checks every x402 build makes on it."""
    required = c.get("required") if is_object(c) else None
    accepted = c.get("accepted") if is_object(c) else None
    wrong = chosen(required, accepted, _IS_LN)
    if wrong is not True:
        return wrong if isinstance(wrong, Refusal) else Refusal("x402/option-not-this-pairing")
    assert is_object(required) and is_object(accepted)
    return required, accepted


def _ln_accepted(presented: object) -> Mapping[str, Any] | Refusal:
    if not is_v2(presented):
        return Refusal("x402/not-v2")
    assert is_object(presented)
    accepted = presented.get("accepted")
    if not is_ln_option(accepted):
        return Refusal("x402/option-not-this-pairing")
    assert is_object(accepted)
    return accepted


@dataclass(frozen=True, slots=True)
class X402ExactLnbtc:
    id: str = LNBTC
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(filter_of(_with_metadata(True)))(doc)

    def build(self, choice: Json, h: AtrHash) -> LnUnsigned | Refusal:
        """The invoice to pay, once its m is h and its h is the request hash."""
        c = _choice(choice)
        if isinstance(c, Refusal):
            return c
        required, accepted = c
        b = check_option(accepted, h)
        if isinstance(b, Refusal):
            return b
        return LnUnsigned({"kind": "bolt11-pay", "invoice": accepted["extra"]["invoice"]}, required, accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the invoice the payer paid: its m field. No signature is verified."""
        accepted = _ln_accepted(presented)
        if isinstance(accepted, Refusal):
            return accepted
        b = decode(accepted["extra"]["invoice"])
        if isinstance(b, Refusal):
            return b
        return invoice_h(b, "m")


@dataclass(frozen=True, slots=True)
class X402ExactLnbtcInvoiceNamed:
    id: str = NAMED
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(filter_of(_with_metadata(False)))(doc)

    def build(self, choice: Json, h: AtrHash) -> LnUnsigned | Refusal:
        """Pays only an invoice that the ATR's own x402 slot names."""
        c = _choice(choice)
        if isinstance(c, Refusal):
            return c
        required, accepted = c
        b = check_option(accepted, None)
        if isinstance(b, Refusal):
            return b
        invoice = accepted["extra"]["invoice"]
        if not atr_names_invoice(choice.get("atr"), invoice):
            return Refusal("ln/invoice-not-named")
        return LnUnsigned({"kind": "bolt11-pay", "invoice": invoice}, required, accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The candidate hash: the echoed legal context's value. The paid invoice carries none."""
        accepted = _ln_accepted(presented)
        if isinstance(accepted, Refusal):
            return accepted
        b = check_option(accepted, None)
        if isinstance(b, Refusal):
            return b
        extensions = presented.get("extensions")
        lc = extensions.get("legalContext") if is_object(extensions) else None
        decoded = legal_context_info(lc.get("info")) if is_object(lc) else None
        return Refusal("ln/no-legal-context") if decoded is None else decoded[0]


# ── mpp/charge/lightning and mpp/session/lightning ──

MPP_CHARGE = "mpp/charge/lightning"
MPP_SESSION = "mpp/session/lightning"
MPP_NETWORKS: Mapping[str, Currency] = {"mainnet": "bc", "signet": "tbs", "regtest": "bcrt"}
_OPEN = "open"


def _ln_fields(pairing: str, request: Mapping[str, Any]) -> tuple[Any, Any]:
    """Where a pairing's invoice and payment hash sit in the decoded request."""
    if pairing == MPP_SESSION:
        return request.get("depositInvoice"), request.get("paymentHash")
    d = request.get("methodDetails")
    return (d.get("invoice"), d.get("paymentHash")) if is_object(d) else (None, None)


def _ln_challenge_checks(pairing: str, c: object, h: AtrHash, placed: bool) -> Bolt11 | Refusal:
    """The checks of what the seller's node wrote: the invoice decodes, its one h is h, it has no d, the request has
    no description, its payment hash is the request's, its currency is the challenge's network, and expires is no
    later than the invoice's own expiry."""
    checked = check_challenge(c, placed)
    if isinstance(checked, Refusal):
        return checked
    if pairing not in checked.pairings:
        return Refusal("mpp/not-this-pairing")
    invoice, payment_hash = _ln_fields(pairing, checked.request)
    if not isinstance(invoice, str):
        return Refusal("ln/invoice-malformed")
    b = decode(invoice)
    if isinstance(b, Refusal):
        return b
    d = invoice_h(b, "h")
    if isinstance(d, Refusal) or d != normal_hash(h):
        return Refusal("mpp/carrier-not-challenge")
    if FIELD["d"] in b.tags:
        return Refusal("ln/description-inline")
    if "description" in checked.request:
        return Refusal("ln/description-present")
    if payment_hash != b.payment_hash.hex():
        return Refusal("ln/payment-hash-mismatch")
    if pairing == MPP_CHARGE and "network" in checked.details:
        network = checked.details["network"]
        if not isinstance(network, str) or MPP_NETWORKS.get(network) != b.currency:
            return Refusal("ln/currency-network")
    if checked.expires > b.timestamp + b.expiry:
        return Refusal("ln/expires-after-invoice")
    return b


def _amountless(value: object) -> bool:
    """Whether value is a BOLT11 invoice with no amount in its human-readable part."""
    if not isinstance(value, str):
        return False
    b = decode(value)
    return not isinstance(b, Refusal) and b.amount_msat is None


@dataclass(frozen=True, slots=True)
class LnMppUnsigned:
    """The invoice the payer's node pays exactly, and the credential its preimage completes."""

    request: dict[str, Any]
    _pairing: str
    _challenge: Mapping[str, Any]
    _return_invoice: object

    def complete(self, preimage: object) -> dict[str, Any] | Refusal:
        if not isinstance(preimage, str) or PREIMAGE.fullmatch(preimage) is None:
            return Refusal("ln/preimage-malformed")
        if self._pairing == MPP_CHARGE:
            return {"challenge": self._challenge, "payload": {"preimage": preimage}}
        return {
            "challenge": self._challenge,
            "payload": {"action": _OPEN, "preimage": preimage, "returnInvoice": self._return_invoice},
        }


@dataclass(frozen=True, slots=True)
class MppLightning:
    id: str
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return mpp_read(doc)

    def build(self, choice: Json, h: AtrHash) -> LnMppUnsigned | Refusal:
        """The invoice to pay, after the checks of what the seller's node wrote."""
        challenge = choice.get("challenge") if is_object(choice) else None
        if not is_object(challenge) or not isinstance(challenge.get("id"), str):
            return Refusal("mpp/credential-malformed")
        b = _ln_challenge_checks(self.id, challenge, h, True)
        if isinstance(b, Refusal):
            return b
        return_invoice = choice.get("returnInvoice")
        if self.id == MPP_SESSION and not _amountless(return_invoice):
            return Refusal("ln/return-invoice-malformed")
        request = decode_object(challenge["request"])
        assert request is not None
        invoice, _ = _ln_fields(self.id, request)
        return LnMppUnsigned(
            {"kind": "bolt11-pay", "invoice": invoice}, self.id, challenge, return_invoice
        )

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The echoed challenge's hash, held to the invoice the payer paid. No signature is verified."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        cb = challenge_bound(shaped)
        if isinstance(cb, Refusal):
            return cb
        c = shaped["challenge"]
        if c.get("method") != "lightning" or c.get("intent") != ("charge" if self.id == MPP_CHARGE else "session"):
            return Refusal("mpp/not-this-pairing")
        invoice, payment_hash = _ln_fields(self.id, cb.request)
        b = decode(invoice) if isinstance(invoice, str) else Refusal("ln/invoice-malformed")
        if isinstance(b, Refusal):
            return b
        d = invoice_h(b, "h")
        if isinstance(d, Refusal) or d != cb.h:
            return Refusal("mpp/carrier-not-challenge")
        if payment_hash != b.payment_hash.hex():
            return Refusal("ln/payment-hash-mismatch")
        if self.id == MPP_SESSION and shaped["payload"].get("action") != _OPEN:
            return Refusal("ln/no-payment-in-action")
        return cb.h


# The one network name every Lightning session channel key carries: a bearer or close challenge names no invoice.
_SESSION_CHANNEL_NETWORK = "lightning"
_PAYMENT_HASH = re.compile(r"[0-9a-fA-F]{64}")


@dataclass(frozen=True, slots=True)
class MppLightningSession(MppLightning):
    """mpp/session/lightning: the MPP Lightning binding with the channel members of its session."""

    id: str = MPP_SESSION

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """The session action: open opens the channel, bearer and topUp are within it, close ends it."""
        c = credential_of(presented)
        if isinstance(c, Refusal):
            return c
        a = c["payload"].get("action")
        if a == _OPEN:
            return "open"
        if a in ("bearer", "topUp"):
            return "within"
        if a == "close":
            return "close"
        return Refusal("mpp/session-action")

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The session's id: the open's challenge paymentHash, else the payload's sessionId, as lowercase hex."""
        kind = self.channel_kind(presented)
        if isinstance(kind, Refusal):
            return kind
        request = presented["challenge"].get("request")
        decoded = decode_object(request) if isinstance(request, str) else None
        if kind == "open":
            session_id = decoded.get("paymentHash") if decoded is not None else None
        else:
            session_id = presented["payload"].get("sessionId")
        if not isinstance(session_id, str) or _PAYMENT_HASH.fullmatch(session_id) is None:
            return Refusal("mpp/credential-malformed")
        return ChannelRef(_SESSION_CHANNEL_NETWORK, session_id.lower())

    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A bearer proof is the deposit preimage, and a topUp pays a new invoice: neither carries the hash."""
        return Refusal("mpp/not-bound-within")
