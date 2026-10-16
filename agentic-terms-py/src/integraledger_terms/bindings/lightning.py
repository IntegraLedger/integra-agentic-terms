"""The buyer halves of the Lightning pairings on x402 and MPP: read, build with complete, and bound.

On x402/exact/lnbtc the seller's node writes the ATR hash as the invoice's m field and signs it; on
x402/exact/lnbtc/invoice-named the invoice carries no hash and the ATR's x402 slot names the invoice instead. On MPP the
seller's node writes the ATR hash as the invoice's description hash h. The payer signs nothing; it pays the invoice. No
signature is verified here.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import MAX_ATR_BYTES, AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._bolt11 import FIELD, Bolt11, Currency, decode, invoice_h
from ._channel import ChannelKind, ChannelRef
from ._jose import member_names, parse_json
from ._mpp import check_challenge, credential_of, echoed_for, measured, mpp_broadcaster, session_broadcaster
from ._mpp import read as mpp_read
from ._mpp_checks import decode_object
from ._lcp import is_object, legal_context_info, normal_hash
from ._x402 import (
    OptionFilter,
    accepted_by,
    chosen,
    filter_of,
    is_amount,
    is_v2,
    payment_with,
    read_for,
    timeout_seconds,
    x402_broadcaster,
)

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


def check_option(o: Mapping[str, Any], h: AtrHash | Literal["any"] | None) -> Bolt11 | Refusal:
    """The x402 option checks both Lightning pairings make, on an exact option on a Lightning network with an
    invoice, in this order: the invoice decodes (else the decoder's refusal); its m field, where h is a hash or "any",
    is one 32-byte field (ln/no-metadata, ln/field-repeated, ln/field-length) carrying h when h is a hash
    (ln/no-metadata), and where h is None the invoice has none (ln/not-this-pairing); its h field is one 32-byte field
    (ln/no-description-hash, ln/field-repeated, ln/field-length) equal to extra.requestHash, 64 lower-case hex digits
    (ln/request-hash-mismatch); its currency is the one x402 gives the option's network (ln/currency-network); and
    x402's client checks on the option's own fields hold (x402/option-malformed). Each pairing's option filter makes
    them with "any" or None, so its read offers only an option its build and bound take; build makes them with the
    ATR hash on x402/exact/lnbtc."""
    extra = o["extra"]
    b = decode(extra["invoice"])
    if isinstance(b, Refusal):
        return b
    if h is not None:
        m = invoice_h(b, "m")
        if isinstance(m, Refusal):
            return m
        if h != "any" and m != normal_hash(h):
            return Refusal("ln/no-metadata")
    elif FIELD["m"] in b.tags:
        return Refusal("ln/not-this-pairing")
    d = invoice_h(b, "h")
    if isinstance(d, Refusal):
        return d
    request_hash = extra.get("requestHash")
    if not isinstance(request_hash, str) or _REQUEST_HASH.fullmatch(request_hash) is None or d != "0x" + request_hash:
        return Refusal("ln/request-hash-mismatch")
    network = _option_network_refused(o, b)
    if network is not None:
        return network
    pay_to = o.get("payTo")
    amount = o.get("amount")
    if (
        extra.get("paymentFlow") != "upfront"
        or o.get("asset") != "BTC"
        or not isinstance(pay_to, str)
        or _PAY_TO.fullmatch(pay_to) is None
        or not is_amount(amount)
        or _POSITIVE.fullmatch(amount) is None
        or timeout_seconds(o.get("maxTimeoutSeconds")) is None
    ):
        return Refusal("x402/option-malformed")
    return b


def _option_network_refused(o: Mapping[str, Any], b: Bolt11) -> Refusal | None:
    """ln/currency-network unless the invoice's currency is the one x402 gives the option's network."""
    return None if NETWORKS[o["network"]] == b.currency else Refusal("ln/currency-network")


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


def _filter_with(h: Literal["any"] | None) -> OptionFilter:
    """The option filter over check_option with h: an option the checks pass is served, else their refusal."""

    def check(o: Mapping[str, Any]) -> Literal[True] | Refusal | None:
        if not is_ln_option(o):
            return None
        b = check_option(o, h)
        return b if isinstance(b, Refusal) else True

    return check


# x402/exact/lnbtc's option filter: check_option with the invoice's m field read but not compared, so an invoice
# without one is ln/no-metadata. Its read offers the options it serves, and its bound holds a presented payment's
# option to it.
_LNBTC_FILTER = _filter_with("any")
# x402/exact/lnbtc/invoice-named's option filter: check_option with no m field allowed, so an invoice with one is
# ln/not-this-pairing. Its read offers the options it serves, and its bound holds a presented payment's option to it.
_NAMED_FILTER = _filter_with(None)


def _choice(c: object) -> tuple[Mapping[str, Any], Mapping[str, Any]] | Refusal:
    """The chosen option, after the checks every x402 build makes on it."""
    required = c.get("required") if is_object(c) else None
    accepted = c.get("accepted") if is_object(c) else None
    wrong = chosen(required, accepted, _IS_LN)
    if wrong is not True:
        return wrong
    assert is_object(required) and is_object(accepted)
    return required, accepted


def _ln_accepted(presented: object, check: OptionFilter) -> Mapping[str, Any] | Refusal:
    """A presented payment's accepted, held to the pairing's filter by accepted_by."""
    if not is_v2(presented):
        return Refusal("x402/not-v2")
    assert is_object(presented)
    return accepted_by(presented.get("accepted"), check)


@dataclass(frozen=True, slots=True)
class X402ExactLnbtc:
    id: str = LNBTC
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(_LNBTC_FILTER)(doc)

    def build(self, choice: Json, h: AtrHash) -> LnUnsigned | Refusal:
        """The invoice to pay, once its m is h and its h is the request hash. H is checked first: a value that is not a
        32-byte hash, "any" included, is ln/no-metadata."""
        if normal_hash(h) is None:
            return Refusal("ln/no-metadata")
        c = _choice(choice)
        if isinstance(c, Refusal):
            return c
        required, accepted = c
        b = check_option(accepted, h)
        if isinstance(b, Refusal):
            return b
        return LnUnsigned({"kind": "bolt11-pay", "invoice": accepted["extra"]["invoice"]}, required, accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the invoice the payer paid: its m field, from an option the pairing's filter serves, so the
        invoice's fields, its currency and the option's own fields are the ones build checks. No signature is
        verified."""
        accepted = _ln_accepted(presented, _LNBTC_FILTER)
        if isinstance(accepted, Refusal):
            return accepted
        b = decode(accepted["extra"]["invoice"])
        assert not isinstance(b, Refusal)
        return invoice_h(b, "m")

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payer broadcasts: its node pays the invoice before the preimage is presented, and the seller's node,
        which received the payment, confirms it. bound reads no payload, so the gate is x402_shape's without it."""
        return x402_broadcaster(presented, "payer", payload=None)


@dataclass(frozen=True, slots=True)
class X402ExactLnbtcInvoiceNamed:
    id: str = NAMED
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(_NAMED_FILTER)(doc)

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
        """The candidate hash: the echoed legal context's value, under an option the pairing's filter serves. The paid
        invoice carries none."""
        accepted = _ln_accepted(presented, _NAMED_FILTER)
        if isinstance(accepted, Refusal):
            return accepted
        extensions = presented.get("extensions")
        lc = extensions.get("legalContext") if is_object(extensions) else None
        decoded = legal_context_info(lc.get("info")) if is_object(lc) else None
        return Refusal("ln/no-legal-context") if decoded is None else decoded[0]

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payer broadcasts: its node pays the invoice before the preimage is presented, and the seller's node,
        which received the payment, confirms it. bound reads no payload, so the gate is x402_shape's without it."""
        return x402_broadcaster(presented, "payer", payload=None)


# ── mpp/charge/lightning and mpp/session/lightning ──

MPP_CHARGE = "mpp/charge/lightning"
MPP_SESSION = "mpp/session/lightning"
_OPEN = "open"


def _ln_invoice(pairing: str, request: Mapping[str, Any]) -> Any:
    """A pairing's invoice in the decoded request: methodDetails.invoice on the charge, depositInvoice on the
    session."""
    if pairing == MPP_SESSION:
        return request.get("depositInvoice")
    d = request.get("methodDetails")
    return d.get("invoice") if is_object(d) else None


def _ln_challenge_checks(pairing: str, c: object, h: AtrHash, placed: bool) -> Bolt11 | Refusal:
    """The checks of what the seller's node wrote: the challenge offers the pairing, which holds the invoice to
    pairings_of's Lightning checks (it decodes, has one h and no d, carries the request's payment hash, is on the
    network the challenge names, and expires no earlier than the challenge), and the invoice's h is h."""
    checked = check_challenge(c, placed)
    if isinstance(checked, Refusal):
        return checked
    if pairing not in checked.pairings:
        return Refusal("mpp/not-this-pairing")
    invoice = _ln_invoice(pairing, checked.request)
    if not isinstance(invoice, str):
        return Refusal("ln/invoice-malformed")
    b = decode(invoice)
    if isinstance(b, Refusal):
        return b
    d = invoice_h(b, "h")
    if isinstance(d, Refusal) or d != normal_hash(h):
        return Refusal("mpp/carrier-not-challenge")
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
        """The credential carrying the preimage, measured (measured) before the preimage's form is read, as bound
        measures a credential before it reads the payment."""
        payload: dict[str, Any] = (
            {"preimage": preimage}
            if self._pairing == MPP_CHARGE
            else {"action": _OPEN, "preimage": preimage, "returnInvoice": self._return_invoice}
        )
        credential = measured({"challenge": self._challenge, "payload": payload})
        if isinstance(credential, Refusal):
            return credential
        if not isinstance(preimage, str) or PREIMAGE.fullmatch(preimage) is None:
            return Refusal("ln/preimage-malformed")
        return credential


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
        invoice = _ln_invoice(self.id, request)
        return LnMppUnsigned(
            {"kind": "bolt11-pay", "invoice": invoice}, self.id, challenge, return_invoice
        )

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The echoed challenge's hash, held to the invoice the payer paid: the echoed challenge is held to the
        pairing's filter (echoed_for), which checks the invoice as build does, and the invoice's h is the hash the
        challenge's id derives from. On the session, only the open action is the session's payment. No signature is
        verified."""
        echoed = echoed_for(presented, self.id)
        if isinstance(echoed, Refusal):
            return echoed
        b = decode(_ln_invoice(self.id, echoed.checked.request))
        if isinstance(b, Refusal):
            return b
        d = invoice_h(b, "h")
        if isinstance(d, Refusal) or d != echoed.h:
            return Refusal("mpp/carrier-not-challenge")
        if self.id == MPP_SESSION and echoed.payload.get("action") != _OPEN:
            return Refusal("ln/no-payment-in-action")
        return echoed.h

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payer broadcasts: its node pays the invoice before the preimage is presented, and the seller's node,
        which received the payment, confirms it, for a credential within credential_shape's gate (mpp_broadcaster)."""
        return mpp_broadcaster(presented, lambda c: "payer")


def _session_broadcasts(c: Mapping[str, Any]) -> Broadcaster | Refusal:
    """Who broadcasts a Lightning session payment, by its action: the payer an opening, a bearer proof or a top-up; the
    seller's node the close. Any other action is ln/no-payment-in-action, as bound refuses it."""
    a = c["payload"].get("action")
    if a == _OPEN or a == "bearer" or a == "topUp":
        return "payer"
    return "payee" if a == "close" else Refusal("ln/no-payment-in-action")


# The one network name every Lightning session channel key carries: a bearer or close challenge names no invoice.
_SESSION_CHANNEL_NETWORK = "lightning"
_PAYMENT_HASH = re.compile(r"[0-9a-fA-F]{64}")


@dataclass(frozen=True, slots=True)
class MppLightningSession(MppLightning):
    """mpp/session/lightning: the MPP Lightning binding with the channel members of its session."""

    id: str = MPP_SESSION

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """By the payment's action, for the actions channel_kind takes (_session_broadcasts). "payer": the opening and a
        top-up, whose deposits the payer's node paid, and a bearer proof, which draws on them; the seller's node, which
        received each deposit, confirms it. "payee": the close, whose refund the seller's node pays. Any other action
        gets ln/no-payment-in-action, as bound refuses it."""
        return session_broadcaster(presented, self.channel_kind, _session_broadcasts, "ln/no-payment-in-action")

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
        """The session's id: the open's challenge paymentHash, else the payload's sessionId, as lowercase hex. The open
        is held as bound holds it (echoed_for), whose refusal it gives: H from the echoed challenge's id, the challenge's
        intent and method, which must be the session's, and the pairing's filter. A bearer, top-up or close payment is
        read from its payload alone."""
        kind = self.channel_kind(presented)
        if isinstance(kind, Refusal):
            return kind
        if kind == "open":
            held = echoed_for(presented, self.id)
            if isinstance(held, Refusal):
                return held
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
        """A bearer proof carries no hash; a topUp is within the session and is found by channel_ref."""
        return Refusal("mpp/not-bound-within")
