"""The buyer halves of the Lightning pairings on MPP: read, build with complete, and bound.

The seller's node writes the ATR hash as the invoice's description hash h. The payer signs nothing; it pays the invoice.
No signature is verified here.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._bolt11 import Bolt11, decode, invoice_h
from ._channel import ChannelKind, ChannelRef
from ._mpp import (
    check_challenge,
    chosen_held,
    credential_of,
    echoed_for,
    measured,
    measuring,
    mpp_broadcaster,
    session_broadcaster,
)
from ._mpp import read as mpp_read
from ._mpp_checks import decode_object
from ._lcp import is_object, normal_hash

PREIMAGE = re.compile(r"[0-9a-f]{64}")


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
    coverage: Coverage = "none"
    agreement: AgreementData | None = None

    def read(self, doc: Json) -> Advertised | Refusal:
        return mpp_read(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> LnMppUnsigned | Refusal:
        """The payment of the chosen challenge's invoice. A choice that is not an object is mpp/credential-malformed.
        The challenge is held as bound holds an echoed one, with bound's code for each fault, in bound's order
        (chosen_held), then its invoice as bound reads it (_ln_challenge_checks), whose h must be the hash the
        challenge's id derives from (mpp/carrier-not-challenge); an id that derives from a hash other than h is then
        mpp/id-not-ours. The challenge is read from the snapshot chosen_held returns, which the credential carries."""
        if not is_object(choice):
            return Refusal("mpp/credential-malformed")
        held = chosen_held(choice.get("challenge"), self.id)
        if isinstance(held, Refusal):
            return held
        held_h, checked = held
        challenge = dict(checked.challenge)
        b = _ln_challenge_checks(self.id, challenge, held_h, True)
        if isinstance(b, Refusal):
            return b
        if not isinstance(h, str) or not hash_equals(held_h, h):
            return Refusal("mpp/id-not-ours")
        return_invoice = choice.get("returnInvoice")
        if self.id == MPP_SESSION and not _amountless(return_invoice):
            return Refusal("ln/return-invoice-malformed")
        invoice = _ln_invoice(self.id, checked.request)
        return LnMppUnsigned(
            {"kind": "bolt11-pay", "invoice": invoice}, self.id, challenge, return_invoice
        )

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
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

    @measuring
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

    @measuring
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

    @measuring
    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A bearer proof carries no hash; a topUp is within the session and is found by channel_ref."""
        return Refusal("mpp/not-bound-within")
