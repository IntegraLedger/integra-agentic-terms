"""The card requests (terms' profile buyer-gate.md, rule 13): tap-field, vic-reference, vi-checkout and
vi-checkout-mandate. None signs a transfer of value: the card charge is the seller's, made through the card network, and
the payment moves on no ledger, so the summary's network is None; nothing in the request names the charge's amount, its
payee or its currency, so the summary names no amount and no payee, and its asset is the empty string. Nor does the
request name an expiry: the agent's signer or the user's wallet sets the signature's own, so the request signs no end. A
Verifiable Intent request grants the checkout its signature binds, shown as grant: the agent's checkout payload, or the
payload of the checkout_jwt the checkout mandate names."""

import copy
from collections.abc import Mapping
from typing import Any

from ._types import Summary, Validity
from .bindings._jose import decode_json_segment, js_length
from .bindings.card import MAX_CHECKOUT_JWT


def _nothing_named(grant: Any = None) -> Summary:
    """What every card request shows, made anew for each: no amount, payee or currency named, no ledger, and no end
    signed; its atr is filled by the gate."""
    return Summary(
        payees=(),
        asset="",
        network=None,
        validity=Validity(not_before=None, not_after=None, unit="seconds"),
        grant=grant,
        atr=b"",
    )


def _text(v: object) -> bool:
    """A non-empty string no longer than the longest checkout_jwt the protocol package reads."""
    return isinstance(v, str) and v != "" and js_length(v) <= MAX_CHECKOUT_JWT


def tap_field(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """tap-field, the nonce for the agent's message signatures: card/visa-tap, card/mastercard-agent-pay."""
    return _nothing_named() if request.get("kind") == "tap-field" and _text(request.get("nonce")) else None


def vic_reference(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """vic-reference, the transaction reference for the agent's credential request: card/visa-vic."""
    ok = request.get("kind") == "vic-reference" and _text(request.get("transactionReferenceId"))
    return _nothing_named() if ok else None


def vi_checkout(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """vi-checkout, the agent's checkout payload for its checkout_jwt: its grant is the payload, a copy, so nothing the
    approver does to the summary reaches the request the signer is handed."""
    checkout = request.get("checkout")
    if request.get("kind") != "vi-checkout" or not isinstance(checkout, Mapping):
        return None
    return _nothing_named(copy.deepcopy(dict(checkout)))


def vi_checkout_mandate(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """vi-checkout-mandate, the checkout mandate for the user's L2 or the agent's L3b: its grant is the payload of the
    checkout_jwt it names, its second segment as canonical base64url of UTF-8 JSON naming an object."""
    m = request.get("checkoutMandate")
    if request.get("kind") != "vi-checkout-mandate" or not isinstance(m, Mapping) or not _text(request.get("transactionId")):
        return None
    jwt = m.get("checkout_jwt")
    if m.get("vct") != "mandate.checkout.1" or not _text(jwt) or not _text(m.get("checkout_hash")):
        return None
    assert isinstance(jwt, str)
    parts = jwt.split(".")
    if len(parts) != 3:
        return None
    payload = decode_json_segment(parts[1])
    return _nothing_named(payload) if isinstance(payload, dict) else None


def vi_immediate(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """card/mastercard-vi/immediate: the agent's checkout payload, or the checkout mandate for the user's L2."""
    return vi_checkout(request) or vi_checkout_mandate(request)
