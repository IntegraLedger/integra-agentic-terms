"""The requests of the checkout protocols (terms' profile buyer-gate.md, rule 13): AP2's closed Checkout Mandate over
the merchant's checkout_jwt (ap2-checkout-mandate), the UCP checkout a mandate issuer signs over (ucp-checkout), the UCP
checkout a platform's signed request completes with the legal_context member (ucp-legal-context), and ACP's
delegated-payment allowance (acp-allowance). Each authorises a charge the seller's own processor makes, in a currency's
minor units, and the payment moves on no ledger, so the summary's network is None."""

import datetime
import re
from collections.abc import Mapping, Sequence
from typing import Any

from ._types import Payee, Refusal, Summary, Validity
from .bindings._jose import js_length
from .bindings._lcp import safe_int
from .bindings.ap2_checkout_mandate import checkout_hash_of, jws_payload

# The longest currency, merchant or account text read.
MAX_TEXT = 256
# The longest checkout JWT read: 1 MiB, the protocol package's bound on it.
MAX_JWT = 1_048_576
_HASH = re.compile(r"0x[0-9a-f]{64}")
_RFC3339 = re.compile(r"(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))")
_CHECKOUT_VCT = "mandate.checkout.1"
_NO_END = Validity(not_before=None, not_after=None, unit="seconds")
_EPOCH = datetime.date(1970, 1, 1).toordinal()


def _text(v: object) -> str | None:
    return v if isinstance(v, str) and 0 < js_length(v) <= MAX_TEXT else None


def _amount(v: object) -> str | None:
    n = safe_int(v)
    return str(n) if n is not None and n >= 0 else None


def _total(totals: object) -> str | None:
    """The amount of a checkout's one totals entry of type total, as a decimal string; else None."""
    if not isinstance(totals, Sequence) or isinstance(totals, (str, bytes, bytearray)):
        return None
    found = [t for t in totals if isinstance(t, Mapping) and t.get("type") == "total"]
    return _amount(found[0].get("amount")) if len(found) == 1 else None


def _checkout(c: object, named: bool) -> Summary | None:
    """A checkout's charge: the amount of its one total, in currency's minor units, paid to the merchant merchant.id
    names where named reads one, to no payee the request names otherwise. The checkout names no expiry, and the payment
    moves on no ledger: the network is None."""
    if not isinstance(c, Mapping):
        return None
    amount = _total(c.get("totals"))
    currency = _text(c.get("currency"))
    if amount is None or currency is None:
        return None
    payees: tuple[Payee, ...] = ()
    if named and "merchant" in c:
        merchant = c["merchant"]
        account = _text(merchant.get("id")) if isinstance(merchant, Mapping) else None
        if account is None:
            return None
        payees = (Payee(account=account, amount=amount),)
    return Summary(amount=amount, payees=payees, asset=currency, network=None, validity=_NO_END, atr=b"")


def ap2_checkout_mandate(
    request: Mapping[str, Any], network: str | None = None, opened: object = None
) -> Summary | None:
    """ap2-checkout-mandate: the closed Checkout Mandate's claims, content, which commit to the checkout by
    checkout_hash: its checkout_jwt is read only where checkout_hash is that JWT's hash, the base64url of its SHA-256,
    and its payload is the checkout read, the merchant merchant.id where it names one."""
    content = request.get("content")
    if request.get("kind") != "ap2-checkout-mandate" or not isinstance(content, Mapping):
        return None
    jwt = content.get("checkout_jwt")
    if content.get("vct") != _CHECKOUT_VCT or not isinstance(jwt, str) or js_length(jwt) > MAX_JWT:
        return None
    if checkout_hash_of(jwt) != content.get("checkout_hash"):
        return None
    payload = jws_payload(jwt)
    return None if isinstance(payload, Refusal) else _checkout(payload, True)


def ucp_checkout(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """ucp-checkout: the checkout the mandate issuer signs over."""
    return _checkout(request.get("checkout"), False) if request.get("kind") == "ucp-checkout" else None


def ucp_legal_context(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """ucp-legal-context: the checkout the platform's signed request completes, with the member {type, value}."""
    member = request.get("legal_context")
    if request.get("kind") != "ucp-legal-context" or not isinstance(member, Mapping):
        return None
    value = member.get("value")
    if member.get("type") != "sha256" or not isinstance(value, str) or _HASH.fullmatch(value) is None:
        return None
    return _checkout(request.get("checkout"), False)


def _unix_seconds(s: object) -> str | None:
    """An RFC 3339 date-time (section 5.6) as Unix seconds, a fraction of a second rounded up so the end is never read
    early; None for another text, a field out of its range, or a time before 1970."""
    m = _RFC3339.fullmatch(s) if isinstance(s, str) and len(s) <= 64 else None
    if m is None:
        return None
    y, mo, d, hh, mi, ss = (int(m.group(i)) for i in range(1, 7))
    try:
        days = datetime.date(y, mo, d).toordinal() - _EPOCH
    except ValueError:
        return None
    if hh > 23 or mi > 59 or ss > 60:
        return None
    offset = 0
    if m.group(8) is not None:
        oh, om = int(m.group(9)), int(m.group(10))
        if oh > 23 or om > 59:
            return None
        offset = (-1 if m.group(8) == "-" else 1) * (oh * 3600 + om * 60)
    fraction = 1 if m.group(7) is not None and re.search(r"[1-9]", m.group(7)) else 0
    t = days * 86_400 + hh * 3600 + mi * 60 + ss - offset + fraction
    return str(t) if 0 <= t <= 2**53 - 1 else None


def acp_allowance(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """acp-allowance: ACP's allowance, the most the merchant may charge: max_amount, in currency's minor units, to
    merchant_id, until expires_at."""
    a = request.get("allowance")
    if request.get("kind") != "acp-allowance" or not isinstance(a, Mapping):
        return None
    maximum, until = _amount(a.get("max_amount")), _unix_seconds(a.get("expires_at"))
    currency, merchant = _text(a.get("currency")), _text(a.get("merchant_id"))
    if maximum is None or until is None or currency is None or merchant is None:
        return None
    return Summary(
        maximum=maximum,
        payees=(Payee(account=merchant, amount=maximum),),
        asset=currency,
        network=None,
        validity=Validity(not_before=None, not_after=until, unit="seconds"),
        atr=b"",
    )
