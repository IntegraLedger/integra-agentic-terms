"""The buyer halves of the ACP pairings acp/checkout/delegated and acp/checkout/undelegated: read, build with
complete, and bound.

The ATR hash is the checkout session's id, with the link beside it in the session's metadata.legal_context, and,
where the handler requires delegate_payment, the allowance's checkout_session_id. Nothing here signs or verifies a
signature.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Json, Refusal
from ._codec import canonical_or_none
from ._jose import js_length, json_bytes
from ._lcp import (
    AgreementFault,
    MAX_SAFE_INTEGER,
    agreement_in,
    is_hash_with_non_https_link,
    is_object,
    legal_context_info,
    normal_hash,
)

DELEGATED = "acp/checkout/delegated"
UNDELEGATED = "acp/checkout/undelegated"
METADATA_KEY = "legal_context"
MAX_SESSION_BYTES = 1_048_576
HASH_LENGTH = 66
MAX_LINK = 2048
MAX_MERCHANT_ID = 256
MAX_EXPIRES_AT = 64
_CURRENCY = re.compile(r"[a-z]{3}")
_DATE_TIME = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?([Zz]|([+-])([0-9]{2}):([0-9]{2}))"
)
ALLOWANCE_MEMBERS = ("reason", "max_amount", "currency", "checkout_session_id", "merchant_id", "expires_at")


def _is_safe_uint(value: object) -> bool:
    """A JSON number holding a non-negative safe integer."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return 0 <= value <= MAX_SAFE_INTEGER


def _days_in(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def is_rfc3339_date_time(text: str) -> bool:
    """RFC 3339 date-time: full-date "T" full-time, with a time offset, and each field in its range."""
    m = _DATE_TIME.fullmatch(text)
    if m is None:
        return False
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if month < 1 or month > 12 or day < 1 or day > _days_in(year, month):
        return False
    if int(m.group(4)) > 23 or int(m.group(5)) > 59 or int(m.group(6)) > 60:
        return False
    if m.group(9) is not None and (int(m.group(10)) > 23 or int(m.group(11)) > 59):
        return False
    return True


def _is_allowance(a: object) -> bool:
    """Exactly ACP's six allowance members, with reason one_time, strings, and a non-negative safe integer amount."""
    if not is_object(a):
        return False
    if len(a) != len(ALLOWANCE_MEMBERS) or not all(k in a for k in ALLOWANCE_MEMBERS):
        return False
    return (
        a["reason"] == "one_time"
        and _is_safe_uint(a["max_amount"])
        and isinstance(a["currency"], str)
        and isinstance(a["checkout_session_id"], str)
        and isinstance(a["merchant_id"], str)
        and isinstance(a["expires_at"], str)
    )


def _read(doc: object) -> Advertised | Refusal:
    """The hash from id, and the link and, when present, the agreement URL from metadata.legal_context, whose value
    must decode to the same 32 bytes. No other place is read."""
    if not is_object(doc):
        return Refusal("acp/session-malformed")
    size = json_bytes(doc)
    if size is None:
        return Refusal("acp/session-malformed")
    if size > MAX_SESSION_BYTES:
        return Refusal("acp/too-large")
    session_id = doc.get("id")
    if isinstance(session_id, str) and js_length(session_id) > HASH_LENGTH:
        return Refusal("acp/too-large")
    h = normal_hash(session_id)
    if h is None:
        return Refusal("acp/id-not-hash")
    metadata = doc.get("metadata")
    if not is_object(metadata) or METADATA_KEY not in metadata:
        return Refusal("acp/no-legal-context")
    lc = metadata[METADATA_KEY]
    decoded = legal_context_info(lc)
    if decoded is None:
        return Refusal("acp/link-not-https" if is_hash_with_non_https_link(lc) else "acp/legal-context-malformed")
    if js_length(decoded[1]) > MAX_LINK:
        return Refusal("acp/legal-context-malformed")
    if not hash_equals(decoded[0], h):
        return Refusal("acp/legal-context-conflict")
    agreement = agreement_in(lc)
    if isinstance(agreement, AgreementFault):
        return Refusal(f"acp/{agreement.fault}")
    return Advertised(
        h=h, link=decoded[1], offer={"session": doc}, agreement=agreement if isinstance(agreement, str) else None
    )


@dataclass(frozen=True, slots=True)
class AcpUnsigned:
    """The allowance the agent's delegate_payment request carries."""

    allowance: dict[str, Any]
    _kept: str = field(repr=False)

    def complete(self, request: object) -> Any:
        """The request, only when its allowance is the one built."""
        if not is_object(request):
            return Refusal("acp/allowance-changed")
        given = canonical_or_none(request.get("allowance"))
        if given is None or given != self._kept:
            return Refusal("acp/allowance-changed")
        return request


@dataclass(frozen=True, slots=True)
class AcpCheckoutDelegated:
    id: str = DELEGATED
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Json, h: AtrHash) -> AcpUnsigned | Refusal:
        """The allowance from the buyer's own values, in ACP's order, with checkout_session_id = h."""
        if not is_object(choice):
            return Refusal("acp/choice-malformed")
        session = choice.get("session")
        session_id = session.get("id") if isinstance(session, Mapping) else None
        nh = normal_hash(h)
        if nh is None or not isinstance(session_id, str) or not hash_equals(session_id, nh):
            return Refusal("acp/hash-not-session")
        max_amount = choice.get("max_amount")
        currency = choice.get("currency")
        merchant_id = choice.get("merchant_id")
        expires_at = choice.get("expires_at")
        if isinstance(merchant_id, str) and js_length(merchant_id) > MAX_MERCHANT_ID:
            return Refusal("acp/too-large")
        if isinstance(expires_at, str) and js_length(expires_at) > MAX_EXPIRES_AT:
            return Refusal("acp/too-large")
        if (
            not _is_safe_uint(max_amount)
            or not isinstance(currency, str)
            or _CURRENCY.fullmatch(currency) is None
            or not isinstance(merchant_id, str)
            or merchant_id == ""
            or not isinstance(expires_at, str)
            or not is_rfc3339_date_time(expires_at)
        ):
            return Refusal("acp/choice-malformed")
        built = {
            "reason": "one_time",
            "max_amount": max_amount,
            "currency": currency,
            "checkout_session_id": nh,
            "merchant_id": merchant_id,
            "expires_at": expires_at,
        }
        kept = canonical_or_none(built)
        if kept is None:
            return Refusal("acp/choice-malformed")
        return AcpUnsigned(dict(built), kept)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The allowance's checkout_session_id, lowercase. No signature is verified."""
        if not is_object(presented):
            return Refusal("acp/allowance-malformed")
        a = presented.get("allowance")
        if not _is_allowance(a):
            return Refusal("acp/allowance-malformed")
        assert is_object(a)
        h = normal_hash(a["checkout_session_id"])
        return h if h is not None else Refusal("acp/id-not-hash")


@dataclass(frozen=True, slots=True)
class AcpCheckoutUndelegated:
    id: str = UNDELEGATED
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Json, h: AtrHash) -> Refusal:
        return Refusal("acp/nothing-to-sign")

    def bound(self, presented: Json) -> Refusal:
        return Refusal("acp/not-buyer-signed")
