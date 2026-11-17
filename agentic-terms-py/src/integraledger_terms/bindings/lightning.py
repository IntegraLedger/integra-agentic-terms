"""The buyer halves of the Lightning pairings: read, build with complete, and bound.

On x402/exact/lnbtc/payment-hash the ATR commits the option's extra.paymentHash, the payment hash of the invoice the
seller's node issues after the agreement. On MPP the seller's node writes the ATR hash as the invoice's description hash
h. The payer signs nothing; it pays the invoice.
"""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash, hash_equals
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._bolt11 import Bolt11, Currency, FIELD, decode, invoice_h
from ._codec import canonical_or_none, utf16_key
from ._jose import js_length
from ._secp256k1 import point_of
from ._x402 import (
    OptionFilter,
    chosen,
    is_amount,
    legal_context_of,
    payment_with,
    presented_with,
    read_for,
    timeout_seconds,
    x402_broadcaster,
)
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
from ._lcp import is_object, normal_hash, safe_int

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
    agreement_on: str | None = "any"

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


# ── x402/exact/lnbtc/payment-hash ──

LNBTC = "x402/exact/lnbtc/payment-hash"
# x402's lnbtc networks, mainnet and testnet3, with the BOLT 11 currency of each.
LNBTC_NETWORKS: Mapping[str, Currency] = {
    "lnbtc:000000000019d6689c085ae165831e93": "bc",
    "lnbtc:000000000933ea01ad0ee984209779ba": "tb",
}
# The scheme's default clock-skew allowance, in seconds.
SKEW_SECONDS = 60
# lcp's MAX_REQUEST_BYTES: a body, a bound field's value and the binding object's RFC 8785 form, each at most this long.
MAX_REQUEST_BYTES = 1_048_576
# The most names lcp reads in one requestBindingParams list, and the longest URL or URI it reads in a request binding.
MAX_BOUND_NAMES = 64
MAX_URI = 8192
_PAY_TO = re.compile(r"[0-9a-f]{66}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_POSITIVE = re.compile(r"[1-9][0-9]{0,77}")
# RFC 9110 section 5.1's token, its letters lower-case: a bound header's name as the scheme's http:1 writes it.
_LOWER_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9a-z]+")
# RFC 9110 section 9.1: a method is a token.
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_URI_CHARS = re.compile(r"[\x21-\x7e]+")
_URI = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):(.*)", re.DOTALL)
_AUTHORITY = re.compile(r"//([^/?]*)")
_FIELD_LINE = re.compile(r"[\t\x20-\x7e]*")
_HTTP_DOMAIN = "x402:exact:lnbtc:bolt11:http:1"
_MCP_DOMAIN = "x402:exact:lnbtc:bolt11:mcp:1"


def _is_pay_to(v: object) -> bool:
    """66 lowercase hex digits encoding a valid compressed secp256k1 public key."""
    if not isinstance(v, str) or _PAY_TO.fullmatch(v) is None or v[:2] not in ("02", "03"):
        return False
    return point_of(int(v[2:], 16), v[:2] == "03") is not None


def _is_lnbtc(o: object) -> bool:
    """An exact option on one of x402's two lnbtc networks."""
    return is_object(o) and o.get("scheme") == "exact" and isinstance(o.get("network"), str) and o["network"] in LNBTC_NETWORKS


def _bound_params(profile: object, params: object) -> bool:
    """profile is http:1 or mcp:1 and params holds exactly that profile's parameters in the scheme's form: on http:1,
    headers, lower-case field names in ascending order, no duplicates, payment-signature not among them; on mcp:1,
    server, an absolute URI with no user information or fragment, and metadata, non-empty names in RFC 8785's member
    order, no duplicates, neither x402/payment nor progressToken among them."""
    if not is_object(params):
        return False
    keys = sorted(params)
    if profile == "http:1":
        return keys == ["headers"] and _sorted_names(params["headers"], lambda n: _LOWER_TOKEN.fullmatch(n) is not None and n != "payment-signature")
    if profile == "mcp:1":
        return (
            keys == ["metadata", "server"]
            and _absolute_uri(params["server"], False)
            and _sorted_names(params["metadata"], lambda n: n != "" and n not in ("x402/payment", "progressToken"))
        )
    return False


def _sorted_names(names: object, ok: Any) -> bool:
    """At most 64 distinct strings, each ok, in ascending order of UTF-16 code units."""
    if not isinstance(names, list) or len(names) > MAX_BOUND_NAMES:
        return False
    if not all(isinstance(n, str) and ok(n) for n in names):
        return False
    return all(utf16_key(names[i - 1]) < utf16_key(names[i]) for i in range(1, len(names)))


def _absolute_uri(v: object, http: bool) -> bool:
    """An absolute URI in ASCII syntax of at most 8,192 characters with no fragment and no user information; with http,
    one whose scheme is http or https and whose authority is not empty."""
    if not isinstance(v, str) or len(v) > MAX_URI or _URI_CHARS.fullmatch(v) is None or "#" in v:
        return False
    m = _URI.fullmatch(v)
    if m is None:
        return False
    rest = m.group(2)
    a = _AUTHORITY.match(rest) if rest.startswith("//") else None
    authority = a.group(1) if a is not None else None
    if authority is not None and "@" in authority:
        return False
    if not http:
        return True
    return m.group(1).lower() in ("http", "https") and authority is not None and len(authority) > 0


def _value_hash(data: bytes | None) -> str:
    """SHA-256 of 0x01 and the bytes, or of the single byte 0x00 where the value is absent, as lowercase hex."""
    return hashlib.sha256(b"\x00" if data is None else b"\x01" + data).hexdigest()


def _field_value(record: Mapping[str, Any], name: str) -> str | None | Literal[False]:
    """The field's value by RFC 9421 section 2.1's default rules: each line without its leading and trailing spaces
    and tabs, the lines joined by a comma and a space; None where the field is absent. False where two keys name the
    field, a value is not a string or a list of strings, it holds a character outside visible ASCII, the space and the
    tab, or the joined value is over 1 MiB."""
    keys = [k for k in record if isinstance(k, str) and k.lower() == name]
    if len(keys) > 1:
        return False
    if not keys:
        return None
    v = record[keys[0]]
    lines = [v] if isinstance(v, str) else v if isinstance(v, list) else None
    if lines is None or not all(isinstance(line, str) for line in lines):
        return False
    if not lines:
        return None
    if not all(_FIELD_LINE.fullmatch(line) for line in lines):
        return False
    joined = ", ".join(line.strip(" \t") for line in lines)
    return False if len(joined) > MAX_REQUEST_BYTES else joined


def request_hash(profile: object, params: object, request: object, resource_url: object) -> str | Refusal:
    """The scheme's request hash of the buyer's request under profile and params, as 64 lowercase hex digits: SHA-256
    of the UTF-8 of RFC 8785's form of the profile's binding object (lcp's requestHash). ln/request-hash-mismatch where
    the request is not of profile, where on http:1 resource_url is not the request's URL, or on mcp:1 the option's server
    is not the request's; ln/request-binding-malformed where params are not the profile's or the request cannot be
    bound. The request is {profile: "http:1", method, url, body, headers?}, body bytes, or {profile: "mcp:1", server,
    name, arguments?, meta?}."""
    malformed = Refusal("ln/request-binding-malformed")
    if not _bound_params(profile, params):
        return malformed
    if not is_object(request) or request.get("profile") != profile:
        return Refusal("ln/request-hash-mismatch")
    assert is_object(params)
    binding: dict[str, Any]
    if profile == "http:1":
        method, url, body = request.get("method"), request.get("url"), request.get("body")
        if not isinstance(method, str) or _TOKEN.fullmatch(method) is None or not _absolute_uri(url, True):
            return malformed
        if not isinstance(body, (bytes, bytearray)) or len(body) > MAX_REQUEST_BYTES:
            return malformed
        if "headers" in request and not is_object(request["headers"]):
            return malformed
        if resource_url != url:
            return Refusal("ln/request-hash-mismatch")
        headers = request.get("headers") or {}
        bound: list[Any] = []
        for name in params["headers"]:
            value = _field_value(headers, name)
            if value is False:
                return malformed
            bound.append({"name": name, "valueHash": _value_hash(None if value is None else value.encode("ascii"))})
        binding = {"bodyHash": hashlib.sha256(bytes(body)).hexdigest(), "domain": _HTTP_DOMAIN, "headers": bound, "method": method, "url": url}
    else:
        server, name = request.get("server"), request.get("name")
        if server != params["server"]:
            return Refusal("ln/request-hash-mismatch")
        if not isinstance(name, str) or name == "":
            return malformed
        args, meta = request.get("arguments"), request.get("meta")
        if ("arguments" in request and not is_object(args)) or ("meta" in request and not is_object(meta)):
            return malformed
        given: Mapping[str, Any] = meta if is_object(meta) else {}
        bound = []
        for n in params["metadata"]:
            if n not in given:
                bound.append({"name": n, "valueHash": _value_hash(None)})
                continue
            text = canonical_or_none(given[n])
            if text is None:
                return malformed
            bound.append({"name": n, "valueHash": _value_hash(text.encode("utf-8"))})
        binding = {
            "arguments": dict(args) if is_object(args) else {},
            "domain": _MCP_DOMAIN,
            "metadata": bound,
            "method": "tools/call",
            "name": name,
            "server": params["server"],
        }
    text = canonical_or_none(binding)
    if text is None or js_length(text) > MAX_REQUEST_BYTES:
        return malformed
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _option_members(o: Mapping[str, Any]) -> Refusal | None:
    """The checks of the option's own members (lcp profile x402-exact-lnbtc.md, rule 6, a to c): asset BTC, amount a
    positive integer of at most 78 digits, maxTimeoutSeconds a positive safe integer, payTo a valid compressed secp256k1
    key as 66 lowercase hex digits, extra an object with paymentFlow upfront and assetTransferMethod absent or bolt11
    (x402/option-malformed); extra.paymentHash 64 lowercase hex digits (ln/payment-hash-required); extra.requestHash 64
    lowercase hex digits (ln/request-hash-mismatch); and the request binding's profile and parameters in the scheme's
    form (ln/request-binding-malformed)."""
    extra = o.get("extra")
    amount = o.get("amount")
    if (
        not is_object(extra)
        or extra.get("paymentFlow") != "upfront"
        or ("assetTransferMethod" in extra and extra["assetTransferMethod"] != "bolt11")
        or o.get("asset") != "BTC"
        or not is_amount(amount)
        or _POSITIVE.fullmatch(amount) is None
        or timeout_seconds(o.get("maxTimeoutSeconds")) is None
        or not _is_pay_to(o.get("payTo"))
    ):
        return Refusal("x402/option-malformed")
    payment_hash, request_hash_ = extra.get("paymentHash"), extra.get("requestHash")
    if not isinstance(payment_hash, str) or _HEX64.fullmatch(payment_hash) is None:
        return Refusal("ln/payment-hash-required")
    if not isinstance(request_hash_, str) or _HEX64.fullmatch(request_hash_) is None:
        return Refusal("ln/request-hash-mismatch")
    if not _bound_params(extra.get("requestBindingProfile"), extra.get("requestBindingParams")):
        return Refusal("ln/request-binding-malformed")
    return None


def option_checks(o: Mapping[str, Any]) -> Bolt11 | Refusal:
    """The checks of an option with its invoice (lcp profile x402-exact-lnbtc.md, rule 6, a to k), in this order: the
    option's own members; the invoice decoded strictly; exactly one h and no d (ln/no-description-hash,
    ln/field-repeated, ln/description-inline); the h field the request hash (ln/request-hash-mismatch); the signing key
    payTo (ln/signer-not-payee); the currency the network's (ln/currency-network); the amount amount
    (ln/amount-mismatch); the expiry maxTimeoutSeconds (ln/expiry-mismatch); and the invoice's p extra.paymentHash
    (ln/payment-hash-mismatch). No clock and no request is read."""
    members = _option_members(o)
    if members is not None:
        return members
    extra = o["extra"]
    s = decode(extra.get("invoice"))
    if isinstance(s, Refusal):
        return s
    d = invoice_h(s, "h")
    if isinstance(d, Refusal):
        return d
    if FIELD["d"] in s.tags:
        return Refusal("ln/description-inline")
    if d != "0x" + extra["requestHash"]:
        return Refusal("ln/request-hash-mismatch")
    if s.signer != o["payTo"]:
        return Refusal("ln/signer-not-payee")
    if LNBTC_NETWORKS[o["network"]] != s.currency:
        return Refusal("ln/currency-network")
    if s.amount_msat is None or str(s.amount_msat) != o["amount"]:
        return Refusal("ln/amount-mismatch")
    if s.expiry != timeout_seconds(o["maxTimeoutSeconds"]):
        return Refusal("ln/expiry-mismatch")
    return s if s.payment_hash.hex() == extra["paymentHash"] else Refusal("ln/payment-hash-mismatch")


def _lnbtc_filter(o: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """The option filter: an exact option on an lnbtc network is served where it carries its invoice and passes
    option_checks, and refused with their refusal otherwise."""
    if not _is_lnbtc(o):
        return None
    s = option_checks(o)
    return s if isinstance(s, Refusal) else True


_LNBTC_FILTER: OptionFilter = _lnbtc_filter


def check_preimage(preimage: object, payment_hash: object) -> Literal[True] | Refusal:
    """True where preimage is 64 lowercase hex digits whose SHA-256 is payment_hash, itself 64 lowercase hex digits;
    else ln/preimage-malformed, ln/payment-hash-required or ln/preimage-mismatch, in that order."""
    if not isinstance(preimage, str) or _HEX64.fullmatch(preimage) is None:
        return Refusal("ln/preimage-malformed")
    if not isinstance(payment_hash, str) or _HEX64.fullmatch(payment_hash) is None:
        return Refusal("ln/payment-hash-required")
    return True if hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == payment_hash else Refusal("ln/preimage-mismatch")


def without_invoice(option: object) -> object:
    """The option without extra.invoice, the member the seller's node writes after the agreement, so the ATR's slot
    holds the option with its extra.paymentHash and no invoice. An option that carries a refused member is
    x402/option-malformed; a value that is not an object, or an option with no invoice, comes back as it is."""
    if is_object(option) and "refused" in option:
        return Refusal("x402/option-malformed")
    if not is_object(option) or not is_object(option.get("extra")) or "invoice" not in option["extra"]:
        return option
    extra = {k: v for k, v in option["extra"].items() if k != "invoice"}
    return {**option, "extra": extra}


@dataclass(frozen=True, slots=True)
class LnbtcUnsigned:
    """The invoice the payer's node pays exactly, and the payment its preimage completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _payment_hash: str

    def complete(self, preimage: object) -> dict[str, Any] | Refusal:
        """The payment {x402Version: 2, resource, accepted, payload: {preimage}, extensions}, once the preimage is 64
        lowercase hex digits (ln/preimage-malformed) whose SHA-256 is the invoice's p (ln/preimage-mismatch)."""
        checked = check_preimage(preimage, self._payment_hash)
        if isinstance(checked, Refusal):
            return checked
        return payment_with(self._required, self._accepted, {"preimage": preimage})


@dataclass(frozen=True, slots=True)
class X402ExactLnbtcPaymentHash:
    """x402/exact/lnbtc/payment-hash. The payer broadcasts: its node pays the invoice before the preimage is presented.
    No ledger shows the payment."""

    id: str = LNBTC
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "any"

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(_LNBTC_FILTER)(doc)

    def unplaced(self, option: object) -> object:
        return without_invoice(option)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> LnbtcUnsigned | Refusal:
        """What the buyer's node pays, after the scheme's client checks: H is a valid ATR hash (x402/payload-malformed);
        now is a non-negative safe integer (ln/time-malformed); the option is the document's and passes the filter; H
        is the document's (x402/legal-context-conflict); the request hash of the buyer's request is extra.requestHash
        (request_hash's refusals); the invoice's creation time is no later than now plus 60 s (ln/created-in-future)
        and its creation time plus its expiry is later than now (ln/invoice-expired)."""
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        if not is_object(choice):
            return Refusal("x402/not-v2")
        now = safe_int(choice.get("now"))
        if now is None or now < 0:
            return Refusal("ln/time-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, _LNBTC_FILTER)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        lc = legal_context_of(required.get("extensions"))
        if isinstance(lc, Refusal):
            return lc
        if normal_hash(lc[0]) != nh:
            return Refusal("x402/legal-context-conflict")
        s = option_checks(accepted)
        assert not isinstance(s, Refusal)
        extra = accepted["extra"]
        resource = required.get("resource")
        want = request_hash(
            extra.get("requestBindingProfile"),
            extra.get("requestBindingParams"),
            choice.get("request"),
            resource.get("url") if is_object(resource) else None,
        )
        if isinstance(want, Refusal):
            return want
        if want != extra["requestHash"]:
            return Refusal("ln/request-hash-mismatch")
        if s.timestamp > now + SKEW_SECONDS:
            return Refusal("ln/created-in-future")
        if s.timestamp + s.expiry <= now:
            return Refusal("ln/invoice-expired")
        return LnbtcUnsigned({"kind": "bolt11-pay", "invoice": extra["invoice"]}, required, accepted, s.payment_hash.hex())

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """The H the payment's echoed extensions.legalContext names, once the presented accepted passes the filter (so
        its invoice's p is the echoed extra.paymentHash) and the preimage is 64 lowercase hex digits
        (ln/preimage-malformed) whose SHA-256 is that p (ln/preimage-mismatch). The echoed H only locates the sale,
        whose ATR commits the echoed payment hash. No ledger is read."""
        p = presented_with(presented, _LNBTC_FILTER)
        if isinstance(p, Refusal):
            return p
        accepted, payload, extensions = p
        s = option_checks(accepted)
        assert not isinstance(s, Refusal)
        checked = check_preimage(payload.get("preimage"), s.payment_hash.hex())
        if isinstance(checked, Refusal):
            return checked
        lc = legal_context_of(extensions)
        return lc if isinstance(lc, Refusal) else lc[0]

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payer broadcasts: its node pays the invoice before the preimage is presented, for a payment within
        x402_shape's gate."""
        return x402_broadcaster(presented, "payer")
