"""The return after an agreement (lcp profile legal-context-return.md; terms' profile buyer-gate.md, rule 12): the
Legal-Context value read and written as the protocol package reads and writes it (fromLegalContextHeader,
toLegalContextHeader), an agreement option's serves (servesOf), and transact's path for a first response that offers
the agreement and no charge option: it pays the agreement, chosen by the charge it serves, and returns ToReturn."""

import asyncio
import base64
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

import httpx

from . import _agreement, _gate
from ._checks import Approval, request_held
from ._core import AtrHash, atr_hash, hash_equals
from ._parse import parse_atr
from ._types import (
    Advertised,
    Agreed,
    AgreementPayment,
    Binding,
    Declined,
    Refusal,
    ResourceRequest,
    Signer,
    ToApprove,
    ToReturn,
)
from .bindings._lcp import from_lcp_string, is_https_link, is_other_scheme_link, normal_hash, to_lcp_string
from .bindings._mpp_checks import decode_string_map
from .bindings._x402 import MAX_OPTIONS

LEGAL_CONTEXT_SERVES = "legalContextServes"
RETURN_VALUE_BYTES = 32

_LCP_TOKEN = re.compile(r"lcp:sha256:0x[0-9a-f]{64}")
_SERVED = re.compile(r"(?:x402|mpp)/(?:[0-9]|[12][0-9]|3[01])")
_MAX_SERVED = 32
_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_TOKEN_CHAR = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z:/]")
_KEY_CHAR = re.compile(r"[a-z0-9_\-.*]")
_LOWER_HEX = "0123456789abcdef"
_MALFORMED = Refusal("return/header-malformed")


def _at(s: str, i: int) -> str:
    return s[i] if 0 <= i < len(s) else ""


def _skip_spaces(s: str, i: int) -> int:
    while _at(s, i) == " ":
        i += 1
    return i


def _token_at(s: str, i: int) -> int:
    c = _at(s, i)
    if not (c.isascii() and c.isalpha() or c == "*"):
        return -1
    j = i + 1
    while _at(s, j) and _TOKEN_CHAR.fullmatch(_at(s, j)):
        j += 1
    return j


def _key_at(s: str, i: int) -> int:
    c = _at(s, i)
    if not ("a" <= c <= "z" or c == "*"):
        return -1
    j = i + 1
    while _at(s, j) and _KEY_CHAR.fullmatch(_at(s, j)):
        j += 1
    return j


def _number_at(s: str, i: int, decimal: bool) -> int:
    j = i + 1 if _at(s, i) == "-" else i
    start = j
    while "0" <= _at(s, j) <= "9" and _at(s, j):
        j += 1
    whole = j - start
    if whole == 0:
        return -1
    if _at(s, j) != ".":
        return -1 if whole > 15 else j
    if not decimal or whole > 12:
        return -1
    point = j
    j += 1
    while "0" <= _at(s, j) <= "9" and _at(s, j):
        j += 1
    fraction = j - point - 1
    return -1 if fraction == 0 or fraction > 3 else j


def _byte_sequence(text: str) -> bytes | None:
    body = text
    if len(body) % 4 == 0:
        body = re.sub(r"={1,2}$", "", body)
    if len(body) % 4 == 1 or any(ch not in _BASE64 for ch in body):
        return None
    spare = (len(body) * 6) % 8
    if spare:
        last = _BASE64.index(body[-1]) & ~((1 << spare) - 1)
        body = body[:-1] + _BASE64[last]
    return base64.b64decode(body + "=" * ((4 - len(body) % 4) % 4))


def _display_at(s: str, i: int) -> int:
    if _at(s, i + 1) != '"':
        return -1
    out = bytearray()
    j = i + 2
    while j < len(s):
        d = ord(s[j])
        if d < 0x20 or d > 0x7E:
            return -1
        if d == 0x25:
            hx = s[j + 1 : j + 3]
            if len(hx) != 2 or hx[0] not in _LOWER_HEX or hx[1] not in _LOWER_HEX:
                return -1
            out.append(int(hx, 16))
            j += 3
            continue
        if d == 0x22:
            try:
                bytes(out).decode("utf-8")
            except UnicodeDecodeError:
                return -1
            return j + 1
        out.append(d)
        j += 1
    return -1


def _bare_item_at(s: str, i: int) -> tuple[bytes | None, int] | None:
    """A bare item at i (RFC 9651): its bytes where it is a byte sequence, else None, and the index after it."""
    c = _at(s, i)
    if not c:
        return None
    if c == "-" or "0" <= c <= "9":
        end = _number_at(s, i, True)
        return None if end == -1 else (None, end)
    if c == '"':
        j = i + 1
        while j < len(s):
            d = ord(s[j])
            if d == 0x5C:
                if _at(s, j + 1) not in ('"', "\\") or not _at(s, j + 1):
                    return None
                j += 2
                continue
            if d == 0x22:
                return None, j + 1
            if d < 0x20 or d > 0x7E:
                return None
            j += 1
        return None
    if c == ":":
        close = s.find(":", i + 1)
        if close == -1:
            return None
        data = _byte_sequence(s[i + 1 : close])
        return None if data is None else (data, close + 1)
    if c == "?":
        return (None, i + 2) if _at(s, i + 1) in ("0", "1") and _at(s, i + 1) else None
    if c == "@":
        end = _number_at(s, i + 1, False)
        return None if end == -1 else (None, end)
    if c == "%":
        end = _display_at(s, i)
        return None if end == -1 else (None, end)
    end = _token_at(s, i)
    return None if end == -1 else (None, end)


def from_legal_context_header(value: object) -> tuple[AtrHash, bytes | None] | Refusal:
    """lcp's fromLegalContextHeader: H's LCP string as an sf-token, with at most the parameter rv, a byte sequence of 32
    bytes; H and the return value, or return/header-malformed."""
    if not isinstance(value, str):
        return _MALFORMED
    i = _skip_spaces(value, 0)
    token_end = _token_at(value, i)
    if token_end == -1:
        return _MALFORMED
    token = value[i:token_end]
    h = from_lcp_string(token) if _LCP_TOKEN.fullmatch(token) else None
    if h is None:
        return _MALFORMED
    i = token_end
    rv: tuple[bytes | None, bool] | None = None
    while _at(value, i) == ";":
        i = _skip_spaces(value, i + 1)
        key_end = _key_at(value, i)
        if key_end == -1:
            return _MALFORMED
        key = value[i:key_end]
        i = key_end
        item: tuple[bytes | None, bool] = (None, False)
        if _at(value, i) == "=":
            parsed = _bare_item_at(value, i + 1)
            if parsed is None:
                return _MALFORMED
            item = (parsed[0], parsed[0] is not None)
            i = parsed[1]
        if key != "rv":
            return _MALFORMED
        rv = item
    if _skip_spaces(value, i) != len(value):
        return _MALFORMED
    if rv is None:
        return h, None
    data, is_bytes = rv
    if not is_bytes or data is None or len(data) != RETURN_VALUE_BYTES:
        return _MALFORMED
    return h, data


def to_legal_context_header(h: AtrHash, return_value: bytes | None = None) -> str | Refusal:
    """lcp's toLegalContextHeader: H's LCP string, with ;rv=:<base64>: where a return value of 32 bytes is given."""
    normal = normal_hash(h)
    if normal is None:
        return _MALFORMED
    if return_value is None:
        return to_lcp_string(normal)
    if len(return_value) != RETURN_VALUE_BYTES:
        return _MALFORMED
    return f"{to_lcp_string(normal)};rv=:{base64.b64encode(return_value).decode('ascii')}:"


def serves_of(option: object) -> tuple[str, ...] | None | Refusal:
    """lcp's servesOf: the charges an agreement option serves, from extra.legalContextServes on x402 and the opaque
    member legalContextServes on MPP; None where it names none."""
    if not isinstance(option, Mapping):
        return Refusal("return/serves-malformed")
    listed: Any
    if isinstance(option.get("scheme"), str):
        if "extra" not in option:
            return None
        extra = option["extra"]
        if not isinstance(extra, Mapping):
            return Refusal("return/serves-malformed")
        listed = extra.get(LEGAL_CONTEXT_SERVES)
    else:
        if "opaque" not in option:
            return None
        opaque = option["opaque"]
        members = decode_string_map(opaque) if isinstance(opaque, str) else None
        if members is None:
            return Refusal("return/serves-malformed")
        joined = members.get(LEGAL_CONTEXT_SERVES)
        listed = joined.split(" ") if isinstance(joined, str) else joined
    if listed is None:
        return None
    if (
        not isinstance(listed, list)
        or not 0 < len(listed) <= _MAX_SERVED
        or not all(isinstance(x, str) and _SERVED.fullmatch(x) for x in listed)
        or len(set(listed)) != len(listed)
    ):
        return Refusal("return/serves-malformed")
    return tuple(listed)


@dataclass(frozen=True, slots=True)
class Offered:
    """An agreement option of a first response, the read of the response holding only it, and the charges it serves."""

    option: dict[str, Any]
    read: Advertised
    serves: tuple[str, ...]


def agreement_options(required: object) -> list[Offered] | Refusal | None:
    """The agreement options of a first response that offers the agreement and no charge option: each option of
    accepts, in document order, with the charges it names as served and the read of the response holding only that
    option by the first x402 pairing, in the protocol package's order, that reads it. Every option's serves is read
    first, so the answer does not depend on their order: None where accepts is not a list of 1 to 32 options or an
    option names no charge it serves; else the protocol package's refusal of the first option whose serves it refuses
    (return/serves-malformed), which the gate declines rather than reading the response as a charge; else None unless
    each option is read by such a pairing."""
    accepts = required.get("accepts") if isinstance(required, Mapping) else None
    if not isinstance(accepts, list) or not 0 < len(accepts) <= MAX_OPTIONS:
        return None
    assert isinstance(required, Mapping)
    served = [serves_of(option) for option in accepts]
    if any(serves is None for serves in served):
        return None
    refused = next((serves for serves in served if isinstance(serves, Refusal)), None)
    if refused is not None:
        return refused
    out: list[Offered] = []
    for option, serves in zip(accepts, served):
        if not isinstance(serves, tuple):
            return None
        only = {**required, "accepts": [option]}
        read = next((r for r in (b.read(only) for b in _agreement._x402_bindings()) if isinstance(r, Advertised)), None)
        if read is None:
            return None
        out.append(Offered(option=option, read=read, serves=serves))
    return out


async def to_return(
    doc: Any,
    binding: Binding,
    offers: Sequence[Offered],
    signer: Signer,
    account: str,
    fetch: httpx.AsyncClient,
    resource_request: ResourceRequest,
    returned: tuple[AtrHash, bytes | None] | None,
    approval: Approval,
    signal: asyncio.Event | None,
) -> ToReturn | Declined:
    """The return after an agreement: the ATR fetched from the response's link, compared with its H and with the return
    value's, parsed, and its request commitment held to the buyer's request; then, for each agreement option in document
    order and each charge it names as served, x402/<i>, the option at index i of the ATR's x402 slot, the first such
    charge the pairing reads, the account can pay and checks 9 to 11 pass on (its build with H, its summary and its
    ceiling) is chosen, and that agreement option, where the charge's agreementOn admits it, is paid, asked of the
    approver as the act agreement, and its receipt awaited. No charge is signed, and no agreement is paid for a charge
    those checks decline: the next served charge is tried, and where every one is declined there, the first decline is
    returned. A pairing whose agreement is never a charge, or a response with no such charge, is no-payable-option."""
    read = offers[0].read
    url = read.agreement
    if not isinstance(url, str):
        return Declined("agreement-not-offered", "The first response names no agreement URL.")
    if not is_https_link(read.link):
        fault = "link-not-https" if is_other_scheme_link(read.link) else "legal-context-malformed"
        return Declined("link-not-https", f"x402/{fault}")
    atr_bytes = await _gate._fetch(fetch, read.link)
    if isinstance(atr_bytes, Declined):
        return atr_bytes
    h = atr_hash(atr_bytes)
    if not hash_equals(read.h, h) or (returned is not None and not hash_equals(returned[0], h)):
        return Declined("hash-mismatch", "The bytes the link served do not hash to the advertised ATR hash.")
    parsed = parse_atr(atr_bytes)
    if isinstance(parsed, Declined):
        return parsed
    other_request = request_held(binding, parsed.value, resource_request)
    if other_request is not None:
        return other_request
    own = getattr(binding, "agreement", None)
    if getattr(own, "only", False) is True:
        return Declined("no-payable-option", "x402/no-payable-option")
    slot = parsed.value.get("x402") if isinstance(parsed.value, Mapping) else None
    listed = slot.get("accepts") if isinstance(slot, Mapping) else None
    charges: list[Any] = listed if isinstance(listed, list) else []
    piece = _gate._piece(binding)
    assert piece is not None
    first: Declined | None = None
    for offered in offers:
        for name in offered.serves:
            at = re.fullmatch(r"x402/([0-9]+)", name)
            charge = charges[int(at.group(1))] if at is not None and int(at.group(1)) < len(charges) else None
            if not isinstance(charge, Mapping):
                continue
            only = {**doc, "accepts": [charge]}
            charge_read = binding.read(only)
            if isinstance(charge_read, Refusal):
                continue
            chosen = piece.choose(charge_read, account, approval.inputs, _gate._now(), _gate._ref(), only)
            if isinstance(chosen, Refusal):
                continue
            built = _gate._built(
                piece, binding, replace(chosen, agreement=url), atr_bytes, h, account, approval.inputs, approval.ceilings
            )
            if isinstance(built, Declined):
                first = first if first is not None else built
                continue
            approved = AgreementPayment(url=url, option=offered.option, required=dict(doc))
            agreed = await _agreement.exchange(
                atr_bytes,
                url,
                signer,
                fetch,
                approved=approved,
                inputs=approval.inputs,
                signal=signal,
                ns="x402",
                approval=approval,
                chosen=chosen,
                charge=binding,
            )
            if isinstance(agreed, Declined):
                return agreed
            if not isinstance(agreed, Agreed):
                return Declined("agreement-failed", "The agreement was not paid.")
            header = to_legal_context_header(h, returned[1] if returned is not None else None)
            if isinstance(header, Refusal):
                return Declined("offer-unreadable", header.code)
            return ToReturn(agreement=agreed.receipt, legal_context=header, charge=name, atr_bytes=atr_bytes, h=h)
    return first if first is not None else Declined("no-payable-option", "x402/no-payable-option")
