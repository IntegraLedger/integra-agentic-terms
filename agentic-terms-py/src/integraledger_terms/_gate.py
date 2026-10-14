"""The buyer gate: fetch the ATR, compare its hash with the advertised one, build the payment with that hash, pay the
agreement the buyer's agent approved when the pairing's payment is not itself a public proof, sign only on a match, and
return the payment only when the ATR hash the pairing reads from the completed payment is the hash of the bytes, or, for
a pairing whose proof is the agreement payment, complete the payment without that reading."""

import asyncio
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

import httpx

from . import _agreement
from ._core import MAX_ATR_BYTES, AtrHash, atr_hash, hash_equals
from ._types import (
    AgreementPayment,
    Binding,
    Checked,
    Chosen,
    Confirmed,
    DeclineCode,
    Declined,
    Finished,
    Inputs,
    Json,
    Moved,
    Next,
    Piece,
    Refusal,
    Signature,
    Signer,
    Step,
    ToApprove,
    Transacted,
)
from .bindings._lcp import is_https_link, is_other_scheme_link
from .pieces import PIECES

FETCH_DEADLINE_S = 10.0

# A build refusal that means the pairing has nothing for the buyer to sign: the gate confirms only.
_NOTHING_TO_SIGN = re.compile(r".*/(no-signed-place|nothing-to-sign)")
# The most signer calls one payment takes: a funding and then a voucher.
_MAX_STEPS = 2
# ASCII digits only: re's [0-9] matches no other script's digits.
_DECIMAL = re.compile(r"[0-9]+")


def _namespace(binding: Binding) -> str:
    """The pairing's namespace: its id up to the first "/"."""
    return str(binding.id).split("/", 1)[0]


def _link_refusal(binding: Binding, link: object) -> str:
    """The protocol package's refusal code for a link that is not an https link, in the pairing's namespace."""
    return f"{_namespace(binding)}/{'link-not-https' if is_other_scheme_link(link) else 'legal-context-malformed'}"


def _now() -> int:
    return int(time.time())


def _ref() -> str:
    """24 random bytes as unpadded base64url: 32 characters from [A-Za-z0-9_-]."""
    return secrets.token_urlsafe(24)


def _piece(binding: Binding) -> Piece | None:
    binding_id = getattr(binding, "id", None)
    return PIECES.get(binding_id) if isinstance(binding_id, str) else None


def _account(signer: object) -> Any:
    """The signer's account as it gives it; None for a signer with none. transact and the agreement exchange decline a
    signer whose account is not a string."""
    return getattr(signer, "account", None)


def _unsupported(binding: Binding) -> Declined:
    return Declined("pairing-not-supported", f"The gate has no buyer piece for the pairing {getattr(binding, 'id', None)}.")


def _declared_over(declared: str | None, bound: int) -> bool:
    """Whether a Content-Length value declares more than bound bytes, read as the TypeScript gate reads it: ASCII digits
    alone once surrounding whitespace is stripped, compared by their significant digits, so a value of any length is
    read. Any other value declares nothing."""
    value = (declared or "").strip()
    if _DECIMAL.fullmatch(value) is None:
        return False
    significant = value.lstrip("0") or "0"
    return len(significant) > len(str(bound)) or int(significant) > bound


def _too_large() -> Declined:
    return Declined("atr-too-large", f"The ATR is larger than {MAX_ATR_BYTES} bytes.")


# The request header that asks for the body with no content coding, so the bytes hashed are the bytes sent.
IDENTITY = {"Accept-Encoding": "identity"}


def is_identity(content_encoding: str | None) -> bool:
    """Whether a Content-Encoding value names no coding: absent, empty, or identity."""
    return (content_encoding or "").strip().lower() in ("", "identity")


async def _fetch(fetch: httpx.AsyncClient, link: str) -> bytes | Declined:
    """One GET asking for the identity coding, no redirect, one deadline over headers and body that is also the
    request's own httpx timeout, and at most MAX_ATR_BYTES read as sent. A 200 whose Content-Encoding names any coding
    is declined with its body unread: nothing is decoded. A response the client's transport has already read in whole
    is taken as read."""
    try:
        async with asyncio.timeout(FETCH_DEADLINE_S):
            async with fetch.stream(
                "GET", link, headers=IDENTITY, follow_redirects=False, timeout=FETCH_DEADLINE_S
            ) as response:
                if response.status_code != 200:
                    return Declined("atr-unfetchable", f"The link answered status {response.status_code}.")
                if not is_identity(response.headers.get("content-encoding")):
                    return Declined("atr-unfetchable", "The link served a content coding other than identity.")
                if _declared_over(response.headers.get("content-length"), MAX_ATR_BYTES):
                    return _too_large()
                if response.is_stream_consumed:
                    return response.content if len(response.content) <= MAX_ATR_BYTES else _too_large()
                body = bytearray()
                async for chunk in response.aiter_raw():
                    body += chunk
                    if len(body) > MAX_ATR_BYTES:
                        return _too_large()
                return bytes(body)
    except Exception:
        return Declined("atr-unfetchable", "The ATR could not be fetched from the link.")


def _build(piece: Piece, binding: Binding, chosen: Chosen, h: AtrHash, atr_bytes: bytes) -> Any:
    """The pairing's build over the choice the piece revives from chosen; a raise is the pairing's build-failed."""
    try:
        choice = piece.choice(chosen, atr_bytes)
        if isinstance(choice, Refusal):
            return choice
        return piece.build(binding, choice, h)
    except Exception:
        return Refusal(binding.id.split("/")[0] + "/build-failed")


def _public_proof(binding: Binding) -> bool:
    return getattr(binding, "public_proof", False) is True


def _moves(piece: Piece, unsigned: Any) -> bool:
    """Whether the signer, handed the build's first request, moves the payment itself."""
    moves = getattr(piece, "moves", None)
    if moves is None:
        return False
    request = piece.request(unsigned)
    return isinstance(request, Mapping) and moves(request) is True


def json_form(value: Any) -> Any:
    """A signing request as the signer receives it: every byte string as 0x and lowercase hex, the rest as given."""
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    if isinstance(value, Mapping):
        return {k: json_form(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_form(v) for v in value]
    return value


def _bound(binding: Binding, presented: Any) -> AtrHash | Refusal:
    try:
        return binding.bound(presented)
    except Exception:
        return Refusal("bound-failed")


async def confirm(
    doc: Any, binding: Binding, account: str, fetch: httpx.AsyncClient, inputs: Inputs | None = None
) -> Confirmed | Declined:
    """Read the offer (the seller's document as given: an object, a list of challenges, or a string), choose the option,
    fetch the ATR and compare hashes. Only on a match build, with the hash computed. request is what the signer is
    handed, or None when nothing is handed to the signer: the pairing has nothing for the buyer to sign, or the build is
    itself the payment, which finish completes with no signature. For a pairing whose payment is not itself a public
    proof, chosen.agreement is the agreement URL the offer names. Inputs that are not a mapping are declined
    no-payable-option with <namespace>/input-malformed before the offer is read."""
    piece = _piece(binding)
    if piece is None:
        return _unsupported(binding)
    if inputs is not None and not isinstance(inputs, Mapping):
        return Declined("no-payable-option", f"{_namespace(binding)}/input-malformed")
    advertised = binding.read(doc)
    if isinstance(advertised, Refusal):
        return Declined("offer-unreadable", advertised.code)
    agreement = None if _public_proof(binding) else advertised.agreement
    if agreement is not None and not isinstance(agreement, str):
        return Declined("offer-unreadable", "The offer names an agreement URL that is not a string.")
    given = inputs if inputs is not None else {}
    choice = piece.choose(advertised, account, given, _now(), _ref(), doc)
    if isinstance(choice, Refusal):
        return Declined("no-payable-option", choice.code)
    chosen = choice if agreement is None else replace(choice, agreement=agreement)
    if not is_https_link(advertised.link):
        return Declined("link-not-https", _link_refusal(binding, advertised.link))
    fetched = await _fetch(fetch, advertised.link)
    if isinstance(fetched, Declined):
        return fetched
    computed = atr_hash(fetched)
    if not hash_equals(advertised.h, computed):
        return Declined("hash-mismatch", "The bytes the link served do not hash to the advertised ATR hash.")
    if not _public_proof(binding) and agreement is None:
        return Declined(
            "agreement-not-offered", "The pairing's payment carries no public proof and the offer names no agreement URL."
        )
    unsigned = _build(piece, binding, chosen, computed, fetched)
    if isinstance(unsigned, Refusal):
        if _NOTHING_TO_SIGN.fullmatch(unsigned.code):
            return Confirmed(chosen=chosen, request=None, atr_bytes=fetched, h=computed)
        return Declined("offer-unreadable", unsigned.code)
    request = piece.request(unsigned)
    if isinstance(request, Refusal):
        return Declined("offer-unreadable", request.code)
    return Confirmed(chosen=chosen, request=json_form(request), atr_bytes=fetched, h=computed)


def finish(atr_bytes: bytes, chosen: Chosen, signature: Signature, binding: Binding) -> Finished | Next | Declined:
    """Rebuild the payment from chosen and the bytes, join the signer's answer, and return the payment only when the
    pairing's bound reads the hash of these bytes from the completed payment. For a pairing whose payment is not a
    public proof and whose bound finds no signed place for the hash, the proof is the agreement payment, and the
    completed payment is returned as it is. A payment signed in steps returns the next request. Where the signer moved
    the payment itself, a decline keeps it as moved."""
    piece = _piece(binding)
    if piece is None:
        return _unsupported(binding)
    if len(atr_bytes) > MAX_ATR_BYTES:
        return _too_large()
    if not isinstance(chosen, Chosen) or not isinstance(chosen.choice, Mapping):
        return Declined("offer-unreadable", "The chosen payment carries no choice to build from.")
    if chosen.pairing != binding.id:
        return Declined("pairing-not-supported", f"The chosen payment is not for the pairing {binding.id}.")
    h = atr_hash(atr_bytes)
    unsigned = _build(piece, binding, chosen, h, atr_bytes)
    if isinstance(unsigned, Refusal):
        return Declined("offer-unreadable", unsigned.code)
    moves = signature is not None and _moves(piece, unsigned)

    def keep(code: DeclineCode, detail: str, signed: Any) -> Declined:
        return Declined(code, detail, Moved(signed, atr_bytes, h) if moves else None)

    try:
        signed = piece.complete(unsigned, signature, chosen)
    except Exception:
        return keep("signed-not-bound", "The signer's answer did not complete the payment.", signature)
    if isinstance(signed, Refusal):
        return keep("signed-not-bound", signed.code, signature)
    if isinstance(signed, Step):
        return Next(next=json_form(signed.next), h=h)
    sent = piece.sent(signed)
    bound = _bound(binding, signed)
    on_agreement = not _public_proof(binding) and isinstance(bound, Refusal) and _NOTHING_TO_SIGN.fullmatch(bound.code)
    if not on_agreement and (isinstance(bound, Refusal) or not hash_equals(bound, h)):
        return keep("signed-not-bound", "What was signed does not carry the hash of these bytes.", sent)
    landed = signed.get("landed") if sent is not signed and isinstance(signed, Mapping) else None
    return Finished(signed=sent, h=h, landed=landed)


def check(atr_bytes: bytes, presented: Any, binding: Binding) -> Checked | Declined:
    """Confirms that the ATR hash the pairing reads from a payment held later is the SHA-256 of the kept bytes. A
    payment from which the pairing reads no ATR hash is declined signed-not-bound."""
    if len(atr_bytes) > MAX_ATR_BYTES:
        return _too_large()
    h = atr_hash(atr_bytes)
    bound = _bound(binding, presented)
    if isinstance(bound, Refusal) or not hash_equals(bound, h):
        return Declined("signed-not-bound", "The payment does not carry the hash of these bytes.")
    return Checked(h=h)


async def pay(binding: Binding, chosen: Chosen, signer: Signer, atr_bytes: bytes) -> Finished | Declined | None:
    """Build and sign the payment chosen names, with the hash of atr_bytes: the signer is called once, or once per step
    for a payment signed in steps, and the payment is returned only through finish. None where the pairing has nothing
    for the buyer to sign."""
    piece = _piece(binding)
    if piece is None:
        return _unsupported(binding)
    h = atr_hash(atr_bytes)
    unsigned = _build(piece, binding, chosen, h, atr_bytes)
    if isinstance(unsigned, Refusal):
        if _NOTHING_TO_SIGN.fullmatch(unsigned.code):
            return None
        return Declined("offer-unreadable", unsigned.code)
    request = piece.request(unsigned)
    if isinstance(request, Refusal):
        return Declined("offer-unreadable", request.code)
    return await _sign_steps(binding, chosen, json_form(request) if request is not None else None, signer, atr_bytes, h)


async def _sign_steps(
    binding: Binding, chosen: Chosen, first: dict[str, Any] | None, signer: Signer, atr_bytes: bytes, h: AtrHash
) -> Finished | Declined | None:
    """The signer, once per step in order, then finish over its answers. A first request of None is a build that is
    itself the payment: finish completes it with no signer call, or None where there is nothing to sign."""
    if first is None:
        whole = finish(atr_bytes, chosen, None, binding)
        if isinstance(whole, Declined) and _NOTHING_TO_SIGN.fullmatch(whole.detail):
            return None
        if isinstance(whole, Next):
            return Declined("signed-not-bound", "The pairing asked for a signature it did not request.")
        return whole
    piece = _piece(binding)
    moves = piece is not None and getattr(piece, "moves", None) is not None and piece.moves(first) is True
    answers: list[Signature] = []
    request = first
    for _ in range(_MAX_STEPS):
        try:
            answers.append(await signer.sign(request))
        except Exception:
            kept = Moved(answers[0] if len(answers) == 1 else list(answers), atr_bytes, h) if moves and answers else None
            return Declined("signer-failed", "The signer did not sign.", kept)
        finished = finish(atr_bytes, chosen, answers[0] if len(answers) == 1 else list(answers), binding)
        if isinstance(finished, (Declined, Finished)):
            return finished
        request = finished.next
    kept = Moved(list(answers), atr_bytes, h) if moves else None
    return Declined("signed-not-bound", "The pairing asked for more signatures than a payment takes.", kept)


async def transact(
    doc: Any,
    binding: Binding,
    signer: Signer,
    fetch: httpx.AsyncClient,
    *,
    inputs: Inputs | None = None,
    agreement_signer: Signer | None = None,
    approved: AgreementPayment | None = None,
    signal: asyncio.Event | None = None,
) -> Transacted | ToApprove | Declined:
    """confirm, then, for a pairing whose payment is not itself a public proof, the agreement, then the signer, then
    finish. Without approved, an agreement not yet recorded is returned as ToApprove, the agreement payment for the
    agent to approve, and nothing is signed; with approved, that payment is signed and paid, and the resource's payment
    is signed only with the agreement's receipt in hand. The signer is called once for the payment, or once per step for
    a payment signed in steps, and, when no agreement_signer is given, first for the approved agreement payment; it is
    never called on a decline before it. Where the build is itself the payment the signer is not called for it; where
    the pairing has nothing for the buyer to sign, signed is None after the comparison. agreement is the agreement's
    receipt, where the pairing needs one. Setting signal ends the agreement exchange. Inputs that are not a mapping, an
    agreement signer with no sign method, an approved value that is not an AgreementPayment, a signal that is not an
    asyncio.Event, or a signer or agreement signer whose account is not a string are declined no-payable-option with
    <namespace>/input-malformed before any fetch or signer call."""
    if _piece(binding) is None:
        return _unsupported(binding)
    agreement_signer_ok = agreement_signer is None or (
        callable(getattr(agreement_signer, "sign", None)) and isinstance(_account(agreement_signer), str)
    )
    if (
        (inputs is not None and not isinstance(inputs, Mapping))
        or not agreement_signer_ok
        or (approved is not None and not isinstance(approved, AgreementPayment))
        or (signal is not None and not isinstance(signal, asyncio.Event))
        or not isinstance(_account(signer), str)
    ):
        return Declined("no-payable-option", f"{_namespace(binding)}/input-malformed")
    given = inputs if inputs is not None else {}
    confirmed = await confirm(doc, binding, _account(signer), fetch, given)
    if isinstance(confirmed, Declined):
        return confirmed
    atr_bytes, chosen = confirmed.atr_bytes, confirmed.chosen
    receipt = None
    if chosen.agreement is not None:
        agreed = await _agreement.exchange(
            atr_bytes,
            chosen.agreement,
            agreement_signer if agreement_signer is not None else signer,
            fetch,
            approved=approved,
            inputs=given,
            signal=signal,
            ns=_namespace(binding),
        )
        if isinstance(agreed, (Declined, ToApprove)):
            return agreed
        receipt = agreed.receipt

    done = await _sign_steps(binding, chosen, confirmed.request, signer, atr_bytes, confirmed.h)
    if isinstance(done, Declined):
        return done
    if done is None:
        return Transacted(signed=None, atr_bytes=atr_bytes, h=confirmed.h, agreement=receipt)
    return Transacted(signed=done.signed, atr_bytes=atr_bytes, h=done.h, agreement=receipt, landed=done.landed)
