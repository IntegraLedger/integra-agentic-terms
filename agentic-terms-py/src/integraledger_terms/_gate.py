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
from typing import Any, cast

import httpx

from . import _agreement, _return
from ._checks import Approval, approves, ceilings_ok, floor_missing, network_of, request_held, shown, slot_holds, steps_of
from ._core import MAX_ATR_BYTES, AtrHash, atr_hash, hash_equals
from ._deadline import held_to_deadline, with_deadline
from ._parse import parse_atr
from ._summary import Opened, summary_of
from ._types import (
    AgreementChallenges,
    AgreementPayment,
    Approver,
    Binding,
    Ceilings,
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
    ResourceRequest,
    Signature,
    Signer,
    SigningStep,
    Summary,
    Step,
    ToApprove,
    ToReturn,
    Transacted,
    Act,
    agreement_of,
    bound_act,
    build_act,
    coverage_of,
)
from .bindings._lcp import is_https_link, is_other_scheme_link
from .bindings._mpp import Held, fetched_of
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


def _is_act(v: object) -> bool:
    """Whether v is an act the gate builds: "payment" or "agreement"."""
    return v == "payment" or v == "agreement"


# HTTP whitespace, as the Fetch standard names it: tab, LF, CR and space.
_HTTP_WHITESPACE = "\t\n\r "


def _trim_http_whitespace(value: str) -> str:
    """A header value without its leading and trailing HTTP whitespace, as Fetch normalizes one. Any other character
    stays, so a value it surrounds is read as written."""
    return value.strip(_HTTP_WHITESPACE)


def _declared_over(declared: str | None, bound: int) -> bool:
    """Whether a Content-Length value declares more than bound bytes, read as the TypeScript gate reads it: ASCII digits
    alone, surrounding spaces, tabs, CRs and LFs aside, compared by their significant digits, so a value of any length
    is read. Any other value declares nothing."""
    value = _trim_http_whitespace(declared or "")
    if _DECIMAL.fullmatch(value) is None:
        return False
    significant = value.lstrip("0") or "0"
    return len(significant) > len(str(bound)) or int(significant) > bound


def _too_large() -> Declined:
    return Declined("atr-too-large", f"The ATR is larger than {MAX_ATR_BYTES} bytes.")


# The request header that asks for the body with no content coding, so the bytes hashed are the bytes sent.
IDENTITY = {"Accept-Encoding": "identity"}


def is_identity(content_encoding: str | None) -> bool:
    """Whether a Content-Encoding value names no coding: absent, empty, or identity, surrounding spaces, tabs, CRs and
    LFs aside."""
    return _trim_http_whitespace(content_encoding or "").lower() in ("", "identity")


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
        if chosen.act == "agreement":
            return build_act(binding, choice, h, "agreement")
        return piece.build(binding, choice, h)
    except Exception:
        return Refusal(binding.id.split("/")[0] + "/build-failed")


def _kept(piece: Piece, chosen: Chosen, unsigned: Any) -> Chosen:
    """chosen with what the build drew itself, such as a random value, where the piece keeps it, so that a rebuild from
    it gives the request the signer was handed."""
    kept = getattr(piece, "kept", None)
    return chosen if kept is None else cast(Chosen, kept(chosen, unsigned))


def _full(binding: Binding) -> bool:
    """Whether the pairing is at coverage full, its payment itself a public proof of the hash. A binding that states
    no coverage is taken as at coverage none, so its payment is made only after the agreement."""
    return coverage_of(binding) == "full"


def _moves(piece: Piece, unsigned: Any) -> bool:
    """Whether the signer, handed the build's first request, moves the payment itself."""
    moves = getattr(piece, "moves", None)
    if moves is None:
        return False
    request = piece.request(unsigned)
    return isinstance(request, Mapping) and moves(request) is True


def _moved_by(piece: Piece, signature: Signature) -> bool:
    """Whether the signer's answer shows that its side moved the payment itself, where the piece reads that from the
    answer."""
    moved_by = getattr(piece, "moved_by", None)
    if moved_by is None:
        return False
    try:
        return moved_by(signature) is True
    except Exception:
        return False


def json_form(value: Any) -> Any:
    """A signing request as the signer receives it: every byte string as 0x and lowercase hex, the rest as given. It
    walks without recursion, each mapping and list formed once however often it is reached, and keeps each one it has
    reached for the walk, so no id is reused within it. A request of any depth or shape is handed over as the TypeScript
    gate hands it."""

    def form(v: Any) -> Any:
        if isinstance(v, (bytes, bytearray)):
            return "0x" + bytes(v).hex()
        if not isinstance(v, (Mapping, list, tuple)):
            return v
        if id(v) in formed:
            return formed[id(v)][1]
        out: dict[Any, Any] | list[Any] = {} if isinstance(v, Mapping) else []
        formed[id(v)] = (v, out)
        pending.append((v.items() if isinstance(v, Mapping) else enumerate(v), out))
        return out

    formed: dict[int, tuple[Any, Any]] = {}
    pending: list[tuple[Any, Any]] = []
    top = form(value)
    while pending:
        members, out = pending.pop()
        for k, v in members:
            if isinstance(out, dict):
                out[k] = form(v)
            else:
                out.append(form(v))
    return top


def _bound(binding: Binding, presented: Any, h: AtrHash | None = None, act: Act = "payment") -> AtrHash | Refusal:
    """The binding's bound, for the act: for an agreement, given h (bound_act)."""
    try:
        if act == "agreement" and h is not None:
            out: AtrHash | Refusal = bound_act(binding, presented, h, act)
            return out
        return binding.bound(presented)
    except Exception:
        return Refusal("bound-failed")


async def confirm(
    doc: Any,
    binding: Binding,
    account: str,
    fetch: httpx.AsyncClient,
    *,
    resource_request: ResourceRequest,
    inputs: Inputs | None = None,
    ceilings: Ceilings | None = None,
    act: Act = "payment",
) -> Confirmed | Declined:
    """Read the offer (the seller's document as given: an object, a list of challenges, or a string), choose the option,
    fetch the ATR and compare hashes; parse the bytes, hold the option chosen to the ATR's binding slot and the buyer's
    request to its request commitment; and only then build, with the hash computed, and hold the request to its summary
    and its ceiling (terms' profile buyer-gate.md, checks 1 to 11). request is what the signer is handed, with its
    summary, or None when nothing is handed to the signer: the pairing has nothing for the buyer to sign, or the build
    is itself the payment, which finish completes with no signature. For a pairing at coverage none, whose payment is
    not itself a public proof, chosen.agreement is the agreement URL the offer names. With act="agreement", the offer is
    an agreement URL's payment request and the payment is built as the agreement payment, as agree builds it, for a
    caller that pays the agreement by hand: the pairing's payment must be able to be an agreement (its registry data
    holds agreement), else it is declined no-payable-option with <namespace>/no-payable-option, and the option and the
    request are not held to the ATR's binding slot, which lists the charge's options and commits to the charge's
    request; chosen.act is then "agreement". A resource_request that is not a mapping, inputs that are not a mapping,
    ceilings that are not a mapping, or an act that is neither "payment" nor "agreement" are declined
    no-payable-option with <namespace>/input-malformed before the offer is read."""
    if _piece(binding) is None:
        return _unsupported(binding)
    if not _args_ok(resource_request, inputs, ceilings, str(binding.id)) or not _is_act(act):
        return Declined("no-payable-option", f"{_namespace(binding)}/input-malformed")
    gated = await _gate(
        doc, binding, account, fetch, resource_request, inputs if inputs is not None else {}, ceilings, act=act
    )
    return gated if isinstance(gated, Declined) else gated[0]


# A deadline kept in chosen: a decimal string, as the TypeScript gate takes it.
_DEADLINE = re.compile(r"[0-9]{1,78}")


def _given_choice(chosen: object, pairing: str) -> Chosen | None:
    """The choice of a chosen given back, of confirm's form for the pairing, with the latest deadline it keeps for a
    wallet that picks the expiry, and without the agreement URL the offer names again; None for another form."""
    if not isinstance(chosen, Chosen) or chosen.pairing != pairing:
        return None
    if not isinstance(chosen.choice, Mapping) or not isinstance(chosen.ref, str):
        return None
    deadline = chosen.deadline
    if deadline is not None and (not isinstance(deadline, str) or _DEADLINE.fullmatch(deadline) is None):
        return None
    return Chosen(pairing=pairing, choice=dict(chosen.choice), ref=chosen.ref, deadline=deadline)


def _args_ok(resource_request: object, inputs: object, ceilings: object, pairing: str) -> bool:
    """Whether the gate's arguments are of the profile's form: resource_request a mapping, inputs a mapping or None,
    and ceilings a mapping or None whose value for the paid pairing, where given, is of rule 8's form (ceilings_ok)."""
    return (
        isinstance(resource_request, Mapping)
        and (inputs is None or isinstance(inputs, Mapping))
        and ceilings_ok(ceilings, pairing)
    )


async def _gate(
    doc: Any,
    binding: Binding,
    account: str,
    fetch: httpx.AsyncClient,
    resource_request: ResourceRequest,
    inputs: Inputs,
    ceilings: Ceilings | None,
    given: Chosen | None = None,
    act: Act = "payment",
) -> tuple[Confirmed, int] | Declined:
    """Checks 3 to 11 of the profile, for confirm and transact, once the pairing and the arguments are known good: the
    confirmed payment and the number of signings it takes. Given the payment confirm chose, its choice is built again
    exactly rather than chosen anew with the gate's clock and a new reference. act is the act the payment is built as:
    for "agreement", the pairing's payment must be able to be an agreement, and the option and the request are not held
    to the binding slot."""
    piece = _piece(binding)
    if piece is None:
        return _unsupported(binding)
    if act == "agreement" and agreement_of(binding) is None:
        return Declined("no-payable-option", f"{_namespace(binding)}/no-payable-option")
    floor = floor_missing(str(binding.id), inputs)
    if floor is not None:
        return floor
    advertised = binding.read(doc)
    if isinstance(advertised, Refusal):
        return Declined("offer-unreadable", advertised.code)
    agreement = None if _full(binding) else advertised.agreement
    if agreement is not None and not isinstance(agreement, str):
        return Declined("offer-unreadable", "The offer names an agreement URL that is not a string.")
    choice = given if given is not None else piece.choose(advertised, account, inputs, _now(), _ref(), doc)
    if isinstance(choice, Refusal):
        return Declined("no-payable-option", choice.code)
    chosen = choice if agreement is None else replace(choice, agreement=agreement)
    if act == "agreement":
        chosen = replace(chosen, act="agreement")
    if not is_https_link(advertised.link):
        return Declined("link-not-https", _link_refusal(binding, advertised.link))
    fetched = await _fetch(fetch, advertised.link)
    if isinstance(fetched, Declined):
        return fetched
    computed = atr_hash(fetched)
    if not hash_equals(advertised.h, computed):
        return Declined("hash-mismatch", "The bytes the link served do not hash to the advertised ATR hash.")
    parsed = parse_atr(fetched)
    if isinstance(parsed, Declined):
        return parsed
    # The binding slot lists the charge's options and commits to the charge's request: no agreement payment is held to it.
    if act == "payment":
        not_held = slot_holds(binding, chosen, parsed.value)
        if not_held is not None:
            return not_held
        other_request = request_held(binding, parsed.value, resource_request)
        if other_request is not None:
            return other_request
    if not _full(binding) and agreement is None:
        return Declined(
            "agreement-not-offered", "The pairing's payment carries no public proof and the offer names no agreement URL."
        )
    return _built(piece, binding, chosen, fetched, computed, account, inputs, ceilings)


def _built(
    piece: Piece,
    binding: Binding,
    chosen: Chosen,
    fetched: bytes,
    computed: AtrHash,
    account: str,
    inputs: Inputs,
    ceilings: Ceilings | None,
) -> tuple[Confirmed, int] | Declined:
    """Checks 9 to 11 of the profile on the payment chosen: built with the H the gate computed, its request summarised
    and held to the pairing's ceiling; the confirmed payment and the number of signings it takes. The return after an
    agreement makes them on the charge it chooses before the agreement is paid."""
    unsigned = _build(piece, binding, chosen, computed, fetched)
    if isinstance(unsigned, Refusal):
        if _NOTHING_TO_SIGN.fullmatch(unsigned.code):
            return Confirmed(chosen=chosen, request=None, atr_bytes=fetched, h=computed), 0
        return Declined("offer-unreadable", unsigned.code)
    request = piece.request(unsigned)
    if isinstance(request, Refusal):
        return Declined("offer-unreadable", request.code)
    bounded = with_deadline(binding, None if request is None else json_form(request), chosen, inputs, ceilings, _now())
    if isinstance(bounded, Declined):
        return bounded
    formed, chosen = bounded
    kept = _kept(piece, chosen, unsigned)
    if formed is None:
        return Confirmed(chosen=kept, request=None, atr_bytes=fetched, h=computed), 0
    summary = shown(binding, formed, fetched, inputs, ceilings, network_of(account), None, account)
    if isinstance(summary, Declined):
        return summary
    return Confirmed(chosen=kept, request=formed, atr_bytes=fetched, h=computed, summary=summary), steps_of(piece, unsigned)


def finish(
    atr_bytes: bytes,
    chosen: Chosen,
    signature: Signature,
    binding: Binding,
    *,
    ceilings: Ceilings | None = None,
    act: Act = "payment",
) -> Finished | Next | Declined:
    """Rebuild the payment from chosen and the bytes, join the signer's answer, and return the payment only when the
    pairing's bound reads the hash of these bytes from the completed payment. For a pairing at coverage none, whose
    payment is not a public proof, and whose bound finds no signed place for the hash, the proof is the agreement payment, and the
    completed payment is returned as it is. A payment signed in steps returns the next request with its summary, only
    once it has a summary and is within the pairing's ceiling, ceilings raising it (checks 10 and 11). Where the signer
    moved the payment itself, a decline keeps it as moved. act is the act confirm built the payment as: "agreement" for
    an agreement payment paid by hand, which is rebuilt as the agreement payment and whose hash bound reads where it
    carries the agreement's own single-use value; "payment", the default, for any other. A chosen whose act is
    "agreement", as confirm returns it for that act, is rebuilt as the agreement payment either way. ceilings that are
    not a mapping, or an act that is neither "payment" nor "agreement", are declined no-payable-option with
    <namespace>/input-malformed."""
    if not ceilings_ok(ceilings, str(getattr(binding, "id", ""))) or not _is_act(act):
        return Declined("no-payable-option", f"{_namespace(binding)}/input-malformed")
    if act == "agreement" and isinstance(chosen, Chosen):
        chosen = replace(chosen, act="agreement")
    out = _finish(atr_bytes, chosen, signature, binding)
    if not isinstance(out, Step):
        return out
    opened = _opened(binding, chosen, atr_bytes, signature)
    account = _confirmed_for(chosen, opened)
    summary = shown(binding, out.next, atr_bytes, {}, ceilings, network_of(account), opened, account)
    return summary if isinstance(summary, Declined) else Next(next=out.next, summary=summary, h=atr_hash(atr_bytes))


def _confirmed_for(chosen: Chosen, opened: Opened | None) -> str | None:
    """The CAIP-10 account a payment signed in steps was confirmed for, which finish, given no account, hands its later
    step's summary: the payer's address the piece keeps in chosen.choice["from"], on the network of the step that
    opened the payment; None where either is absent."""
    choice = chosen.choice if isinstance(chosen, Chosen) else None
    address = choice.get("from") if isinstance(choice, Mapping) else None
    network = opened.summary.network if opened is not None else None
    return f"{network}:{address}" if isinstance(address, str) and isinstance(network, str) else None


def _opened(binding: Binding, chosen: Chosen, atr_bytes: bytes, signature: Signature) -> Opened | None:
    """The step that opened a payment signed in steps, for its later step's summary: the first request the build hands
    the signer, rebuilt from chosen as finish rebuilds it, its summary and the signer's answer; None where it has none."""
    piece = _piece(binding)
    if piece is None:
        return None
    unsigned = _build(piece, binding, chosen, atr_hash(atr_bytes), atr_bytes)
    first = None if isinstance(unsigned, Refusal) else piece.request(unsigned)
    if first is None or isinstance(first, Refusal):
        return None
    formed = json_form(first)
    summary = summary_of(str(binding.id), formed, atr_bytes)
    return None if summary is None else Opened(request=formed, summary=summary, signature=signature)


def _finish(atr_bytes: bytes, chosen: Chosen, signature: Signature, binding: Binding) -> Finished | Step | Declined:
    """finish without checks 10 and 11 on a later step's request, which the signing steps make with the approval: a
    later step's request is returned as the Step it is, in the form the signer is handed it."""
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
    moves = signature is not None and (_moves(piece, unsigned) or _moved_by(piece, signature))

    def keep(code: DeclineCode, detail: str, signed: Any) -> Declined:
        return Declined(code, detail, Moved(signed, atr_bytes, h) if moves else None)

    try:
        signed = piece.complete(unsigned, signature, chosen)
    except Exception:
        return keep("signed-not-bound", "The signer's answer did not complete the payment.", signature)
    if isinstance(signed, Refusal):
        return keep("signed-not-bound", signed.code, signature)
    if isinstance(signed, Step):
        return Step(next=json_form(signed.next))
    sent = piece.sent(signed)
    bound = _bound(binding, signed, h, chosen.act)
    on_agreement = not _full(binding) and isinstance(bound, Refusal) and _NOTHING_TO_SIGN.fullmatch(bound.code)
    if not on_agreement and (isinstance(bound, Refusal) or not hash_equals(bound, h)):
        return keep(
            "signed-not-bound", "The pairing does not read the hash of the compared bytes from the payment.", sent
        )
    # A wallet that picked the expiry is held to the latest deadline it was handed; a payment past it is discarded.
    request = piece.request(unsigned)
    formed = None if request is None or isinstance(request, Refusal) else json_form(request)
    late = held_to_deadline(binding, formed, signed, chosen)
    if late is not None:
        return late
    landed = fetched_of(signed) if sent is not signed else None
    return Finished(signed=sent, h=h, landed=landed)


def check(
    atr_bytes: bytes, presented: Any, binding: Binding, landed: Any = None, act: Act = "payment"
) -> Checked | Declined:
    """Confirms that the ATR hash the pairing reads from a payment held later is the SHA-256 of the kept bytes, with
    the landed receipt finish or transact returned beside the payment, where it returned one, held in Held, as
    @integraledger/lcp holds it under the payment's own FETCHED member: an attribute no JSON decode makes, as bound
    reads it. The caller passes as landed only the receipt its own reader read for the payment, as finish or transact
    returned it, never a value another party sent. act is the act the payment was paid as: "agreement" for the
    agreement payment, which bound is then given with the hash, so it reads the hash where the payment carries the
    agreement's own single-use value in its place; "payment", the default, for any other. A payment from which the
    pairing reads no ATR hash is declined signed-not-bound, as is a landed receipt that is not a JSON object beside a
    payment that is one. A landed member of the payment's own is not read."""
    if len(atr_bytes) > MAX_ATR_BYTES:
        return _too_large()
    if landed is not None:
        if not isinstance(landed, Mapping) or not isinstance(presented, Mapping):
            return Declined("signed-not-bound", "The landed receipt is not a JSON object beside the payment.")
        presented = Held(presented, landed)
    h = atr_hash(atr_bytes)
    bound = _bound(binding, presented, h, act)
    if isinstance(bound, Refusal) or not hash_equals(bound, h):
        return Declined(
            "signed-not-bound", "The pairing does not read the hash of the compared bytes from the payment."
        )
    return Checked(h=h)


async def pay(
    binding: Binding, chosen: Chosen, signer: Signer, atr_bytes: bytes, approval: Approval | None = None
) -> Finished | Declined | None:
    """Build and sign the payment chosen names, with the hash of atr_bytes: the signer is called once, or once per step
    for a payment signed in steps, and the payment is returned only through finish. None where the pairing has nothing
    for the buyer to sign. With approval, each signing is first held to its summary and ceiling and asked of the
    approver."""
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
    first = json_form(request) if request is not None else None
    # Where a ceiling holds the payment (approval), a wallet that picks the expiry is handed the latest it may sign.
    if approval is not None:
        bounded = with_deadline(binding, first, chosen, approval.inputs, approval.ceilings, _now())
        if isinstance(bounded, Declined):
            return bounded
        first, chosen = bounded
    kept = _kept(piece, chosen, unsigned)
    return await _sign_steps(binding, kept, first, signer, atr_bytes, h, approval, steps_of(piece, unsigned))


def _agreement_only(binding: Binding) -> bool:
    """Whether the pairing's agreement is never a charge (agreement.only): its every payment is the sale's agreement,
    and is shown to the approver as the act agreement."""
    return getattr(getattr(binding, "agreement", None), "only", False) is True


async def _sign_steps(
    binding: Binding,
    chosen: Chosen,
    first: dict[str, Any] | None,
    signer: Signer,
    atr_bytes: bytes,
    h: AtrHash,
    approval: Approval | None = None,
    count: int = 1,
) -> Finished | Declined | None:
    """The signer, once per step in order, then finish over its answers. A first request of None is a build that is
    itself the payment: finish completes it with no signer call, or None where there is nothing to sign. With approval,
    each step's request is held to its summary and its ceiling and asked of the approver before the signer is called
    for it (checks 10 to 12); count is the number of signings the build takes."""
    if first is None:
        whole = _finish(atr_bytes, chosen, None, binding)
        if isinstance(whole, Declined) and _NOTHING_TO_SIGN.fullmatch(whole.detail):
            return None
        if isinstance(whole, Step):
            return Declined("signed-not-bound", "The pairing asked for a signature it did not request.")
        return whole
    piece = _piece(binding)
    moves = piece is not None and getattr(piece, "moves", None) is not None and piece.moves(first) is True
    answers: list[Signature] = []
    request = first
    opened: Opened | None = None
    for step in range(_MAX_STEPS):
        summary: Summary | None = None
        if approval is not None:
            approved = await approves(
                binding,
                "agreement" if _agreement_only(binding) else chosen.act,
                request,
                atr_bytes,
                SigningStep(index=step, count=max(count, step + 1)),
                approval,
                network_of(_account(signer)),
                opened,
                _account(signer),
            )
            if isinstance(approved, Declined):
                kept = Moved(answers[0] if len(answers) == 1 else list(answers), atr_bytes, h) if moves and answers else None
                return replace(approved, moved=kept)
            summary = approved
        try:
            answers.append(await signer.sign(request))
        except Exception:
            kept = Moved(answers[0] if len(answers) == 1 else list(answers), atr_bytes, h) if moves and answers else None
            return Declined("signer-failed", "The signer did not sign.", kept)
        finished = _finish(atr_bytes, chosen, answers[0] if len(answers) == 1 else list(answers), binding)
        if isinstance(finished, (Declined, Finished)):
            return finished
        if step == 0 and summary is not None:
            opened = Opened(request=request, summary=summary, signature=answers[0])
        request = finished.next
    kept = Moved(list(answers), atr_bytes, h) if moves else None
    return Declined("signed-not-bound", "The pairing asked for more signatures than a payment takes.", kept)


async def transact(
    doc: Any,
    binding: Binding,
    signer: Signer,
    fetch: httpx.AsyncClient,
    *,
    approver: Approver,
    resource_request: ResourceRequest,
    inputs: Inputs | None = None,
    ceilings: Ceilings | None = None,
    legal_context: str | None = None,
    agreement_signer: Signer | None = None,
    approved: AgreementPayment | None = None,
    signal: asyncio.Event | None = None,
    chosen: Chosen | None = None,
) -> Transacted | ToApprove | AgreementChallenges | ToReturn | Declined:
    """The gate's checks, then, for a pairing whose payment is not itself a public proof, the agreement, then the signer,
    then finish. Every signing, the agreement payment's among them, is first held to its summary and its ceiling and
    asked of approver, and the signer is called only for what it approves (terms' profile buyer-gate.md, checks 1 to
    12). Without approved, an agreement not yet recorded is returned as ToApprove, the agreement payment for the agent
    to approve, and nothing is signed; with approved, that payment is asked of approver, signed and paid, and the
    resource's payment is asked of approver and signed only with the agreement's receipt in hand. The signer is called
    once for the payment, or once per step for a payment signed in steps, and, when no agreement_signer is given, first
    for the approved agreement payment; it is never called on a decline before it. Where the build is itself the payment
    the signer is not called for it; where the pairing has nothing for the buyer to sign, signed is None after the
    comparison. agreement is the agreement's receipt, where the pairing needs one. Setting signal ends the agreement
    exchange. An approver that is not callable, a resource_request, inputs or ceilings that are not a mapping, a
    legal_context that is not a string, an agreement signer with no sign method, an approved value that is not an
    AgreementPayment, a signal that is not an asyncio.Event, a chosen that is not a Chosen of confirm's form for the
    pairing, or a signer or agreement signer whose account is not a string are declined no-payable-option with
    <namespace>/input-malformed before any fetch or signer call.

    With chosen, the payment confirm chose, unchanged, the gate builds that exact request, the one the approver
    approved, instead of choosing anew with its clock and a new reference.

    Where the pairing is paid after its agreement and the first response offers the agreement and no charge option,
    its every option naming the charges it serves, transact pays the agreement and returns ToReturn. legal_context is
    that response's return value, its Legal-Context header or MCP _meta value as received: one the protocol package's
    fromLegalContextHeader refuses is declined offer-unreadable with its code before any fetch, and one whose H is not
    the ATR's hash-mismatch."""
    if _piece(binding) is None:
        return _unsupported(binding)
    agreement_signer_ok = agreement_signer is None or (
        callable(getattr(agreement_signer, "sign", None)) and isinstance(_account(agreement_signer), str)
    )
    if (
        not callable(approver)
        or not _args_ok(resource_request, inputs, ceilings, str(binding.id))
        or (legal_context is not None and not isinstance(legal_context, str))
        or not agreement_signer_ok
        or (approved is not None and not isinstance(approved, AgreementPayment))
        or (signal is not None and not isinstance(signal, asyncio.Event))
        or (chosen is not None and _given_choice(chosen, str(binding.id)) is None)
        or not isinstance(_account(signer), str)
    ):
        return Declined("no-payable-option", f"{_namespace(binding)}/input-malformed")
    given = inputs if inputs is not None else {}
    returned: AtrHash | None = None
    return_value: bytes | None = None
    if legal_context is not None:
        read = _return.from_legal_context_header(legal_context)
        if isinstance(read, Refusal):
            return Declined("offer-unreadable", read.code)
        returned, return_value = read
    approval = Approval(approver=approver, ceilings=ceilings, inputs=given)
    # Check 3 before anything is paid, the agreement a first response offers among it.
    floor = floor_missing(str(binding.id), given)
    if floor is not None:
        return floor

    ns = _namespace(binding)
    if ns in ("x402", "mpp") and not _full(binding):
        offers = _return.agreement_options(doc) if ns == "x402" else _return.mpp_agreement_options(doc)
        if isinstance(offers, Refusal):
            return Declined("offer-unreadable", offers.code)
        if offers is not None:
            return await _return.to_return(
                doc,
                binding,
                offers,
                agreement_signer if agreement_signer is not None else signer,
                _account(signer),
                fetch,
                resource_request,
                (returned, return_value) if returned is not None else None,
                approval,
                signal,
                ns,
            )

    again = None if chosen is None else _given_choice(chosen, str(binding.id))
    gated = await _gate(doc, binding, _account(signer), fetch, resource_request, given, ceilings, again)
    if isinstance(gated, Declined):
        return gated
    confirmed, count = gated
    atr_bytes, chosen = confirmed.atr_bytes, confirmed.chosen
    if returned is not None and not hash_equals(returned, confirmed.h):
        return Declined("hash-mismatch", "The return value names another ATR hash than the one the link served.")
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
            approval=approval,
            chosen=chosen,
            charge=binding,
        )
        if isinstance(agreed, (Declined, ToApprove, AgreementChallenges)):
            return agreed
        receipt = agreed.receipt

    done = await _sign_steps(binding, chosen, confirmed.request, signer, atr_bytes, confirmed.h, approval, count)
    if isinstance(done, Declined):
        return done
    if done is None:
        return Transacted(signed=None, atr_bytes=atr_bytes, h=confirmed.h, agreement=receipt)
    return Transacted(signed=done.signed, atr_bytes=atr_bytes, h=done.h, agreement=receipt, landed=done.landed)
