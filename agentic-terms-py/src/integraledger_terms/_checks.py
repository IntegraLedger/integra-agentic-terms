"""The checks of terms' profile buyer-gate.md that the gate makes on what it fetched and built: the option chosen against
the binding slot (rule 6), the buyer's request against the slot's request commitment (rule 7), the ceiling and the
served floor (rules 8 and 9), and the approval of each signing (rule 11). The parse (rule 5) is _parse."""

import copy
import inspect
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from ._commitment import issued_form, request_commitment, tool_call_commitment, x402_unplaced
from ._summary import Opened, start_of, summary_of
from ._types import (
    Act,
    Approver,
    Binding,
    Ceilings,
    Chosen,
    DeclineCode,
    Declined,
    Inputs,
    Refusal,
    SigningStep,
    Summary,
    ToSign,
    Validity,
)
from .bindings._codec import canonical_or_none

MAX_SAFE_INTEGER = 2**53 - 1


def _declined(code: DeclineCode, detail: str) -> Declined:
    return Declined(code, detail)


# ── The option chosen and the binding slot (rule 6).

# The member of each protocol's binding slot that lists the options offered.
_LISTING: Mapping[str, str] = {
    "x402": "accepts",
    "mpp": "challenges",
    "acp": "options",
    "ap2": "options",
    "card": "options",
    "ucp": "options",
    "ack": "paymentOptions",
}


def _unplaced(binding: Binding, option: object) -> object:
    """The option as the pairing's unplaced gives it: the binding's own, where it has one, else the protocol package's
    rule for the pairing (_commitment.x402_unplaced)."""
    own = getattr(binding, "unplaced", None)
    return own(option) if callable(own) else x402_unplaced(str(binding.id), option)


def slot_holds(binding: Binding, chosen: Chosen, atr: object) -> Declined | None:
    """Where the ATR's binding slot lists the options offered, option-not-in-atr for an option chosen that equals none
    of them: an x402 option as the pairing's unplaced gives it against each member as the slot holds it, by RFC 8785
    form; an MPP challenge and each member by their bound members (issuedDigest's, without id and the protocol
    package's opaque members). The option chosen is the choice's accepted (x402) or challenge (MPP); a pairing whose
    choice holds neither is not compared."""
    protocol = str(binding.id).split("/", 1)[0]
    listing = _LISTING.get(protocol)
    if listing is None or not isinstance(atr, Mapping):
        return None
    slot = atr.get(protocol)
    if not isinstance(slot, Mapping) or listing not in slot:
        return None
    listed = slot[listing]
    members: Sequence[Any] = listed if isinstance(listed, list) else []
    choice = chosen.choice if isinstance(chosen.choice, Mapping) else {}
    not_held = _declined("option-not-in-atr", f"The ATR's {protocol} slot does not hold the option chosen.")
    if protocol == "mpp":
        if "challenge" not in choice:
            return None
        try:
            want = issued_form(choice["challenge"])
            if want is None:
                return not_held
            return None if any(issued_form(m) == want for m in members) else not_held
        except Exception:
            return not_held
    if protocol != "x402" or "accepted" not in choice:
        return None
    try:
        option = _unplaced(binding, choice["accepted"])
    except Exception:
        return not_held
    text = None if isinstance(option, Refusal) else canonical_or_none(option)
    if text is None:
        return not_held
    return None if any(canonical_or_none(m) == text for m in members) else not_held


# ── The buyer's request and the binding slot (rule 7).

_HTTP_MEMBERS = {"method", "path", "query", "bodyDigest"}
_MCP_MEMBERS = {"tool", "argumentsDigest"}
_NO_FORM = "The ATR's request commitment is of no form the protocol package writes."


def request_held(binding: Binding, atr: object, resource_request: object) -> Declined | None:
    """Where the binding slot is x402 and holds a request member, request-mismatch unless it is the commitment the
    protocol package computes of the buyer's request in the same form: over HTTP requestCommitment with the header names
    it lists, in order; over MCP toolCallCommitment. A refused request gives the package's code as the detail; a member
    of neither form is declined."""
    if str(binding.id).split("/", 1)[0] != "x402" or not isinstance(atr, Mapping):
        return None
    slot = atr.get("x402")
    if not isinstance(slot, Mapping) or "request" not in slot:
        return None
    committed = slot["request"]
    if not isinstance(committed, Mapping):
        return _declined("request-mismatch", _NO_FORM)
    keys = set(committed.keys())
    computed: dict[str, Any] | Refusal
    if keys == _HTTP_MEMBERS or keys == _HTTP_MEMBERS | {"headers"}:
        listed = committed.get("headers")
        names: list[str] | None = None
        if "headers" in committed:
            if not isinstance(listed, list) or not all(isinstance(h, Mapping) and isinstance(h.get("name"), str) for h in listed):
                return _declined("request-mismatch", _NO_FORM)
            names = [h["name"] for h in listed]
        computed = request_commitment(resource_request, names)
    elif keys == _MCP_MEMBERS:
        computed = tool_call_commitment(resource_request)
    else:
        return _declined("request-mismatch", _NO_FORM)
    if isinstance(computed, Refusal):
        return _declined("request-mismatch", computed.code)
    want = canonical_or_none(dict(committed))
    if want is not None and canonical_or_none(computed) == want:
        return None
    return _declined("request-mismatch", "The ATR commits to another request than the buyer's.")


# ── The ceiling and the served floor (rules 8 and 9).

# A pairing's ceiling where ceilings raises none and no service serves a floor: 600 seconds.
DEFAULT_CEILING_S = 600


@dataclass(frozen=True, slots=True)
class _Floor:
    input: str
    margin: int


# The rails whose payment service serves a floor: the input that carries it, and the service's own margin.
_FLOORS: Mapping[str, _Floor] = {"x402/exact/eip155/gateway-batched": _Floor("minValiditySeconds", 100)}

# Seconds per unit of a deadline signed as a height, by the network's CAIP-2 namespace (the profile's pace table):
# Cardano's networks are named in the cardano and the cip34 namespaces alike (CIP-34, Chain ID Registry).
_PACE: Mapping[str, float] = {
    "algorand": 2.82,
    "cardano": 1,
    "cip34": 1,
    "near": 0.6,
    "polkadot": 6,
    "solana": 0.3,
    "sui": 86_400,
    "xrpl": 5,
}

# Each pairing's read.life, where the protocol package's registry data states one: the bound the rail itself puts on a
# payment whose payer signs no deadline, and its unit. The protocol package states it in
# src/internal/data/solana.ts (LIFE, line 15, for its nine pairings at lines 64 to 276), src/internal/data/hedera.ts:28
# (x402/exact/hedera) and :77 (mpp/charge/lcp/hedera), and src/internal/data/algorand.ts:24 (x402/exact/algorand).
_LIFE: Mapping[str, tuple[int, str]] = {
    "mpp/charge/solana": (150, "blocks"),
    "mpp/charge/solana/unsponsored": (150, "blocks"),
    "mpp/subscription/solana": (150, "blocks"),
    "mpp/session/solana/memo": (150, "blocks"),
    "mpp/session/solana/stock": (150, "blocks"),
    "mpp/charge/lcp/hedera": (180, "seconds"),
    "mpp/charge/usdc/solana": (150, "blocks"),
    "x402/batch-settlement/solana": (150, "blocks"),
    "x402/exact/algorand": (1000, "rounds"),
    "x402/exact/hedera": (180, "seconds"),
    "x402/exact/solana": (150, "blocks"),
    "x402/upto/solana": (150, "blocks"),
}


def _is_positive_safe(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 < v <= MAX_SAFE_INTEGER


def is_ceilings(v: object) -> bool:
    """Whether ceilings has rule 8's outer form, a mapping or None; each pairing's own value is read when that pairing
    is paid."""
    return v is None or isinstance(v, Mapping)


def ceilings_ok(ceilings: object, pairing: str) -> bool:
    """Whether ceilings has rule 8's form for a call that pays pairing: a mapping or None, and the paid pairing's value,
    where given, a positive safe integer or "no-end", so a malformed one is declined before anything is fetched. A
    value for an id the call does not pay is read only if that pairing is paid, as an agreement payment's is."""
    if not is_ceilings(ceilings):
        return False
    return not isinstance(_raised(cast("Ceilings | None", ceilings), pairing), Refusal)


def _raised(ceilings: Ceilings | None, pairing: str) -> int | Literal["no-end"] | None | Refusal:
    """pairing's raised ceiling: a positive safe integer, "no-end", None where none is given, or a Refusal where the
    value is of no form rule 8 gives."""
    if ceilings is None or pairing not in ceilings:
        return None
    v = ceilings[pairing]
    if v == "no-end" or _is_positive_safe(v):
        return v
    return Refusal("malformed")


def floor_missing(pairing: str, inputs: Inputs) -> Declined | None:
    """floor-missing, naming the input, where the pairing's rail serves a floor and inputs does not hold it as a
    positive safe integer."""
    floor = _FLOORS.get(pairing)
    if floor is None or _is_positive_safe(inputs.get(floor.input)):
        return None
    return _declined("floor-missing", floor.input)


def _namespace(network: str | None) -> str:
    """The CAIP-2 namespace of a network, or "" where the payment moves on no ledger and the summary names none."""
    return "" if network is None else network.split(":", 1)[0]


def _life_of(pairing: str, network: str | None) -> float | None:
    """read.life in seconds, or None where the data states none or no pace converts it."""
    life = _LIFE.get(pairing)
    if life is None:
        return None
    value, unit = life
    if unit == "seconds":
        return value
    pace = _PACE.get(_namespace(network))
    return None if pace is None else value * pace


def _big(v: str | None) -> int | None:
    return int(v) if v is not None and v.isascii() and v.isdigit() and len(v) <= 78 else None


# The input that gives the start of a deadline signed as a height where neither the request nor the build signs one, by
# the network's CAIP-2 namespace: on the XRP Ledger ledgerIndex, the index of the validated ledger the caller read,
# since the protocol package's XRPL builds take LastLedgerSequence itself from the caller and sign no start.
_STARTS: Mapping[str, str] = {"xrpl": "ledgerIndex"}


def _is_index(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE_INTEGER


def _given_start(network: str | None, inputs: Inputs) -> int | None:
    """The start the caller gives in inputs for a deadline signed as a height on network, where its chain has one."""
    name = _STARTS.get(_namespace(network))
    v = None if name is None else inputs.get(name)
    return v if isinstance(v, int) and _is_index(v) else None


def _window(pairing: str, v: Validity, network: str | None, now: int, inputs: Inputs) -> float | Literal["no-end"] | None:
    """How long the signed payment stays payable, in seconds, from the summary's validity: a deadline in seconds less
    the gate's clock; a deadline signed as a height less the start the request signs, else the height the caller gave
    the build, else the start the caller gives in inputs (ledgerIndex on the XRP Ledger), times the chain's pace; where
    the payer signs no deadline, the pairing's read.life; "no-end" where none of these bounds it; None where the window
    cannot be read."""
    if v.not_after is None:
        life = _life_of(pairing, network)
        return "no-end" if life is None else life
    until = _big(v.not_after)
    if until is None:
        return None
    if v.unit == "seconds":
        return until - now
    pace = _PACE.get(_namespace(network))
    start = _big(v.not_before)
    if start is None:
        start = start_of(pairing, inputs)
    if start is None:
        start = _given_start(network, inputs)
    if pace is None or start is None:
        return None
    return (until - start) * pace


def within_ceiling(pairing: str, summary: Summary, inputs: Inputs, ceilings: Ceilings | None, now: int) -> Declined | None:
    """Check 11 on a summary: no-end for a payment that signs no end unless ceilings maps the pairing to "no-end", and
    past-ceiling for one payable longer than the pairing's ceiling: 600 seconds, or on a rail with a served floor that
    floor plus the service's margin, raised to ceilings' value where it is larger. A deadline signed as a height on a
    chain whose start the caller gives (ledgerIndex on the XRP Ledger), with no start signed or given, is
    no-payable-option with the chain's namespace's input-missing (xrpl/input-missing)."""
    ns = pairing.split("/", 1)[0]
    raised = _raised(ceilings, pairing)
    if isinstance(raised, Refusal):
        return _declined("no-payable-option", f"{ns}/input-malformed")
    v = summary.validity
    chain = _namespace(summary.network)
    start_name = _STARTS.get(chain)
    if v.unit != "seconds" and v.not_after is not None and v.not_before is None and start_name is not None:
        if start_of(pairing, inputs) is None and not _is_index(inputs.get(start_name)):
            return _declined("no-payable-option", f"{chain}/input-missing")
    window = _window(pairing, summary.validity, summary.network, now, inputs)
    if window == "no-end":
        return None if raised == "no-end" else _declined("no-end", f"The payment through {pairing} signs no end.")
    if raised == "no-end":
        return None
    if window is None:
        return _declined("past-ceiling", f"The gate cannot read how long the payment through {pairing} stays payable.")
    floor = _FLOORS.get(pairing)
    ceiling = DEFAULT_CEILING_S
    if floor is not None:
        given = inputs.get(floor.input)
        if not _is_positive_safe(given):
            return _declined("floor-missing", floor.input)
        assert isinstance(given, int)
        ceiling = given + floor.margin
    if raised is not None:
        ceiling = max(ceiling, raised)
    if window > ceiling:
        shown = math.ceil(window)
        return _declined("past-ceiling", f"The payment through {pairing} stays payable {shown} s, past its ceiling of {ceiling} s.")
    return None


# ── The approval (rule 11).


@dataclass(frozen=True, slots=True)
class Approval:
    """What the approver and the ceiling read beside each signing: the callback, the raised ceilings and the inputs."""

    approver: Approver
    ceilings: Ceilings | None
    inputs: Inputs


def steps_of(unsigned: object) -> int:
    """The number of signings a build takes: two where it holds a funding and the voucher that follows it, else one."""
    return 2 if callable(getattr(unsigned, "voucher", None)) and hasattr(unsigned, "funding") else 1


def _now() -> int:
    """The gate's own clock, the one its build reads."""
    from . import _gate

    return _gate._now()


def network_of(account: object) -> str | None:
    """The CAIP-2 network of a CAIP-10 account (namespace:reference:address): namespace:reference; None for any value
    of another form."""
    if not isinstance(account, str):
        return None
    parts = account.split(":", 2)
    return f"{parts[0]}:{parts[1]}" if len(parts) == 3 else None


def shown(
    binding: Binding,
    request: Mapping[str, Any],
    atr_bytes: bytes,
    inputs: Inputs,
    ceilings: Ceilings | None,
    network: str | None = None,
    opened: Opened | None = None,
) -> Summary | Declined:
    """Checks 10 and 11 on a request handed to the signer: its summary, read with network, the signing account's
    CAIP-2 network where the gate knows the account, and opened, for a later step of a payment signed in steps, the
    step that opened its channel; or the decline."""
    pairing = str(binding.id)
    summary = summary_of(pairing, request, atr_bytes, network, opened)
    if summary is None:
        return _declined("summary-missing", f"The gate has no summary of the {request.get('kind')} request of {pairing}.")
    ceiling = within_ceiling(pairing, summary, inputs, ceilings, _now())
    return summary if ceiling is None else ceiling


async def approves(
    binding: Binding,
    act: Act,
    request: dict[str, Any],
    atr_bytes: bytes,
    step: SigningStep,
    approval: Approval,
    network: str | None = None,
    opened: Opened | None = None,
) -> Summary | Declined:
    """Checks 10 to 12 on one signing: the summary, read with network, the signing account's CAIP-2 network, and
    opened, for a later step, the step that opened its channel; the ceiling; then the approver, asked once with ToSign;
    any answer but True, a raise or a failed awaitable is not-approved. The summary the approver approved, or the
    decline."""
    summary = shown(binding, request, atr_bytes, approval.inputs, approval.ceilings, network, opened)
    if isinstance(summary, Declined):
        return summary
    to_sign = ToSign(act=act, pairing=str(binding.id), request=copy.deepcopy(request), summary=summary, step=step)
    try:
        answer: object = approval.approver(to_sign)
        if inspect.isawaitable(answer):
            answer = await answer
    except Exception:
        answer = None
    if answer is True:
        return summary
    return _declined("not-approved", f"The approver did not approve step {step.index + 1} of {step.count}.")
