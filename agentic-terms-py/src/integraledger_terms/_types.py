"""The values the gate and the bindings exchange, and the shapes of a binding, a buyer piece and a signer."""

import inspect
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, NotRequired, Protocol, TypedDict

from ._core import AtrHash

Json = Mapping[str, Any]

# The signer's answer, as JSON: a signature for the kinds whose payment takes one signature, an object for the kinds
# whose payment takes several values, and a list, in order, for a payment signed in steps. Byte strings are 0x hex,
# except where the signers guide names another form for the kind: base58, base64, or hex digits without 0x.
Signature = Any

# The buyer's own values a pairing's build needs beside the offer, such as a recent block or an account nonce.
Inputs = Mapping[str, Any]

DeclineCode = Literal[
    "pairing-not-supported",
    "offer-unreadable",
    "no-payable-option",
    "link-not-https",
    "atr-unfetchable",
    "atr-too-large",
    "hash-mismatch",
    "signer-failed",
    "signed-not-bound",
    "agreement-not-offered",
    "agreement-pending",
    "agreement-failed",
    "not-approved",
    "atr-malformed",
    "option-not-in-atr",
    "request-mismatch",
    "summary-missing",
    "past-ceiling",
    "no-end",
    "floor-missing",
]

# A pairing's coverage, as the protocol package's registry data states it: "full" where the payer's own signed act,
# on a public ledger, binds all of H, so the payment is itself the proof; "none" where no public payer-signed act
# carries H, so the payment is made only after the agreement is recorded.
Coverage = Literal["full", "none"]


@dataclass(frozen=True, slots=True)
class AgreementData:
    """The registry's agreement datum of a pairing whose payment can itself be the agreement: floor, the smallest amount
    the scheme and token admit ("0", a count of base units, or "rule" where the pairing's build evaluates it), and only,
    where the form is offered as an agreement and never as a charge."""

    floor: str
    only: bool = False


def coverage_of(binding: object) -> Coverage | None:
    """The binding's coverage, or None where it states none the registry admits."""
    c = getattr(binding, "coverage", None)
    return "full" if c == "full" else "none" if c == "none" else None


def agreement_of(binding: object) -> AgreementData | None:
    """The binding's agreement datum, where its payment can itself be the agreement, and only at coverage full."""
    a = getattr(binding, "agreement", None)
    return a if isinstance(a, AgreementData) and coverage_of(binding) == "full" else None


# The act a payment is built and checked for: the sale's payment, or the agreement payment made before a payment at
# coverage none. On a pairing whose single-use value is H itself, the agreement carries the agreement's own value
# (agreement_value), so the two acts under one H never share a single-use value.
Act = Literal["payment", "agreement"]


# Who puts what a payer presents on its rail: "payer", which sent the payment before presenting it, so the seller reads
# a landed payment, or "payee", the seller, or the facilitator or processor acting for it, which sends or executes it.
Broadcaster = Literal["payer", "payee"]


@dataclass(frozen=True, slots=True)
class Moved:
    """What the signer moved before a decline: the payment as signed, in the protocol's own form, with the ATR bytes
    and their hash, for the buyer to keep and present again."""

    signed: Any
    atr_bytes: bytes
    h: AtrHash


@dataclass(frozen=True, slots=True)
class Declined:
    """A decline. moved is present when the signer moved the payment before the decline."""

    code: DeclineCode
    detail: str
    moved: Moved | None = None


@dataclass(frozen=True, slots=True)
class Chosen:
    """What the gate chose to pay, so finish can rebuild the same request. agreement is the agreement URL the seller's
    offer names, for a pairing at coverage none, whose payment is not itself a public proof of the ATR hash. act is the
    act the payment is built and checked for: "agreement" for the agreement payment, else "payment". deadline, for a
    form whose wallet picks the expiry, is the latest deadline the request handed to it carries, a decimal string in
    the form's unit, so that a rebuild gives the request the signer was handed and the signed deadline is held to it."""

    pairing: str
    choice: dict[str, Any]
    ref: str
    agreement: str | None = None
    act: Act = "payment"
    deadline: str | None = None


@dataclass(frozen=True, slots=True)
class Confirmed:
    """The comparison passed. `request` is what the signer is handed, with its summary, or None when nothing is handed
    to the signer: the pairing has nothing for the buyer to sign, or the build is itself the payment, which finish
    completes with no signature."""

    chosen: Chosen
    request: dict[str, Any] | None
    atr_bytes: bytes
    h: AtrHash
    summary: "Summary | None" = None


@dataclass(frozen=True, slots=True)
class Finished:
    """The payment and the hash of the bytes it carries. landed is the landed receipt the completion carried for bound
    and the payment sent leaves out, where there is one, as JSON, so check and open_channel can later read the payment
    with it."""

    signed: dict[str, Any]
    h: AtrHash
    landed: Any = None


@dataclass(frozen=True, slots=True)
class Next:
    """The next request of a payment signed in steps, with its summary, the authority signing it grants (terms'
    profile buyer-gate.md, rule 13), which finish computes before it returns the request, and the hash of the
    bytes."""

    next: dict[str, Any]
    summary: "Summary"
    h: AtrHash


@dataclass(frozen=True, slots=True)
class Step:
    """A piece's answer for a payment signed in steps: the request the signer is handed next."""

    next: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AgreementPayment:
    """The agreement payment, for the buyer's agent to approve before anything is signed: the agreement URL; option, the
    option of the agreement URL's payment request that the gate pays, whose amount, asset, payTo and network are the
    terms the agent approves; and required, that payment request as the agreement URL served it."""

    url: str
    option: dict[str, Any]
    required: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ToApprove:
    """An agreement payment the agent approves before it is signed, with the ATR bytes the gate compared and their
    hash."""

    approve: AgreementPayment
    atr_bytes: bytes
    h: AtrHash


@dataclass(frozen=True, slots=True)
class AgreementChallenges:
    """The agreement resource's MPP agreement challenges, where its one 402 offers no x402 agreement option and one or
    more WWW-Authenticate: Payment challenges for the ATR's H: each in the seller's order, for the caller's own MPP
    client to pay at the agreement URL, with the ATR bytes the gate compared and their hash. terms signs none of them."""

    agreement_challenges: tuple[dict[str, Any], ...]
    atr_bytes: bytes
    h: AtrHash


@dataclass(frozen=True, slots=True)
class AgreementReceipt:
    """The agreement resource's receipt: its statement that an agreement payment carrying the ATR hash is recorded, in
    network by transaction. The gate checks its form and that atr_hash is H, and does not read the transaction. unpaid
    is True where the agreement resource answered the unpaid request with this receipt: the call made no agreement
    payment and read none, so the receipt is the agreement resource's statement alone (terms' profile buyer-gate.md,
    rule 18); False where it answered the paid request."""

    atr_hash: AtrHash
    agreed: Literal[True]
    network: str
    transaction: str
    unpaid: bool = False


@dataclass(frozen=True, slots=True)
class Transacted:
    """The payment, the bytes compared, their hash, and the agreement's receipt when the agreement was paid first.
    `signed` is None when the pairing has nothing for the buyer to sign. `landed` is finish's, where it gives one."""

    signed: dict[str, Any] | None
    atr_bytes: bytes
    h: AtrHash
    agreement: AgreementReceipt | None = None
    landed: Any = None


@dataclass(frozen=True, slots=True)
class Checked:
    h: AtrHash


@dataclass(frozen=True, slots=True)
class Agreed:
    receipt: AgreementReceipt


@dataclass(frozen=True, slots=True)
class Refusal:
    code: str


@dataclass(frozen=True, slots=True)
class Advertised:
    """What a binding's read gives the gate: H, the link, what the pairing's piece chooses from, and the agreement URL
    when the offer names one."""

    h: AtrHash
    link: str
    offer: dict[str, Any]
    agreement: str | None = None


class Unsigned(Protocol):
    @property
    def typed_data(self) -> dict[str, Any]: ...

    def complete(self, signature: str) -> dict[str, Any] | Refusal: ...


class Binding(Protocol):
    """A pairing's buyer half. Each binding also carries the registry's coverage and agreement data, read with
    coverage_of and agreement_of: coverage "full" where the pairing's payment is itself a public proof of the hash, so
    an agreement URL is not paid, and agreement where that payment can itself be the agreement."""

    @property
    def id(self) -> str: ...

    def read(self, doc: Any) -> Advertised | Refusal: ...

    def build(self, choice: Any, h: AtrHash, act: Act | None = None) -> Any:
        """The unsigned payment for the choice, which is the pairing's own: an object for most pairings, the
        checkout_jwt string for VI's. For the act agreement, on a pairing whose single-use value is H itself, the
        payment carries the agreement's own value for H."""
        ...

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H as the presented payment carries it; given {"act": "agreement", "h": H}, H where the payment carries the
        agreement's own value for H, on a pairing whose agreement has one."""
        ...

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """Who puts the presented payment on its rail: "payer" or "payee". It answers only for a payment of a type and
        kind the pairing takes, within the shape gate bound applies first, and gives any other payment the refusal bound
        gives that fault; a fault bound finds in H, the challenge, an amount or a signature does not change the answer.
        A session's or batch channel's bound reads the opening alone, so for any other action the reader is
        channel_kind: a payment it refuses for its own content gets its refusal. It reads no rail and no peer."""
        ...


class Signer(Protocol):
    @property
    def account(self) -> str: ...

    async def sign(self, request: Json) -> Signature: ...


class Piece(Protocol):
    """One pairing's buyer piece: which option to pay, the build input it revives from Chosen, what the signer is
    handed, and how the signer's answer completes the payment."""

    def choose(
        self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Any
    ) -> Chosen | Refusal: ...

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any: ...

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any: ...

    def request(self, unsigned: Any) -> dict[str, Any] | None | Refusal: ...

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal: ...

    def sent(self, signed: dict[str, Any]) -> dict[str, Any]: ...

    def moves(self, request: Json) -> bool:
        """True when the signer, handed this first request, moves the payment itself before the gate reads what was
        signed."""
        ...


def _takes(method: Callable[..., Any], name: str) -> bool:
    try:
        return name in inspect.signature(method).parameters
    except (TypeError, ValueError):
        return False


def build_act(binding: Binding, choice: Any, h: AtrHash, act: Act) -> Any:
    """The binding's build for the act: build(choice, h, act="agreement") for an agreement where the binding's build
    takes the act, as the protocol package's build(choice, h, act) does, else build(choice, h). A binding whose build
    takes no act carries the same single-use value on both acts."""
    build: Any = binding.build
    if act == "agreement" and _takes(build, "act"):
        return build(choice, h, act="agreement")
    return build(choice, h)


def bound_act(binding: Binding, presented: Any, h: AtrHash, act: Act) -> Any:
    """The binding's bound for the act: for an agreement, bound(presented, given={"act": "agreement", "h": h}) where
    the binding's bound takes it, as the protocol package's bound(presented, {act, h}) does, which gives h where the
    payment carries the agreement's own value; else bound(presented)."""
    bound: Any = binding.bound
    if act == "agreement" and _takes(bound, "given"):
        return bound(presented, given={"act": "agreement", "h": h})
    return bound(presented)


class HttpRequest(TypedDict):
    """The buyer's own request over HTTP, as the protocol package's request commitment reads it: the method token and the
    request-target as received, the body's bytes, and, where the request has header fields, each field's name with its
    value or its lines in the order received."""

    method: str
    target: str
    body: bytes
    headers: NotRequired[Mapping[str, str | Sequence[str]]]


class ToolCall(TypedDict):
    """The buyer's own request over MCP: the tools/call request's params.name and params.arguments."""

    name: str
    arguments: NotRequired[Mapping[str, Any]]


# The request the buyer is about to pay, the one the seller's offer answered.
ResourceRequest = HttpRequest | ToolCall

# The raised ceilings: a pairing id mapped to a positive integer of seconds (a bool is no integer), the longest a signed
# payment through it may stay payable, or to "no-end", which lifts the pairing's ceiling and admits a form that signs no
# end.
Ceilings = Mapping[str, int | Literal["no-end"]]


@dataclass(frozen=True, slots=True)
class SigningStep:
    """Which signing of a payment the approver is asked about: index, from 0, of count signings."""

    index: int
    count: int


@dataclass(frozen=True, slots=True)
class Payee:
    """A payee of the summary: its account as the form names it, and its part of the amount or of the maximum."""

    account: str
    amount: str


@dataclass(frozen=True, slots=True)
class Validity:
    """From and until when the signed payment is payable, each None where the form signs none, in unit: "seconds" for
    Unix seconds, or a chain's own unit (a round, a slot, a block, a ledger or an epoch)."""

    not_before: str | None
    not_after: str | None
    unit: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Summary:
    """Every authority the signature grants, read from the request handed to the signer. Each integer is a decimal
    string, each amount in the asset's base units, each time in Unix seconds but a validity whose unit names another. A
    member the form does not have is None; payees, asset, network, validity and atr are always present."""

    amount: str | None = None
    maximum: str | None = None
    payees: tuple[Payee, ...]
    period: str | None = None
    limit_per_period: str | None = None
    end: str | None = None
    operator: str | None = None
    authorization_expiry: str | None = None
    refund_expiry: str | None = None
    deposit: str | None = None
    closable_by: tuple[str, ...] | None = None
    grant: Any = None
    asset: str
    # The CAIP-2 network, or None where the payment moves on no ledger (a card network, a fiat checkout).
    network: str | None
    validity: Validity
    atr: bytes


@dataclass(frozen=True, slots=True)
class ToSign:
    """What the approver is asked about, once for each signing, before the signer is called for it: the act ("payment",
    the payment for the resource, or "agreement", the agreement payment), the id of the pairing whose build made the
    request, the request the signer will be handed, as the signer is handed it, its summary, and the step."""

    act: Act
    pairing: str
    request: dict[str, Any]
    summary: Summary
    step: SigningStep


# The approval callback transact requires: True, or an awaitable of it, approves the signing; any other answer, a raise
# or a failed awaitable approves nothing.
Approver = Callable[[ToSign], bool | Awaitable[bool]]


@dataclass(frozen=True, slots=True)
class ToReturn:
    """What transact returns once the agreement of a pairing paid after its agreement is paid, or is left to the
    caller's own MPP client: the agreement's receipt, where transact paid an x402 agreement option, else None; the
    Legal-Context value the caller sends when it repeats its request; the charge chosen, <slot>/<i>; the ATR's bytes the
    gate compared; H, their SHA-256; and, where the agreement resource offers only MPP agreement challenges, those
    challenges in the seller's order, which transact signs none of, else None. Exactly one of agreement and
    agreement_challenges is not None. No charge is signed before the return."""

    agreement: AgreementReceipt | None
    legal_context: str
    charge: str
    atr_bytes: bytes
    h: AtrHash
    agreement_challenges: tuple[dict[str, Any], ...] | None = None
