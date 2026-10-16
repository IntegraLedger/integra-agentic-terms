"""The values the gate and the bindings exchange, and the shapes of a binding, a buyer piece and a signer."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

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
]

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
    offer names, for a pairing whose payment is not itself a public proof of the ATR hash."""

    pairing: str
    choice: dict[str, Any]
    ref: str
    agreement: str | None = None


@dataclass(frozen=True, slots=True)
class Confirmed:
    """The comparison passed. `request` is what the signer is handed, or None when nothing is handed to the signer: the
    pairing has nothing for the buyer to sign, or the build is itself the payment, which finish completes with no
    signature."""

    chosen: Chosen
    request: dict[str, Any] | None
    atr_bytes: bytes
    h: AtrHash


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
    """The next request of a payment signed in steps."""

    next: dict[str, Any]
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
class AgreementReceipt:
    """The agreement resource's answer once the agreement payment carrying the ATR hash is recorded."""

    atr_hash: AtrHash
    agreed: Literal[True]
    network: str
    transaction: str


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
    @property
    def id(self) -> str: ...

    @property
    def public_proof(self) -> bool:
        """Whether the pairing's payment is itself a public proof of the hash, so an agreement URL is not paid."""
        ...

    def read(self, doc: Any) -> Advertised | Refusal: ...

    def build(self, choice: Any, h: AtrHash) -> Any:
        """The unsigned payment for the choice, which is the pairing's own: an object for most pairings, the
        checkout_jwt string for VI's."""
        ...

    def bound(self, presented: Any) -> AtrHash | Refusal: ...

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
