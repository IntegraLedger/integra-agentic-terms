"""The buyer pieces MPP's pairings share: the first challenge, in document order, that offers the pairing on the
account's network, as MPP's network reads it; the choice the build takes; the build's request exactly as built; the
credential the signer's answer completes; and the piece of a pairing
whose build has nothing for the buyer to sign."""

import base64
import binascii
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Binding, Chosen, Inputs, Json, Refusal, Signature, Step
from ..bindings._jose import parse_json
from ..bindings._mpp import network, pairings_of
from ._base import BasePiece
from ._common import InputKind, account_of, bigint_of, broadcasts, bytes_of, inputs_of

EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_B64_BODY = re.compile(r"[A-Za-z0-9+/]*={0,2}")

Accept = Callable[[Mapping[str, Any]], Refusal | None]


def request_of(c: object) -> dict[str, Any] | None:
    """The request a challenge carries, decoded from base64url JSON, or None."""
    if not isinstance(c, Mapping) or not isinstance(c.get("request"), str):
        return None
    b64 = c["request"].replace("-", "+").replace("_", "/")
    b64 += "=" * ((4 - len(b64) % 4) % 4)
    if _B64_BODY.fullmatch(b64) is None:
        return None
    try:
        value = parse_json(base64.b64decode(b64, validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def pairings_of_placed(c: object) -> tuple[str, ...]:
    """The pairings a placed challenge offers: MPP's pairings_of over the challenge without its opaque."""
    if not isinstance(c, Mapping):
        return ()
    issued = {k: v for k, v in c.items() if k != "opaque"}
    p = pairings_of(issued)
    return () if isinstance(p, Refusal) else p


def challenges_of(read: Advertised) -> Sequence[Any]:
    offer = read.offer
    challenges = offer.get("challenges") if isinstance(offer, Mapping) else None
    return challenges if isinstance(challenges, list) else []


def mpp_choose(pairing: str, spec: Mapping[str, InputKind], accept: Accept | None = None) -> Callable[..., Chosen | Refusal]:
    """The first challenge offering pairing on the account's EVM network, with the choice MPP's build takes: the
    challenge, from, now, and the buyer's own inputs named in spec."""

    def choose(read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        a = account_of(account)
        if a is None or a.namespace != "eip155" or EVM_ADDRESS.fullmatch(a.address) is None:
            return Refusal("mpp/no-payable-option")
        challenge = next(
            (c for c in challenges_of(read) if pairing in pairings_of_placed(c) and network(c) == a.network), None
        )
        if challenge is None:
            return Refusal("mpp/no-payable-option")
        refused = accept(challenge) if accept is not None else None
        if refused is not None:
            return refused
        given = inputs_of(inputs, pairing, spec)
        if isinstance(given, Refusal):
            return given
        return Chosen(pairing=pairing, choice={"challenge": challenge, "from": a.address, "now": now, **given}, ref=ref)

    return choose


def mpp_choice(chosen: Chosen) -> Any:
    """The choice as MPP's build takes it, with deposit as an int where the choice carries one."""
    c = chosen.choice if isinstance(chosen, Chosen) and isinstance(chosen.choice, dict) else None
    if c is None:
        return Refusal("mpp/choice-malformed")
    if "deposit" not in c:
        return c
    deposit = bigint_of(c["deposit"])
    return Refusal("mpp/choice-malformed") if deposit is None else {**c, "deposit": deposit}


def mpp_request(unsigned: Any) -> dict[str, Any] | Refusal:
    """The build's request, exactly as built."""
    r = getattr(unsigned, "request", None)
    if not isinstance(r, Mapping):
        return Refusal("mpp/request-malformed")
    return dict(r)


def mpp_complete(unsigned: Any, signature: Signature) -> dict[str, Any] | Refusal:
    """The credential for a one-value answer: a signature, a signed transaction or a transaction hash, as 0x hex."""
    if not isinstance(signature, str):
        return Refusal("mpp/credential-malformed")
    out: dict[str, Any] | Refusal = unsigned.complete(signature)
    return out


class MppChargePiece(BasePiece):
    """The buyer piece for an MPP charge pairing whose answer is one value."""

    def __init__(self, pairing: str, spec: Mapping[str, InputKind], accept: Accept | None = None) -> None:
        self.pairing = pairing
        self._choose = mpp_choose(pairing, spec, accept)

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        return self._choose(read, account, inputs, now, ref, doc)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return mpp_choice(chosen)

    def request(self, unsigned: Any) -> dict[str, Any] | Refusal:
        return mpp_request(unsigned)

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        return mpp_complete(unsigned, signature)

    def moves(self, request: Json) -> bool:
        return broadcasts(request)


# ── The rail pieces.

RailComplete = Callable[[Any, Signature, Chosen], "dict[str, Any] | Step | Refusal"]


@dataclass(frozen=True, slots=True)
class MppRail:
    """One MPP rail pairing's buyer piece, described by what differs between pairings: the account's CAIP-2
    namespace (None where the challenge's network alone decides), the form of its address, the choice field the
    address fills (None when the build takes none), whether the build takes now, the buyer's own values beside the
    challenge, the choice as the build takes it, the request handed to the signer, and the completion."""

    pairing: str
    namespace: str | None
    address: re.Pattern[str]
    payer: str | None
    now: bool
    inputs: Callable[[Mapping[str, Any], Inputs], "dict[str, Any] | Refusal"]
    revive: Callable[[dict[str, Any]], Any]
    complete: RailComplete
    request: Callable[[Any], "dict[str, Any] | None | Refusal"] | None = None
    # The challenge's network where the account's own network is the configured one, in place of MPP's network.
    network: Callable[[Mapping[str, Any], str], "str | Refusal"] | None = None


def rail_choose(rail: MppRail) -> Callable[..., Chosen | Refusal]:
    """The first challenge offering the pairing on the account's network, with the choice the build takes."""

    def choose(read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        a = account_of(account)
        if a is None or (rail.namespace is not None and a.namespace != rail.namespace) or rail.address.fullmatch(a.address) is None:
            return Refusal("mpp/no-payable-option")
        network_of = rail.network if rail.network is not None else (lambda c, _account: network(c))
        challenge = next(
            (c for c in challenges_of(read) if rail.pairing in pairings_of_placed(c) and network_of(c, a.network) == a.network),
            None,
        )
        if challenge is None:
            return Refusal("mpp/no-payable-option")
        given = rail.inputs(request_of(challenge) or {}, inputs)
        if isinstance(given, Refusal):
            return given
        choice: dict[str, Any] = {"challenge": challenge}
        if rail.payer is not None:
            choice[rail.payer] = a.address
        if rail.now:
            choice["now"] = now
        choice.update(given)
        return Chosen(pairing=rail.pairing, choice=choice, ref=ref)

    return choose


def built_request(unsigned: Any) -> dict[str, Any] | Refusal:
    """The build's request, exactly as built."""
    r = getattr(unsigned, "request", None)
    return dict(r) if isinstance(r, Mapping) else Refusal("mpp/request-malformed")


class MppRailPiece(BasePiece):
    """The buyer piece for one MPP rail pairing."""

    def __init__(self, rail: MppRail) -> None:
        self.pairing = rail.pairing
        self._rail = rail
        self._choose = rail_choose(rail)

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        return self._choose(read, account, inputs, now, ref, doc)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = chosen.choice if isinstance(chosen, Chosen) and isinstance(chosen.choice, dict) else None
        if c is None or not isinstance(c.get("challenge"), Mapping):
            return Refusal("mpp/choice-malformed")
        return self._rail.revive(c)

    def request(self, unsigned: Any) -> dict[str, Any] | None | Refusal:
        return self._rail.request(unsigned) if self._rail.request is not None else built_request(unsigned)

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        return self._rail.complete(unsigned, signature, chosen)


def signature64(signature: Signature) -> bytes | Refusal:
    """A 64-byte signature given as 0x hex, as bytes."""
    out = bytes_of(signature, 64)
    return Refusal("mpp/credential-malformed") if out is None else out


def hex_digits(value: object) -> str | None:
    """The hex digits of a 0x hex answer, without the prefix."""
    return value[2:] if isinstance(value, str) and bytes_of(value) is not None and len(value) > 2 else None


def complete_with(answer: Callable[[Signature], Any]) -> RailComplete:
    """The completion of a build whose complete takes the signer's answer as given, converted by answer."""

    def complete(unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        a = answer(signature)
        if isinstance(a, Refusal):
            return a
        out: dict[str, Any] | Refusal = unsigned.complete(a)
        return out

    return complete


def session_revive(c: dict[str, Any]) -> Any:
    """A session opening's choice as the build takes it, with deposit as an int where the choice carries one."""
    return mpp_choice(Chosen(pairing="", choice=c, ref=""))


# ── Confirm only.


class MppConfirmOnlyPiece(BasePiece):
    """The buyer piece for a pairing whose build has nothing for the buyer to sign: the first challenge, in document
    order, that offers the pairing. The gate's comparison is the whole of the buyer's step."""

    def __init__(self, pairing: str) -> None:
        self.pairing = pairing

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        challenge = next((c for c in challenges_of(read) if self.pairing in pairings_of_placed(c)), None)
        if challenge is None:
            return Refusal("mpp/no-payable-option")
        return Chosen(pairing=self.pairing, choice={"challenge": challenge, "now": now}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = chosen.choice if isinstance(chosen, Chosen) and isinstance(chosen.choice, dict) else None
        return Refusal("mpp/choice-malformed") if c is None or not isinstance(c.get("challenge"), Mapping) else c

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        return binding.build(choice, h)

    def request(self, unsigned: Any) -> Refusal:
        return Refusal("mpp/nothing-to-sign")

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> Refusal:
        return Refusal("mpp/nothing-to-sign")
