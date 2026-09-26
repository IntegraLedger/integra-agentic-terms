"""The buyer piece shared by x402 rail pairings: the first option on the account's network, the buyer's own inputs
beside it as JSON, the build's request exactly as built, and the payment the signer's answer completes, with the
payment identifier appended where the challenge advertises it."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ._base import BasePiece
from ._common import choice_of, first_option, with_payment_identifier


def x402_payment(required: Mapping[str, Any], accepted: Mapping[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """The x402 payment for a payload, echoing the challenge's resource and extensions unchanged, omitted when
    absent."""
    payment: dict[str, Any] = {"x402Version": 2}
    if "resource" in required:
        payment["resource"] = required["resource"]
    if "extensions" in required:
        payment["extensions"] = required["extensions"]
    payment["accepted"] = accepted
    payment["payload"] = payload
    return payment


@dataclass(frozen=True, slots=True)
class Rail:
    """One x402 rail pairing's buyer piece, described by what differs between rails."""

    pairing: str
    # The account's CAIP-2 namespace, and the form of its address.
    namespace: str
    address: re.Pattern[str]
    # The choice field the account's address fills, or None when the build takes none.
    payer: str | None
    # True when the build takes now.
    now: bool
    # The buyer's own values the build takes beside the option, as JSON, or the refusal naming the first missing.
    inputs: Callable[[Mapping[str, Any], Inputs], dict[str, Any] | Refusal]
    # The choice's JSON fields as the build takes them.
    revive: Callable[[dict[str, Any]], dict[str, Any] | Refusal]
    # The signer's answer as the build's complete takes it.
    answer: Callable[[Signature], Any]
    # The payment's payload, where the build's complete returns only the signed transaction as a string.
    payload: Callable[[str], dict[str, Any]] | None = None


class RailPiece(BasePiece):
    def __init__(self, rail: Rail) -> None:
        self.rail = rail
        self.pairing = rail.pairing

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        rail = self.rail
        o = first_option(read, account, rail.namespace, rail.pairing, rail.address)
        if isinstance(o, Refusal):
            return Refusal("x402/no-payable-option")
        given = rail.inputs(o.accepted, inputs)
        if isinstance(given, Refusal):
            return given
        choice: dict[str, Any] = {"required": o.required, "accepted": o.accepted}
        if rail.payer is not None:
            choice[rail.payer] = o.address
        if rail.now:
            choice["now"] = now
        choice.update(given)
        return Chosen(pairing=rail.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = choice_of(chosen)
        if c is None or not isinstance(c.get("required"), Mapping) or not isinstance(c.get("accepted"), Mapping):
            return Refusal("x402/choice-malformed")
        return self.rail.revive(c)

    def request(self, unsigned: Any) -> dict[str, Any] | Refusal:
        request = getattr(unsigned, "request", None)
        return request if isinstance(request, dict) else Refusal("x402/request-malformed")

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        answer = self.rail.answer(signature)
        if isinstance(answer, Refusal):
            return answer
        c = choice_of(chosen)
        assert c is not None
        completed = unsigned.complete(answer)
        if isinstance(completed, Refusal):
            return completed
        if isinstance(completed, str):
            if self.rail.payload is None:
                return Refusal("x402/payload-malformed")
            signed = x402_payment(c["required"], c["accepted"], self.rail.payload(completed))
        else:
            signed = completed
        return with_payment_identifier(signed, c["required"], chosen.ref)
