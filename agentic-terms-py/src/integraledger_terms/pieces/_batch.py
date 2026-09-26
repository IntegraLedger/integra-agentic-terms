"""What the x402 batch-settlement pieces share: the deposit the buyer commits, random salts drawn once, the batch
signing request exactly as built, the payment the list of answers completes with the payment identifier appended where
the challenge advertises it, and the choice's decimal members revived."""

import re
import secrets
from collections.abc import Mapping, Sequence
from typing import Any

from .._types import Chosen, Inputs, Refusal, Signature
from ..bindings._channel import BatchUnsigned
from ._common import bigint_of, choice_of, with_payment_identifier


def deposit_of(accepted: Mapping[str, Any], inputs: Inputs) -> str | Refusal:
    """The deposit: extra.minDeposit when the option carries one, else the buyer's deposit input. A deposit above the
    buyer's maxDeposit input, when given, is refused."""
    extra = accepted.get("extra")
    has_min = isinstance(extra, Mapping) and "minDeposit" in extra
    deposit = bigint_of(extra["minDeposit"] if isinstance(extra, Mapping) and has_min else inputs.get("deposit"))
    if deposit is None:
        return Refusal("x402/option-malformed" if has_min else "x402/input-missing")
    if "maxDeposit" in inputs:
        maximum = bigint_of(inputs["maxDeposit"])
        if maximum is None:
            return Refusal("x402/input-missing")
        if deposit > maximum:
            return Refusal("x402/deposit-above-maximum")
    return str(deposit)


def random_salt32() -> str:
    """32 random bytes as 0x hex."""
    return "0x" + secrets.token_bytes(32).hex()


def random_u64() -> str:
    """8 random bytes as a decimal u64."""
    return str(int.from_bytes(secrets.token_bytes(8), "big"))


def batch_request(unsigned: Any) -> dict[str, Any]:
    """The build's requests as one batch request, signed in order."""
    assert isinstance(unsigned, BatchUnsigned)
    return {"kind": "batch", "requests": list(unsigned.requests)}


def batch_complete(unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
    """The payment the list of answers, one per request in order, completes."""
    assert isinstance(unsigned, BatchUnsigned)
    if (
        not isinstance(signature, Sequence)
        or isinstance(signature, str)
        or len(signature) != len(unsigned.requests)
        or not all(isinstance(s, str) for s in signature)
    ):
        return Refusal("x402/signature-malformed")
    signed = unsigned.complete(list(signature))
    if isinstance(signed, Refusal):
        return signed
    return with_payment_identifier(signed, chosen.choice.get("required"), chosen.ref)


def revive_decimals(chosen: Chosen, keys: Sequence[str]) -> dict[str, Any] | Refusal:
    """The choice with the named decimal members as ints, or a refusal when one is not a decimal."""
    c = choice_of(chosen)
    if c is None:
        return Refusal("x402/choice-malformed")
    out = dict(c)
    for key in keys:
        if key not in c:
            continue
        value = bigint_of(c[key])
        if value is None:
            return Refusal("x402/choice-malformed")
        out[key] = value
    return out


def optional_inputs(inputs: Inputs, ns: str, spec: Mapping[str, re.Pattern[str] | str]) -> dict[str, Any] | Refusal:
    """The optional inputs of the given kinds that are present ("object", or a pattern a string matches), or the
    refusal naming the first malformed one."""
    out: dict[str, Any] = {}
    for key, kind in spec.items():
        if key not in inputs:
            continue
        value = inputs[key]
        ok = (
            isinstance(value, Mapping)
            if kind == "object"
            else isinstance(kind, re.Pattern) and isinstance(value, str) and kind.fullmatch(value) is not None
        )
        if not ok:
            return Refusal(f"{ns}/input-missing")
        out[key] = value
    return out
