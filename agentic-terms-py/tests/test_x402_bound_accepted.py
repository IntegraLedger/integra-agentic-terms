"""Every x402 pairing's bound holds a presented payment's accepted to the option filter its own read applies.

The payments are the ones @integraledger/lcp's x402 vector files hold, and the pairings are the ones those files'
boundAccepted rows name. x402 v2's PaymentPayload carries accepted, the PaymentRequirements object the payer chose
(specs/x402-specification-v2.md at x402-foundation/x402 e95b06661e), and the protocol package's refusal list gives
x402/payload-malformed for a presented payment whose accepted is not an object."""

from collections.abc import Iterator
from typing import Any

import pytest

import integraledger_terms
from integraledger_terms import Refusal

from support import VECTORS, load

X402_FILES = sorted(path.name for path in VECTORS.glob("x402-*.json"))
BINDINGS: dict[str, Any] = {
    binding.id: binding
    for binding in (getattr(integraledger_terms, name) for name in integraledger_terms.__all__)
    if isinstance(getattr(binding, "id", None), str) and binding.id.startswith("x402/")
}


def payments_in(value: Any) -> Iterator[dict[str, Any]]:
    """Every x402 v2 payment in a vector file: an object with x402Version 2, an object accepted and an object
    payload."""
    if isinstance(value, list):
        for item in value:
            yield from payments_in(item)
    elif isinstance(value, dict):
        if value.get("x402Version") == 2 and isinstance(value.get("accepted"), dict) and isinstance(value.get("payload"), dict):
            yield value
        for item in value.values():
            yield from payments_in(item)


PAYMENTS = [payment for name in X402_FILES for payment in payments_in(load(name))]


def test_the_x402_bindings_are_the_pairings_the_vector_files_name() -> None:
    named = {row["pairing"] for name in X402_FILES for row in load(name).get("boundAccepted", {}).get("rows", [])}
    assert named, "the x402 vector files hold no boundAccepted rows"
    assert set(BINDINGS) == named


_REMOVED = object()
NOT_AN_OBJECT: list[tuple[str, object]] = [
    ("null", None),
    ("a string", "exact"),
    ("a number", 2),
    ("an array", []),
    ("removed", _REMOVED),
]


@pytest.mark.parametrize("pairing", sorted(BINDINGS))
def test_a_presented_payment_whose_accepted_is_not_an_object_is_payload_malformed(pairing: str) -> None:
    """A vector payment the pairing's bound binds, with accepted replaced by each value that is not an object, or
    removed: bound refuses it x402/payload-malformed."""
    binding = BINDINGS[pairing]
    payment = next((p for p in PAYMENTS if not isinstance(binding.bound(p), Refusal)), None)
    assert payment is not None, f"no vector payment that {pairing}'s bound binds"
    for what, value in NOT_AN_OBJECT:
        presented = {k: v for k, v in payment.items() if k != "accepted"}
        if value is not _REMOVED:
            presented["accepted"] = value
        assert (what, binding.bound(presented)) == (what, Refusal("x402/payload-malformed"))
