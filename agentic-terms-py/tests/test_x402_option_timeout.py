"""Every x402 pairing's read offers an option whose maxTimeoutSeconds is a positive safe integer, and no other.

x402 v2's PaymentRequirements gives maxTimeoutSeconds as the number of seconds the payment may take
(specs/x402-specification-v2.md at x402-foundation/x402 e95b06661e), and @integraledger/lcp's option filters hold it to a
positive safe integer, a JSON number with an integral value such as 60.0 reading as that integer. The options are the
ones @integraledger/lcp's vector files hold."""

from collections.abc import Iterator
from typing import Any

import pytest

import integraledger_terms
from integraledger_terms import Refusal

from support import VECTORS, load

BINDINGS: dict[str, Any] = {
    binding.id: binding
    for binding in (getattr(integraledger_terms, name) for name in integraledger_terms.__all__)
    if isinstance(getattr(binding, "id", None), str) and binding.id.startswith("x402/")
}
FILES = sorted(path.name for path in VECTORS.glob("x402-*.json")) + ["buyer.json"]


def options_in(value: Any) -> Iterator[dict[str, Any]]:
    """Every object in a vector file that names a scheme and a network, as an x402 option does."""
    if isinstance(value, list):
        for item in value:
            yield from options_in(item)
    elif isinstance(value, dict):
        if isinstance(value.get("scheme"), str) and isinstance(value.get("network"), str):
            yield value
        for item in value.values():
            yield from options_in(item)


OPTIONS = [option for name in FILES for option in options_in(load(name))]
ABSENT = object()

# Each maxTimeoutSeconds and whether a filter offers it: an integral JSON number from 1 to 2^53 - 1, and nothing else.
TIMEOUTS: list[tuple[str, object, bool]] = [
    ("1", 1, True),
    ("60", 60, True),
    ("60.0", 60.0, True),
    ("60.5", 60.5, False),
    ('"60"', "60", False),
    ("0", 0, False),
    ("-1", -1, False),
    ("-60.0", -60.0, False),
    ("2^53", 2**53, False),
    ("true", True, False),
    ("null", None, False),
    ("absent", ABSENT, False),
]


def offering(*options: Any) -> dict[str, Any]:
    """A document offering the options, with a legal context."""
    info = {"type": "sha256", "value": "0x" + "00" * 32, "legalContextUrl": "https://pairing.invalid/"}
    return {
        "x402Version": 2,
        "resource": {"url": "https://pairing.invalid/"},
        "accepts": list(options),
        "extensions": {"legalContext": {"info": info}},
    }


def with_timeout(option: dict[str, Any], timeout: object) -> dict[str, Any]:
    changed = {k: v for k, v in option.items() if k != "maxTimeoutSeconds"}
    if timeout is not ABSENT:
        changed["maxTimeoutSeconds"] = timeout
    return changed


def offered_at_60(pairing: str) -> dict[str, Any] | None:
    """The first vector option the pairing's read offers once its maxTimeoutSeconds is 60."""
    read = BINDINGS[pairing].read
    return next((o for o in OPTIONS if not isinstance(read(offering(with_timeout(o, 60))), Refusal)), None)


def test_the_rule_is_read_on_the_29_x402_pairings() -> None:
    """The test below runs once per x402 binding: the 29 x402 pairings of the protocol package's BINDINGS."""
    assert len(BINDINGS) == 29


@pytest.mark.parametrize("pairing", sorted(BINDINGS))
def test_an_x402_option_is_offered_only_with_a_positive_safe_integer_timeout(pairing: str) -> None:
    """Of a document holding the option under each timeout, read offers the ones with a positive safe integer, in
    document order; a document holding one option under any other timeout is x402/no-payable-option."""
    option = offered_at_60(pairing)
    assert option is not None, f"no vector option that {pairing}'s read offers"
    read = BINDINGS[pairing].read
    accepts = [with_timeout(option, timeout) for _, timeout, _ in TIMEOUTS]
    answer = read(offering(*accepts))
    assert not isinstance(answer, Refusal), answer
    labels = {id(o): label for o, (label, _, _) in zip(accepts, TIMEOUTS)}
    assert [labels[id(o)] for o in answer.offer["options"]] == [label for label, _, offers in TIMEOUTS if offers]
    for (label, _, offers), changed in zip(TIMEOUTS, accepts):
        if not offers:
            assert (label, read(offering(changed))) == (label, Refusal("x402/no-payable-option"))
