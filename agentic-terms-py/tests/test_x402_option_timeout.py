"""Every x402 pairing's read offers an option whose maxTimeoutSeconds is a positive safe integer, and no other.

x402 v2's PaymentRequirements gives maxTimeoutSeconds as the number of seconds the payment may take
(specs/x402-specification-v2.md at x402-foundation/x402 e95b06661e), and @integraledger/lcp's option filters hold it to
a positive safe integer, a JSON number with an integral value such as 60.0 reading as that integer. The options are the
ones @integraledger/lcp's vector files hold."""

from typing import Any

import pytest

from integraledger_terms import Refusal

from x402_options import BINDINGS, first_offered, offering

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


def with_timeout(option: dict[str, Any], timeout: object) -> dict[str, Any]:
    changed = {k: v for k, v in option.items() if k != "maxTimeoutSeconds"}
    if timeout is not ABSENT:
        changed["maxTimeoutSeconds"] = timeout
    return changed


def test_the_rule_is_read_on_the_29_x402_pairings() -> None:
    """The test below runs once per x402 binding: the 29 x402 pairings of the protocol package's BINDINGS."""
    assert len(BINDINGS) == 29


@pytest.mark.parametrize("pairing", sorted(BINDINGS))
def test_an_x402_option_is_offered_only_with_a_positive_safe_integer_timeout(pairing: str) -> None:
    """Of a document holding the option under each timeout, read offers the ones with a positive safe integer, in
    document order; a document holding one option under any other timeout is x402/no-payable-option."""
    option = first_offered(pairing, lambda o: with_timeout(o, 60))
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
