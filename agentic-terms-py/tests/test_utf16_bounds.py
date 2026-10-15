"""Each bound the Python bindings count in UTF-16 code units, as String.prototype.length counts a string (ECMA-262
§6.1.4): Casper's name and version (64), Stripe's metadata key (40) and value (500), a Stacks contract name (128) and
the MPP echoed-request budget. Each bound is the protocol package's. A string at the bound passes and one unit past it
does not; a code-point count would pass the astral strings past each bound, which is the control."""

import pytest

from integraledger_terms.bindings import _mpp, _mpp_checks, x402_exact_casper
from integraledger_terms.bindings._jose import js_length

ASTRAL = "\U0001f600"  # one code point, two code units
PAIR = "\ud83d\ude00"  # the same two code units held as two code points
LONE = "\ud800"  # one code unit
BMP = "\u00e9"  # one code unit


@pytest.mark.parametrize(("text", "units"), [("", 0), ("a", 1), (BMP, 1), (ASTRAL, 2), (PAIR, 2), (LONE, 1), ("\udc00" + LONE, 2), ("a" + ASTRAL * 3, 7)])
def test_js_length_counts_utf16_code_units(text: str, units: int) -> None:
    assert js_length(text) == units


def at_and_past(bound: int, piece: str) -> tuple[str, str]:
    """The piece repeated to exactly the bound in UTF-16 code units, and one piece more."""
    n = bound // js_length(piece)
    assert n * js_length(piece) == bound
    return piece * n, piece * (n + 1)


PIECES = ("a", BMP, ASTRAL, PAIR, LONE)


@pytest.mark.parametrize("piece", PIECES)
def test_casper_names_are_bounded_at_64_units(piece: str) -> None:
    at, past = at_and_past(64, piece)
    assert x402_exact_casper._is_name(at) and not x402_exact_casper._is_name(past)
    assert not x402_exact_casper._is_name("")


def test_casper_the_control_an_astral_name_of_33_code_points_is_66_units() -> None:
    assert len(ASTRAL * 33) <= 64 and not x402_exact_casper._is_name(ASTRAL * 33)


@pytest.mark.parametrize("piece", PIECES)
def test_stripe_metadata_keys_and_values_are_bounded_at_40_and_500_units(piece: str) -> None:
    key_at, key_past = at_and_past(40, piece)
    value_at, value_past = at_and_past(500, piece)
    assert _mpp_checks.stripe_metadata_valid({key_at: value_at}, True) is None
    assert _mpp_checks.stripe_metadata_valid({key_past: "v"}, True) is not None
    assert _mpp_checks.stripe_metadata_valid({"k": value_past}, True) is not None


def test_stripe_the_control_astral_text_past_each_bound_in_units_is_within_it_in_code_points() -> None:
    assert len(ASTRAL * 21) <= 40 and _mpp_checks.stripe_metadata_valid({ASTRAL * 21: "v"}, True) is not None
    assert len(ASTRAL * 251) <= 500 and _mpp_checks.stripe_metadata_valid({"k": ASTRAL * 251}, True) is not None


def stacks(name: str) -> object:
    details = {"type": "stacks", "stacks": {"chainId": "1", "contractAddress": "S" + "P" * 39, "contractName": name}}
    return _mpp_checks.usdc_charge_pairings({"amount": "1", "recipient": "r"}, details, {})


def test_a_stacks_contract_name_is_bounded_at_128_units() -> None:
    assert stacks("a" * 128) == ["mpp/charge/usdc/stacks"]
    assert stacks("a" * 129) != ["mpp/charge/usdc/stacks"]


@pytest.mark.parametrize("piece", PIECES)
def test_the_echoed_request_budget_counts_a_string_in_units(piece: str) -> None:
    """A string costs its units and its two quotes; a member name its units, its quotes and a colon."""
    for n in (1, 7):
        text = piece * n
        cost = js_length(text) + 2
        assert _mpp._json_within(text, cost) and not _mpp._json_within(text, cost - 1)
        member = 2 + js_length(text) + 3 + 8
        assert _mpp._json_within({text: 1}, member) and not _mpp._json_within({text: 1}, member - 1)


def test_the_echoed_request_budget_the_control_an_astral_string_costs_two_units_a_code_point() -> None:
    assert not _mpp._json_within(ASTRAL * 7, len(ASTRAL * 7) + 2)
