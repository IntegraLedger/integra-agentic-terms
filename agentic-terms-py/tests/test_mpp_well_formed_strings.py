"""A string MPP hashes or signs must have a UTF-8 form: one holding a lone surrogate has none, so it is refused where it
is read, as the protocol package refuses it, and nothing is hashed, signed or raised. A challenge's realm, which the
challenge hash takes, is mpp/challenge-malformed when the challenge is checked and when an echoed challenge is read; an
id is left to its read as H. The challenges are the vector files' (mpp-challenge.json's R_T and R_E), each with one
member given a lone surrogate."""

from collections.abc import Iterator
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_EVM_AUTHORIZATION, Declined, Refusal
from support import confirm
from integraledger_terms import _gate
from integraledger_terms.bindings._mpp import challenge_bound, check_challenge
from integraledger_terms.pieces._mpp import pairings_of_placed

from breadth import ABC, H, LINK, run
from mpp_docs import MC, issued, placed_doc
from support import load, piece_confirm, serving

LONE = "\ud800"
AUTH = load("mpp-charge-evm-authorization.json")["fixed"]
ACCOUNT = f"eip155:84532:{AUTH['payer']}"


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_gate, "_now", lambda: AUTH["now"])
    yield


def placed() -> dict[str, Any]:
    return placed_doc(issued("tempo", "charge", MC["fixed"]["R_T"]), H, LINK)[0]


def test_a_realm_with_no_utf8_form_is_challenge_malformed_when_the_challenge_is_checked() -> None:
    good = placed()
    bad = {**good, "realm": good["realm"] + LONE}
    assert not isinstance(check_challenge(good, True), Refusal)
    assert check_challenge(bad, True) == Refusal("mpp/challenge-malformed")
    assert pairings_of_placed(bad) == ()


def test_through_the_gate_a_realm_with_no_utf8_form_offers_nothing_and_nothing_is_fetched() -> None:
    # The control, read, chosen and built by the pairing's own steps over the vectors' abc, with no gate.
    own = placed_doc(issued("evm", "charge", MC["fixed"]["R_E"]), H, LINK)[0]
    assert not isinstance(piece_confirm([own], MPP_CHARGE_EVM_AUTHORIZATION, ACCOUNT, {"tokenDomain": AUTH["tokenDomain"]}), Declined)
    bad = {**own, "realm": own["realm"] + LONE}
    link = serving(ABC)
    out = run(lambda c: confirm([bad], MPP_CHARGE_EVM_AUTHORIZATION, ACCOUNT, c, {"tokenDomain": AUTH["tokenDomain"]}), link)
    assert out == Declined("no-payable-option", "mpp/no-payable-option")
    assert link.calls == 0


def test_an_echoed_challenge_whose_realm_has_no_utf8_form_is_challenge_malformed() -> None:
    good = placed()
    credential = {"challenge": good, "payload": {"type": "hash", "hash": "0x" + "ab" * 32}}
    assert not isinstance(challenge_bound(credential), Refusal)
    bad = {**credential, "challenge": {**good, "realm": good["realm"] + LONE}}
    assert challenge_bound(bad) == Refusal("mpp/challenge-malformed")
