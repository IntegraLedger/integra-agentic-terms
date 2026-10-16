"""A string MPP hashes or signs must have a UTF-8 form: one holding a lone surrogate has none, so it is refused where it
is read, as the protocol package refuses it, and nothing is hashed, signed or raised. A challenge's realm, which the
attribution memo and the challenge hash take, is mpp/challenge-malformed when the challenge is checked and when an
echoed challenge is read; an id is left to its read as H. MPP Hedera's charge build holds the chosen challenge as
bound holds an echoed one, so such a realm is mpp/challenge-malformed and such an id mpp/id-not-ours, from build and
from bound, and such a clientId is hedera/option-malformed; a Tempo charge's clientId is
mpp/input-malformed; MPP Solana's session proof raises TypeError for such a channelId, payer or challengeId. The
challenges are the vector files' (mpp-challenge.json's R_T and the Tempo memo pairing; mpp-charge-hedera.json), each
with one member given a lone surrogate."""

from collections.abc import Iterator
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_HEDERA, MPP_CHARGE_TEMPO_MEMO, Declined, Refusal, confirm
from integraledger_terms import _gate
from integraledger_terms.bindings._codec import js_json
from integraledger_terms.bindings._mpp import challenge_bound, check_challenge
from integraledger_terms.bindings.mpp_charge_hedera import build_charge
from integraledger_terms.bindings.mpp_session_solana import session_proof
from integraledger_terms.pieces._mpp import pairings_of_placed

from breadth import ABC, H, LINK, run
from mpp_docs import MC, issued, placed_doc
from support import load, serving

LONE = "\ud800"
MEMO = load("mpp-charge-tempo-memo.json")
HEDERA = load("mpp-charge-hedera.json")["fixed"]
ACCOUNT = f"eip155:42431:{MEMO['fixed']['payer']}"


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_gate, "_now", lambda: MEMO["fixed"]["now"])
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
    bad = {**placed(), "realm": placed()["realm"] + LONE}
    link = serving(ABC)
    out = run(lambda c: confirm([bad], MPP_CHARGE_TEMPO_MEMO, ACCOUNT, c), link)
    assert out == Declined("no-payable-option", "mpp/no-payable-option")
    assert link.calls == 0


def test_an_echoed_challenge_whose_realm_has_no_utf8_form_is_challenge_malformed() -> None:
    good = placed()
    credential = {"challenge": good, "payload": {"type": "hash", "hash": "0x" + "ab" * 32}}
    assert not isinstance(challenge_bound(credential), Refusal)
    bad = {**credential, "challenge": {**good, "realm": good["realm"] + LONE}}
    assert challenge_bound(bad) == Refusal("mpp/challenge-malformed")


def test_a_tempo_client_id_with_no_utf8_form_is_input_malformed() -> None:
    choice = {"challenge": placed(), "from": MEMO["fixed"]["payer"], "now": MEMO["fixed"]["now"]}
    assert not isinstance(MPP_CHARGE_TEMPO_MEMO.build({**choice, "clientId": "agent-1"}, H), Refusal)
    assert MPP_CHARGE_TEMPO_MEMO.build({**choice, "clientId": "agent" + LONE}, H) == Refusal("mpp/input-malformed")


def test_a_hedera_charge_refuses_an_id_or_realm_with_bounds_code_and_a_client_id_with_no_utf8_form() -> None:
    """The build holds the challenge as bound holds an echoed one: a realm that is not well-formed is
    mpp/challenge-malformed, and an id that is not is no id derived from H, mpp/id-not-ours, from build and from bound
    (well-formed-strings.test.ts in @integraledger/lcp 0.4.1); such a client id is hedera/option-malformed."""
    own = placed_doc(issued("hedera", "charge", js_json(HEDERA["request"]), realm=HEDERA["realm"]), H, LINK)[0]
    c = {
        "payer": HEDERA["payer"],
        "node": HEDERA["node"],
        "validStart": {"seconds": int(HEDERA["validStart"]["seconds"]), "nanos": HEDERA["validStart"]["nanos"]},
        "maxFee": int(HEDERA["maxFee"]),
    }
    assert not isinstance(build_charge({"challenge": own, **c}, H), Refusal)
    for member, code in (("realm", "mpp/challenge-malformed"), ("id", "mpp/id-not-ours")):
        bad = {**own, member: own[member] + LONE}
        assert build_charge({"challenge": bad, **c}, H) == Refusal(code)
        pushed = {"challenge": bad, "payload": {"type": "hash", "transactionId": "0.0.5555@1700000000.0"}}
        assert MPP_CHARGE_HEDERA.bound(pushed) == Refusal(code)
    assert build_charge({"challenge": own, **c, "clientId": "agent" + LONE}, H) == Refusal("hedera/option-malformed")


@pytest.mark.parametrize("at", [0, 1, 2], ids=["channelId", "payer", "challengeId"])
def test_a_session_proof_over_a_string_with_no_utf8_form_raises_type_error(at: int) -> None:
    args = ["channel", "payer", "challenge"]
    assert isinstance(session_proof(*args), bytes)
    args[at] = args[at] + LONE
    with pytest.raises(TypeError):
        session_proof(*args)
