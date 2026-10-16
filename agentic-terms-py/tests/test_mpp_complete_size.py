"""Each MPP pairing whose build returns a complete that makes a credential, run on its vector file's B2 inputs and the
payment its B6 row carries (credential_size.PAIRINGS), against mpp-challenge.json's rows: buildChallenge (each build
holds the chosen challenge as bound holds the challenge a credential echoes), and a change made to the caller's
challenge after build, which does not reach the credential. Expected values are the rows' and @integraledger/lcp
0.4.1's (mpp-complete-size.test.ts)."""

import copy
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_EVM_TRANSACTION, Refusal

from credential_size import (
    MC,
    PAIRINGS,
    after_build,
    answered,
    buyer,
    built,
    mv11_transaction,
    set_up,
    size_of,
    with_fault,
)

CHALLENGE_ROWS: list[dict[str, Any]] = MC["buildChallenge"]["rows"]
assert len(CHALLENGE_ROWS) == 8
FAULTS = ("opaque", "legalContext", "leastSize", "id", "digest", "challenge")


def test_each_build_challenge_row_makes_one_fault() -> None:
    for row in CHALLENGE_ROWS:
        assert sum(k in row for k in FAULTS) == 1, row["case"]


@pytest.mark.parametrize("pairing", list(PAIRINGS))
@pytest.mark.parametrize("row", CHALLENGE_ROWS, ids=[r["case"] for r in CHALLENGE_ROWS])
def test_build_challenge_build_refuses_with_the_code_bound_gives(pairing: str, row: dict[str, Any]) -> None:
    """build refuses the row's challenge with the row's code before it returns a complete, and bound gives the same
    code for the pairing's credential with its challenge replaced by the row's."""
    s = set_up(pairing)
    assert "opaque" in s.placed
    plain = s.complete(s.placed)
    challenge = with_fault(s.placed, row)
    if "leastSize" in row:
        assert size_of({"challenge": challenge, "payload": {}}) == row["leastSize"]
    assert answered(lambda: s.complete(challenge)) == ("build", Refusal(row["expect"]))
    assert PAIRINGS[pairing].binding.bound({**plain, "challenge": challenge}) == Refusal(row["expect"])


@pytest.mark.parametrize("row", CHALLENGE_ROWS, ids=[r["case"] for r in CHALLENGE_ROWS])
def test_build_challenge_on_the_evm_transaction_charge_whatever_the_transaction(row: dict[str, Any]) -> None:
    """The EVM transaction charge's complete holds the echoed challenge (echoed_for) before it reads the transaction,
    as bound does: so whatever transaction it is given (0xzz, 0x02c0 or MV11's), build and complete give bound's code
    for the row's challenge."""
    b2 = buyer("mpp-charge-evm-transaction.json", "mpp/charge/evm/transaction", "B2")
    assert b2 is not None

    def run(challenge: Any, signature: str) -> Any:
        choice = {"challenge": challenge, "from": b2["input"]["account"].split(":")[2], "now": b2["input"]["now"]}
        return built(MPP_CHARGE_EVM_TRANSACTION.build(choice, b2["advertised"])).complete(signature)

    placed = set_up("mpp/charge/evm/transaction").placed
    plain = run(placed, mv11_transaction())
    challenge = with_fault(placed, row)
    for signature in ("0xzz", "0x02c0", mv11_transaction()):
        assert answered(lambda: run(challenge, signature))[1] == Refusal(row["expect"]), signature
        presented = {**plain, "challenge": challenge, "payload": {**plain["payload"], "signature": signature}}
        assert MPP_CHARGE_EVM_TRANSACTION.bound(presented) == Refusal(row["expect"]), signature


@pytest.mark.parametrize("pairing", list(PAIRINGS))
def test_a_change_to_the_callers_challenge_after_build_does_not_reach_the_credential(pairing: str) -> None:
    """Each build holds a snapshot of the chosen challenge's members, which its complete's credential carries, never
    the caller's object: removing opaque from the caller's challenge and changing its realm between build and complete
    leaves the credential as the unchanged run makes it, and bound's answer with it."""
    s = set_up(pairing)
    plain = s.complete(s.placed)
    mine = dict(s.placed)

    def change() -> None:
        del mine["opaque"]
        mine["realm"] = "another.example"

    after_build.append(change)
    try:
        made = s.complete(mine)
    finally:
        after_build.clear()
    assert "opaque" not in mine and mine["realm"] == "another.example"
    assert made == plain
    assert made["challenge"] is not mine
    assert PAIRINGS[pairing].binding.bound(made) == s.answer
    assert PAIRINGS[pairing].binding.bound(copy.deepcopy(made)) == s.answer
