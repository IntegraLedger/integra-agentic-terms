"""Each MPP pairing whose build returns a complete that makes a credential, run on its vector file's B2 inputs and the
payment its B6 row carries (credential_size.PAIRINGS), against mpp-challenge.json's rows: buildChallenge (each build
holds the chosen challenge as bound holds the challenge a credential echoes); a change made to the caller's challenge
after build, which does not reach the credential; and inChannelSize on the session pairings with channel members and
no build_within. Expected values are the rows' and @integraledger/lcp 0.4.1's (mpp-complete-size.test.ts)."""

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
    described,
    description_for,
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


IN_CHANNEL_ROWS: list[dict[str, Any]] = MC["inChannelSize"]["rows"]
assert len(IN_CHANNEL_ROWS) == 3


def channel_answers(binding: Any, c: Any) -> list[Any]:
    return [binding.channel_kind(c), binding.channel_ref(c), binding.bound_within(c)]


@pytest.mark.parametrize("pairing", ["mpp/session/lightning", "mpp/subscription/tempo"])
@pytest.mark.parametrize("row", IN_CHANNEL_ROWS, ids=[r["case"] for r in IN_CHANNEL_ROWS])
def test_in_channel_size_the_channel_members_of_the_sessions_without_a_build_within(
    pairing: str, row: dict[str, Any]
) -> None:
    """channel_kind, channel_ref and bound_within measure the payment they are given, here the pairing's opening,
    padded by a description to the row's size: a taken row is answered as the unpadded opening is, and the one over
    the bound is the row's code from all three."""
    s = set_up(pairing)
    binding = PAIRINGS[pairing].binding
    plain = s.complete(s.placed)
    sized = {**plain, "challenge": described(s.placed, description_for(plain, row["size"]))}
    assert size_of(sized) == row["size"]
    if row.get("taken"):
        assert channel_answers(binding, sized) == channel_answers(binding, plain)
    else:
        assert channel_answers(binding, sized) == [Refusal(row["expect"])] * 3


def _session_build(pairing: str) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """The pairing's build on its B2 inputs under its placed challenge, and its B6 credential."""
    s = set_up(pairing)
    b2 = buyer(PAIRINGS[pairing].file, pairing, "B2")
    b6 = buyer(PAIRINGS[pairing].file, pairing, "B6")
    assert b2 is not None and b6 is not None
    account = b2["input"]["account"].split(":")[2]
    choice: dict[str, Any] = {"challenge": s.placed, "from": account}
    if pairing == "mpp/session/xrpl":
        i = b2["input"]["inputs"]
        choice |= {"deposit": int(i["deposit"]), "xrpl": {**i["xrpl"], "publicKey": i["xrpl"]["publicKey"][2:]}}
    unsigned = PAIRINGS[pairing].binding.build(choice, s.h)
    assert not isinstance(unsigned, Refusal), unsigned
    return unsigned, s.placed, b6["input"]["presented"]


def test_the_solana_session_complete_refuses_an_opening_that_is_not_an_object_as_bound_does() -> None:
    """complete holds {challenge, payload: open} to bound's read: a payload that is not an object is
    mpp/credential-malformed, from complete and from bound (mpp-complete-size.test.ts in @integraledger/lcp 0.4.1)."""
    unsigned, placed, _ = _session_build("mpp/session/solana")
    for opening in (None, "x", 5):
        assert unsigned.complete(opening) == Refusal("mpp/credential-malformed"), opening
        bound = PAIRINGS["mpp/session/solana"].binding.bound({"challenge": placed, "payload": opening})
        assert bound == Refusal("mpp/credential-malformed"), opening


def test_the_xrpl_session_complete_reads_the_blob_as_bound_reads_it_before_the_claim_signature() -> None:
    """A signedBlob that is not a string is xrpl/blob-malformed, bound's code for it, with B6's claim signature and
    with zz; B6's blob with the claim signature zz, which bound does not read, is mpp/credential-malformed from
    complete, while bound gives H (mpp-complete-size.test.ts in @integraledger/lcp 0.4.1)."""
    unsigned, _, b6 = _session_build("mpp/session/xrpl")
    binding = PAIRINGS["mpp/session/xrpl"].binding
    blob, signature = b6["payload"]["transaction"], b6["payload"]["signature"]
    for claim in (signature, "zz"):
        assert unsigned.complete({"signedBlob": 5, "claimSignature": claim}) == Refusal("xrpl/blob-malformed"), claim
        presented = {**b6, "payload": {**b6["payload"], "transaction": 5, "signature": claim}}
        assert binding.bound(presented) == Refusal("xrpl/blob-malformed"), claim
    assert unsigned.complete({"signedBlob": blob, "claimSignature": "zz"}) == Refusal("mpp/credential-malformed")
    assert binding.bound({**b6, "payload": {**b6["payload"], "signature": "zz"}}) == set_up("mpp/session/xrpl").h
