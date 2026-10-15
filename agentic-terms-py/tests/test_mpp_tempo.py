"""The gate's rows, as the TypeScript gate's tests run them, for MPP's Tempo charges (pairings-mpp.test.ts): B2 and B6
for memo and push, and the splits rows. Expected values are the vector files': MV7's calldata and wire, the splits'
calls, and MV13's landed receipt."""

import copy
import hashlib
import json
from collections.abc import Iterator
from datetime import datetime
from typing import Any

import pytest

from integraledger_terms import (
    MPP_CHARGE_TEMPO_MEMO,
    MPP_CHARGE_TEMPO_PUSH,
    Refusal,
    Binding,
    Checked,
    Confirmed,
    Finished,
    Transacted,
    check,
    confirm,
    finish,
    transact,
)
from integraledger_terms import _gate
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings._rlp import rlp_bytes, rlp_list, rlp_uint_bytes

from breadth import ABC, ABD, H, LINK, Pairing, Recording, build_and_sign, code, plant, run
from mpp_docs import MC, issued, placed_doc
from support import load, serving

MEMO = load("mpp-charge-tempo-memo.json")
PUSH = load("mpp-charge-tempo-push.json")
NOW: int = MEMO["fixed"]["now"]


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    yield


def account(fixed: dict[str, Any]) -> str:
    return f"eip155:42431:{fixed['payer']}"


def doc_of(request_json: str) -> list[dict[str, Any]]:
    return placed_doc(issued("tempo", "charge", request_json), H, LINK)


@pytest.mark.parametrize(("v", "binding"), [(MEMO, MPP_CHARGE_TEMPO_MEMO), (PUSH, MPP_CHARGE_TEMPO_PUSH)], ids=["memo", "push"])
def test_a_tempo_charge_of_amount_0_names_no_pairing(v: dict[str, Any], binding: Any) -> None:
    # The vector file's zeroAmount rows ("0", "00", and "0" with supportedModes) name no pairing, and the pairing's
    # build answers the row's code.
    rows = v["zeroAmount"]
    assert len(rows["requests"]) == 3
    for request_json in rows["requests"]:
        named = pairings_of(issued("tempo", "charge", request_json))
        assert not isinstance(named, Refusal) and list(named) == rows["expectPairings"]
        out = binding.build({"challenge": doc_of(request_json)[0], "from": v["fixed"]["payer"]}, H)
        assert out == Refusal(rows["expect"]["code"])


def _b(hex_text: str) -> bytes:
    return bytes.fromhex(hex_text[2:])


def tempo_wire(calls: list[dict[str, str]], chain_id: int, valid_before: int) -> str:
    """A 0x76 transaction around calls, as MV7's wire: 0x76 ‖ rlp([chainId, 1, 2, 100000, calls, [], 0, 0,
    validBefore, "", feeToken, "", [], 0x11 × 65]), the fee token the first call's target."""
    body = rlp_list(
        [
            rlp_uint_bytes(chain_id),
            rlp_uint_bytes(1),
            rlp_uint_bytes(2),
            rlp_uint_bytes(100000),
            rlp_list([rlp_list([rlp_bytes(_b(c["to"])), rlp_uint_bytes(0), rlp_bytes(_b(c["data"]))]) for c in calls]),
            rlp_list([]),
            rlp_uint_bytes(0),
            rlp_uint_bytes(0),
            rlp_uint_bytes(valid_before),
            rlp_bytes(b""),
            rlp_bytes(_b(calls[0]["to"])),
            rlp_bytes(b""),
            rlp_list([]),
            rlp_bytes(b"\x11" * 65),
        ]
    )
    return "0x76" + body.hex()


def memo_wire(request: Any) -> str:
    assert request["kind"] == "tempo-call", request
    return tempo_wire([request["call"]], request["chainId"], request["validBefore"])


MEMO_P = Pairing(
    binding=MPP_CHARGE_TEMPO_MEMO, doc=doc_of(MC["fixed"]["R_T"]), account=account(MEMO["fixed"]), answer=memo_wire
)

def test_mpp_charge_tempo_memo_b6_mv7_calldata_and_wire() -> None:
    mv7 = MEMO["MV7"]

    def inspect(request: Any) -> None:
        assert request["kind"] == "tempo-call"
        assert request["call"]["data"] == mv7["expectCalldata"]
        assert request["broadcast"] is False
        wire = bytes.fromhex(memo_wire(request)[2:])
        assert len(wire) == mv7["expectWireLength"]
        assert "0x" + hashlib.sha256(wire).hexdigest() == mv7["expectWireSha256"]

    build_and_sign(MEMO_P, inspect)


SPLITS = MEMO["splits"]


@pytest.mark.parametrize(("binding", "broadcast"), [(MPP_CHARGE_TEMPO_MEMO, False), (MPP_CHARGE_TEMPO_PUSH, True)], ids=["memo", "push"])
def test_mpp_charge_tempo_splits_primary_then_each_split(binding: Binding, broadcast: bool) -> None:
    request = json.loads(SPLITS["request"])
    if broadcast:
        del request["methodDetails"]["supportedModes"]
    doc: Any = doc_of(json.dumps(request))
    out = run(lambda c: confirm(doc, binding, account(MEMO["fixed"]), c), serving(ABC))
    assert isinstance(out, Confirmed), out
    r = out.request
    assert r is not None and r["kind"] == "tempo-calls"
    assert r["calls"] == SPLITS["expectCalls"]
    assert r["broadcast"] is broadcast
    assert r["chainId"] == 42431
    if not broadcast:
        wire = tempo_wire(r["calls"], r["chainId"], r["validBefore"])
        done = finish(ABC, out.chosen, wire, binding)
        assert isinstance(done, Finished), done
        assert done.h == H
        assert check(ABC, done.signed, binding) == Checked(h=H)


@pytest.mark.parametrize(("binding", "broadcast"), [(MPP_CHARGE_TEMPO_MEMO, False), (MPP_CHARGE_TEMPO_PUSH, True)], ids=["memo", "push"])
def test_mpp_charge_tempo_build_writes_the_primary_then_each_split(binding: Binding, broadcast: bool) -> None:
    """The binding's own build, as the protocol package's: with splits, a tempo-calls request of the splits rows'
    calls."""
    request = json.loads(SPLITS["request"])
    if broadcast:
        del request["methodDetails"]["supportedModes"]
    out = binding.build({"challenge": doc_of(json.dumps(request))[0], "from": MEMO["fixed"]["payer"], "now": NOW}, H)
    assert not isinstance(out, Refusal), out
    assert out.request["kind"] == "tempo-calls"
    assert out.request["calls"] == SPLITS["expectCalls"]
    assert (out.request["chainId"], out.request["broadcast"]) == (42431, broadcast)


def with_splits(splits: Any, broadcast: bool = False) -> list[dict[str, Any]]:
    """The splits request placed as the seller places it, then its request swapped for one with other splits: the
    challenge a seller sends when it places a request the pairing's filter refuses."""
    request = json.loads(SPLITS["request"])
    if broadcast:
        del request["methodDetails"]["supportedModes"]
    placed = doc_of(json.dumps(request))[0]
    request["methodDetails"] = {**request["methodDetails"], "splits": splits}
    return [{**placed, "request": issued("tempo", "charge", json.dumps(request))["request"]}]


def test_mpp_charge_tempo_the_splits_rows_are_read() -> None:
    assert len(SPLITS["agreedRefusals"]["rows"]) > 0


def test_mpp_charge_tempo_a_split_amount_is_a_uint256() -> None:
    """A split's amount is the uint256 its transfer call writes (draft-tempo-charge-00, Split Payments): 2^256 - 1
    reads, 2^256 is mpp/splits-malformed."""
    request = json.loads(SPLITS["request"])
    recipient = request["recipient"]
    for amount, expect in ((str(2**256 - 1), Refusal("mpp/input-malformed")), (str(2**256), Refusal("mpp/splits-malformed"))):
        request["methodDetails"] = {**request["methodDetails"], "splits": [{"recipient": recipient, "amount": amount}]}
        assert (amount, pairings_of(issued("tempo", "charge", json.dumps(request)))) == (amount, expect)


@pytest.mark.parametrize("row", SPLITS["agreedRefusals"]["rows"], ids=[r["case"] for r in SPLITS["agreedRefusals"]["rows"]])
def test_mpp_charge_tempo_splits_rows_offer_no_pairing_and_decline_before_any_fetch(row: dict[str, Any]) -> None:
    doc: Any = with_splits(row["splits"])
    as_issued = {k: v for k, v in doc[0].items() if k not in ("id", "opaque")}
    assert pairings_of(as_issued) == Refusal(row["expect"])
    link = serving(ABC)
    out = run(lambda c: confirm(doc, MPP_CHARGE_TEMPO_MEMO, account(MEMO["fixed"]), c), link)
    assert (code(out), getattr(out, "detail", None)) == ("no-payable-option", "mpp/no-payable-option")
    assert link.calls == 0


@pytest.mark.parametrize(("binding", "broadcast"), [(MPP_CHARGE_TEMPO_MEMO, False), (MPP_CHARGE_TEMPO_PUSH, True)], ids=["memo", "push"])
def test_mpp_charge_tempo_a_splits_member_present_as_null_offers_nothing(binding: Binding, broadcast: bool) -> None:
    """The Tempo charge draft (draft-tempo-charge-00, L223-318): splits, where present, holds at least one entry. A
    splits member present as null is no list of entries, so the challenge offers neither Tempo pairing."""
    doc: Any = with_splits(None, broadcast)
    link = serving(ABC)

    def never(request: Any) -> Any:
        raise AssertionError("the signer was called")

    signer = Recording(account(MEMO["fixed"]), never)
    out = run(lambda c: transact(doc, binding, signer, c), link)
    assert (code(out), getattr(out, "detail", None)) == ("no-payable-option", "mpp/no-payable-option")
    assert link.calls == 0
    assert signer.requests == []


MEMO_REFUSALS = MEMO["agreedRefusals"]["rows"]


def test_mpp_charge_tempo_memo_chain_rows_are_read() -> None:
    assert len(MEMO_REFUSALS) > 0


@pytest.mark.parametrize("row", MEMO_REFUSALS, ids=[r["case"] for r in MEMO_REFUSALS])
def test_mpp_charge_tempo_memo_a_transaction_for_another_chain_is_refused(row: dict[str, Any]) -> None:
    """The vector file's chain rows: MV7's wire T with its chain id, its first field, the row's transactionChainId,
    presented against C_T placed at position 0, as MV7's is. draft-tempo-charge-00 binds the transaction to the
    challenge's chainId, 42431 where it names none."""
    presented = next(r for r in MEMO["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]
    call = {"to": MEMO["fixed"]["pathUSD"], "data": MEMO["MV7"]["expectCalldata"]}
    valid_before = int(datetime.fromisoformat(presented["challenge"]["expires"]).timestamp())
    assert tempo_wire([call], 42431, valid_before) == presented["payload"]["signature"]
    assert MPP_CHARGE_TEMPO_MEMO.bound(copy.deepcopy(presented)) == H
    wire = tempo_wire([call], row["transactionChainId"], valid_before)
    other = {**copy.deepcopy(presented), "payload": {"type": "transaction", "signature": wire}}
    assert MPP_CHARGE_TEMPO_MEMO.bound(other) == Refusal(row["expect"])


@pytest.mark.parametrize("row", MEMO_REFUSALS, ids=[f"signed for {r['transactionChainId']}" for r in MEMO_REFUSALS])
def test_mpp_charge_tempo_memo_a_challenge_naming_no_chain_is_paid_on_42431(row: dict[str, Any]) -> None:
    """The vector file's chain rows, under C_T without methodDetails.chainId: draft-tempo-charge-00 has the payer sign
    for 42431 where the challenge names no chain. MV7's wire T, signed for 42431, binds H, and the same T signed for
    the row's transactionChainId is the row's refusal."""
    presented = next(r for r in MEMO["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]
    raw = b64u_decode(presented["challenge"]["request"])
    assert raw is not None
    request = json.loads(raw)
    del request["methodDetails"]["chainId"]
    challenge = {**presented["challenge"], "request": b64u_encode(json.dumps(request, separators=(",", ":")).encode())}
    call = {"to": MEMO["fixed"]["pathUSD"], "data": MEMO["MV7"]["expectCalldata"]}
    valid_before = int(datetime.fromisoformat(presented["challenge"]["expires"]).timestamp())

    def signed_for(chain_id: int) -> dict[str, Any]:
        wire = tempo_wire([call], chain_id, valid_before)
        return {**copy.deepcopy(presented), "challenge": challenge, "payload": {"type": "transaction", "signature": wire}}

    assert MPP_CHARGE_TEMPO_MEMO.bound(signed_for(42431)) == H
    assert MPP_CHARGE_TEMPO_MEMO.bound(signed_for(row["transactionChainId"])) == Refusal(row["expect"])


MV13 = PUSH["MV13"]


def push_answer(request: Any) -> dict[str, Any]:
    return {
        "hash": MV13["T_P"],
        "landed": {"transaction": MV13["T_P"], "blockNumber": MV13["receipt"]["blockNumber"], "logs": copy.deepcopy(MV13["receipt"]["logs"])},
    }


PUSH_P = Pairing(
    binding=MPP_CHARGE_TEMPO_PUSH, doc=doc_of(PUSH["fixed"]["R_TNoModes"]), account=account(PUSH["fixed"]), answer=push_answer
)


def test_mpp_charge_tempo_push_b6_the_landed_memo_binds_it_and_the_payment_sent_has_no_landed_receipt() -> None:
    p = PUSH_P
    confirmed = run(lambda c: confirm(p.doc, p.binding, p.account, c), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    r = confirmed.request
    assert r is not None and r["kind"] == "tempo-call" and r["broadcast"] is True
    answer = push_answer(r)
    done = finish(ABC, confirmed.chosen, answer, p.binding)
    assert isinstance(done, Finished), done
    assert done.h == H
    assert "landed" not in done.signed
    assert done.signed["payload"] == {"type": "hash", "hash": MV13["T_P"]}
    landed = answer["landed"]
    assert check(ABC, {**done.signed, "landed": landed}, p.binding) == Checked(h=H)
    assert code(check(ABD, {**done.signed, "landed": landed}, p.binding)) == "signed-not-bound"
    signer = Recording(p.account, p.answer)
    whole = run(lambda c: transact(p.doc, p.binding, signer, c), serving(ABC))
    assert isinstance(whole, Transacted), whole
    assert len(signer.requests) == 1
    assert whole.signed == done.signed


# A push credential that carries no landed receipt has not been read yet: the protocol package's push bound answers
# tempo/read-first for no landed member, a landed of None and landed logs that are not a list, and H with the receipt
# its B6 row presents.
def test_mpp_charge_tempo_push_bound_without_a_landed_receipt_is_read_first() -> None:
    presented = next(r for r in PUSH["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]
    landed = presented["landed"]
    bare = {k: v for k, v in presented.items() if k != "landed"}
    for c in (bare, {**bare, "landed": None}, {**bare, "landed": {**landed, "logs": {}}}):
        assert MPP_CHARGE_TEMPO_PUSH.bound(copy.deepcopy(c)) == Refusal("tempo/read-first")
    assert MPP_CHARGE_TEMPO_PUSH.bound(copy.deepcopy(presented)) == H
