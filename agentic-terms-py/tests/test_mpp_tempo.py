"""The gate's rows, as the TypeScript gate's tests run them, for MPP's Tempo charges (pairings-mpp.test.ts): B2 and B6
for memo and push, and the splits rows. Expected values are the vector files': MV7's calldata and wire, the splits'
calls, and MV13's landed receipt."""

import copy
import hashlib
import json
from collections.abc import Iterator
from typing import Any

import pytest

from integraledger_terms import (
    MPP_CHARGE_TEMPO_MEMO,
    MPP_CHARGE_TEMPO_PUSH,
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


@pytest.mark.parametrize("row", SPLITS["agreedRefusals"]["rows"], ids=[r["case"] for r in SPLITS["agreedRefusals"]["rows"]])
def test_mpp_charge_tempo_splits_refusals_before_any_fetch(row: dict[str, Any]) -> None:
    request = json.loads(SPLITS["request"])
    request["methodDetails"] = {**request["methodDetails"], "splits": row["splits"]}
    doc: Any = doc_of(json.dumps(request))
    link = serving(ABC)
    out = run(lambda c: confirm(doc, MPP_CHARGE_TEMPO_MEMO, account(MEMO["fixed"]), c), link)
    assert (code(out), getattr(out, "detail", None)) == ("no-payable-option", row["expect"])
    assert link.calls == 0


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
