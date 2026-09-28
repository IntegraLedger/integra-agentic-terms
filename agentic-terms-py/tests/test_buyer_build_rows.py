"""buyer.json's rows named with a pairing (BS1, BS2, BX1), through the gate. Each case gives its own inputs (BX1: its
own document) and its own expect: a decline with its detail and no signer call, or one signer call with the request's
kind. A BX1 case's refusal is what the checks of the placed challenge return, which leaves the gate no challenge it can
pay. The link serves abc, whose SHA-256 (FIPS 180-2 B.1) is each document's H. Every expected value, and every input,
is the row's."""

import copy
from typing import Any

import httpx
import pytest
from breadth import Recording, run
from support import BUYER, Link

import integraledger_terms as terms
from integraledger_terms import Confirmed, Declined, Refusal, _gate, confirm, transact
from integraledger_terms.bindings._mpp import check_challenge

BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.isupper() and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}
ROWS = [r for r in BUYER["rows"] if r["name"] in ("BS1", "BS2", "BX1")]
CASES = [(r, c) for r in ROWS for c in r["input"]["cases"]]


def serving(body: bytes) -> Link:
    return Link(lambda request: httpx.Response(200, content=body))


def test_the_file_holds_bs1_bs2_and_bx1() -> None:
    assert [r["name"] for r in ROWS] == ["BS1", "BS2", "BX1"]


@pytest.mark.parametrize(("row", "case"), CASES, ids=[f"{r['name']} {c['case']}" for r, c in CASES])
def test_build_row(row: dict[str, Any], case: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    given = row["input"]
    if "now" in given:
        monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    binding = BINDINGS[given["pairing"]]
    doc = case.get("doc", given.get("doc"))
    inputs = case.get("inputs", given.get("inputs", {}))
    served = bytes.fromhex(given["servesHex"])
    expect = case["expect"]

    def unanswered(request: Any) -> Any:
        raise RuntimeError("the row compares only what the signer is handed")

    signer = Recording(given["account"], unanswered)
    out = run(lambda c: transact(copy.deepcopy(doc), binding, signer, c, inputs=inputs), serving(served))
    assert len(signer.requests) == expect["signCalls"]
    confirmed = run(lambda c: confirm(copy.deepcopy(doc), binding, given["account"], c, inputs), serving(served))
    if "decline" in expect:
        assert isinstance(out, Declined) and (out.code, out.detail) == (expect["decline"], expect["detail"]), out
        assert isinstance(confirmed, Declined), confirmed
        assert (confirmed.code, confirmed.detail) == (expect["decline"], expect["detail"])
    else:
        assert [r["kind"] for r in signer.requests] == [expect["signRequestKind"]]
        assert isinstance(confirmed, Confirmed) and confirmed.request is not None, confirmed
        assert confirmed.request["kind"] == expect["signRequestKind"]
    if "refusal" in expect:
        assert check_challenge(doc[0], True) == Refusal(expect["refusal"])
