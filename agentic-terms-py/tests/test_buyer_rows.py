"""Every vector file's buyer group, run through the gate. B2, the plant: transact with a counting signer over the row's
document, account, inputs and clock, the link serving the planted ATR, declines hash-mismatch and never calls the
signer; confirm declines the same. B6: check over the file's signed payment gives H for the ATR and declines
signed-not-bound for the planted ATR. Every expected value, and every input, is the row's."""

import copy
import json
from typing import Any

import httpx
import pytest
from breadth import Recording, run
from support import VECTORS, Link

import integraledger_terms as terms
from integraledger_terms import Checked, Declined, _gate, check, confirm, transact

BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.isupper() and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}
ROWS: list[tuple[str, dict[str, Any]]] = [
    (path.name, row)
    for path in sorted(VECTORS.glob("*.json"))
    for row in (json.loads(path.read_bytes()).get("buyer") or {}).get("rows", [])
]


def serving(body: bytes) -> Link:
    return Link(lambda request: httpx.Response(200, content=body))


def test_the_files_hold_a_b2_for_every_pairing_the_gate_serves() -> None:
    b2 = sorted({row["pairing"] for _, row in ROWS if row["name"] == "B2"})
    assert b2 == sorted(BINDINGS)


B2 = [(f, r) for f, r in ROWS if r["name"] == "B2"]
B6 = [(f, r) for f, r in ROWS if r["name"] == "B6"]


@pytest.mark.parametrize(("file", "row"), B2, ids=[f"{f} {r['pairing']}" for f, r in B2])
def test_b2_the_plant(file: str, row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    given = row["input"]
    if "now" in given:
        monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    binding = BINDINGS[row["pairing"]]
    inputs = given.get("inputs", {})
    served = bytes.fromhex(given["servesHex"])

    def never(request: Any) -> Any:
        raise AssertionError("the signer is never called on a plant")

    signer = Recording(given["account"], never)
    out = run(lambda c: transact(copy.deepcopy(given["doc"]), binding, signer, c, inputs=inputs), serving(served))
    assert isinstance(out, Declined) and out.code == row["expect"]["decline"], out
    assert len(signer.requests) == row["expect"]["signCalls"]
    link = serving(served)
    confirmed = run(lambda c: confirm(copy.deepcopy(given["doc"]), binding, given["account"], c, inputs), link)
    assert isinstance(confirmed, Declined) and confirmed.code == row["expect"]["decline"], confirmed
    assert link.calls == 1


@pytest.mark.parametrize(("file", "row"), B6, ids=[f"{f} {r['pairing']}" for f, r in B6])
def test_b6_check(file: str, row: dict[str, Any]) -> None:
    binding = BINDINGS[row["pairing"]]
    got: list[dict[str, str]] = []
    for c in row["input"]["check"]:
        out = check(bytes.fromhex(c["bytesHex"]), copy.deepcopy(row["input"]["presented"]), binding)
        got.append({"h": out.h} if isinstance(out, Checked) else {"decline": out.code})
    assert got == row["expect"]
