"""The approval summary of the EVM requests (profile buyer-gate.md, rule 13), over the TypeScript gate's
test/summary-evm.json, which both languages run. Each row's request is built by the pairing's buyer piece from the
protocol package's buyer row B2 of the row's file, its document, account, inputs and time, the document's one option
replaced by the file's value at the row's accepts where it names one, over the ATR abc; its summary is the row's expect
with the ATR's bytes. Every expected value is read from the vectors file's row the row names."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from support import STAND_IN, load, piece_confirm

import integraledger_terms as terms
from integraledger_terms import Declined, _gate
from integraledger_terms._summary import summary_of
from integraledger_terms._types import Payee, Summary, Validity

ROWS: list[dict[str, Any]] = json.loads(
    (Path(__file__).resolve().parents[2] / "agentic-terms" / "test" / "summary-evm.json").read_bytes()
)["rows"]
BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.isupper() and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}


def expected(e: dict[str, Any]) -> Summary:
    """The row's expect, written as the TypeScript summary is, as the Python summary with the ATR abc."""
    v = e["validity"]
    return Summary(
        amount=e.get("amount"),
        maximum=e.get("maximum"),
        payees=tuple(Payee(account=p["account"], amount=p["amount"]) for p in e["payees"]),
        period=e.get("period"),
        limit_per_period=e.get("limitPerPeriod"),
        end=e.get("end"),
        operator=e.get("operator"),
        authorization_expiry=e.get("authorizationExpiry"),
        refund_expiry=e.get("refundExpiry"),
        deposit=e.get("deposit"),
        closable_by=None if e.get("closableBy") is None else tuple(e["closableBy"]),
        grant=e.get("grant"),
        asset=e["asset"],
        network=e["network"],
        validity=Validity(not_before=v["notBefore"], not_after=v["notAfter"], unit=v["unit"]),
        atr=STAND_IN,
    )


@pytest.mark.parametrize("row", ROWS, ids=[f"{r['pairing']} ({r['file']} B2, expect from {r['from']})" for r in ROWS])
def test_the_summary_of_the_request_each_pairing_s_piece_builds_from_its_b2_row(
    row: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    file = load(row["file"])
    b2 = next(r for r in file["buyer"]["rows"] if r["name"] == "B2" and r["pairing"] == row["pairing"])
    given = b2["input"]
    if "now" in given:
        monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    doc = copy.deepcopy(given["doc"])
    if "accepts" in row:
        option: Any = file
        for key in row["accepts"].split("."):
            option = option[key]
        doc["accepts"] = [copy.deepcopy(option)]
    built = piece_confirm(doc, BINDINGS[row["pairing"]], given["account"], given.get("inputs") or {})
    assert not isinstance(built, Declined), built
    assert built.request is not None
    assert summary_of(row["pairing"], built.request, STAND_IN) == expected(row["expect"])
