"""The approval summary of the Casper, Starknet, Concordium, Polkadot, Aptos, Cardano and Sui requests (terms' profile
buyer-gate.md, rule 13), over summary-rail.json (agentic-terms/test/summary-rail.json, which the TypeScript tests run
too). Each row's request is built by the pairing's buyer piece from the protocol package's buyer row B2 of the row's
file, its document, account, inputs and time, over the ATR abc; its summary is the row's expect with the ATR's bytes.
Every expected value is read from the vectors file's rows the row names."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

import integraledger_terms as terms
from integraledger_terms import Confirmed, _gate
from integraledger_terms._summary import summary_of
from integraledger_terms._types import Payee, Summary, Validity
from support import STAND_IN, load, piece_confirm

ROWS: list[dict[str, Any]] = json.loads(
    (Path(__file__).resolve().parents[2] / "agentic-terms" / "test" / "summary-rail.json").read_text("utf-8")
)["rows"]
BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.isupper() and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}
# The summary's members as the rows name them, each as the Summary names it.
MEMBERS = {
    "amount": "amount",
    "maximum": "maximum",
    "period": "period",
    "limitPerPeriod": "limit_per_period",
    "end": "end",
    "operator": "operator",
    "authorizationExpiry": "authorization_expiry",
    "refundExpiry": "refund_expiry",
    "deposit": "deposit",
    "grant": "grant",
    "asset": "asset",
    "network": "network",
}


def expected(expect: dict[str, Any], atr: bytes) -> Summary:
    """A row's expect, every member of the summary as the rows name it, with the ATR's bytes."""
    rest = {k: v for k, v in expect.items() if k not in ("payees", "validity", "closableBy")}
    assert set(rest) <= set(MEMBERS), set(rest) - set(MEMBERS)
    v = expect["validity"]
    closable = expect.get("closableBy")
    return Summary(
        **{MEMBERS[k]: value for k, value in rest.items()},
        payees=tuple(Payee(account=p["account"], amount=p["amount"]) for p in expect["payees"]),
        closable_by=None if closable is None else tuple(closable),
        validity=Validity(not_before=v["notBefore"], not_after=v["notAfter"], unit=v["unit"]),
        atr=atr,
    )


@pytest.mark.parametrize("row", ROWS, ids=[f"{r['pairing']} ({r['file']} B2, expect from {r['from']})" for r in ROWS])
def test_the_summary_of_the_request_each_pairings_piece_builds_from_its_b2_row(row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    b2 = next((r for r in load(row["file"])["buyer"]["rows"] if r["name"] == "B2" and r["pairing"] == row["pairing"]), None)
    assert b2 is not None, f"{row['file']} has no B2 row for {row['pairing']}"
    given = b2["input"]
    if given.get("now") is not None:
        monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    built = piece_confirm(copy.deepcopy(given["doc"]), BINDINGS[row["pairing"]], given["account"], given.get("inputs") or {})
    assert isinstance(built, Confirmed), built
    assert built.request is not None, "nothing to sign"
    assert summary_of(row["pairing"], built.request, STAND_IN) == expected(row["expect"], STAND_IN)
