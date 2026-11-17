"""The summaries of the NEAR, Tron and TON requests, which hand the signer only a hash (terms' profile buyer-gate.md, rule
13), over summary-hash.json, the rows summary-hash.test.ts runs. Each row's request is built by the pairing's buyer
piece from the protocol package's buyer row B2 of the row's file, its document and account, with the row's inputs and
time, over the ATR abc; the request carries the hash the file's independent tools computed, and its summary, read from
the request as the gate hands it to the signer, every byte string as 0x and lowercase hex, is the row's expect. Every
expected value is read from the vectors file's rows the row names."""

import json
from pathlib import Path
from typing import Any

import pytest
from support import load, piece_confirm

from integraledger_terms import X402_EXACT_NEAR, X402_EXACT_TRON_LCP_TRC20_MEMO, X402_EXACT_TVM, Binding, Confirmed, _gate
from integraledger_terms._checks import network_of
from integraledger_terms._summary import summary_of
from integraledger_terms._types import Payee, Summary, Validity

SHARED: dict[str, Any] = json.loads(
    (Path(__file__).resolve().parents[2] / "agentic-terms" / "test" / "summary-hash.json").read_text("utf-8")
)
BINDINGS: dict[str, Binding] = {b.id: b for b in (X402_EXACT_NEAR, X402_EXACT_TRON_LCP_TRC20_MEMO, X402_EXACT_TVM)}


def resolved(v: Any, file: Any) -> Any:
    """v with each {"$ref": pointer} replaced by the value at that JSON Pointer (RFC 6901) in file."""
    if isinstance(v, list):
        return [resolved(x, file) for x in v]
    if not isinstance(v, dict):
        return v
    if isinstance(v.get("$ref"), str):
        at = file
        for k in v["$ref"].split("/")[1:]:
            k = k.replace("~1", "/").replace("~0", "~")
            at = at[int(k)] if isinstance(at, list) else at[k]
        return at
    return {k: resolved(x, file) for k, x in v.items()}


def summary(e: dict[str, Any]) -> Summary:
    """The row's expect as the Python summary, its ATR's bytes empty."""
    v = e["validity"]
    return Summary(
        amount=e.get("amount"),
        payees=tuple(Payee(account=p["account"], amount=p["amount"]) for p in e["payees"]),
        asset=e["asset"],
        network=e["network"],
        validity=Validity(not_before=v["notBefore"], not_after=v["notAfter"], unit=v["unit"]),
        atr=b"",
    )


@pytest.mark.parametrize("r", SHARED["rows"], ids=[f"{r['pairing']} {r['file']}" for r in SHARED["rows"]])
def test_hash_request_summaries(r: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    file = load(r["file"])
    b2 = next(x for x in file["buyer"]["rows"] if x["name"] == "B2" and x["pairing"] == r["pairing"])
    now = resolved(r["now"], file)
    monkeypatch.setattr(_gate, "_now", lambda: now)
    account = b2["input"]["account"]
    built = piece_confirm(b2["input"]["doc"], BINDINGS[r["pairing"]], account, resolved(r["inputs"], file))
    assert isinstance(built, Confirmed) and built.request is not None, built
    handed = built.request.get("hash", built.request.get("txid"))
    assert handed == "0x" + str(resolved(r["requestHash"], file)).removeprefix("0x")
    assert summary_of(r["pairing"], built.request, b"", network_of(account)) == summary(resolved(r["expect"], file))
