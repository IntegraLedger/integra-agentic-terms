"""x402-exact-ccd.json's D3.wireForm: bound and complete take only x402's wire form of the signed transaction, the
JSON-serialized V1 sponsored transaction, JSON.parse(Transaction.toJSONString(tx)); any other value is
ccd/transaction-malformed, never an exception. The rows name the members the Concordium SDK's object holds as bigints
before serialization. Python reads JSON numbers as int, so the wire form's numbers are Python ints and are read; the
members named here hold values that are not JSON data instead (bytes, a set, a non-finite number, an object with a
non-string member name), and the asText row is the transaction as JSON text, not parsed."""

import copy
import json
from typing import Any

import pytest
from support import load

from integraledger_terms import X402_EXACT_CCD, Refusal

CCD = load("x402-exact-ccd.json")
D3 = CCD["D3"]
ROWS = D3["wireForm"]["rows"]
NOT_JSON: list[Any] = [b"\x01", {1}, float("nan"), {1: 2}]


def at(payment: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(payment)
    keys = path.split(".")
    node = out
    for k in keys[:-1]:
        node = node[k]
    node[keys[-1]] = value
    return out


def test_the_wire_form_is_read() -> None:
    for base in ("ccd", "plt"):
        assert X402_EXACT_CCD.bound(copy.deepcopy(D3[base]["payment"])) == D3[base]["expect"]


@pytest.mark.parametrize("row", ROWS, ids=[r["case"] for r in ROWS])
def test_any_other_value_is_transaction_malformed(row: dict[str, Any]) -> None:
    payment = D3[row["base"]]["payment"]
    expect = Refusal(row["expect"]["code"])
    if row.get("asText"):
        text = json.dumps(payment["payload"]["signedTransaction"], separators=(",", ":"))
        assert X402_EXACT_CCD.bound(at(payment, "payload.signedTransaction", text)) == expect
        return
    for path in row["bigints"]:
        for value in NOT_JSON:
            assert X402_EXACT_CCD.bound(at(payment, path, value)) == expect


def test_complete_takes_only_a_json_object() -> None:
    O, F = CCD["fixed"]["O"], CCD["fixed"]
    required = {"x402Version": 2, "resource": F["resource"], "accepts": [O]}
    u = X402_EXACT_CCD.build({"required": required, "accepted": O, "now": F["now"]}, F["H"])
    assert not isinstance(u, Refusal), u
    signed = D3["ccd"]["payment"]["payload"]["signedTransaction"]
    assert u.complete(copy.deepcopy(signed)) == D3["ccd"]["payment"]
    malformed = Refusal("ccd/transaction-malformed")
    assert u.complete(json.dumps(signed)) == malformed
    for value in NOT_JSON:
        assert u.complete({**copy.deepcopy(signed), "header": {**signed["header"], "nonce": value}}) == malformed
