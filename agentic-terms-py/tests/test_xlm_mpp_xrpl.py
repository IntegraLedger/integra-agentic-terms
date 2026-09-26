"""mpp/charge/xrpl: the TypeScript gate's placement, B2, B6, missing-input, B10 and B16 rows, and the buyer half's
vector rows. Expected values are the vector file's; the wallet stub answers with V3's signed blob, as the TypeScript
gate's test does."""

import json
from typing import Any

from integraledger_terms import MPP_CHARGE_XRPL, Declined, Refusal, confirm
from integraledger_terms.bindings._xrpl import mpp_invoice_id, same_invoice

from breadth import ABC, H, LINK, Pairing, build_and_sign, plant, run
from mpp_docs import issued, place_carrier
from support import load, serving
from xlm_support import EVM_ACCOUNT, b16, mpp_b10

V = load("mpp-charge-xrpl.json")
F: dict[str, Any] = V["fixed"]
B: dict[str, Any] = V["build"]
INVOICE = mpp_invoice_id(H)


def carrier(value: Any) -> str | Refusal:
    return INVOICE if value is None or same_invoice(value, INVOICE) else Refusal("xrpl/carrier-occupied")


def doc_of(challenge: dict[str, Any]) -> Any:
    return place_carrier([challenge], H, LINK, challenge, carrier)


def answer(request: Any) -> Any:
    assert request["kind"] == "xrpl-tx", request["kind"]
    assert request["txJson"]["InvoiceID"] == F["invoiceId"]
    return "0x" + V["V3"]["blob"]


XRPL = Pairing(
    binding=MPP_CHARGE_XRPL,
    doc=doc_of(V["challenge"]),
    account=f"xrpl:1:{F['account']}",
    answer=answer,
    inputs={"fee": B["fee"], "sequence": B["sequence"], "lastLedgerSequence": B["lastLedgerSequence"]},
)


def test_mpp_charge_xrpl_placed_challenge_is_the_vectors() -> None:
    assert XRPL.doc == [V["place"]["expect"]]

def test_mpp_charge_xrpl_b6_payment_carries_v3_fields_and_blob_completes_bound_credential() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "xrpl-tx"
        assert request["txJson"] == {
            "TransactionType": "Payment",
            "Flags": 0,
            "Account": F["account"],
            "Destination": F["request"]["recipient"],
            "Amount": F["request"]["amount"],
            "InvoiceID": F["invoiceId"],
            "Fee": B["fee"],
            "Sequence": B["sequence"],
            "LastLedgerSequence": B["lastLedgerSequence"],
        }
        assert "5011" + F["invoiceId"] in V["V3"]["blob"]

    signed, _ = build_and_sign(XRPL, inspect)
    assert signed["payload"] == {"type": "transaction", "blob": V["V3"]["blob"]}


def test_mpp_charge_xrpl_without_ledger_reads_no_payable_option_before_any_fetch() -> None:
    link = serving(ABC)
    out = run(lambda c: confirm(XRPL.doc, MPP_CHARGE_XRPL, XRPL.account, c, {"fee": "12"}), link)
    assert out == Declined("no-payable-option", "mpp/input-missing")
    assert link.calls == 0


def test_mpp_charge_xrpl_b10_http_link() -> None:
    mpp_b10(XRPL)


def test_mpp_charge_xrpl_b16_other_accounts() -> None:
    b16(XRPL, [EVM_ACCOUNT, f"xrpl:0:{F['account']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def credential(payload: dict[str, Any]) -> dict[str, Any]:
    return {"challenge": XRPL.doc[0], "payload": payload}


def test_mpp_charge_xrpl_v3_bound_v4_and_plant() -> None:
    assert INVOICE == F["invoiceId"]
    assert MPP_CHARGE_XRPL.bound(credential({"type": "transaction", "blob": V["V3"]["blob"]})) == V["V3"]["expectBound"]
    assert MPP_CHARGE_XRPL.bound(credential({"type": "transaction", "blob": V["V4"]["blob"]})) == Refusal(V["V4"]["expect"])
    assert MPP_CHARGE_XRPL.bound(credential({"type": "transaction", "blob": V["plant"]["blob"]})) == Refusal(
        V["plant"]["expect"]
    )


def test_mpp_charge_xrpl_occupied_and_refusals() -> None:
    occupied = issued("xrpl", "charge", json.dumps(V["occupied"]["request"]), F["realm"], F["expires"])
    assert doc_of(occupied) == Refusal(V["occupied"]["expect"])
    rows = {r["case"]: r for r in V["refusals"]}
    hash_row = rows["type=hash not yet fetched"]
    assert MPP_CHARGE_XRPL.bound(credential(hash_row["payload"])) == Refusal(hash_row["expect"])
    memos = {**F["request"], "methodDetails": {**F["request"]["methodDetails"], "memos": []}}
    placed = doc_of(issued("xrpl", "charge", json.dumps(memos), F["realm"], F["expires"]))
    assert isinstance(placed, list)
    choice = {"challenge": placed[0], "account": F["account"], **B}
    assert MPP_CHARGE_XRPL.build(choice, H) == Refusal(rows["build on a request with methodDetails.memos"]["expect"])
    good = {"challenge": XRPL.doc[0], "account": F["account"], **B}
    for bad in ({"fee": "-1"}, {"sequence": 2**32}, {"lastLedgerSequence": "1000"}, {"account": 7}):
        assert MPP_CHARGE_XRPL.build({**good, **bad}, H) == Refusal("mpp/input-malformed")
    # The challenge names H2 while its request's invoiceId, and the signed InvoiceID, are H.
    h2_doc = place_carrier([V["challenge"]], F["H2"], LINK, V["challenge"], lambda issued_value: INVOICE)
    assert isinstance(h2_doc, list)
    agreed = {r["case"]: r["expect"] for r in V["agreedRefusals"]["rows"]}
    expect = agreed["a signed InvoiceID that is the request's invoiceId but not the echoed challenge's hash"]
    presented = {"challenge": h2_doc[0], "payload": {"type": "transaction", "blob": V["V3"]["blob"]}}
    assert MPP_CHARGE_XRPL.bound(presented) == Refusal(expect)
