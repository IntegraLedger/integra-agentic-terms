"""mpp/charge/xrpl: the TypeScript gate's placement, B2, B6, missing-input, B10 and B16 rows, and the buyer half's
vector rows. Expected values are the vector file's; the wallet stub answers with V3's signed blob, as the TypeScript
gate's test does."""

import json
from typing import Any

from integraledger_terms import MPP_CHARGE_XRPL, Declined, Refusal, confirm, transact
from integraledger_terms.bindings._xrpl import Blob, decode_blob, mpp_invoice_id, network_id_held, same_invoice

from breadth import ABC, H, LINK, Pairing, Recording, build_and_sign, plant, run
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
    return V["V3"]["blob"]


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
    # The pairing's filter refuses a request with memos: the seller's placement and the build alike.
    memos_refused = Refusal(rows["build on a request with methodDetails.memos"]["expect"])
    memos = {**F["request"], "methodDetails": {**F["request"]["methodDetails"], "memos": []}}
    asked = issued("xrpl", "charge", json.dumps(memos), F["realm"], F["expires"])
    assert doc_of(asked) == memos_refused
    choice = {"challenge": {**XRPL.doc[0], "request": asked["request"]}, "account": F["account"], **B}
    assert MPP_CHARGE_XRPL.build(choice, H) == memos_refused
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


def test_mpp_charge_xrpl_a_blob_answered_in_0x_hex_is_declined_signed_not_bound() -> None:
    # The build's complete reads the signed blob as hex digits without 0x, as the XRP Ledger writes it.
    signer = Recording(XRPL.account, lambda r: "0x" + V["V3"]["blob"])
    out = run(lambda c: transact(XRPL.doc, MPP_CHARGE_XRPL, signer, c, inputs=XRPL.inputs), serving(ABC))
    assert isinstance(out, Declined) and (out.code, out.detail) == ("signed-not-bound", "xrpl/blob-malformed"), out


def test_network_id_held_reads_network_id_as_rippled_does_on_both_sides_of_1024() -> None:
    # rippled 3.4.1's preflight0 (src/libxrpl/tx/Transactor.cpp L73-93): a network whose id is at most 1024 takes a
    # transaction without NetworkID only (telNETWORK_ID_MAKES_TX_NON_CANONICAL); one above 1024 takes one whose
    # NetworkID is its own id only (telREQUIRES_NETWORK_ID, telWRONG_NETWORK). Each network MPP's XRPL methods name is
    # at most 1024, so the pairings reach the first branch; the second is read here.
    blob = decode_blob(V["V3"]["blob"])
    assert isinstance(blob, Blob) and "NetworkID" not in blob.tx
    tx = blob.tx
    assert [network_id_held(tx, f"xrpl:{n}") for n in (0, 1, 1024)] == [True, True, True]
    assert [network_id_held({**tx, "NetworkID": n}, "xrpl:1") for n in (0, 1, 1024, 1025)] == [False] * 4
    assert network_id_held({**tx, "NetworkID": 1024}, "xrpl:1024") is False
    assert network_id_held(tx, "xrpl:1025") is False
    assert network_id_held({**tx, "NetworkID": 1025}, "xrpl:1025") is True
    assert [network_id_held({**tx, "NetworkID": n}, "xrpl:1025") for n in (1026, 21337, 1)] == [False] * 3


def without_signature(tx: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in tx.items() if k != "TxnSignature"}


def test_mpp_charge_xrpl_a_payment_carrying_network_id_on_testnet_is_refused_by_bound_and_complete() -> None:
    # The agreedRefusals rows that carry blobs hold V3's Payment with each of their networkIds, signed again by V3's
    # payer: each blob decodes to V3's fields and that NetworkID. The challenge's network is testnet, whose id, 1, is at
    # most 1024, where rippled refuses a NetworkID, so bound and the build's complete refuse each with the row's code;
    # V3's blob, which carries none, completes.
    rows = [r for r in V["agreedRefusals"]["rows"] if "blobs" in r]
    assert rows, "mpp-charge-xrpl.json holds no agreedRefusals row with blobs"
    base = decode_blob(V["V3"]["blob"])
    assert isinstance(base, Blob) and "NetworkID" not in base.tx
    u = MPP_CHARGE_XRPL.build({"challenge": XRPL.doc[0], "account": F["account"], **B}, H)
    assert not isinstance(u, Refusal), u
    assert u.complete(V["V3"]["blob"]) == credential({"type": "transaction", "blob": V["V3"]["blob"]})
    for row in rows:
        assert set(row) == {"case", "networkIds", "blobs", "expect"}, row["case"]
        for network_id, blob in zip(row["networkIds"], row["blobs"], strict=True):
            decoded = decode_blob(blob)
            assert isinstance(decoded, Blob)
            assert without_signature(decoded.tx) == {**without_signature(base.tx), "NetworkID": network_id}
            presented = credential({"type": "transaction", "blob": blob})
            assert (network_id, MPP_CHARGE_XRPL.bound(presented)) == (network_id, Refusal(row["expect"]))
            assert (network_id, u.complete(blob)) == (network_id, Refusal(row["expect"]))


def test_mpp_charge_xrpl_complete_gives_a_multisigned_blob_the_refusal_bound_gives() -> None:
    # The build's complete decodes the signed blob as bound does before it reads NetworkID, so each multisigned row's
    # blob, a Payment signed by several keys, gets the row's code from both.
    u = MPP_CHARGE_XRPL.build({"challenge": XRPL.doc[0], "account": F["account"], **B}, H)
    assert not isinstance(u, Refusal), u
    rows = V["multisigned"]["rows"]
    assert rows
    for row in rows:
        presented = credential({"type": "transaction", "blob": row["blob"]})
        want = (row["case"], Refusal(row["expect"]), Refusal(row["expect"]))
        assert (row["case"], MPP_CHARGE_XRPL.bound(presented), u.complete(row["blob"])) == want
