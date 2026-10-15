"""x402/exact/xrpl: the TypeScript gate's B2, B6, ticket sequence, B10 and B16 rows, and the buyer half's vector rows.
Expected values are the vector file's; the wallet stub answers with V2's signed blob, as the TypeScript gate's test
does."""

import copy
from typing import Any

from integraledger_terms import X402_EXACT_XRPL, Confirmed, Declined, Refusal, confirm, finish
from integraledger_terms.bindings import _xrpl

from breadth import ABC, H, Pairing, build_and_sign, plant, run, x402_doc
from support import load, serving
from xlm_support import EVM_ACCOUNT, b10, b16

X = load("x402-exact-xrpl.json")
F: dict[str, Any] = X["fixed"]
V2: dict[str, Any] = X["V2"]
# The option as advertise places H: extra.invoiceId is the hash's LCP string.
OPTION: dict[str, Any] = V2["accepted"]
assert OPTION["extra"]["invoiceId"] == F["L"] and F["H"] == H


def answer(request: Any) -> Any:
    assert request["kind"] == "xrpl-tx", request["kind"]
    assert request["txJson"] == V2["expectTxJson"]
    return V2["blob"]


XRPL = Pairing(
    binding=X402_EXACT_XRPL,
    doc=x402_doc(OPTION, F["resource"]),
    account=f"{F['option']['network']}:{F['payer']}",
    answer=answer,
    inputs=V2["build"],
)


def presented(blob: str, accepted: Any = OPTION) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": accepted, "payload": {"signedTxBlob": blob}}

def test_x402_exact_xrpl_b6_payment_is_v2_and_blob_completes_bound_payment() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "xrpl-tx"
        assert request["txJson"] == V2["expectTxJson"]

    signed, _ = build_and_sign(XRPL, inspect)
    assert signed["payload"] == {"signedTxBlob": V2["blob"]}


def test_x402_exact_xrpl_ticket_sequence_option_takes_ticket_sequence() -> None:
    option = copy.deepcopy(OPTION)
    option["extra"]["assetTransferMethod"] = "ticketSequence"
    doc = x402_doc(option, F["resource"])
    inputs = {k: v for k, v in V2["build"].items() if k != "sequence"} | {"ticketSequence": 9}
    out = run(lambda c: confirm(doc, X402_EXACT_XRPL, XRPL.account, c, inputs), serving(ABC))
    assert isinstance(out, Confirmed) and out.request is not None, out
    assert out.request["txJson"]["Sequence"] == 0 and out.request["txJson"]["TicketSequence"] == 9


def test_x402_exact_xrpl_b10_http_link() -> None:
    b10(XRPL)


def test_x402_exact_xrpl_b16_other_accounts() -> None:
    b16(XRPL, [EVM_ACCOUNT, f"xrpl:0:{F['payer']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def test_x402_exact_xrpl_v1_invoice_ids() -> None:
    assert _xrpl.x402_invoice_id(H) == X["V1"]["x402InvoiceId"]
    assert _xrpl.mpp_invoice_id(H) == X["V1"]["mppInvoiceId"]


def test_x402_exact_xrpl_v2_bound_and_blob_hash() -> None:
    assert X402_EXACT_XRPL.bound(presented(V2["blob"])) == V2["expectBound"]
    blob = _xrpl.decode_blob(V2["blob"])
    assert isinstance(blob, _xrpl.Blob)
    assert blob.hash == V2["expectReference"]["transaction"]
    assert blob.tx["InvoiceID"] == V2["expectReference"]["expect"]
    assert blob.tx["LastLedgerSequence"] == V2["expectReference"]["lastLedgerSequence"]
    signing = {k: v for k, v in blob.tx.items() if k not in ("SigningPubKey", "TxnSignature")}
    assert signing == V2["expectTxJson"]


def test_x402_exact_xrpl_v3_blob_hash_and_invoice() -> None:
    blob = _xrpl.decode_blob(X["V3"]["blob"])
    assert isinstance(blob, _xrpl.Blob)
    assert blob.hash == X["V3"]["hash"]
    assert blob.tx["InvoiceID"] == X["V3"]["invoiceId"]


def test_x402_exact_xrpl_v4_mpp_blob_under_x402_is_carrier_mismatch() -> None:
    row = X["V4"]["v3UnderX402"]
    assert X402_EXACT_XRPL.bound(presented(row["blob"], row["accepted"])) == Refusal(row["expect"])


def test_x402_exact_xrpl_plant_memo_is_never_the_carrier() -> None:
    row = X["plant"]
    blob = _xrpl.decode_blob(row["blob"])
    assert isinstance(blob, _xrpl.Blob) and blob.hash == row["hash"]
    assert X402_EXACT_XRPL.bound(presented(row["blob"], row["accepted"])) == Refusal(row["expect"])


def test_x402_exact_xrpl_strict_encoding_rows_are_refused() -> None:
    rows = X["strictEncoding"]["rows"]
    assert len(rows) == 3
    for row in rows:
        assert _xrpl.decode_blob(row["blob"]) == Refusal(row["expect"]), row["case"]
        assert X402_EXACT_XRPL.bound(presented(row["blob"], V2["accepted"])) == Refusal(row["expect"]), row["case"]


def test_x402_exact_xrpl_agreed_refusals() -> None:
    codes = {r["case"]: r["expect"] for r in X["agreedRefusals"]["rows"]}
    malformed = codes["a blob that is not an even number of hex digits, or that the codec cannot decode"]
    assert X402_EXACT_XRPL.bound(presented(V2["blob"][:-1])) == Refusal(malformed)
    assert X402_EXACT_XRPL.bound(presented(V2["blob"][:-2])) == Refusal(malformed)
    assert X402_EXACT_XRPL.bound(presented("12" * 2049)) == Refusal(codes["a blob over 4096 hex characters"])
    other = {**OPTION, "extra": {**OPTION["extra"], "areFeesSponsored": True}}
    assert X402_EXACT_XRPL.bound(presented(V2["blob"], other)) == Refusal(
        codes["a payment whose option fails the pairing's filter"]
    )
    choice = {"required": XRPL.doc, "accepted": XRPL.doc["accepts"][0], "account": F["payer"], **V2["build"]}
    option_malformed = codes[
        "build with a malformed fee, sequence, ticket sequence or LastLedgerSequence, or an amount build cannot write"
    ]
    for bad in ({"fee": "0"}, {"sequence": -1}, {"lastLedgerSequence": 2**32}, {"fee": "1.5"}):
        assert X402_EXACT_XRPL.build({**choice, **bad}, H) == Refusal(option_malformed)


def test_x402_exact_xrpl_a_blob_answered_in_0x_hex_is_declined_signed_not_bound() -> None:
    # The build's complete reads the signed blob as hex digits without 0x, as the XRP Ledger writes it.
    out = run(lambda c: confirm(XRPL.doc, X402_EXACT_XRPL, XRPL.account, c, XRPL.inputs), serving(ABC))
    assert isinstance(out, Confirmed), out
    done = finish(out.atr_bytes, out.chosen, "0x" + V2["blob"], X402_EXACT_XRPL)
    assert isinstance(done, Declined) and (done.code, done.detail) == ("signed-not-bound", "xrpl/blob-malformed"), done


def built_on(doc: dict[str, Any]) -> Any:
    """The build's unsigned Payment for V2's payer and inputs, on the document's one option."""
    u = X402_EXACT_XRPL.build({"required": doc, "accepted": doc["accepts"][0], "account": F["payer"], **V2["build"]}, H)
    assert not isinstance(u, Refusal), u
    return u


def test_x402_exact_xrpl_a_blob_whose_network_id_the_option_network_does_not_take_is_refused() -> None:
    # rippled 3.4.1's preflight0 (src/libxrpl/tx/Transactor.cpp L73-93): a network whose id is at most 1024 takes a
    # transaction without NetworkID only, and one above 1024 one whose NetworkID is its own id only. The agreedRefusals
    # rows that carry blobs hold V2's Payment, with each of their networkIds where they name them, for V2's option on
    # the row's network: each blob decodes to V2's fields and that NetworkID. bound and the build's complete refuse
    # each with the row's code.
    rows = [r for r in X["agreedRefusals"]["rows"] if "blobs" in r]
    assert rows, "x402-exact-xrpl.json holds no agreedRefusals row with blobs"
    base = _xrpl.decode_blob(V2["blob"])
    assert isinstance(base, _xrpl.Blob) and "NetworkID" not in base.tx
    unsigned = {k: v for k, v in base.tx.items() if k != "TxnSignature"}
    for row in rows:
        assert set(row) - {"networkIds"} == {"case", "network", "blobs", "expect"}, row["case"]
        doc = x402_doc({**OPTION, "network": row["network"]}, F["resource"])
        u = built_on(doc)
        ids = row.get("networkIds", [None] * len(row["blobs"]))
        for network_id, blob in zip(ids, row["blobs"], strict=True):
            decoded = _xrpl.decode_blob(blob)
            assert isinstance(decoded, _xrpl.Blob)
            carried = {} if network_id is None else {"NetworkID": network_id}
            assert {k: v for k, v in decoded.tx.items() if k != "TxnSignature"} == unsigned | carried
            want = (row["network"], network_id, Refusal(row["expect"]))
            assert (row["network"], network_id, X402_EXACT_XRPL.bound(presented(blob, doc["accepts"][0]))) == want
            assert (row["network"], network_id, u.complete(blob)) == want


def test_x402_exact_xrpl_a_network_above_1024_takes_its_own_network_id() -> None:
    # The control: on xrpl:21337 the build writes NetworkID 21337, and V2's Payment carrying it is taken by bound and
    # the build's complete. The blob is the agreedRefusals row's Payment with NetworkID 21338, its NetworkID field
    # (UInt32 field 1: 0x21) set to 21337; bound and complete verify no signature.
    row = next(r for r in X["agreedRefusals"]["rows"] if r.get("networkIds") == [21338])
    assert row["network"] == "xrpl:21337" and row["blobs"][0].count("210000535A") == 1
    blob = row["blobs"][0].replace("210000535A", "2100005359")
    decoded = _xrpl.decode_blob(blob)
    assert isinstance(decoded, _xrpl.Blob) and decoded.tx["NetworkID"] == 21337
    doc = x402_doc({**OPTION, "network": "xrpl:21337"}, F["resource"])
    u = built_on(doc)
    assert u.request["txJson"]["NetworkID"] == 21337
    assert X402_EXACT_XRPL.bound(presented(blob, doc["accepts"][0])) == H
    done = u.complete(blob)
    assert not isinstance(done, Refusal) and done["payload"] == {"signedTxBlob": blob}


def test_x402_exact_xrpl_complete_gives_a_multisigned_blob_the_refusal_bound_gives() -> None:
    # The build's complete decodes the signed blob as bound does before it reads NetworkID, so each multisigned row's
    # blob, a Payment signed by several keys, gets the row's code from both.
    u = built_on(XRPL.doc)
    rows = X["multisigned"]["rows"]
    assert rows
    for row in rows:
        want = (row["case"], Refusal(row["expect"]), Refusal(row["expect"]))
        assert (row["case"], X402_EXACT_XRPL.bound(presented(row["blob"])), u.complete(row["blob"])) == want
