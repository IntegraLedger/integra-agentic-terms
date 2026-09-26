"""x402/exact/xrpl: the TypeScript gate's B2, B6, ticket sequence, B10 and B16 rows, and the buyer half's vector rows.
Expected values are the vector file's; the wallet stub answers with V2's signed blob, as the TypeScript gate's test
does."""

import copy
from typing import Any

from integraledger_terms import X402_EXACT_XRPL, Confirmed, Refusal, confirm
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
    return "0x" + V2["blob"]


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
