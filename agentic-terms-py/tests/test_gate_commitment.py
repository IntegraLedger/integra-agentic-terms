"""The gate's mirror of what the TypeScript gate takes from the protocol package, held by the package's own vectors: the
request commitment over HTTP, with and without named header fields, and over MCP (x402-request-commitment.json, whose
oracles are Python's hashlib, a node:http server and canonicalize 5.1.0), and an MPP challenge's bound members as
issuedDigest reads them (mpp-server-checks.json: the unplaced rows, the echoed opaque object, and the order rows'
digestEqual), each value computed by Python's json, base64 and hashlib."""

from typing import Any

import pytest

from integraledger_terms._commitment import issued_digest, request_commitment, tool_call_commitment
from integraledger_terms import X402_EXACT_SOLANA, X402_EXACT_TVM, X402_EXACT_XRPL, Chosen, Confirmed, Declined
from integraledger_terms._checks import slot_holds
from integraledger_terms._types import Refusal

from support import load, piece_confirm

RC = load("x402-request-commitment.json")
SC = load("mpp-server-checks.json")


def http_request(r: Any, fill: dict[str, Any] | None) -> Any:
    """The vector's request, its body the UTF-8 bytes of bodyUtf8, with the row's fill applied."""
    if not isinstance(r, dict):
        return r
    out = {k: v for k, v in r.items() if k != "bodyUtf8"}
    if "bodyUtf8" in r:
        out["body"] = r["bodyUtf8"].encode("utf-8")
    if fill is not None and fill.get("member") == "target":
        out["target"] = "/" + fill["char"] * (fill["length"] - 1)
    elif fill is not None and fill.get("member") == "body":
        out["body"] = (fill["char"] * fill["length"]).encode("utf-8")
    elif fill is not None:
        line = fill["char"] * fill["length"]
        out["headers"] = {fill["name"]: [line] * fill["lines"] if "lines" in fill else line}
    return out


def answer(got: Any, expect: dict[str, Any]) -> Any:
    return {"refused": True, "code": got.code} if isinstance(got, Refusal) else got


HTTP = [(k, r) for k in ("http", "httpRefusals", "httpHeaders", "httpHeaderRefusals") for r in RC[k]]


@pytest.mark.parametrize(("part", "row"), HTTP, ids=[f"{k}: {r['case']}" for k, r in HTTP])
def test_request_commitment_over_http(part: str, row: dict[str, Any]) -> None:
    got = request_commitment(http_request(row["request"], row.get("fill")), row.get("fields"))
    assert answer(got, row["expect"]) == row["expect"]


MCP = [(k, r) for k in ("mcp", "mcpRefusals") for r in RC[k]]


@pytest.mark.parametrize(("part", "row"), MCP, ids=[f"{k}: {r['case']}" for k, r in MCP])
def test_tool_call_commitment_over_mcp(part: str, row: dict[str, Any]) -> None:
    call = row["call"]
    if "fillLength" in row:
        call = {**call, "arguments": {"a": row["fill"] * row["fillLength"]}}
    assert answer(tool_call_commitment(call), row["expect"]) == row["expect"]


@pytest.mark.parametrize("row", SC["unplaced"]["rows"], ids=[r["case"] for r in SC["unplaced"]["rows"]])
def test_issued_digest_reads_a_challenge_as_its_pairing_unplaced_gives_it(row: dict[str, Any]) -> None:
    assert issued_digest(row["issued"]) == row["expectDigest"]
    assert issued_digest(row["placed"]) == row["expectDigest"]


def test_issued_digest_reads_an_echoed_opaque_object_by_its_members() -> None:
    first = SC["opaqueObject"]["rows"][0]
    assert first["expect"]["digestEqual"] is True
    assert issued_digest(first["credential"]["challenge"]) == SC["opaqueObject"]["recorded"]


@pytest.mark.parametrize("row", SC["order"]["rows"], ids=[r["case"] for r in SC["order"]["rows"]])
def test_issued_digest_equals_the_recorded_digest_as_the_order_rows_state(row: dict[str, Any]) -> None:
    assert (issued_digest(row["credential"]["challenge"]) == row["recorded"]) is row["expect"]["digestEqual"]


# x402/exact/xrpl places H in the option's extra.invoiceId, and lcp's unplaced removes it (src/x402-exact-xrpl.ts:154), so
# an ATR whose x402 slot lists the option as issued (lcp's tie, src/x402.ts:339) holds the option the buyer chose from the
# placed offer. The option as issued is x402-exact-xrpl.json's fixed.option, the placed one its V2 accepted; the option
# of another pairing, x402-exact-eip155-eip3009.json's fixed.O, is held by no such slot.
def test_the_x402_slot_holds_the_xrpl_option_chosen_without_its_invoice_id() -> None:
    xrpl = load("x402-exact-xrpl.json")
    issued, placed = xrpl["fixed"]["option"], xrpl["V2"]["accepted"]
    assert "invoiceId" in placed["extra"] and "invoiceId" not in issued.get("extra", {})
    doc = {"x402Version": 2, "resource": xrpl["fixed"]["resource"], "accepts": [placed],
           "extensions": {"legalContext": {"info": {"type": "sha256", "value": xrpl["fixed"]["H"],
                                                    "legalContextUrl": "https://seller.example/atr"}}}}  # fmt: skip
    confirmed = piece_confirm(doc, X402_EXACT_XRPL, f"{issued['network']}:{xrpl['fixed']['payer']}", xrpl["V2"]["build"])
    assert isinstance(confirmed, Confirmed) and confirmed.chosen.choice["accepted"] == placed, confirmed
    request = load("x402-request-commitment.json")["http"][0]["expect"]
    assert slot_holds(X402_EXACT_XRPL, confirmed.chosen, {"x402": {"accepts": [issued], "request": request}}) is None
    other = load("x402-exact-eip155-eip3009.json")["fixed"]["O"]
    not_held = slot_holds(X402_EXACT_XRPL, confirmed.chosen, {"x402": {"accepts": [other], "request": request}})
    assert isinstance(not_held, Declined) and not_held.code == "option-not-in-atr", not_held


# x402/exact/solana places H in the option's extra.memo, which lcp's unplaced removes with the extra the removal empties
# (src/x402-exact-solana.ts:134), and x402/exact/tvm in extra.forwardPayload, removed with the extra kept
# (src/tvm.ts:1937); the slot lists the option as issued. The issued options are x402-exact-solana.json's fixed.option
# and x402-exact-tvm.json's fixed.O, the placed ones the first's V2 accepted and the second's fixed.placed; the option of
# another pairing, x402-exact-eip155-eip3009.json's fixed.O, is held by no such slot.
SOL, TVM = load("x402-exact-solana.json"), load("x402-exact-tvm.json")
PLACED = [
    pytest.param(X402_EXACT_SOLANA, SOL["fixed"]["option"], SOL["V2"]["accepted"], "memo", id="x402/exact/solana"),
    pytest.param(X402_EXACT_TVM, TVM["fixed"]["O"], TVM["fixed"]["placed"], "forwardPayload", id="x402/exact/tvm"),
]


@pytest.mark.parametrize(("binding", "issued", "placed", "member"), PLACED)
def test_the_x402_slot_holds_the_option_chosen_as_its_pairing_unplaced_gives_it(
    binding: Any, issued: dict[str, Any], placed: dict[str, Any], member: str
) -> None:
    assert member in placed["extra"] and member not in issued.get("extra", {})
    chosen = Chosen(pairing=str(binding.id), choice={"accepted": placed}, ref="placed")
    assert slot_holds(binding, chosen, {"x402": {"accepts": [issued]}}) is None
    other = load("x402-exact-eip155-eip3009.json")["fixed"]["O"]
    not_held = slot_holds(binding, chosen, {"x402": {"accepts": [other]}})
    assert isinstance(not_held, Declined) and not_held.code == "option-not-in-atr", not_held
