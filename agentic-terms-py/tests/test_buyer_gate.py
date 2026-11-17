"""The gate's own vectors, terms' profile buyer-gate.md (vectors/buyer-gate.json, which the TypeScript gate runs too).
Each row runs through transact with the row's pairing, document, ATR bytes, request, inputs and ceilings, the clock at
the file's now, an approver that answers the row's approves, and a signer that is the file's payer key where the row
is signed; the decline, the signer's and the approver's call counts and what the approver was asked are the row's. A
row whose pairing has no buyer piece yet answers pairing-not-supported, the gate's first check, with no call, asserted
and never skipped. The parse's rows are the file's and the protocol package's check-8 rows in core-vectors.json
(refusals answered core/content-not-json, and jsonDepth), which the profile names as the parse's rows too. The first
response's return value is held to lcp's legal-context-return.json. Every input and expected value is the vector
files'."""

import asyncio
import copy
import dataclasses
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

import integraledger_terms as terms
from integraledger_terms import Declined, Refusal, ToSign, _gate, _return
from integraledger_terms._parse import is_one_json_text
from integraledger_terms.pieces import PIECES

from support import StubBinding, core_vectors, load, sign_typed

V: dict[str, Any] = json.loads((Path(__file__).resolve().parents[2] / "agentic-terms" / "vectors" / "buyer-gate.json").read_text("utf-8"))
BINDINGS = {getattr(b, "id"): b for b in (getattr(terms, n) for n in terms.__all__) if isinstance(getattr(b, "id", None), str)}


class Payer:
    """The file's payer key, signing the typed data it is handed, counting its requests."""

    def __init__(self, signs: bool) -> None:
        self.account: str = V["fixed"]["account"]
        self.signs = signs
        self.requests: list[Any] = []

    async def sign(self, request: Any) -> str:
        self.requests.append(request)
        if not self.signs:
            raise AssertionError("the signer is not called on this row")
        return sign_typed(request["typedData"])


def serving(link: str, body: bytes) -> tuple[httpx.AsyncClient, list[str]]:
    """The link serving body with status 200 and no content coding; any other URL answers 404."""
    calls: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=body) if str(request.url) == link else httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handle)), calls


def resource_request(row: dict[str, Any]) -> dict[str, Any]:
    r = row["resourceRequest"]
    return {"method": r["method"], "target": r["target"], "body": r["bodyUtf8"].encode("utf-8")}


@pytest.mark.parametrize("row", V["rows"], ids=[r["name"] for r in V["rows"]])
def test_buyer_gate_rows_through_transact(row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: V["fixed"]["now"])
    doc = copy.deepcopy(V["fixed"]["documents"][row["pairing"]])
    doc["extensions"]["legalContext"]["info"]["value"] = row["atr"]["sha256"]
    body = bytes.fromhex(row["atr"]["hex"])
    signer = Payer(row["expect"]["signerCalls"] > 0)
    asked: list[ToSign] = []

    def approver(to_sign: ToSign) -> bool:
        asked.append(to_sign)
        approves: bool = row["approves"]
        return approves

    pending = row["pairing"] not in PIECES
    binding = BINDINGS[row["pairing"]] if row["pairing"] in BINDINGS else type("Unbound", (), {"id": row["pairing"]})()

    async def go() -> tuple[Any, list[str]]:
        client, calls = serving(V["fixed"]["link"], body)
        async with client:
            out = await terms.transact(
                doc,
                binding,
                signer,
                client,
                approver=approver,
                resource_request=resource_request(row),  # type: ignore[arg-type]
                inputs=row["inputs"],
                ceilings=row.get("ceilings"),
            )
        return out, calls

    out, calls = asyncio.run(go())
    if pending:
        assert isinstance(out, Declined) and out.code == "pairing-not-supported"
        assert [len(signer.requests), len(asked), len(calls)] == [0, 0, 0]
        return
    expect = row["expect"]
    assert (out.code if isinstance(out, Declined) else None) == expect["decline"], out
    if "detail" in expect:
        assert isinstance(out, Declined) and out.detail == expect["detail"]
    assert [len(signer.requests), len(asked)] == [expect["signerCalls"], expect["approverCalls"]]
    if "asked" in expect:
        got = [{"act": a.act, "pairing": a.pairing, "step": {"index": a.step.index, "count": a.step.count}} for a in asked]
        assert got == expect["asked"]
        for i, a in enumerate(asked):
            assert a.request == signer.requests[i]
            assert a.summary.atr == body


@pytest.mark.parametrize("row", V["parse"]["rows"], ids=[r["name"] for r in V["parse"]["rows"]])
def test_the_parse_rows_of_the_profile(row: dict[str, Any]) -> None:
    assert is_one_json_text(bytes.fromhex(row["hex"])) is row["accept"]


CORE = core_vectors()
CHECK8 = [r for r in CORE["refusals"] if r.get("expect") == "core/content-not-json" and isinstance(r.get("contentHex"), str)]


def test_core_vectors_hold_check_8_refusals_with_bytes() -> None:
    assert CHECK8


@pytest.mark.parametrize("row", CHECK8, ids=[r["name"] for r in CHECK8])
def test_the_parse_refuses_lcp_check_8_refusals(row: dict[str, Any]) -> None:
    assert is_one_json_text(bytes.fromhex(row["contentHex"])) is False


@pytest.mark.parametrize("row", CORE["jsonDepth"]["rows"], ids=[r["name"] for r in CORE["jsonDepth"]["rows"]])
def test_the_parse_takes_lcp_json_depth_rows(row: dict[str, Any]) -> None:
    assert is_one_json_text(row["text"].encode("utf-8")) is row["accept"]


# The first response's return value, transact's legal_context: each value of lcp's legal-context-return.json readRefusals
# is declined offer-unreadable with its code before any fetch, approver or signer call (a value that is not a string is
# no legal_context of the profile's form: no-payable-option, x402/input-malformed); its read row "H alone", whose H is
# not the ATR's the link serves, is declined hash-mismatch before the approver. The document, ATR and request are
# buyer-gate.json's row "approved".
RETURN = load("legal-context-return.json")
APPROVED = next(r for r in V["rows"] if r["name"] == "approved")


def run_return(legal_context: Any, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, list[int]]:
    monkeypatch.setattr(_gate, "_now", lambda: V["fixed"]["now"])
    doc = copy.deepcopy(V["fixed"]["documents"][APPROVED["pairing"]])
    signer = Payer(False)
    asked: list[ToSign] = []

    def approver(to_sign: ToSign) -> bool:
        asked.append(to_sign)
        return True

    async def go() -> tuple[Any, list[str]]:
        client, calls = serving(V["fixed"]["link"], bytes.fromhex(APPROVED["atr"]["hex"]))
        async with client:
            out = await terms.transact(
                doc,
                BINDINGS[APPROVED["pairing"]],
                signer,
                client,
                approver=approver,
                resource_request=resource_request(APPROVED),  # type: ignore[arg-type]
                legal_context=legal_context,
            )
        return out, calls

    out, calls = asyncio.run(go())
    return out, [len(calls), len(asked), len(signer.requests)]


@pytest.mark.parametrize("r", RETURN["readRefusals"], ids=[r["case"] for r in RETURN["readRefusals"]])
def test_a_refused_return_value_declines_before_any_fetch(r: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    expected = ("offer-unreadable", r["expect"]["code"]) if isinstance(r["value"], str) else ("no-payable-option", "x402/input-malformed")
    out, calls = run_return(r["value"], monkeypatch)
    assert isinstance(out, Declined) and (out.code, out.detail) == expected
    assert calls == [0, 0, 0]


# lcp's own functions of the return, mirrored in _return, held to legal-context-return.json's rows: write and its
# refusals (to_legal_context_header), read (from_legal_context_header) and serves (serves_of), each row's expected value.
@pytest.mark.parametrize("r", RETURN["write"] + RETURN["writeRefusals"], ids=[r["case"] for r in RETURN["write"] + RETURN["writeRefusals"]])
def test_the_return_header_is_written_as_lcp_writes_it(r: dict[str, Any]) -> None:
    rv = bytes.fromhex(r["returnValueHex"]) if "returnValueHex" in r else None
    out = _return.to_legal_context_header(r["h"], rv)
    assert (out.code if isinstance(out, Refusal) else out) == (r["expect"]["code"] if isinstance(r["expect"], dict) else r["expect"])


@pytest.mark.parametrize("r", RETURN["read"], ids=[r["case"] for r in RETURN["read"]])
def test_the_return_header_is_read_as_lcp_reads_it(r: dict[str, Any]) -> None:
    out = _return.from_legal_context_header(r["value"])
    assert not isinstance(out, Refusal), out
    h, rv = out
    if "expect" in r:
        assert (h, rv) == (r["expect"]["h"], None)
    else:
        assert (h, rv) == (r["expectH"], bytes.fromhex(r["expectReturnValueHex"]))


@pytest.mark.parametrize("r", RETURN["serves"], ids=[r["case"] for r in RETURN["serves"]])
def test_the_charges_an_agreement_option_serves_are_read_as_lcp_reads_them(r: dict[str, Any]) -> None:
    out = _return.serves_of(r["option"])
    assert (list(out) if isinstance(out, tuple) else out) == r["expect"]


def test_a_return_value_naming_another_h_is_hash_mismatch_before_the_approver(monkeypatch: pytest.MonkeyPatch) -> None:
    r = next(x for x in RETURN["read"] if x["case"] == "H alone")
    out, calls = run_return(r["value"], monkeypatch)
    assert isinstance(out, Declined) and out.code == "hash-mismatch"
    assert calls == [1, 0, 0]


def run_approved(
    go: Any, monkeypatch: pytest.MonkeyPatch, accepts: list[Any] | None = None, later: int = 0
) -> tuple[Any, list[str]]:
    """go(doc, client) over buyer-gate.json's row "approved": its document advertising its ATR's hash (with accepts
    replaced where given), the link serving that ATR, the gate's clock at the file's now plus later seconds; the result
    and the URLs fetched."""
    monkeypatch.setattr(_gate, "_now", lambda: V["fixed"]["now"] + later)
    doc = copy.deepcopy(V["fixed"]["documents"][APPROVED["pairing"]])
    doc["extensions"]["legalContext"]["info"]["value"] = APPROVED["atr"]["sha256"]
    if accepts is not None:
        doc["accepts"] = accepts

    async def main() -> tuple[Any, list[str]]:
        client, calls = serving(V["fixed"]["link"], bytes.fromhex(APPROVED["atr"]["hex"]))
        async with client:
            return await go(doc, client), calls

    return asyncio.run(main())


# Rule 1: ceilings whose value for the pairing the call pays is not of rule 8's form (a positive safe integer or
# "no-end"; 0 is neither) are declined no-payable-option, x402/input-malformed, before anything is fetched.
def test_a_malformed_ceiling_for_the_paid_pairing_is_declined_before_any_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    binding, ceilings = BINDINGS[APPROVED["pairing"]], {APPROVED["pairing"]: 0}
    out, calls = run_approved(
        lambda doc, c: terms.confirm(
            doc, binding, V["fixed"]["account"], c, resource_request=resource_request(APPROVED), ceilings=ceilings  # type: ignore[arg-type]
        ),
        monkeypatch,
    )
    assert out == Declined("no-payable-option", "x402/input-malformed") and calls == [], (out, calls)


# An approval answered after the clock has moved: row "approved"'s request, as confirm builds it at the file's now, is
# approved by an approver that approves that request alone, and transact, called 5 seconds later with confirm's chosen
# kept as JSON, rebuilds that exact request and signs it once (rule 1's chosen; rule 3).
def test_transact_given_confirms_chosen_5_s_later_signs_the_request_confirm_built(monkeypatch: pytest.MonkeyPatch) -> None:
    binding, account = BINDINGS[APPROVED["pairing"]], V["fixed"]["account"]
    confirmed, _ = run_approved(
        lambda doc, c: terms.confirm(doc, binding, account, c, resource_request=resource_request(APPROVED)),  # type: ignore[arg-type]
        monkeypatch,
    )
    assert isinstance(confirmed, terms.Confirmed), confirmed
    chosen = terms.Chosen(**json.loads(json.dumps(dataclasses.asdict(confirmed.chosen))))
    signer = Payer(True)
    asked: list[ToSign] = []

    def approver(to_sign: ToSign) -> bool:
        asked.append(to_sign)
        return to_sign.request == confirmed.request

    out, _ = run_approved(
        lambda doc, c: terms.transact(
            doc, binding, signer, c, approver=approver, resource_request=resource_request(APPROVED), chosen=chosen  # type: ignore[arg-type]
        ),
        monkeypatch,
        later=5,
    )
    assert not isinstance(out, Declined), out
    assert (len(signer.requests), len(asked)) == (1, 1)
    assert signer.requests[0] == confirmed.request


# Rule 12: a first response whose agreement option names the charges it serves in a form lcp's servesOf refuses (each
# of legal-context-return.json's servesRefusals rows as the response's one option) is declined offer-unreadable with
# that code, before any fetch, approver or signer call, through a pairing paid after its agreement (row "approved"'s
# pairing at coverage none); it is not read as a charge.
@pytest.mark.parametrize("r", RETURN["servesRefusals"], ids=[r["case"] for r in RETURN["servesRefusals"]])
def test_a_refused_serves_is_declined_not_read_as_a_charge(r: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    binding = StubBinding(inner=BINDINGS[APPROVED["pairing"]], id=APPROVED["pairing"], coverage="none")
    signer = Payer(False)
    asked: list[ToSign] = []

    def approver(to_sign: ToSign) -> bool:
        asked.append(to_sign)
        return True

    out, calls = run_approved(
        lambda doc, c: terms.transact(
            doc, binding, signer, c, approver=approver, resource_request=resource_request(APPROVED)  # type: ignore[arg-type]
        ),
        monkeypatch,
        [r["option"]],
    )
    assert isinstance(out, Declined) and (out.code, out.detail) == ("offer-unreadable", r["expect"]["code"]), out
    assert (calls, asked, signer.requests) == ([], [], [])


# Rule 5 (RFC 7493, section 2.2): an integer outside -(2^53 - 1) to 2^53 - 1 is refused, however many digits it has.
# CPython 3.11 and later refuse to convert a decimal string of more than 4,300 digits to an int (ValueError), so a seller
# serving such an integer under its own matching hash made the gate raise where it must decline atr-malformed. The
# document is row "approved"'s, advertising the SHA-256 of the bytes served; nothing is asked or signed.
def test_an_integer_of_more_than_4300_digits_is_declined_atr_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    body = b'{"a":1' + b"0" * 4300 + b"}"
    monkeypatch.setattr(_gate, "_now", lambda: V["fixed"]["now"])
    doc = copy.deepcopy(V["fixed"]["documents"][APPROVED["pairing"]])
    doc["extensions"]["legalContext"]["info"]["value"] = "0x" + hashlib.sha256(body).hexdigest()
    signer = Payer(False)
    asked: list[ToSign] = []

    def approver(to_sign: ToSign) -> bool:
        asked.append(to_sign)
        return True

    async def go() -> tuple[Any, list[str]]:
        client, calls = serving(V["fixed"]["link"], body)
        async with client:
            out = await terms.transact(
                doc,
                BINDINGS[APPROVED["pairing"]],
                signer,
                client,
                approver=approver,
                resource_request=resource_request(APPROVED),  # type: ignore[arg-type]
            )
        return out, calls

    out, calls = asyncio.run(go())
    assert isinstance(out, Declined) and out.code == "atr-malformed", out
    assert [len(calls), len(asked), len(signer.requests)] == [1, 0, 0]
    assert is_one_json_text(body) is False


# Whether a first response offers the agreement alone does not depend on the order of its options: one option naming no
# charge it serves (legal-context-return.json's serves row "an x402 option with no such member") makes it a charge offer
# whichever comes first, beside an option whose serves lcp refuses (each servesRefusals row).
@pytest.mark.parametrize("r", RETURN["servesRefusals"], ids=[r["case"] for r in RETURN["servesRefusals"]])
def test_an_option_naming_no_served_charge_makes_a_charge_offer_in_either_order(r: dict[str, Any]) -> None:
    plain = next(x for x in RETURN["serves"] if x["case"] == "an x402 option with no such member")["option"]
    doc = V["fixed"]["documents"][APPROVED["pairing"]]
    assert _return.agreement_options({**doc, "accepts": [r["option"], plain]}) is None
    assert _return.agreement_options({**doc, "accepts": [plain, r["option"]]}) is None


# Rule 12, the return after an agreement (lcp profile legal-context-return.md): a first response offering the agreement
# alone, its options naming x402/0 in extra.legalContextServes as legal-context-return.json's serves rows do, and an ATR
# whose x402 slot lists the charge option at index 0. The ATR is row "approved"'s A with that list added to its slot, its
# SHA-256 from hashlib; the document is row "approved"'s, advertising that hash and buyer.json's agreement URL.
AGREEMENT_URL: str = load("buyer.json")["fixed"]["agreement"]["url"]
SERVES_X402_0: dict[str, Any] = RETURN["serves"][0]["option"]


def agreement_first(charge: dict[str, Any], options: list[dict[str, Any]]) -> tuple[dict[str, Any], bytes]:
    a = json.loads(bytes.fromhex(APPROVED["atr"]["hex"]))
    atr = json.dumps({**a, "x402": {**a["x402"], "accepts": [charge]}}, separators=(",", ":")).encode("utf-8")
    doc = copy.deepcopy(V["fixed"]["documents"][APPROVED["pairing"]])
    doc["accepts"] = options
    info = doc["extensions"]["legalContext"]["info"]
    info["value"] = "0x" + hashlib.sha256(atr).hexdigest()
    info["legalContextAgreementUrl"] = AGREEMENT_URL
    return doc, atr


def run_agreement_first(
    doc: dict[str, Any], atr: bytes, binding: Any, monkeypatch: pytest.MonkeyPatch, **options: Any
) -> tuple[Any, list[ToSign], int]:
    """transact over the first response, the link serving atr, an approver answering False and a signer that is never
    called; the result, what the approver was asked and the number of signer calls."""
    monkeypatch.setattr(_gate, "_now", lambda: V["fixed"]["now"])
    signer = Payer(False)
    asked: list[ToSign] = []

    def approver(to_sign: ToSign) -> bool:
        asked.append(to_sign)
        return False

    async def go() -> Any:
        client, _calls = serving(V["fixed"]["link"], atr)
        async with client:
            return await terms.transact(
                doc, binding, signer, client, approver=approver, resource_request=resource_request(APPROVED), **options  # type: ignore[arg-type]
            )

    out = asyncio.run(go())
    return out, asked, len(signer.requests) + sum(len(getattr(s, "requests", [])) for s in options.values())


@dataclass
class SolanaPayer:
    """x402-exact-solana.json's B2 payer, which is never asked to sign here."""

    account: str
    requests: list[Any] = field(default_factory=list)

    async def sign(self, request: Any) -> str:
        self.requests.append(request)
        raise AssertionError("the agreement signer is not called")


# The charge follows only an agreement option its pairing's agreementOn admits, on the return path as on the ordinary one.
# The charge is row "approved"'s option through a stub of its pairing at coverage none stating agreementOn same-network;
# an agreement option on another network, buyer.json BA9's requiredMixed's first, x402-exact-solana.json's option, with
# that file's B2 payer and inputs, is declined no-payable-option before the approver; lcp's serves row on the charge's own
# network is asked of the approver as the agreement.
def test_the_return_pays_only_an_agreement_option_the_charges_agreement_on_admits(monkeypatch: pytest.MonkeyPatch) -> None:
    charge = V["fixed"]["documents"][APPROVED["pairing"]]["accepts"][0]
    binding = StubBinding(inner=BINDINGS[APPROVED["pairing"]], id=APPROVED["pairing"], coverage="none", agreement_on="same-network")
    solana_b2 = next(r for r in load("x402-exact-solana.json")["buyer"]["rows"] if r["name"] == "B2")["input"]
    mixed = load("buyer.json")["fixed"]["agreement"]["requiredMixed"]["accepts"][0]
    other = {**mixed, "extra": {**mixed["extra"], "legalContextServes": ["x402/0"]}}
    payer = SolanaPayer(solana_b2["account"])
    out, asked, signed = run_agreement_first(
        *agreement_first(charge, [other]), binding, monkeypatch, agreement_signer=payer, inputs=solana_b2["inputs"]
    )
    assert isinstance(out, Declined) and out.code == "no-payable-option", out
    assert (asked, signed) == ([], 0)
    out, asked, signed = run_agreement_first(*agreement_first(charge, [SERVES_X402_0]), binding, monkeypatch)
    assert isinstance(out, Declined) and out.code == "not-approved", out
    assert [(a.act, a.pairing) for a in asked] == [("agreement", APPROVED["pairing"])] and signed == 0


# Checks 9 to 11 on the charge the return chooses come before its agreement is paid (rule 3: each answers before the
# signer is called for the signing it concerns), so no agreement is paid for a charge the gate then declines. The charge
# is x402-exact-eip155-erc7710.json's fixed option, a delegation, which signs no end (lcp profile
# x402-exact-eip155-erc7710.md): declined no-end before the approver or the signer; with its ceiling raised to no-end,
# the one member it differs in, lcp's serves row is asked of the approver as the agreement.
def test_the_return_checks_the_charge_before_it_pays_the_agreement(monkeypatch: pytest.MonkeyPatch) -> None:
    charge = load("x402-exact-eip155-erc7710.json")["fixed"]["option"]
    binding = BINDINGS["x402/exact/eip155/erc7710"]
    doc, atr = agreement_first(charge, [SERVES_X402_0])
    out, asked, signed = run_agreement_first(doc, atr, binding, monkeypatch)
    assert isinstance(out, Declined) and out.code == "no-end", out
    assert (asked, signed) == ([], 0)
    out, asked, signed = run_agreement_first(doc, atr, binding, monkeypatch, ceilings={binding.id: "no-end"})
    assert isinstance(out, Declined) and out.code == "not-approved", out
    assert [(a.act, a.pairing) for a in asked] == [("agreement", APPROVED["pairing"])] and signed == 0
