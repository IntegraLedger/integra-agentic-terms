"""buyer.json's agreement rows (BA1-BA19) and coding rows (BE1, BE2), run from the rows' own data: every input, script
and expected value is the row's or the file's fixed. A row with input.approve runs its entry twice: the first call
returns the agreement payment for approval, whose option is compared with expect.approval, and signs nothing; with
approve true the second call carries that payment back as approved. A row with no approve declines, or pays no
agreement, in its one call. A row's cases share its input and expect except where a case gives its own; a row runs
through transact, or through each gate function its entry or entries names. A step's paymentRequiredHeader and bodyHex
are sent as the fixture's text and bytes are, unchanged. BE1's bodies are the row's hex, served under each case's
Content-Encoding; BE2's gzip body is written by Python's zlib, and its br answer carries the receipt's JSON under
Content-Encoding br, a body the gate declines unread."""

import asyncio
import base64
import copy
import dataclasses
import json
import zlib
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import Advertised, Declined, ToApprove, _agreement, _gate, agree, transact

from support import A, BUYER, D, NOW, Link, StubBinding, digest, row, sign_typed

AG: dict[str, Any] = BUYER["fixed"]["agreement"]
LINK_A: str = BUYER["fixed"]["link"]
SIGNATURES: dict[str, str] = {"B6": row("B6")["expect"]["signature"]}


@dataclass
class Clock:
    now: float = 1000.0


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Freezes the gate's clock at the file's now, and gives the agreement exchange a clock its waits advance."""
    fake = Clock()

    async def sleep(seconds: float) -> None:
        fake.now += seconds

    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    monkeypatch.setattr(_agreement, "_clock", lambda: fake.now)
    monkeypatch.setattr(_agreement, "_sleep", sleep)
    return fake


@dataclass
class Signer:
    """The published Anvil key, through eth-account, recording each request."""

    account: str = BUYER["fixed"]["account"]
    requests: list[dict[str, Any]] = field(default_factory=list)

    async def sign(self, request: Any) -> str:
        self.requests.append(request)
        return sign_typed(request["typedData"])


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def gzip(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return compressor.compress(data) + compressor.flush()


def named(value: str) -> Any:
    """A value a row names by its path in the file, as fixed.agreement.url; any other string is the value itself."""
    if not value.startswith("fixed."):
        return value
    out: Any = BUYER
    for key in value.split("."):
        out = out[key]
    return out


# The members a step, an input and an expect may hold: a row with any other is not run as written.
STEP_KEYS = {"status", "paymentRequired", "paymentRequiredText", "paymentRequiredHeader", "retryAfter", "body", "bodyHex"}
STEP_KEYS |= {"repeats", "contentEncoding"}
INPUT_KEYS = {"doc", "signer", "agreement", "agreementUrl", "approve", "advanceMs", "entry", "entries", "atr", "serves"}
INPUT_KEYS |= {"inputs"}
EXPECT_KEYS = {"decline", "detail", "moved", "signCalls", "paidRequests", "fetches", "agreementFetches", "order"}
EXPECT_KEYS |= {"approval", "agreementMessage", "agreementDigest", "agreementSignature", "paymentSignature", "signed"}
EXPECT_KEYS |= {"receipt", "agreement", "requestHeaders"}


@dataclass
class Seller:
    """Serves atr at the ATR link and plays the script at the agreement URL, one step per request, the last repeating;
    bare counts the 402 answers it sent with no PAYMENT-REQUIRED and the 200 answers with no body, which no row's step
    asks for."""

    script: list[dict[str, Any]]
    atr: bytes = A
    requests: list[httpx.Request] = field(default_factory=list)
    step: int = 0
    bare: int = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) == LINK_A:
            return httpx.Response(200, content=self.atr)
        s = self.script[min(self.step, len(self.script) - 1)]
        if not s.get("repeats"):
            self.step += 1
        headers: dict[str, str] = {}
        if "paymentRequired" in s:
            headers["payment-required"] = b64(json.dumps(AG[s["paymentRequired"]]))
        if "paymentRequiredText" in s:
            headers["payment-required"] = b64(AG[s["paymentRequiredText"]])
        if "paymentRequiredHeader" in s:
            headers["payment-required"] = AG[s["paymentRequiredHeader"]]
        if "retryAfter" in s:
            headers["retry-after"] = s["retryAfter"]
        if "contentEncoding" in s:
            headers["content-encoding"] = s["contentEncoding"]
        content = json.dumps(AG[s["body"]]).encode("utf-8") if "body" in s else None
        if "bodyHex" in s:
            content = bytes.fromhex(AG[s["bodyHex"]])
        if (s["status"] == 402 and "payment-required" not in headers) or (s["status"] == 200 and content is None):
            self.bare += 1
        if content is not None and s.get("contentEncoding") == "gzip":
            content = gzip(content)
        return httpx.Response(s["status"], headers=headers, content=content or b"")

    def link_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if str(r.url) == LINK_A]

    def agreement_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if str(r.url) != LINK_A]

    def paid(self) -> list[str]:
        return [r.headers["payment-signature"] for r in self.agreement_requests() if "payment-signature" in r.headers]


def with_agreement(url: str) -> StubBinding:
    real = BINDING.read(D)
    assert isinstance(real, Advertised)
    return StubBinding(inner=BINDING, public_proof=False, read_answer=dataclasses.replace(real, agreement=url))


def without_agreement() -> StubBinding:
    """The x402/EVM binding as a pairing with no public proof, whose read gives no agreement URL."""
    return StubBinding(inner=BINDING, public_proof=False)


def mixed() -> dict[str, Any]:
    """D with the agreement URL in its legal context after legalContextUrl."""
    doc = copy.deepcopy(D)
    doc["extensions"]["legalContext"]["info"]["legalContextAgreementUrl"] = AG["url"]
    return doc


@dataclass
class Run:
    out: Any
    elapsed: float
    seller: Seller
    signer: Signer


def offer_of(name: str, url: str) -> tuple[Any, Any]:
    """The offer and binding a row's doc describes: BA6 reads D through the public-proof pairing itself, BA12 through
    the stub whose read gives no agreement URL, and every other row through the stub whose read gives url."""
    if name == "BA6":
        return mixed(), BINDING
    if name == "BA12":
        return D, without_agreement()
    return D, with_agreement(url)


def exchange(name: str, inputs: dict[str, Any], expected: dict[str, Any], clock: Clock, entry: str = "transact") -> Run:
    """The row's exchange through entry: one call, or, with approve, the call that asks for approval and, when
    approved, the second."""
    url: str = named(inputs.get("agreementUrl", "fixed.agreement.url"))
    doc, binding = offer_of(name, url)
    seller = Seller(inputs.get("agreement", []), bytes.fromhex(BUYER["fixed"][inputs["serves"]]) if "serves" in inputs else A)
    signer = Signer()
    given = {"inputs": inputs["inputs"]} if "inputs" in inputs else {}
    atr = bytes.fromhex(named(inputs["atr"])) if "atr" in inputs else A

    async def go() -> tuple[Any, float]:
        async with Link(seller.handle).client() as client:

            async def call(approved: Any = None) -> Any:
                more = {**given, "approved": approved} if approved is not None else given
                if entry == "agree":
                    return await agree(atr, url, signer, client, **more)
                assert entry == "transact", f"{name}: no entry {entry}"
                return await transact(doc, binding, signer, client, **more)

            start = clock.now
            out = await call()
            if "approval" in expected:
                assert isinstance(out, ToApprove), f"{name}: the agreement payment is returned for approval"
            if isinstance(out, ToApprove):
                assert "approve" in inputs
                option = out.approve.option
                if "approval" in expected:
                    assert {k: option[k] for k in ("amount", "asset", "payTo", "network")} == expected["approval"]
                assert signer.requests == [] and seller.paid() == []
                if inputs["approve"] is True:
                    start = clock.now
                    out = await call(out.approve)
            return out, clock.now - start

    out, elapsed = asyncio.run(go())
    return Run(out, elapsed, seller, signer)


def compare(inputs: dict[str, Any], e: dict[str, Any], run: Run) -> None:
    """Every expected value the row states, against what the exchange did."""
    out, seller, signer = run.out, run.seller, run.signer
    paid = seller.paid()
    assert seller.bare == 0
    if "decline" in e:
        assert isinstance(out, Declined) and out.code == e["decline"], out
    else:
        assert not isinstance(out, Declined), out
    if "detail" in e:
        assert out.detail == e["detail"], out
    if "moved" in e:
        assert (out.moved is not None) == e["moved"], out
    if "fetches" in e:
        assert len(seller.link_requests()) == e["fetches"]
    if "signCalls" in e:
        assert len(signer.requests) == e["signCalls"]
    if "paidRequests" in e:
        assert len(paid) == e["paidRequests"]
    if "agreementFetches" in e:
        assert len(seller.agreement_requests()) == e["agreementFetches"]
    if "advanceMs" in inputs:
        assert run.elapsed * 1000 == inputs["advanceMs"]
    if "order" in e:
        amounts = {"agreement": int(AG["option"]["amount"]), "payment": int(D["accepts"][0]["amount"])}
        assert [int(q["typedData"]["message"]["value"]) for q in signer.requests] == [amounts[o] for o in e["order"]]
    agreement = signer.requests[0]["typedData"] if signer.requests else None
    if "agreementMessage" in e:
        assert agreement is not None
        message = agreement["message"]
        assert {k: str(message[k]) for k in e["agreementMessage"]} == e["agreementMessage"]
    if "agreementDigest" in e:
        assert agreement is not None and digest(agreement) == e["agreementDigest"]
    if "agreementSignature" in e:
        assert len(set(paid)) == 1
        assert json.loads(base64.b64decode(paid[0]))["payload"]["signature"] == e["agreementSignature"]
    signed = getattr(out, "signed", None)
    for key in ("paymentSignature", "signed"):
        if key in e:
            assert signed is not None and signed["payload"]["signature"] == SIGNATURES[e[key]]
    if "agreement" in e:
        receipt = out.agreement
        assert receipt is not None
        assert {"atrHash": receipt.atr_hash, "agreed": receipt.agreed, "network": receipt.network, "transaction": receipt.transaction} == AG[e["agreement"]]
    for name, value in e.get("requestHeaders", {}).items():
        assert all(q.headers[name] == value for q in seller.requests)


@dataclass
class RowRun:
    case: str
    entry: str
    inputs: dict[str, Any]
    expect: dict[str, Any]


def runs_of(r: dict[str, Any]) -> list[RowRun]:
    """Each run a row asks for: every case, or the row itself, through every entry it names."""
    shared = {k: v for k, v in r["input"].items() if k != "cases"}
    out: list[RowRun] = []
    for c in r["input"].get("cases", [{"case": r["name"]}]):
        inputs = {**shared, **{k: v for k, v in c.items() if k not in ("case", "expect")}}
        for entry in inputs.get("entries", [inputs.get("entry", "transact")]):
            out.append(RowRun(c["case"], entry, inputs, {**r["expect"], **c.get("expect", {})}))
    return out


def play(name: str, run: RowRun, clock: Clock) -> None:
    """Runs one of a row's runs, once its members are found to be those this runner reads."""
    where = f"{name}, {run.case}, through {run.entry}"
    assert set(run.inputs) <= INPUT_KEYS, (where, set(run.inputs) - INPUT_KEYS)
    assert set(run.expect) <= EXPECT_KEYS, (where, set(run.expect) - EXPECT_KEYS)
    for step in run.inputs.get("agreement", []):
        assert set(step) <= STEP_KEYS, (where, set(step) - STEP_KEYS)
    try:
        compare(run.inputs, run.expect, exchange(name, run.inputs, run.expect, clock, run.entry))
    except AssertionError as err:
        raise AssertionError(f"{where}: {err}") from err


BA = [r for r in BUYER["rows"] if r["name"].startswith("BA")]


def test_the_file_holds_ba1_to_ba19() -> None:
    assert [r["name"] for r in BA] == [f"BA{i}" for i in range(1, 20)]


@pytest.mark.parametrize("r", BA, ids=[r["name"] for r in BA])
def test_agreement_row(r: dict[str, Any], clock: Clock) -> None:
    for run in runs_of(r):
        play(r["name"], run, clock)


BE1 = row("BE1")


@pytest.mark.parametrize("case", BE1["input"]["cases"], ids=[c["case"] for c in BE1["input"]["cases"]])
def test_be1_a_coded_atr_is_declined_before_anything_is_hashed_or_signed(case: dict[str, Any]) -> None:
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"content-encoding": case["contentEncoding"]}, content=bytes.fromhex(case["bodyHex"]))

    signer = Signer()

    async def go() -> Any:
        async with Link(handle).client() as client:
            return await transact(D, BINDING, signer, client)

    out = asyncio.run(go())
    assert isinstance(out, Declined) and out.code == BE1["expect"]["decline"]
    assert len(signer.requests) == BE1["expect"]["signCalls"]
    assert [q.headers["accept-encoding"] for q in requests] == [BE1["expect"]["requestHeaders"]["accept-encoding"]]


def test_be1_control_the_identity_coding_is_paid_as_b6() -> None:
    e = BE1["control"]["expect"]
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, headers={"content-encoding": "identity"}, content=A)

    signer = Signer()

    async def go() -> Any:
        async with Link(handle).client() as client:
            return await transact(D, BINDING, signer, client)

    out = asyncio.run(go())
    assert len(signer.requests) == e["signCalls"]
    assert not isinstance(out, Declined) and out.signed is not None
    assert out.signed["payload"]["signature"] == SIGNATURES[e["paymentSignature"]]
    assert [q.headers["accept-encoding"] for q in requests] == [e["requestHeaders"]["accept-encoding"]]


BE2 = row("BE2")


@pytest.mark.parametrize("run", runs_of(BE2), ids=[r.case for r in runs_of(BE2)])
def test_be2_an_agreement_answer_in_another_coding_is_agreement_failed(run: RowRun, clock: Clock) -> None:
    play("BE2", run, clock)
