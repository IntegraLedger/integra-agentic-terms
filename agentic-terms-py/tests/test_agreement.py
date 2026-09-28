"""The agreement step's rows BA1-BA7 against the gate, read from the same buyer vectors as the TypeScript gate, except
the bounds of the agreement exchange: each paid request is bounded by min(maxTimeoutSeconds, 120) + 60 + 10 seconds,
the whole exchange by the agreement option's maxTimeoutSeconds + 180 seconds, a timeout or a 202 is pending and the same payment is sent again after retry-after,
and the end of the bound is agreement-pending with the signed agreement payment kept as moved."""

import asyncio
import base64
import dataclasses
import json
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import (
    Advertised,
    Agreed,
    AgreementPayment,
    AgreementReceipt,
    Confirmed,
    X402_EXACT_EIP155_ERC7710,
    Declined,
    Json,
    Refusal,
    ToApprove,
    Transacted,
    _agreement,
    _gate,
    agree,
    confirm,
    transact,
)

from support import A, ACCOUNT, BUYER, D, HASH_A, LINK_A, NOW, Link, StubBinding, digest, load, recover, row, sign_typed

AG: dict[str, Any] = BUYER["fixed"]["agreement"]
URL: str = AG["url"]
# The exchange bounds for the agreement option, whose maxTimeoutSeconds is 60: 130 s per paid request, 240 s in all.
PAID_REQUEST_S = min(AG["option"]["maxTimeoutSeconds"], 120) + 60 + 10
EXCHANGE_S = AG["option"]["maxTimeoutSeconds"] + 180
B6_SIGNATURE: str = row("B6")["expect"]["signature"]

T = TypeVar("T")


@dataclass
class Clock:
    now: float = 1000.0


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Freezes the gate's clock at NOW, and gives the agreement step a clock that its waits advance."""
    fake = Clock()

    async def sleep(seconds: float) -> None:
        fake.now += seconds

    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    monkeypatch.setattr(_agreement, "_clock", lambda: fake.now)
    monkeypatch.setattr(_agreement, "_sleep", sleep)
    return fake


@dataclass
class RecordingSigner:
    """A signer over the published Anvil key, through eth-account, that records each request."""

    account: str = ACCOUNT
    requests: list[Json] = field(default_factory=list)

    async def sign(self, request: Json) -> str:
        self.requests.append(request)
        return sign_typed(request["typedData"])


def b64(value: object) -> str:
    return base64.b64encode(json.dumps(value).encode("utf-8")).decode("ascii")


@dataclass
class Seller:
    """Serves A at the ATR link and plays a script at the agreement URL, recording each request."""

    script: list[dict[str, Any]]
    requests: list[httpx.Request] = field(default_factory=list)
    step: int = 0

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) == LINK_A:
            return httpx.Response(200, content=A)
        s = self.script[min(self.step, len(self.script) - 1)]
        if not s.get("repeats"):
            self.step += 1
        headers = {}
        if "paymentRequired" in s:
            headers["payment-required"] = b64(AG[s["paymentRequired"]])
        if "retryAfter" in s:
            headers["retry-after"] = s["retryAfter"]
        content = json.dumps(AG[s["body"]]).encode("utf-8") if "body" in s else s.get("raw", "").encode("utf-8")
        return httpx.Response(s["status"], headers=headers, content=content)

    def link(self) -> Link:
        return Link(self.handle)

    def agreement_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if str(r.url) != LINK_A]

    def paid(self) -> list[str]:
        return [r.headers["payment-signature"] for r in self.agreement_requests() if "payment-signature" in r.headers]


def with_agreement(url: str) -> StubBinding:
    real = BINDING.read(D)
    assert isinstance(real, Advertised)
    return StubBinding(inner=BINDING, public_proof=False, read_answer=dataclasses.replace(real, agreement=url))


def run(link: Link, go: Any) -> Any:
    async def main() -> Any:
        async with link.client() as client:
            return await go(client)

    return asyncio.run(main())


async def approve_and_agree(signer: Any, client: httpx.AsyncClient, **options: Any) -> ToApprove | Agreed | Declined:
    """agree in its two calls: the agreement payment to approve, then that payment, approved unchanged."""
    first = await agree(A, URL, signer, client, **options)
    if not isinstance(first, ToApprove):
        return first
    return await agree(A, URL, signer, client, approved=first.approve, **options)


async def approve_and_transact(
    doc: Any, binding: Any, signer: Any, client: httpx.AsyncClient, **options: Any
) -> Transacted | ToApprove | Declined:
    """transact in its two calls: the agreement payment to approve, then the call with that payment approved
    unchanged."""
    first = await transact(doc, binding, signer, client, **options)
    if not isinstance(first, ToApprove):
        return first
    return await transact(doc, binding, signer, client, approved=first.approve, **options)


def declined(result: object, code: str) -> bool:
    return isinstance(result, Declined) and result.code == code


def test_the_agreement_challenges_read_as_the_agreement_option_for_each_hash() -> None:
    read = BINDING.read(AG["required"])
    assert isinstance(read, Advertised)
    assert read.h == HASH_A and read.link == LINK_A and read.offer["options"] == [AG["option"]]
    other = BINDING.read(AG["requiredOtherHash"])
    assert isinstance(other, Advertised)
    assert other.h == BUYER["fixed"]["hashC"]


def test_confirm_carries_the_agreement_url_the_binding_read_in_chosen() -> None:
    seller = Seller([])
    with_url = run(seller.link(), lambda c: confirm(D, with_agreement(URL), ACCOUNT, c))
    assert isinstance(with_url, Confirmed) and with_url.chosen.agreement == URL
    without = run(seller.link(), lambda c: confirm(D, BINDING, ACCOUNT, c))
    assert isinstance(without, Confirmed) and without.chosen.agreement is None


def test_ba1_the_agreement_is_signed_and_paid_first_then_the_full_payment_once(clock: Clock) -> None:
    r = row("BA1")
    seller = Seller(r["input"]["agreement"])
    signer = RecordingSigner()
    start = clock.now
    out = run(seller.link(), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert isinstance(out, Transacted)
    assert clock.now - start == int(r["input"]["agreement"][1]["retryAfter"])

    assert len(signer.requests) == r["expect"]["signCalls"]
    agreement, payment = signer.requests
    m = r["expect"]["agreementMessage"]
    assert agreement["typedData"]["message"] == {
        "from": m["from"],
        "to": m["to"],
        "value": int(m["value"]),
        "validAfter": int(m["validAfter"]),
        "validBefore": int(m["validBefore"]),
        "nonce": m["nonce"],
    }
    assert digest(agreement["typedData"]) == r["expect"]["agreementDigest"]
    assert payment["typedData"]["message"]["nonce"] == HASH_A
    assert payment["typedData"]["message"]["value"] == int(D["accepts"][0]["amount"])

    paid = seller.paid()
    assert len(paid) == r["expect"]["paidRequests"]
    assert len(set(paid)) == 1
    sent = json.loads(base64.b64decode(paid[0]))
    assert sent["payload"]["authorization"]["nonce"] == HASH_A
    assert sent["payload"]["authorization"]["value"] == m["value"]
    assert sent["payload"]["signature"] == r["expect"]["agreementSignature"]
    assert sent["accepted"] == AG["option"]
    assert recover(agreement["typedData"], r["expect"]["agreementSignature"]) == m["from"]

    assert out.signed is not None and out.signed["payload"]["signature"] == B6_SIGNATURE
    assert out.h == HASH_A and out.atr_bytes == A
    assert [str(q.url) for q in seller.requests] == [LINK_A, URL, LINK_A, URL, URL]
    assert "payment-signature" not in seller.agreement_requests()[0].headers


def test_ba1_agree_returns_the_receipt_and_an_agreement_signer_signs_the_agreement() -> None:
    r = row("BA1")
    receipt = AG[r["expect"]["receipt"]]
    out = run(Seller(r["input"]["agreement"]).link(), lambda c: approve_and_agree(RecordingSigner(), c))
    assert out == Agreed(
        AgreementReceipt(
            atr_hash=receipt["atrHash"],
            agreed=True,
            network=receipt["network"],
            transaction=receipt["transaction"],
        )
    )

    signer = RecordingSigner()
    agreement_signer = RecordingSigner()
    whole = run(
        Seller(r["input"]["agreement"]).link(),
        lambda c: approve_and_transact(D, with_agreement(URL), signer, c, agreement_signer=agreement_signer),
    )
    assert isinstance(whole, Transacted)
    assert [q["typedData"]["message"]["value"] for q in agreement_signer.requests] == [1]
    assert [q["typedData"]["message"]["value"] for q in signer.requests] == [10000]


def test_ba2_the_plant_an_agreement_challenge_for_another_hash_is_never_signed() -> None:
    r = row("BA2")
    assert r["plant"] is True
    seller = Seller(r["input"]["agreement"])
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert declined(out, r["expect"]["decline"])
    assert len(signer.requests) == r["expect"]["signCalls"]
    assert len(seller.paid()) == r["expect"]["paidRequests"]

    direct = RecordingSigner()
    assert declined(
        run(Seller(r["input"]["agreement"]).link(), lambda c: approve_and_agree(direct, c)), r["expect"]["decline"]
    )
    assert len(direct.requests) == r["expect"]["signCalls"]


def test_ba3_a_202_that_never_becomes_200_is_pending_at_the_exchange_bound_with_the_agreement_payment_kept(
    clock: Clock,
) -> None:
    r = row("BA3")
    seller = Seller(r["input"]["agreement"])
    signer = RecordingSigner()
    start = clock.now
    out = run(seller.link(), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert declined(out, "agreement-pending")
    assert clock.now - start == EXCHANGE_S
    assert len(signer.requests) == r["expect"]["signCalls"]
    assert signer.requests[0]["typedData"]["message"]["value"] == 1
    retry = int(r["input"]["agreement"][1]["retryAfter"])
    assert len(seller.paid()) == EXCHANGE_S // retry
    assert len(set(seller.paid())) == 1
    assert isinstance(out, Declined) and out.moved is not None
    assert out.moved.h == HASH_A and out.moved.atr_bytes == A
    assert json.loads(base64.b64decode(seller.paid()[0])) == out.moved.signed


def test_ba3_the_exchange_bound_runs_from_the_payments_first_sending_not_from_the_signers_call(clock: Clock) -> None:
    r = row("BA3")
    seller = Seller(r["input"]["agreement"])

    @dataclass
    class SlowSigner(RecordingSigner):
        async def sign(self, request: Json) -> str:
            clock.now += 30
            return await RecordingSigner.sign(self, request)

    start = clock.now
    out = run(seller.link(), lambda c: approve_and_agree(SlowSigner(), c))
    assert declined(out, "agreement-pending")
    assert clock.now - start == 30 + EXCHANGE_S


def test_a_paid_request_that_never_answers_is_bounded_and_sent_again_until_the_exchange_bound(
    clock: Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    seconds: list[float] = []
    real_get = _agreement._get

    async def unanswered(fetch: httpx.AsyncClient, url: str, signature: str | None, s: float) -> Any:
        if signature is None:
            return await real_get(fetch, url, signature, s)
        seconds.append(s)
        clock.now += s
        return _agreement._Unanswered()

    monkeypatch.setattr(_agreement, "_get", unanswered)
    signer = RecordingSigner()
    start = clock.now
    out = run(Seller([{"status": 402, "paymentRequired": "required"}]).link(), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert declined(out, "agreement-pending")
    assert clock.now - start == EXCHANGE_S
    assert seconds == [PAID_REQUEST_S, EXCHANGE_S - PAID_REQUEST_S - 2]
    assert len(signer.requests) == 1


def test_a_paid_request_answered_200_after_15_s_is_waited_for(clock: Clock, monkeypatch: pytest.MonkeyPatch) -> None:
    """The seller bounds its paid request by min(maxTimeoutSeconds, 120) s for the exchange, 10 s for /verify and
    60 s for /settle; an answer at 15 s is inside them."""
    seller = Seller([{"status": 402, "paymentRequired": "required"}, {"status": 200, "body": "receipt"}])
    handle = seller.handle

    def slow(request: httpx.Request) -> httpx.Response:
        if "payment-signature" in request.headers:
            clock.now += 15
        return handle(request)

    signer = RecordingSigner()
    out = run(Link(slow), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert isinstance(out, Transacted) and out.agreement is not None
    assert len(seller.paid()) == 1 and len(signer.requests) == 2


def test_an_answer_that_does_not_complete_the_agreement_payment_sends_nothing() -> None:
    seller = Seller([{"status": 402, "paymentRequired": "required"}])

    @dataclass
    class Wrong(RecordingSigner):
        async def sign(self, request: Json) -> str:
            return "0x00"

    out = run(seller.link(), lambda c: approve_and_agree(Wrong(), c))
    assert declined(out, "signed-not-bound")
    assert seller.paid() == []


def test_an_agreement_placed_by_another_public_proof_pairing_is_paid_by_that_pairing() -> None:
    """The agreement pairing is any pairing with publicProof true, and the build is that pairing's. The option is
    the permit2 vector file's; the rest is buyer.json's."""
    option = load("x402-exact-eip155-permit2.json")["fixed"]["option"]
    required = {**AG["required"], "accepts": [option]}
    seller = Seller([{"status": 402, "paymentRequired": "required"}, {"status": 200, "body": "receipt"}])
    AGP = {**AG, "required": required}
    handle = seller.handle

    def permit2(request: httpx.Request) -> httpx.Response:
        response = handle(request)
        if response.status_code == 402:
            return httpx.Response(402, headers={"payment-required": b64(AGP["required"])})
        return response

    signer = RecordingSigner()
    out = run(Link(permit2), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert isinstance(out, Transacted), out
    assert out.agreement is not None
    assert [q["typedData"]["primaryType"] for q in signer.requests][1] == "TransferWithAuthorization"
    assert len(signer.requests) == 2


def test_an_unpaid_202_is_agreement_pending_and_nothing_is_signed() -> None:
    """Another sending of the agreement is still settling: the gate never pays a second agreement."""
    signer = RecordingSigner()
    out = run(Seller([{"status": 202, "retryAfter": "2"}]).link(), lambda c: approve_and_agree(signer, c))
    assert declined(out, "agreement-pending")
    assert isinstance(out, Declined) and out.moved is None
    assert signer.requests == []


def test_ba4_a_receipt_naming_another_hash_fails_and_the_payment_is_never_signed() -> None:
    r = row("BA4")
    signer = RecordingSigner()
    out = run(Seller(r["input"]["agreement"]).link(), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert declined(out, r["expect"]["decline"])
    assert len(signer.requests) == r["expect"]["signCalls"]
    assert signer.requests[0]["typedData"]["message"]["value"] == 1


def test_ba5_an_http_agreement_url_is_declined_before_any_fetch_of_it() -> None:
    r = row("BA5")
    seller = Seller([])
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: agree(A, r["input"]["agreementUrl"], signer, c))
    assert declined(out, r["expect"]["decline"])
    assert len(seller.requests) == r["expect"]["agreementFetches"]
    assert len(signer.requests) == r["expect"]["signCalls"]

    through = Seller([])
    again = RecordingSigner()
    out = run(through.link(), lambda c: approve_and_transact(D, with_agreement(r["input"]["agreementUrl"]), again, c))
    assert declined(out, r["expect"]["decline"])
    assert len(through.agreement_requests()) == r["expect"]["agreementFetches"]
    assert len(again.requests) == r["expect"]["signCalls"]


@pytest.mark.parametrize(
    ("url", "detail"),
    [
        ("http://pay.seller.example/agreement", "x402/link-not-https"),
        ("not a url", "x402/legal-context-malformed"),
        ("https://u@pay.seller.example/agreement", "x402/legal-context-malformed"),
    ],
)
def test_an_agreement_url_the_gate_refuses_carries_the_protocol_packages_code(url: str, detail: str) -> None:
    seller = Seller([])
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: approve_and_transact(D, with_agreement(url), signer, c))
    assert out == Declined("link-not-https", detail)
    assert len(seller.agreement_requests()) == 0
    assert len(signer.requests) == 0


@pytest.mark.parametrize("binding", [BINDING, X402_EXACT_EIP155_ERC7710], ids=lambda b: str(b.id))
def test_ba5_read_refuses_an_http_agreement_url_as_link_not_https(binding: Any) -> None:
    # BA5 declines an http agreement URL link-not-https; read refuses a well-formed legal context carrying one.
    r = row("BA5")
    doc = json.loads(json.dumps(D))
    doc["extensions"]["legalContext"]["info"]["legalContextAgreementUrl"] = r["input"]["agreementUrl"]
    assert binding.read(doc) == Refusal(f"x402/{r['expect']['decline']}")


def test_ba6_a_pairing_whose_payment_is_a_public_proof_does_not_pay_the_agreement_url() -> None:
    r = row("BA6")
    legal_context = D["extensions"]["legalContext"]
    info = {**legal_context["info"], "legalContextAgreementUrl": URL}
    doc = {**D, "extensions": {**D["extensions"], "legalContext": {**legal_context, "info": info}}}
    seller = Seller([{"status": 402, "paymentRequired": "required"}])
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: transact(doc, BINDING, signer, c))
    assert isinstance(out, Transacted)
    assert len(seller.agreement_requests()) == r["expect"]["agreementFetches"]
    assert len(signer.requests) == r["expect"]["signCalls"]
    assert out.signed is not None and out.signed["payload"]["signature"] == row(r["expect"]["paymentSignature"])["expect"]["signature"]
    assert out.agreement is None


def test_ba7_transact_returns_the_agreements_receipt_beside_the_payment() -> None:
    r = row("BA7")
    out = run(Seller(r["input"]["agreement"]).link(), lambda c: approve_and_transact(D, with_agreement(URL), RecordingSigner(), c))
    assert isinstance(out, Transacted)
    receipt = AG[r["expect"]["agreement"]]
    assert out.agreement == AgreementReceipt(
        atr_hash=receipt["atrHash"], agreed=True, network=receipt["network"], transaction=receipt["transaction"]
    )
    assert out.signed is not None and out.signed["payload"]["signature"] == row(r["expect"]["signed"])["expect"]["signature"]
    plain = run(Seller([]).link(), lambda c: transact(D, BINDING, RecordingSigner(), c))
    assert isinstance(plain, Transacted) and plain.agreement is None


def test_a_recorded_agreement_answers_200_at_once_with_no_signature() -> None:
    signer = RecordingSigner()
    out = run(Seller([{"status": 200, "body": "receipt"}]).link(), lambda c: approve_and_agree(signer, c))
    assert isinstance(out, Agreed) and out.receipt.transaction == AG["receipt"]["transaction"]
    assert signer.requests == []


@pytest.mark.parametrize(
    "script",
    [[{"status": 404}], [{"status": 402}]],
    ids=["an unpaid 404", "a 402 with no PAYMENT-REQUIRED"],
)
def test_other_unpaid_answers_fail_and_nothing_is_signed(script: list[dict[str, Any]]) -> None:
    signer = RecordingSigner()
    assert declined(run(Seller(script).link(), lambda c: approve_and_agree(signer, c)), "agreement-failed")
    assert signer.requests == []


def test_a_paid_402_rechallenge_fails_after_one_signature() -> None:
    signer = RecordingSigner()
    script = [{"status": 402, "paymentRequired": "required"}, {"status": 402, "paymentRequired": "required"}]
    assert declined(run(Seller(script).link(), lambda c: approve_and_agree(signer, c)), "agreement-failed")
    assert len(signer.requests) == 1


def test_a_signer_on_no_offered_chain_has_no_payable_option() -> None:
    signer = RecordingSigner(account="eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
    script = [{"status": 402, "paymentRequired": "required"}]
    assert declined(run(Seller(script).link(), lambda c: approve_and_agree(signer, c)), "no-payable-option")
    assert signer.requests == []


def test_an_agreement_url_that_never_answers_fails_at_the_request_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_agreement, "UNPAID_DEADLINE_S", 0.05)

    async def never(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    def handler(request: httpx.Request) -> Awaitable[httpx.Response]:
        return never(request)

    out = run(Link(handler), lambda c: approve_and_agree(RecordingSigner(), c))
    assert declined(out, "agreement-failed")


# Once the agreement payment is sent, no decline is bare: a 5xx to the paid request is read as a
# timeout, so the same payment is sent again until the exchange bound, which ends agreement-pending with the payment
# kept as moved; any other answer that is not a receipt naming H is agreement-failed with the payment kept as moved.
def _kept_as_moved(out: object, seller: Seller) -> None:
    assert isinstance(out, Declined) and out.moved is not None
    assert json.loads(base64.b64decode(seller.paid()[0])) == out.moved.signed
    assert out.moved.atr_bytes == A
    assert out.moved.h == HASH_A


@pytest.mark.parametrize("status", [504, 500])
def test_a_5xx_to_the_paid_request_is_sent_again_then_agreement_pending_with_moved(status: int, clock: Clock) -> None:
    seller = Seller([{"status": 402, "paymentRequired": "required"}, {"status": status, "repeats": True}])
    signer = RecordingSigner()
    start = clock.now
    out = run(seller.link(), lambda c: approve_and_agree(signer, c))
    assert declined(out, "agreement-pending")
    assert clock.now - start == EXCHANGE_S
    assert len(signer.requests) == 1
    assert len(seller.paid()) > 1 and len(set(seller.paid())) == 1
    _kept_as_moved(out, seller)


@pytest.mark.parametrize(
    "answer",
    [
        {"status": 402, "paymentRequired": "required"},
        {"status": 404},
        {"status": 200, "raw": "not json"},
        {"status": 200, "raw": json.dumps({**AG["receipt"], "atrHash": "0x" + "11" * 32})},
        {"status": 200, "raw": "x" * 65_537},
    ],
    ids=["a paid 402", "a paid 404", "a 200 not JSON", "a 200 naming another hash", "a 200 over 64 KiB"],
)
def test_any_other_answer_to_the_paid_request_is_agreement_failed_with_moved(answer: dict[str, Any]) -> None:
    seller = Seller([{"status": 402, "paymentRequired": "required"}, answer])
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: approve_and_agree(signer, c))
    assert declined(out, "agreement-failed")
    assert len(signer.requests) == 1
    assert len(seller.paid()) == 1
    _kept_as_moved(out, seller)


# The one JSON nesting cap for binding reads, 64 levels of arrays and objects (core-vectors.json jsonDepth.max): a
# PAYMENT-REQUIRED or a receipt nested deeper is not read.
def test_the_agreement_reads_its_json_within_the_nesting_cap() -> None:
    cap = load("core-vectors.json")["jsonDepth"]["max"]

    def nested(depth: int) -> str:
        inner = depth - 1
        return "[" * inner + "{}" + "]" * inner

    from integraledger_terms._agreement import _from_base64_json

    within = base64.b64encode(nested(cap).encode()).decode()
    past = base64.b64encode(nested(cap + 1).encode()).decode()
    assert _from_base64_json(within) is not None
    assert _from_base64_json(past) is None


# A facilitator's settle failure after the agreement payment is sent, as the agreement URL relays it (x402 §9's
# unexpected_settle_error; SettleResponse {success, errorReason, payer, transaction, network}; a failed settle is
# answered 402 with PAYMENT-REQUIRED carrying error). After the payment is sent, a 5xx is read as a timeout and ends agreement-pending with
# moved; a 402, or a 200 whose body is not a receipt naming H, is agreement-failed with moved.
_SETTLE_ERROR = {
    "success": False,
    "errorReason": "unexpected_settle_error",
    "payer": ACCOUNT,
    "transaction": "",
    "network": AG["option"]["network"],
}


@dataclass
class Relaying(Seller):
    """The unpaid request answers the agreement challenge; every paid request answers `status` with the settle error."""

    status: int = 402
    rechallenge: bool = False

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if str(request.url) == LINK_A:
            return httpx.Response(200, content=A)
        if "payment-signature" not in request.headers:
            return httpx.Response(402, headers={"payment-required": b64(AG["required"])})
        headers = {"content-type": "application/json", "payment-response": b64(_SETTLE_ERROR)}
        if self.rechallenge:
            headers["payment-required"] = b64({**AG["required"], "error": "unexpected_settle_error"})
        return httpx.Response(self.status, headers=headers, content=json.dumps(_SETTLE_ERROR).encode("utf-8"))


@pytest.mark.parametrize(
    ("status", "rechallenge", "expected"),
    [(402, True, "agreement-failed"), (502, False, "agreement-pending"), (200, False, "agreement-failed")],
    ids=["a 402 re-challenge whose error is unexpected_settle_error", "a 502 whose body is the settle error", "a 200 whose body is the settle error, naming no receipt"],
)
def test_a_relayed_settle_failure_declines_with_the_sent_payment_kept_as_moved(status: int, rechallenge: bool, expected: str) -> None:
    seller = Relaying([], status=status, rechallenge=rechallenge)
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: approve_and_agree(signer, c))
    assert declined(out, expected)
    assert len(signer.requests) == 1
    assert len(set(seller.paid())) == 1
    _kept_as_moved(out, seller)


def test_through_transact_the_402_settle_failure_declines_agreement_failed_with_moved() -> None:
    seller = Relaying([], status=402, rechallenge=True)
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: approve_and_transact(D, with_agreement(URL), signer, c))
    assert declined(out, "agreement-failed")
    assert len(signer.requests) == 1
    _kept_as_moved(out, seller)


# The agreement payment is a payment the buyer's agent approves like any other. The first call fetches the agreement
# URL's challenge and returns the payment it would make, signing nothing; only a second call carrying that payment back
# signs it. The option paid is chosen with the main payment's rule: the challenge's options in document order, the first
# the signer can pay whose pairing's payment is itself a public proof. The exchange is bounded by that option's
# maxTimeoutSeconds, a JSON number with an integral value, plus 180 s. Options are the vector files': buyer.json's
# agreement option, x402-exact-solana.json's option and x402-exact-eip155-erc7710.json's option.

SOLANA_OPTION: dict[str, Any] = load("x402-exact-solana.json")["fixed"]["option"]
ERC7710_OPTION: dict[str, Any] = load("x402-exact-eip155-erc7710.json")["fixed"]["option"]
OPTION: dict[str, Any] = AG["option"]
RECORDED = [{"status": 200, "body": "receipt"}]
PENDING = [{"status": 202, "retryAfter": "2", "repeats": True}]


@dataclass
class Challenging(Seller):
    """A seller whose unpaid agreement answer is 402 with header as PAYMENT-REQUIRED, then plays the script."""

    header: str = ""

    def handle(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) != LINK_A and "payment-signature" not in request.headers:
            self.requests.append(request)
            return httpx.Response(402, headers={"payment-required": self.header})
        return Seller.handle(self, request)


def with_accepts(accepts: list[Any]) -> str:
    return b64({**AG["required"], "accepts": accepts})


def written(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def test_transact_returns_the_agreement_payment_for_approval_and_signs_nothing() -> None:
    seller = Seller(row("BA1")["input"]["agreement"])
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: transact(D, with_agreement(URL), signer, c))
    assert out == ToApprove(approve=AgreementPayment(url=URL, option=OPTION, required=AG["required"]), atr_bytes=A, h=HASH_A)
    assert signer.requests == []
    assert seller.paid() == []
    assert len(seller.agreement_requests()) == 1


def test_agree_returns_the_agreement_payment_for_approval_and_signs_nothing() -> None:
    seller = Seller(row("BA1")["input"]["agreement"])
    signer = RecordingSigner()
    out = run(seller.link(), lambda c: agree(A, URL, signer, c))
    assert out == ToApprove(approve=AgreementPayment(url=URL, option=OPTION, required=AG["required"]), atr_bytes=A, h=HASH_A)
    assert signer.requests == [] and seller.paid() == []


def test_the_approved_payment_is_signed_as_shown() -> None:
    seller = Seller(row("BA1")["input"]["agreement"])
    signer = RecordingSigner()

    async def go(c: httpx.AsyncClient) -> Any:
        first = await agree(A, URL, signer, c)
        assert isinstance(first, ToApprove)
        return first, await agree(A, URL, signer, c, approved=first.approve)

    first, out = run(seller.link(), go)
    assert isinstance(out, Agreed) and out.receipt.atr_hash == HASH_A
    assert len(signer.requests) == 1
    typed = signer.requests[0]["typedData"]
    option = first.approve.option
    assert [typed["message"]["to"], int(typed["message"]["value"]), typed["domain"]["verifyingContract"]] == [
        option["payTo"],
        int(option["amount"]),
        option["asset"],
    ]
    assert f"eip155:{typed['domain']['chainId']}" == option["network"]
    assert typed["message"]["nonce"] == HASH_A
    assert json.loads(base64.b64decode(seller.paid()[0]))["accepted"] == option
    assert all("payment-signature" in q.headers for q in seller.agreement_requests()[1:])


def test_an_approved_payment_for_another_agreement_url_fails_with_nothing_signed_or_sent() -> None:
    seller = Seller(row("BA1")["input"]["agreement"])
    signer = RecordingSigner()
    approved = AgreementPayment(url="https://api.seller.example/agreement/other", option=OPTION, required=AG["required"])
    out = run(seller.link(), lambda c: agree(A, URL, signer, c, approved=approved))
    assert out == Declined("agreement-failed", "The approved agreement payment names another agreement URL.")
    assert signer.requests == [] and seller.requests == []


def test_an_approved_value_that_is_not_an_agreement_payment_is_no_payable_option() -> None:
    seller = Seller([])
    out = run(seller.link(), lambda c: agree(A, URL, RecordingSigner(), c, approved={"url": URL}))  # type: ignore[arg-type]
    assert out == Declined("no-payable-option", "x402/input-malformed")
    assert seller.requests == []


def test_an_approved_payment_whose_challenge_advertises_another_hash_is_never_signed() -> None:
    seller = Seller([])
    signer = RecordingSigner()
    approved = AgreementPayment(url=URL, option=OPTION, required=AG["requiredOtherHash"])
    assert declined(run(seller.link(), lambda c: agree(A, URL, signer, c, approved=approved)), "hash-mismatch")
    assert signer.requests == [] and seller.requests == []


def test_accepts_solana_then_evm_with_an_evm_signer_approves_and_pays_the_evm_option() -> None:
    seller = Challenging(RECORDED, header=with_accepts([SOLANA_OPTION, OPTION]))
    signer = RecordingSigner()

    async def go(c: httpx.AsyncClient) -> Any:
        first = await agree(A, URL, signer, c)
        assert isinstance(first, ToApprove) and first.approve.option == OPTION
        return await agree(A, URL, signer, c, approved=first.approve)

    out = run(seller.link(), go)
    assert isinstance(out, Agreed)
    assert [int(q["typedData"]["message"]["value"]) for q in signer.requests] == [1]


@pytest.mark.parametrize(
    "first_option",
    [pytest.param(ERC7710_OPTION, id="a pairing with no public proof"), pytest.param({**OPTION, "network": "eip155:1"}, id="another chain")],
)
def test_an_option_the_rule_passes_over_leaves_the_next_one_to_approve(first_option: dict[str, Any]) -> None:
    seller = Challenging(RECORDED, header=with_accepts([first_option, OPTION]))
    out = run(seller.link(), lambda c: agree(A, URL, RecordingSigner(), c))
    assert isinstance(out, ToApprove) and out.approve.option == OPTION


def test_no_option_the_signer_can_pay_with_a_public_proof_pairing_is_no_payable_option() -> None:
    seller = Challenging(RECORDED, header=with_accepts([SOLANA_OPTION, ERC7710_OPTION]))
    signer = RecordingSigner()
    assert declined(run(seller.link(), lambda c: agree(A, URL, signer, c)), "no-payable-option")
    assert signer.requests == []


def test_the_exchange_is_bounded_by_the_chosen_options_max_timeout_seconds(clock: Clock) -> None:
    seller = Challenging(PENDING, header=with_accepts([{**SOLANA_OPTION, "maxTimeoutSeconds": 600}, OPTION]))
    start = clock.now
    out = run(seller.link(), lambda c: approve_and_agree(RecordingSigner(), c))
    assert declined(out, "agreement-pending")
    assert clock.now - start == EXCHANGE_S


def test_max_timeout_seconds_written_60_0_is_the_value_60(clock: Clock) -> None:
    text = json.dumps(AG["required"], separators=(",", ":")).replace('"maxTimeoutSeconds":60', '"maxTimeoutSeconds":60.0')
    assert '"maxTimeoutSeconds":60.0' in text
    seller = Challenging(PENDING, header=written(text))
    signer = RecordingSigner()
    start = clock.now
    out = run(seller.link(), lambda c: approve_and_agree(signer, c))
    assert declined(out, "agreement-pending")
    assert clock.now - start == EXCHANGE_S
    assert len(signer.requests) == 1


@pytest.mark.parametrize("value", ["60.5", "0", '"60"', "9007199254740992"])
def test_max_timeout_seconds_that_is_not_an_integral_number_of_seconds_is_option_malformed(value: str) -> None:
    text = json.dumps(AG["required"], separators=(",", ":")).replace('"maxTimeoutSeconds":60', f'"maxTimeoutSeconds":{value}')
    signer = RecordingSigner()
    out = run(Challenging(RECORDED, header=written(text)).link(), lambda c: agree(A, URL, signer, c))
    assert out == Declined("offer-unreadable", "x402/option-malformed")
    assert signer.requests == []


# The caller's signal, an asyncio.Event, ends the agreement exchange at its next step. Before the agreement payment is
# sent, nothing is signed or sent and the result is agreement-failed; after, the result is agreement-pending with the
# payment as moved.


def test_a_signal_already_set_fails_with_no_request() -> None:
    seller = Seller(row("BA1")["input"]["agreement"])

    async def go(c: httpx.AsyncClient) -> Any:
        signal = asyncio.Event()
        signal.set()
        return await agree(A, URL, RecordingSigner(), c, signal=signal)

    assert declined(run(seller.link(), go), "agreement-failed")
    assert seller.requests == []


def test_a_signal_set_while_the_unpaid_request_is_unanswered_fails_and_nothing_is_signed() -> None:
    signal = asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        signal.set()
        await asyncio.sleep(3600)
        return httpx.Response(500)

    signer = RecordingSigner()
    out = run(Link(handler), lambda c: agree(A, URL, signer, c, signal=signal))
    assert declined(out, "agreement-failed")
    assert signer.requests == []


def test_a_signal_set_after_the_payment_is_sent_is_agreement_pending_with_the_payment_as_moved() -> None:
    seller = Seller(row("BA3")["input"]["agreement"])
    signer = RecordingSigner()
    signal = asyncio.Event()

    def aborting(request: httpx.Request) -> httpx.Response:
        answer = seller.handle(request)
        if len(seller.paid()) == 2:
            signal.set()
        return answer

    async def go(c: httpx.AsyncClient) -> Any:
        first = await agree(A, URL, signer, c)
        assert isinstance(first, ToApprove)
        return await agree(A, URL, signer, c, approved=first.approve, signal=signal)

    out = run(Link(aborting), go)
    assert declined(out, "agreement-pending")
    assert len(seller.paid()) == 2 and len(signer.requests) == 1
    assert isinstance(out, Declined) and out.moved is not None
    assert json.loads(base64.b64decode(seller.paid()[0])) == out.moved.signed


def test_through_transact_a_set_signal_ends_the_exchange_before_the_agreement_is_signed() -> None:
    seller = Seller(row("BA1")["input"]["agreement"])
    signer = RecordingSigner()

    async def go(c: httpx.AsyncClient) -> Any:
        first = await transact(D, with_agreement(URL), signer, c)
        assert isinstance(first, ToApprove)
        signal = asyncio.Event()
        signal.set()
        return await transact(D, with_agreement(URL), signer, c, approved=first.approve, signal=signal)

    assert declined(run(seller.link(), go), "agreement-failed")
    assert signer.requests == [] and seller.paid() == []


def test_through_transact_a_signal_that_is_not_an_event_is_declined_before_any_fetch() -> None:
    seller = Seller([])
    out = run(seller.link(), lambda c: transact(D, with_agreement(URL), RecordingSigner(), c, signal=object()))  # type: ignore[arg-type]
    assert out == Declined("no-payable-option", "x402/input-malformed")
    assert seller.requests == []
