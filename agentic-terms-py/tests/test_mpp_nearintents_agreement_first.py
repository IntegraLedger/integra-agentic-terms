"""mpp/charge/nearintents is confirm-only: the buyer's own wallet broadcasts the deposit and presents its transaction
hash (draft-nearintents-charge-01, section 5.2), and nothing the buyer deposits carries the ATR hash. So the gate
compares the hash, then pays the agreement the offer's agreement URL asks for and waits for its 200, and only then
answers, with nothing signed: the protocol package's record of the pairing begins "Before this payment, the buyer
signed and paid an agreement transaction carrying this ATR's hash". The deposit's own fields reach the wallet in the
challenge confirm chose, as the seller issued it: methodDetails.depositMemo, "Deposit memo required by some origin
chains (e.g., Stellar). Absent or null when not required." (draft-nearintents-charge-01, Method Details), is the
seller's value or None, and the gate adds none. The TypeScript gate's tests run the same rows
(nearintents-agreement-first.test.ts). The ATR, the agreement challenge, its receipts, BA1's agreement nonce and the
payer key are buyer.json's; the request is MPP's own example in mpp-charge-nearintents.json."""

import asyncio
import base64
import copy
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar

import httpx
import pytest

from integraledger_terms import (
    MPP_CHARGE_NEARINTENTS,
    AgreementReceipt,
    Confirmed,
    Declined,
    ToApprove,
    Transacted,
    confirm,
    transact,
)

from mpp_docs import issued, lcp_carrier, place_carrier
from support import A, ACCOUNT, BUYER, C, HASH_A, LINK_A, Link, load, row, sign_typed

N = load("mpp-charge-nearintents.json")
AG: dict[str, Any] = BUYER["fixed"]["agreement"]
AGREEMENT_NONCE: str = row("BA1")["expect"]["agreementMessage"]["nonce"]
MD: dict[str, Any] = N["fixed"]["request"]["methodDetails"]
WALLET_ACCOUNT = f"{MD['originNetwork']}:{MD['refundTo']}"

T = TypeVar("T")


def document_with(deposit_memo: str | None) -> list[dict[str, Any]]:
    """The seller's document: MPP's example request with depositMemo as given, placed for the hash of A, A's link and
    the agreement URL."""
    request = {**N["fixed"]["request"], "methodDetails": {**MD, "depositMemo": deposit_memo}}
    c = issued("nearintents", "charge", json.dumps(request, separators=(",", ":")), N["fixed"]["realm"], N["fixed"]["expires"])
    placed = place_carrier([c], HASH_A, LINK_A, c, lcp_carrier(HASH_A, "near/carrier-occupied"), AG["url"])
    assert isinstance(placed, list), placed
    return placed


def request_of(challenge: dict[str, Any]) -> Any:
    text = challenge["request"]
    return json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))


def seller(events: list[str], receipt: str, atr: bytes = A) -> Link:
    """The seller, recording each request in events: the ATR link serves atr; the agreement URL answers 402 with the
    agreement challenge when unpaid, and 200 with the named receipt once paid."""

    def handle(request: httpx.Request) -> httpx.Response:
        url, paid = str(request.url), "payment-signature" in request.headers
        events.append("atr fetched" if url == LINK_A else ("agreement paid" if paid else "agreement asked") if url == AG["url"] else url)
        if url == LINK_A:
            return httpx.Response(200, content=atr)
        if url != AG["url"]:
            return httpx.Response(404)
        if not paid:
            required = base64.b64encode(json.dumps(AG["required"]).encode("utf-8")).decode("ascii")
            return httpx.Response(402, headers={"payment-required": required})
        return httpx.Response(200, content=json.dumps(AG[receipt]).encode("utf-8"))

    return Link(handle)


@dataclass
class Wallet:
    """The buyer's wallet on the deposit's origin network: the deposit is its own, so the gate never hands it a
    request."""

    events: list[str]
    account: str = WALLET_ACCOUNT

    async def sign(self, request: Any) -> Any:
        self.events.append("wallet signed")
        raise RuntimeError("the deposit is the wallet's own")


@dataclass
class AgreementSigner:
    """The agreement signer, over buyer.json's payer key, recording each request it signs."""

    events: list[str]
    account: str = ACCOUNT
    signed: list[Any] = field(default_factory=list)

    async def sign(self, request: Any) -> str:
        self.events.append("agreement signed")
        self.signed.append(request)
        return sign_typed(request["typedData"])


def run(link: Link, go: Callable[[httpx.AsyncClient], Awaitable[T]]) -> T:
    async def main() -> T:
        async with link.client() as client:
            return await go(client)

    return asyncio.run(main())


def approve_then_transact(doc: Any, events: list[str], agreement: AgreementSigner, link: Link) -> tuple[Any, Any]:
    """transact's two calls: the agreement payment to approve, then the call with it approved, unchanged."""
    first = run(link, lambda c: transact(doc, MPP_CHARGE_NEARINTENTS, Wallet(events), c, agreement_signer=agreement))
    assert isinstance(first, ToApprove), first
    second = run(
        link,
        lambda c: transact(doc, MPP_CHARGE_NEARINTENTS, Wallet(events), c, agreement_signer=agreement, approved=first.approve),
    )
    return first, second


def test_mpp_nearintents_the_agreement_is_approved_then_paid_and_only_then_the_gate_answers() -> None:
    doc = document_with(None)
    events: list[str] = []
    agreement = AgreementSigner(events)
    first = run(seller(events, "receipt"), lambda c: transact(doc, MPP_CHARGE_NEARINTENTS, Wallet(events), c, agreement_signer=agreement))
    assert isinstance(first, ToApprove), first
    assert events == ["atr fetched", "agreement asked"]

    events.clear()
    second = run(
        seller(events, "receipt"),
        lambda c: transact(doc, MPP_CHARGE_NEARINTENTS, Wallet(events), c, agreement_signer=agreement, approved=first.approve),
    )
    assert events == ["atr fetched", "agreement signed", "agreement paid"]
    r = AG["receipt"]
    assert second == Transacted(
        signed=None,
        atr_bytes=A,
        h=HASH_A,
        agreement=AgreementReceipt(atr_hash=r["atrHash"], agreed=True, network=r["network"], transaction=r["transaction"]),
    )
    assert [s["typedData"]["message"]["nonce"] for s in agreement.signed] == [AGREEMENT_NONCE]


def test_mpp_nearintents_an_atr_that_does_not_hash_to_h_is_declined_before_the_agreement_url_is_asked() -> None:
    events: list[str] = []
    out = run(
        seller(events, "receipt", C),
        lambda c: transact(document_with(None), MPP_CHARGE_NEARINTENTS, Wallet(events), c, agreement_signer=AgreementSigner(events)),
    )
    assert isinstance(out, Declined) and out.code == "hash-mismatch", out
    assert events == ["atr fetched"]


def test_mpp_nearintents_an_agreement_receipt_for_another_hash_is_declined_and_never_answered_unsigned() -> None:
    events: list[str] = []
    _, out = approve_then_transact(document_with(None), events, AgreementSigner(events), seller(events, "receiptOtherHash"))
    assert isinstance(out, Declined) and out.code == "agreement-failed", out
    assert "wallet signed" not in events


@pytest.mark.parametrize("deposit_memo", ["4120", None], ids=["a depositMemo", "a null depositMemo"])
def test_mpp_nearintents_the_challenge_reaches_the_wallet_as_issued_and_the_gate_adds_nothing(deposit_memo: str | None) -> None:
    doc = document_with(deposit_memo)
    as_issued = copy.deepcopy(doc)
    confirmed = run(seller([], "receipt"), lambda c: confirm(doc, MPP_CHARGE_NEARINTENTS, WALLET_ACCOUNT, c))
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.request is None
    assert confirmed.chosen.choice == {"challenge": as_issued[0]}
    challenge = confirmed.chosen.choice["challenge"]
    assert challenge["request"] == as_issued[0]["request"]
    assert request_of(challenge)["methodDetails"]["depositMemo"] == deposit_memo

    events: list[str] = []
    _, second = approve_then_transact(doc, events, AgreementSigner(events), seller(events, "receipt"))
    assert isinstance(second, Transacted) and second.signed is None and second.h == HASH_A, second
    assert doc == as_issued
