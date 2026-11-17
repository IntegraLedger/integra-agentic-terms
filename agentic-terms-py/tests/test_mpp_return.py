"""The return after an agreement where the first response is MPP's, and the agreement resource's one 402 (terms' profile
buyer-gate.md, rule 12; the protocol package's legal-context-return.md, rules 1 and 6, and mpp-charge.md, rule 6): that
402 carries x402's PAYMENT-REQUIRED and one WWW-Authenticate: Payment challenge per MPP agreement option. transact pays
an x402 agreement option it finds there, and where the resource offers only MPP agreement challenges it returns them,
signing nothing. Also the return of an x402 charge whose slot option lacks the invoice its read needs
(x402/exact/lnbtc/payment-hash), and parse_challenges, the protocol package's parseChallenges, over mpp-challenge.json's
MV9. Every input is a vector row of the protocol package: the agreement challenge is legal-context-return.json's serves
row naming x402/0 and mpp/1 (mpp-challenge.json's C_E), the charge mpp-charge-evm-transaction.json's B2 challenge as
issued; the ATR, link, agreement URL, its x402 payment request, receipt and payer key are buyer.json's, the Lightning
option x402-exact-lnbtc.json's, and the x402 agreement option buyer-gate.json's row "approved"'s. The TypeScript gate's
tests run the same cases (mpp-return.test.ts)."""

import asyncio
import base64
import copy
import hashlib
import json
from typing import Any

import httpx
import pytest

import integraledger_terms as terms
from integraledger_terms import Declined, ToReturn, ToSign, _gate
from integraledger_terms.bindings._mpp import parse_challenges

from mpp_docs import place
from support import BUYER, EthAccountSigner, load
from test_buyer_gate import SERVES_X402_0, V as GV, agreement_first, resource_request, APPROVED

RET = load("legal-context-return.json")
ET = load("mpp-charge-evm-transaction.json")
LN = load("x402-exact-lnbtc.json")["fixed"]
AG: dict[str, Any] = BUYER["fixed"]["agreement"]
LINK: str = BUYER["fixed"]["link"]
NOW: int = BUYER["fixed"]["now"]
AGREEMENT: dict[str, Any] = next(r["option"] for r in RET["serves"] if "opaque" in r["option"] and "mpp/1" in (r["expect"] or []))
CHARGE: dict[str, Any] = {
    k: v for k, v in next(r for r in ET["buyer"]["rows"] if r["name"] == "B2")["input"]["doc"][0].items() if k not in ("id", "opaque")
}
TRANSACTION = terms.MPP_CHARGE_EVM_TRANSACTION


def field(c: dict[str, Any]) -> str:
    """A challenge as a WWW-Authenticate field value of the Payment scheme."""
    return "Payment " + ", ".join(f'{k}="{v}"' for k, v in c.items())


class Seller:
    """The link serves atr; the agreement URL answers its unpaid request 402 with required, x402's payment request,
    where given, and challenges as WWW-Authenticate, where given, and its paid request 200 with buyer.json's receipt
    for h."""

    def __init__(self, atr: bytes, h: str, required: Any, challenges: list[dict[str, Any]]) -> None:
        self.paid = 0

        def handle(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url == LINK:
                return httpx.Response(200, content=atr)
            if url != AG["url"]:
                return httpx.Response(404)
            if "payment-signature" in request.headers:
                self.paid += 1
                return httpx.Response(200, json={**AG["receipt"], "atrHash": h})
            headers = [("www-authenticate", field(c)) for c in challenges]
            if required is not None:
                headers.append(("payment-required", base64.b64encode(json.dumps(required).encode()).decode()))
            return httpx.Response(402, headers=headers)

        self.client = httpx.AsyncClient(transport=httpx.MockTransport(handle))


def required_for(h: str) -> dict[str, Any]:
    r: dict[str, Any] = copy.deepcopy(AG["required"])
    r["extensions"]["legalContext"]["info"]["value"] = h
    return r


def mpp_atr() -> tuple[bytes, str]:
    """buyer.json's A with an mpp slot listing the agreement challenge and the charge, as issued; and its H."""
    a = json.loads(bytes.fromhex(BUYER["fixed"]["A"]))
    atr = json.dumps({**a, "mpp": {"challenges": [AGREEMENT, CHARGE]}}, separators=(",", ":")).encode()
    return atr, "0x" + hashlib.sha256(atr).hexdigest()


def placed(doc: list[dict[str, Any]], h: str, option: dict[str, Any]) -> dict[str, Any]:
    """option, a challenge of doc, placed for h at its position in doc with buyer.json's link and agreement URL."""
    out = place(doc, h, LINK, option, AG["url"])
    assert isinstance(out, list), out
    challenge: dict[str, Any] = dict(out[doc.index(option)])
    return challenge


def run(doc: Any, seller: Seller, monkeypatch: pytest.MonkeyPatch, **options: Any) -> tuple[Any, list[tuple[str, str]], int]:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    signer = EthAccountSigner()
    asked: list[ToSign] = []

    def approver(t: ToSign) -> bool:
        asked.append(t)
        return True

    async def go() -> Any:
        async with seller.client:
            return await terms.transact(
                doc, TRANSACTION, signer, seller.client, approver=approver, resource_request=resource_request(APPROVED), **options  # type: ignore[arg-type]
            )

    out = asyncio.run(go())
    return out, [(a.act, a.pairing) for a in asked], signer.calls


def test_parse_challenges_reads_mpp_challenge_json_mv9() -> None:
    mv9 = load("mpp-challenge.json")["MV9"]
    for values in (mv9["fieldValues"], [", ".join(mv9["fieldValues"])]):
        out = parse_challenges(values)
        assert not isinstance(out, terms.Refusal) and [c["id"] for c in out] == mv9["expectIds"]


def test_an_mpp_first_response_pays_the_x402_agreement_option_at_the_agreement_url(monkeypatch: pytest.MonkeyPatch) -> None:
    atr, h = mpp_atr()
    agreement = placed([AGREEMENT], h, AGREEMENT)
    seller = Seller(atr, h, required_for(h), [agreement])
    out, asked, signed = run([agreement], seller, monkeypatch)
    assert isinstance(out, ToReturn), out
    assert (out.charge, out.legal_context, out.agreement and out.agreement.atr_hash, out.agreement_challenges) == (
        "mpp/1", "lcp:sha256:" + h, h, None
    )
    assert (asked, signed, seller.paid) == ([("agreement", "x402/exact/eip155/eip3009")], 1, 1)


def test_an_mpp_first_response_returns_mpp_agreement_challenges_signing_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    atr, h = mpp_atr()
    agreement = placed([AGREEMENT], h, AGREEMENT)
    seller = Seller(atr, h, None, [agreement])
    out, asked, signed = run([agreement], seller, monkeypatch)
    assert isinstance(out, ToReturn), out
    assert (out.charge, out.legal_context, out.agreement, out.agreement_challenges) == ("mpp/1", "lcp:sha256:" + h, None, (agreement,))
    assert (asked, signed, seller.paid) == ([], 0, 0)


# The charge, an EIP-1559 transaction, signs no end: its ceiling is raised to "no-end" (the profile's rule 8), as its
# caller must to pay it at all.
def test_an_mpp_charge_naming_the_agreement_url_returns_mpp_agreement_challenges(monkeypatch: pytest.MonkeyPatch) -> None:
    atr = bytes.fromhex(BUYER["fixed"]["A"])
    h = "0x" + hashlib.sha256(atr).hexdigest()
    charge = placed([CHARGE], h, CHARGE)
    agreement = placed([CHARGE, AGREEMENT], h, AGREEMENT)
    seller = Seller(atr, h, None, [agreement])
    out, asked, signed = run([charge], seller, monkeypatch, ceilings={TRANSACTION.id: "no-end"})
    assert isinstance(out, terms.AgreementChallenges), out
    assert (out.agreement_challenges, out.h, asked, signed, seller.paid) == ((agreement,), h, [], 0, 0)


# lcp profile x402-exact-lnbtc.md, rule 3: the ATR's x402 slot holds the option without extra.invoice, which the seller's
# node writes after the agreement, and the pairing's read serves only an option with its invoice (rule 6).
def test_an_lnbtc_charge_without_its_invoice_is_chosen_by_its_own_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: GV["fixed"]["now"])
    doc, atr = agreement_first(LN["offer"], [SERVES_X402_0])
    asked: list[ToSign] = []

    class Node:
        account = f"{LN['offer']['network']}:{LN['payee']}"
        requests: list[Any] = []

        async def sign(self, request: Any) -> str:
            self.requests.append(request)
            raise AssertionError("the node is not called before the charge is served")

    payer = EthAccountSigner(account=GV["fixed"]["account"])

    def approver(t: ToSign) -> bool:
        asked.append(t)
        return False

    async def go() -> Any:
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=atr) if str(r.url) == GV["fixed"]["link"] else httpx.Response(404)))
        async with client:
            return await terms.transact(
                doc, terms.X402_EXACT_LNBTC_PAYMENT_HASH, Node(), client, approver=approver,
                resource_request=resource_request(APPROVED), agreement_signer=payer,  # type: ignore[arg-type]
            )

    out = asyncio.run(go())
    assert isinstance(out, Declined) and out.code == "not-approved", out
    assert ([(a.act, a.pairing) for a in asked], len(Node.requests), payer.calls) == ([("agreement", "x402/exact/eip155/eip3009")], 0, 0)
