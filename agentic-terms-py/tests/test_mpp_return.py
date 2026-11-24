"""The return after an agreement where the first response is MPP's, and the agreement resource's one 402 (terms' profile
buyer-gate.md, rule 12; the protocol package's legal-context-return.md, rules 1 and 6, and mpp-charge.md, rule 6): that
402 carries x402's PAYMENT-REQUIRED and one WWW-Authenticate: Payment challenge per MPP agreement option. transact pays
an x402 agreement option it finds there, and where the resource offers only MPP agreement challenges it returns them,
signing nothing. Also the return of an x402 charge whose slot option lacks the invoice its read needs
(x402/exact/lnbtc/payment-hash), and parse_challenges, the protocol package's parseChallenges, over mpp-challenge.json's
MV9. Every input is a vector row of the protocol package: the agreement challenge is legal-context-return.json's serves
row naming x402/0 and mpp/1 (mpp-challenge.json's C_E), its opaque naming mpp/1 alone, written by that file's recipe
(base64url without padding of RFC 8785's form), since an ATR whose binding slot is mpp holds no x402/0 (lcp profile
legal-context-return.md, rule 6); the charge mpp-charge-evm-transaction.json's B2 challenge as issued; the ATR is buyer.json's A with mpp, listing the challenges, as its binding slot in place of x402; the link,
agreement URL, its x402 payment request, receipt and payer key are buyer.json's, the Lightning
option x402-exact-lnbtc.json's, and the x402 agreement option buyer-gate.json's row "approved"'s. Also a card sale
whose agreement the first response offers as an x402 option. The TypeScript gate's tests run the same cases
(mpp-return.test.ts)."""

import asyncio
import base64
import copy
import hashlib
import json
from typing import Any

import httpx
import pytest

import integraledger_terms as terms
from integraledger_terms import Declined, ToReturn, ToSign, Transacted, _gate
from integraledger_terms.bindings._mpp import parse_challenges

import ed25519
from mpp_docs import place
from support import BUYER, EthAccountSigner, load
from test_buyer_gate import SERVES_X402_0, V as GV, agreement_first, resource_request, APPROVED

RET = load("legal-context-return.json")
ET = load("mpp-charge-evm-transaction.json")
LN = load("x402-exact-lnbtc.json")["fixed"]
AG: dict[str, Any] = BUYER["fixed"]["agreement"]
LINK: str = BUYER["fixed"]["link"]
NOW: int = BUYER["fixed"]["now"]
C_E: dict[str, Any] = next(r["option"] for r in RET["serves"] if "opaque" in r["option"] and "mpp/1" in (r["expect"] or []))
_MEMBERS: dict[str, str] = json.loads(base64.urlsafe_b64decode(C_E["opaque"] + "=" * (-len(C_E["opaque"]) % 4)))
AGREEMENT: dict[str, Any] = {
    **C_E,
    "opaque": base64.urlsafe_b64encode(
        json.dumps({**_MEMBERS, "legalContextServes": "mpp/1"}, separators=(",", ":"), sort_keys=True).encode()
    )
    .rstrip(b"=")
    .decode(),
}
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


def mpp_atr(challenges: list[dict[str, Any]] | None = None) -> tuple[bytes, str]:
    """buyer.json's A with mpp as its binding slot, the member after atrVersion and id, in place of x402, listing
    challenges, as issued (the agreement challenge and the charge where none are given); and its H."""
    a = json.loads(bytes.fromhex(BUYER["fixed"]["A"]))
    rest = {k: v for k, v in a.items() if k not in ("atrVersion", "id", "x402")}
    listed = [AGREEMENT, CHARGE] if challenges is None else challenges
    atr = json.dumps({"atrVersion": a["atrVersion"], "id": a["id"], "mpp": {"challenges": listed}, **rest}, separators=(",", ":")).encode()
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


def test_parse_challenges_reads_challenges_joined_into_one_value_each_within_8192() -> None:
    """Row 8: fetch's Headers.get joins a 402's WWW-Authenticate lines into one value; the 8,192 bound is per Payment
    challenge, the value's 65,536."""
    mv9 = load("mpp-challenge.json")["MV9"]
    line = mv9["fieldValues"][0]
    lines = [line.replace(mv9["expectIds"][0], f"id-{k}") + f', description="{"d" * 600}"' for k in range(32)]
    joined = ", ".join(lines)
    assert len(joined) > 8192
    out = parse_challenges([joined])
    assert not isinstance(out, terms.Refusal) and [c["id"] for c in out] == [f"id-{k}" for k in range(32)]

    def sized(length: int) -> str:
        head = f'{lines[0]}, pad="'
        return head + "a" * (length - len(head) - 1) + '"'

    assert len(sized(8192)) == 8192
    assert len(parse_challenges([sized(8192)])) == 1  # type: ignore[arg-type]
    assert len(parse_challenges([f"{sized(8192)}, {lines[1]}"])) == 2  # type: ignore[arg-type]
    assert len(parse_challenges([f"{lines[1]},  ,{sized(8192)}"])) == 2  # type: ignore[arg-type]
    for over in ([sized(8193)], [f"{lines[1]}, {sized(8193)}"], [f"{sized(8193)}, {lines[1]}"]):
        assert parse_challenges(over) == terms.Refusal("mpp/header-malformed")
    assert parse_challenges([f"{lines[0]}, Basic {'a' * 65_536}"]) == terms.Refusal("mpp/header-malformed")


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


# lcp profile mpp-charge.md, rule 5: the ATR's mpp slot holds a Lightning charge as issued, without the invoice the
# seller's node writes after H, which the pairing's filter of a placed challenge requires. The charge is
# mpp-server-checks.json's Lightning challenge as issued, naming the network mainnet; the buyer's node is on
# x402-exact-lnbtc.json's mainnet network.
def test_an_mpp_lightning_charge_without_its_invoice_is_chosen_by_its_own_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    issued = next(r for r in load("mpp-server-checks.json")["unplaced"]["rows"] if r["case"].startswith("mpp/charge/lightning:"))["issued"]
    atr, h = mpp_atr([AGREEMENT, issued])
    agreement = placed([AGREEMENT], h, AGREEMENT)
    seller = Seller(atr, h, required_for(h), [agreement])
    asked: list[ToSign] = []

    class Node:
        account = f"{LN['offer']['network']}:{LN['payee']}"
        requests: list[Any] = []

        async def sign(self, request: Any) -> str:
            self.requests.append(request)
            raise AssertionError("the node is not called before the charge is served")

    payer = EthAccountSigner()

    def approver(t: ToSign) -> bool:
        asked.append(t)
        return True

    async def go() -> Any:
        async with seller.client:
            return await terms.transact(
                [agreement], terms.MPP_CHARGE_LIGHTNING, Node(), seller.client, approver=approver,
                resource_request=resource_request(APPROVED), agreement_signer=payer,  # type: ignore[arg-type]
            )

    out = asyncio.run(go())
    assert isinstance(out, ToReturn), out
    assert (out.charge, out.legal_context, out.agreement and out.agreement.atr_hash) == ("mpp/1", "lcp:sha256:" + h, h)
    assert ([(t.act, t.pairing) for t in asked], len(Node.requests), payer.calls, seller.paid) == (
        [("agreement", "x402/exact/eip155/eip3009")], 0, 1, 1
    )


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


# lcp profile legal-context-return.md, rule 6, and terms' profile buyer-gate.md, rule 12: the caller passes the charge's
# pairing, card/visa-tap. The ATR, the first response and its link are buyer-gate.json's row serves-card's: lcp's card
# ATR, and the x402 agreement option serving card/0 and card/2. The second response is the legal context lcp's advertise
# of the ATR's visa-tap option writes for H, with buyer.json's agreement URL. The agreement URL answers 402 before the
# agreement is paid and 200 with buyer.json's receipt after. The TAP signer signs card.json C2's sig2 base, its nonce
# the request's, under RFC 9421's test-key-ed25519 (B.1.4), here in its JWK form's d, which gives C2's sig2 over C2's
# base; TAP signs no end, so the charge's ceiling is raised to "no-end" (the profile's rule 8).
def test_a_card_sale_whose_agreement_is_an_x402_option_is_paid_through_the_return(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    row = next(r for r in GV["rows"] if r["name"] == "serves-card")
    atr = bytes.fromhex(row["atr"]["hex"])
    h = "0x" + hashlib.sha256(atr).hexdigest()
    paid = [0]

    def handle(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url == row["link"]:
            return httpx.Response(200, content=atr)
        if url != AG["url"]:
            return httpx.Response(404)
        if "payment-signature" in request.headers:
            paid[0] += 1
        if paid[0] > 0:
            return httpx.Response(200, json={**AG["receipt"], "atrHash": h})
        return httpx.Response(402, headers=[("payment-required", base64.b64encode(json.dumps(required_for(h)).encode()).decode())])

    c2 = load("card.json")["C2"]
    seed = base64.urlsafe_b64decode("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU=")

    class Tap:
        account = BUYER["fixed"]["account"]
        requests: list[Any] = []

        async def sign(self, request: Any) -> dict[str, str]:
            self.requests.append(request)
            base: str = c2["sig2Base"].replace(c2["nonce"], request["nonce"])
            params = base.split('"@signature-params": ', 1)[1]
            signature = base64.b64encode(ed25519.sign(seed, base.encode())).decode()
            return {"signatureInput": f"sig2={params}", "signature": f"sig2=:{signature}:"}

    payer = EthAccountSigner()
    asked: list[ToSign] = []

    def approver(t: ToSign) -> bool:
        asked.append(t)
        return True

    shown = {"legalContext": {"type": "sha256", "value": h, "legalContextUrl": row["link"], "legalContextAgreementUrl": AG["url"]}}

    async def go() -> tuple[Any, Any]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            first = await terms.transact(
                copy.deepcopy(row["document"]), terms.CARD_VISA_TAP, Tap(), client, approver=approver,
                resource_request=resource_request(APPROVED), agreement_signer=payer,  # type: ignore[arg-type]
            )
            if not isinstance(first, ToReturn):
                return first, None
            second = await terms.transact(
                shown, terms.CARD_VISA_TAP, Tap(), client, approver=approver, resource_request=resource_request(APPROVED),  # type: ignore[arg-type]
                legal_context=first.legal_context, ceilings={"card/visa-tap": "no-end"},
            )
            return first, second

    first, second = asyncio.run(go())
    assert isinstance(first, ToReturn), first
    assert (first.charge, first.legal_context, first.agreement and first.agreement.atr_hash) == ("card/0", "lcp:sha256:" + h, h)
    assert isinstance(second, Transacted), second
    assert second.h == h and second.agreement is not None and (second.agreement.atr_hash, second.agreement.unpaid) == (h, True)
    assert ([(a.act, a.pairing) for a in asked], payer.calls, len(Tap.requests), paid[0]) == (
        [("agreement", "x402/exact/eip155/eip3009"), ("payment", "card/visa-tap")], 1, 1, 1
    )
    assert second.signed is not None and f'nonce="{Tap.requests[0]["nonce"]}"' in second.signed["signatureInput"]
    assert terms.CARD_VISA_TAP.bound(second.signed) == h
