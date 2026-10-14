"""transact's options are its four keyword arguments, inputs, agreement_signer, approved and signal. An unknown keyword
raises before any fetch or signer call, as a keyword-only signature does; inputs that are not a mapping, an agreement
signer with no sign method, an approved value that is not an AgreementPayment, or a signal that is not an asyncio.Event
are declined no-payable-option with the namespace's input-malformed detail before any fetch or signer call, as the
TypeScript gate declines them. confirm and agree decline inputs that are not a mapping, and agree an approved payment
not of the agreement payment's form, the same way. The document, the ATR and the signer are buyer.json's."""

import asyncio
import base64
import json
from typing import Any

import httpx
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import AgreementPayment, Chosen, Declined, _gate, agree, check, confirm, finish, transact
from support import ACCOUNT, BUYER, NOW, A, CountingSigner, D, Link, serving

AGREEMENT = BUYER["fixed"]["agreement"]


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def run(signer: CountingSigner, **options: Any) -> tuple[Any, int]:
    link = serving(A)

    async def go() -> Any:
        async with link.client() as client:
            return await transact(D, BINDING, signer, client, **options)

    return asyncio.run(go()), link.calls


@pytest.mark.parametrize("keyword", ["recentBlockhash", "extra", "agreementSigner", "options"])
def test_an_unknown_keyword_raises_before_any_fetch_or_signer_call(keyword: str) -> None:
    signer = CountingSigner()
    with pytest.raises(TypeError):
        run(signer, **{keyword: {}})
    assert signer.requests == []


def test_inputs_given_positionally_raise() -> None:
    link = serving(A)
    signer = CountingSigner()

    async def go() -> Any:
        async with link.client() as client:
            return await transact(D, BINDING, signer, client, {"recentBlockhash": "1" * 32})  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        asyncio.run(go())
    assert (link.calls, signer.requests) == (0, [])


@pytest.mark.parametrize(
    "options",
    [
        {"inputs": "recentBlockhash"},
        {"inputs": ["recentBlockhash"]},
        {"agreement_signer": {"account": ACCOUNT}},
        {"approved": {"url": "https://api.seller.example/agreement"}},
        {"signal": object()},
    ],
)
def test_malformed_members_are_declined_before_any_fetch_or_signer_call(options: dict[str, Any]) -> None:
    signer = CountingSigner()
    out, calls = run(signer, **options)
    assert isinstance(out, Declined)
    assert (out.code, out.detail) == ("no-payable-option", "x402/input-malformed")
    assert (calls, signer.requests) == (0, [])


@pytest.mark.parametrize(
    "options",
    [{}, {"inputs": {}}, {"inputs": None, "agreement_signer": None, "approved": None, "signal": None}],
)
def test_the_members_as_given_pay(options: dict[str, Any]) -> None:
    signer = CountingSigner()
    out, _ = run(signer, **options)
    assert not isinstance(out, Declined) or out.code != "no-payable-option"
    assert len(signer.requests) == 1


@pytest.mark.parametrize("inputs", ["x", 5, []], ids=["a string", "a number", "a list"])
def test_confirm_and_agree_decline_inputs_that_are_not_a_mapping(inputs: Any) -> None:
    # buyer.json's B20 (confirm) and BA16 (agree): no-payable-option with x402/input-malformed, 0 fetches and 0 signer
    # calls, as transact declines them.
    link = serving(A)
    signer = CountingSigner()

    async def go() -> tuple[Any, Any]:
        async with link.client() as client:
            confirmed = await confirm(D, BINDING, ACCOUNT, client, inputs)
            agreed = await agree(A, AGREEMENT["url"], signer, client, inputs=inputs)
            return confirmed, agreed

    for out in asyncio.run(go()):
        assert out == Declined("no-payable-option", "x402/input-malformed")
    assert (link.calls, signer.requests) == (0, [])


def test_agree_declines_an_approved_payment_whose_url_is_not_a_string() -> None:
    # The TypeScript gate's isAgreementPayment: an approved payment holds a string url, an object option and an object
    # required, or it is declined no-payable-option with x402/input-malformed before any fetch or signer call.
    link = serving(A)
    signer = CountingSigner()
    approved = AgreementPayment(url=5, option=AGREEMENT["option"], required=AGREEMENT["required"])  # type: ignore[arg-type]

    async def go() -> Any:
        async with link.client() as client:
            return await agree(A, AGREEMENT["url"], signer, client, approved=approved)

    assert asyncio.run(go()) == Declined("no-payable-option", "x402/input-malformed")
    assert (link.calls, signer.requests) == (0, [])


class NoAccount:
    """A signer with no account."""

    def __init__(self) -> None:
        self.requests: list[Any] = []

    async def sign(self, request: Any) -> str:
        self.requests.append(request)
        return "0x" + "11" * 65


def test_a_signer_with_no_account_pays_no_option() -> None:
    # The TypeScript gate reads the account of such a signer as undefined, which no x402 option's payer can be: transact
    # and agree decline no-payable-option with x402/no-payable-option, and nothing is signed.
    header = base64.b64encode(json.dumps(AGREEMENT["required"]).encode("utf-8")).decode("ascii")
    link = Link(lambda request: httpx.Response(402, headers={"payment-required": header}))
    signer = NoAccount()

    async def go() -> tuple[Any, Any]:
        async with link.client() as client:
            transacted = await transact(D, BINDING, signer, client)  # type: ignore[arg-type]
            agreed = await agree(A, AGREEMENT["url"], signer, client)  # type: ignore[arg-type]
            return transacted, agreed

    for out in asyncio.run(go()):
        assert out == Declined("no-payable-option", "x402/no-payable-option")
    assert (link.calls, signer.requests) == (1, [])


def test_an_atr_that_is_not_bytes_raises_type_error() -> None:
    # hashlib refuses a str with TypeError, as @integraledger/lcp's hash rejects a value that is not a Uint8Array: finish,
    # check and agree raise it, and nothing is fetched or signed.
    link = serving(A)
    signer = CountingSigner()
    chosen = Chosen(pairing=BINDING.id, choice={}, ref="r")
    with pytest.raises(TypeError):
        finish("abc", chosen, None, BINDING)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        check("abc", {}, BINDING)  # type: ignore[arg-type]

    async def go() -> Any:
        async with link.client() as client:
            return await agree("abc", AGREEMENT["url"], signer, client)  # type: ignore[arg-type]

    with pytest.raises(TypeError):
        asyncio.run(go())
    assert (link.calls, signer.requests) == (0, [])
