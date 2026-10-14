"""transact's options are its four keyword arguments, inputs, agreement_signer, approved and signal. An unknown keyword
raises before any fetch or signer call, as a keyword-only signature does; inputs that are not a mapping, an agreement
signer with no sign method, an approved value that is not an AgreementPayment, or a signal that is not an asyncio.Event
are declined no-payable-option with the namespace's input-malformed detail before any fetch or signer call, as the
TypeScript gate declines them. confirm and agree decline inputs that are not a mapping, and agree an approved payment
not of the agreement payment's form, the same way; transact and agree decline a signer, and transact an agreement
signer, whose account is not a string the same way. The document, the ATR and the signer are buyer.json's."""

import asyncio
import base64
import json
import re
from typing import Any

import httpx
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms._core import atr_hash
from integraledger_terms import AgreementPayment, Chosen, Declined, _gate, agree, check, confirm, finish, transact
from support import ACCOUNT, BUYER, NOW, A, CountingSigner, D, Link, serving

AGREEMENT = BUYER["fixed"]["agreement"]


class OddAccount:
    """A signer with no account, or with an account that is not a string."""

    def __init__(self, **account: Any) -> None:
        self.__dict__.update(account)
        self.requests: list[Any] = []

    async def sign(self, request: Any) -> str:
        self.requests.append(request)
        return "0x" + "11" * 65


ODD_ACCOUNTS = [{}, {"account": 7}, {"account": None}]
ODD_ACCOUNT_IDS = ["no account", "an account that is a number", "an account that is None"]


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
        {"agreement_signer": OddAccount()},
        {"agreement_signer": OddAccount(account=7)},
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


@pytest.mark.parametrize("account", ODD_ACCOUNTS, ids=ODD_ACCOUNT_IDS)
def test_a_signer_whose_account_is_not_a_string_is_declined_before_any_fetch_or_signer_call(
    account: dict[str, Any],
) -> None:
    # As the TypeScript gate declines it: transact and agree answer no-payable-option with x402/input-malformed before
    # any fetch or signer call. The agreement URL would answer 402 with its payment request.
    header = base64.b64encode(json.dumps(AGREEMENT["required"]).encode("utf-8")).decode("ascii")
    link = Link(lambda request: httpx.Response(402, headers={"payment-required": header}))
    signer = OddAccount(**account)

    async def go() -> tuple[Any, Any]:
        async with link.client() as client:
            transacted = await transact(D, BINDING, signer, client)  # type: ignore[arg-type]
            agreed = await agree(A, AGREEMENT["url"], signer, client)  # type: ignore[arg-type]
            return transacted, agreed

    for out in asyncio.run(go()):
        assert out == Declined("no-payable-option", "x402/input-malformed")
    assert (link.calls, signer.requests) == (0, [])


@pytest.mark.parametrize("atr", ["abc", [0x61, 0x62, 0x63], {"length": 3}], ids=["a str", "a list of byte values", "a dict"])
def test_an_atr_that_is_not_bytes_raises_type_error(atr: Any) -> None:
    # hashlib refuses a value that is not bytes with TypeError, as @integraledger/lcp's hash rejects a value that is not
    # a Uint8Array: finish, check, pay and agree raise the hash's own TypeError, with no check of the gate's own, and
    # nothing is fetched or signed. A caller's ATR of another type is a programming error, never a decline.
    with pytest.raises(TypeError) as expected:
        atr_hash(atr)
    link = serving(A)
    signer = CountingSigner()
    chosen = Chosen(pairing=BINDING.id, choice={}, ref="r")
    with pytest.raises(TypeError, match=re.escape(str(expected.value))):
        finish(atr, chosen, None, BINDING)
    with pytest.raises(TypeError, match=re.escape(str(expected.value))):
        check(atr, {}, BINDING)

    async def go(paying: bool) -> Any:
        async with link.client() as client:
            if paying:
                return await _gate.pay(BINDING, chosen, signer, atr)
            return await agree(atr, AGREEMENT["url"], signer, client)

    for paying in (True, False):
        with pytest.raises(TypeError, match=re.escape(str(expected.value))):
            asyncio.run(go(paying))
    assert (link.calls, signer.requests) == (0, [])


def test_agree_declines_a_signal_that_is_not_an_event_and_raises_on_an_unknown_keyword() -> None:
    # agree's options are its three keyword arguments, approved, inputs and signal. A signal that is not an
    # asyncio.Event is declined no-payable-option with x402/input-malformed, as the TypeScript gate declines a signal that
    # is not an AbortSignal; an unknown keyword raises TypeError, as a keyword-only signature does, where the TypeScript
    # gate declines an unknown key the same way. Neither fetches or signs.
    header = base64.b64encode(json.dumps(AGREEMENT["required"]).encode("utf-8")).decode("ascii")
    link = Link(lambda request: httpx.Response(402, headers={"payment-required": header}))
    signer = CountingSigner()

    async def go(**options: Any) -> Any:
        async with link.client() as client:
            return await agree(A, AGREEMENT["url"], signer, client, **options)

    for signal in (object(), "stop", asyncio.Lock()):
        assert asyncio.run(go(signal=signal)) == Declined("no-payable-option", "x402/input-malformed")
    with pytest.raises(TypeError):
        asyncio.run(go(agreement_signer=signer))
    assert (link.calls, signer.requests) == (0, [])
    assert not isinstance(asyncio.run(go(signal=asyncio.Event())), Declined)
    assert (link.calls, signer.requests) == (1, [])
