"""transact's options are its four keyword arguments, inputs, agreement_signer, approved and signal. An unknown keyword
raises before any fetch or signer call, as a keyword-only signature does; inputs that are not a mapping, an agreement
signer with no sign method, an approved value that is not an AgreementPayment, or a signal that is not an asyncio.Event
are declined no-payable-option with the namespace's input-malformed detail before any fetch or signer call, as the
TypeScript gate declines them. The document, the ATR and the signer are buyer.json's."""

import asyncio
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import Declined, _gate, transact
from support import ACCOUNT, NOW, A, CountingSigner, D, serving


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
