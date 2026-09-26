"""B18, and what a seller serves never raises: the gate's rows beyond B1-B17, as the TypeScript gate's tests run
them."""

import asyncio
import copy
from typing import Any

import httpx
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import (
    Chosen,
    Confirmed,
    Declined,
    Transacted,
    _gate,
    check,
    confirm,
    finish,
    transact,
)

from support import A, ACCOUNT, NOW, O, CountingSigner, EthAccountSigner, Link, document, row, serving


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def run(go: Any, link: Link) -> Any:
    async def main() -> Any:
        async with link.client() as client:
            return await go(client)

    return asyncio.run(main())


def code(result: Any) -> str | None:
    return result.code if isinstance(result, Declined) else None


B18 = row("B18")


@pytest.mark.parametrize("case", B18["input"]["cases"], ids=[c["case"] for c in B18["input"]["cases"]])
def test_b18_a_payment_identifier_that_cannot_take_an_id(case: dict[str, Any]) -> None:
    doc = document(extensions={"payment-identifier": case["extension"]})
    signer = CountingSigner()
    out = run(lambda c: transact(doc, BINDING, signer, c), serving(A))
    expect = B18["expect"]
    assert out == Declined(expect["decline"], expect["detail"])
    assert len(signer.requests) == expect["signCalls"]


def junk() -> list[tuple[str, Any]]:
    d = document()
    no_extensions = {k: v for k, v in d.items() if k != "extensions"}
    no_extra = {k: v for k, v in O.items() if k != "extra"}
    return [
        ("null", None),
        ("a string", "402"),
        ("an array", [d]),
        ("version 1", {**d, "x402Version": 1}),
        ("no extensions", no_extensions),
        ("accepts not an array", {**d, "accepts": {}}),
        ("an amount of 100 digits", {**d, "accepts": [{**O, "amount": "9" * 100}]}),
        ("an option with no extra", {**d, "accepts": [no_extra]}),
    ]


@pytest.mark.parametrize(("name", "doc"), junk(), ids=[name for name, _ in junk()])
def test_what_a_seller_serves_is_a_decline_value(name: str, doc: Any) -> None:
    signer = CountingSigner()
    out = run(lambda c: transact(doc, BINDING, signer, c), serving(A))
    assert isinstance(out, Declined)
    assert signer.requests == []


def test_a_transport_that_raises_or_serves_text_chunks_is_unfetchable() -> None:
    def raising(request: httpx.Request) -> httpx.Response:
        raise RuntimeError("sync")

    assert code(run(lambda c: confirm(document(), BINDING, ACCOUNT, c), Link(raising))) == "atr-unfetchable"

    class Text(httpx.AsyncByteStream):
        async def __aiter__(self) -> Any:
            yield "text"

    odd = Link(lambda request: httpx.Response(200, stream=Text()))
    assert code(run(lambda c: confirm(document(), BINDING, ACCOUNT, c), odd)) == "atr-unfetchable"


def test_finish_and_check_decline_what_they_cannot_bind() -> None:
    whole = run(lambda c: transact(document(), BINDING, EthAccountSigner(), c), serving(A))
    assert isinstance(whole, Transacted) and whole.signed is not None
    assert code(check(A, None, BINDING)) == "signed-not-bound"
    assert code(check(A, {**whole.signed, "x402Version": 1}, BINDING)) == "signed-not-bound"
    assert code(check(b"\0" * 1_048_577, whole.signed, BINDING)) == "atr-too-large"
    assert code(finish(b"\0" * 1_048_577, Chosen("x", {}, "r"), "0x", BINDING)) == "atr-too-large"
    assert code(finish(A, None, "0x", BINDING)) == "offer-unreadable"  # type: ignore[arg-type]
    confirmed = run(lambda c: confirm(document(), BINDING, ACCOUNT, c), serving(A))
    assert isinstance(confirmed, Confirmed)
    assert code(finish(A, confirmed.chosen, "0x1234", BINDING)) == "signed-not-bound"


def test_finish_declines_a_chosen_payment_for_another_pairing() -> None:
    confirmed = run(lambda c: confirm(document(), BINDING, ACCOUNT, c), serving(A))
    assert isinstance(confirmed, Confirmed)
    other = Chosen("x402/exact/eip155/permit2", copy.deepcopy(confirmed.chosen.choice), confirmed.chosen.ref)
    assert code(finish(A, other, "0x" + "11" * 65, BINDING)) == "pairing-not-supported"
