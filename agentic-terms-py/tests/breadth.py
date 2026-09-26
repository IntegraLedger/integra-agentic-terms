"""What the breadth rows share, as the TypeScript gate's tests do: the ATR bytes the vectors hash, the seller's link, a
fetch stub, a recording signer, the x402 document a pairing's advertise places, and the two rows every pairing adds: B2
(the plant) and B6 (build and sign)."""

import asyncio
import copy
import dataclasses
import hashlib
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from integraledger_terms import (
    Advertised,
    AgreementReceipt,
    Binding,
    Checked,
    Confirmed,
    Declined,
    Finished,
    Json,
    Next,
    Transacted,
    check,
    confirm,
    finish,
    transact,
)

from support import AGREEMENT_BASE, Link, load, receipt_for, serving

# "abc", whose SHA-256 is the vectors' H (FIPS 180-2 B.1); "abd", one byte changed, for the plant.
ABC = b"abc"
ABD = b"abd"
H = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
LINK = "https://atr.seller.example/" + H
AGREEMENT_URL = AGREEMENT_BASE + H
assert "0x" + hashlib.sha256(ABC).hexdigest() == H

LEGAL_CONTEXT_SCHEMA: dict[str, Any] = load("x402-exact-eip155-eip3009.json")["fixed"]["legalContextSchema"]

Answer = Callable[[Any], Any | Awaitable[Any]]


@dataclass
class Recording:
    """A signer that records what it was handed and answers with answer(request)."""

    account: str
    answer: Answer
    requests: list[Any] = field(default_factory=list)

    async def sign(self, request: Json) -> Any:
        self.requests.append(request)
        out = self.answer(request)
        if isinstance(out, Awaitable):
            return await out
        return out


@dataclass
class Pairing:
    binding: Binding
    # The seller's document as the pairing's advertise places it, advertising H and LINK.
    doc: Any
    account: str
    # The test signer's answer to the request the pairing builds.
    answer: Answer
    inputs: Mapping[str, Any] | None = None


class Offered:
    """The binding a seller's offer is read through: for a pairing whose payment is not a public proof, the offer also
    names the agreement URL, as the seller's stack places it beside the carriers."""

    def __init__(self, binding: Binding) -> None:
        self._binding = binding

    def __getattr__(self, name: str) -> Any:
        return getattr(self._binding, name)

    def read(self, doc: Any) -> Any:
        r = self._binding.read(doc)
        return dataclasses.replace(r, agreement=AGREEMENT_URL) if isinstance(r, Advertised) else r


def offered(binding: Binding) -> Binding:
    if getattr(binding, "public_proof", False) is True:
        return binding
    wrapped: Binding = Offered(binding)
    return wrapped


def receipt(h: str = H) -> AgreementReceipt:
    r = receipt_for(h)
    return AgreementReceipt(atr_hash=r["atrHash"], agreed=True, network=r["network"], transaction=r["transaction"])


def x402_doc(
    option: Mapping[str, Any],
    resource: Any,
    h: str = H,
    link: str = LINK,
    agreement: str | None = None,
    extensions: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """An x402 v2 document offering option, with extensions.legalContext naming h and link as advertise writes it."""
    info: dict[str, Any] = {"type": "sha256", "value": h, "legalContextUrl": link}
    if agreement is not None:
        info["legalContextAgreementUrl"] = agreement
    return {
        "x402Version": 2,
        "resource": copy.deepcopy(resource),
        "accepts": [copy.deepcopy(dict(option))],
        "extensions": {**(extensions or {}), "legalContext": {"info": info, "schema": copy.deepcopy(LEGAL_CONTEXT_SCHEMA)}},
    }


def run(go: Callable[[Any], Awaitable[Any]], link: Link) -> Any:
    async def main() -> Any:
        async with link.client() as client:
            return await go(client)

    return asyncio.run(main())


def code(result: Any) -> str | None:
    return result.code if isinstance(result, Declined) else None


def plant(p: Pairing) -> None:
    """B2: the link serves abd; the gate declines hash-mismatch and never calls the signer."""
    signer = Recording(p.account, p.answer)
    binding = offered(p.binding)
    out = run(lambda c: transact(p.doc, binding, signer, c, inputs=p.inputs), serving(ABD))
    assert code(out) == "hash-mismatch", out
    assert signer.requests == []
    confirmed = run(lambda c: confirm(p.doc, binding, p.account, c, p.inputs), serving(ABD))
    assert code(confirmed) == "hash-mismatch", confirmed


def answer_of(p: Pairing, request: Any) -> Any:
    out = p.answer(request)
    if isinstance(out, Awaitable):

        async def wait() -> Any:
            return await out

        return asyncio.run(wait())
    return out


def build_and_sign(p: Pairing, inspect: Callable[[Any], None]) -> tuple[dict[str, Any], Any]:
    """B6: confirm over abc gives the request the pairing builds with H, which inspect checks against the vectors;
    finish with the test signer's answer returns a payment whose bound hash is H; transact signs as many times;
    check confirms that payment against abc and declines it against abd. Returns the payment and the request."""
    binding = offered(p.binding)
    confirmed = run(lambda c: confirm(p.doc, binding, p.account, c, p.inputs), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.h == H
    assert confirmed.request is not None, "nothing to sign"
    inspect(confirmed.request)

    chosen = copy.deepcopy(confirmed.chosen)
    answers = [answer_of(p, confirmed.request)]
    done = finish(ABC, chosen, answers[0], p.binding)
    while isinstance(done, Next):
        answers.append(answer_of(p, done.next))
        done = finish(ABC, chosen, list(answers), p.binding)
    assert isinstance(done, Finished), done
    assert done.h == H

    signer = Recording(p.account, p.answer)
    whole = run(lambda c: transact(p.doc, binding, signer, c, inputs=p.inputs), serving(ABC))
    assert isinstance(whole, Transacted), whole
    assert len(signer.requests) == len(answers)
    assert whole.atr_bytes == ABC
    assert whole.agreement == (None if getattr(p.binding, "public_proof", False) is True else receipt())

    # What the buyer holds to confirm later: the payment, with the landed receipt finish returns beside it, if any.
    assert whole.landed == done.landed
    held = {**done.signed, "landed": done.landed} if done.landed is not None else done.signed
    assert check(ABC, held, p.binding) == Checked(h=H)
    assert code(check(ABD, held, p.binding)) == "signed-not-bound"
    return done.signed, confirmed.request


def confirms_only(p: Pairing) -> Confirmed:
    """B6 for a pairing with nothing for the buyer to sign: confirm gives request None, and transact gives signed
    None without calling the signer."""
    binding = offered(p.binding)
    confirmed = run(lambda c: confirm(p.doc, binding, p.account, c, p.inputs), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.h == H and confirmed.request is None
    signer = Recording(p.account, p.answer)
    whole = run(lambda c: transact(p.doc, binding, signer, c, inputs=p.inputs), serving(ABC))
    assert isinstance(whole, Transacted) and whole.signed is None and whole.h == H, whole
    assert signer.requests == []
    return confirmed


def link_calls(p: Pairing, account: str, doc: Any = None) -> tuple[Any, int]:
    """confirm with the given account (and document), and how many times the link was fetched."""
    link = serving(ABC)
    out = run(lambda c: confirm(p.doc if doc is None else doc, p.binding, account, c, p.inputs), link)
    return out, link.calls


def never(request: Any) -> Any:
    raise AssertionError("the signer was called")
