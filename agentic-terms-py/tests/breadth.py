"""What the breadth rows share, as the TypeScript gate's tests do: the ATR bytes the vectors hash, the seller's link, a
fetch stub, a recording signer, the x402 document a pairing's advertise places, and the two rows every pairing adds: B2
(the plant) and B6 (build and sign). The vectors' ATR is lcp's stand-in abc, which the gate declines at its parse: B6
builds and signs by the pairing's own steps over it, and pays through the gate over buyer.json's fixed.A."""

import asyncio
import copy
import dataclasses
import hashlib
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

import integraledger_terms as _terms
from integraledger_terms import _gate
from integraledger_terms._types import coverage_of
from integraledger_terms import (
    Advertised,
    AgreementReceipt,
    Binding,
    Checked,
    Confirmed,
    Declined,
    Finished,
    Json,
    Transacted,
    check,
)
from support import confirm, transact

from support import (
    AGREEMENT_BASE,
    HASH_A,
    RESOURCE_REQUEST,
    STAND_IN,
    A,
    Link,
    approve_all,
    load,
    piece_confirm,
    receipt_for,
    serving,
    summary_pending,
)

# "abc", whose SHA-256 is the vectors' H (FIPS 180-2 B.1); "abd", one byte changed, for the plant.
ABC = STAND_IN
ABD = b"abd"
H = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
# The vectors' link for H, a random token's path; the agreement URL, a random token's path too.
LINK: str = load("mpp-challenge.json")["fixed"]["link"]
AGREEMENT_URL = AGREEMENT_BASE + str(uuid.uuid4())
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
    # The same document as the pairing's advertise places it for another hash: given, B6 also pays the pairing through
    # the gate over A, its document placed for A's hash (through_gate).
    placed: Callable[[str], Any] | None = None
    # The ceilings the payment through the gate is given, where the profile asks the caller to raise one.
    ceilings: Mapping[str, Any] | None = None


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
    if coverage_of(binding) == "full":
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


def through_gate(p: Pairing, count: int) -> None:
    """The pairing paid through the gate over A, its document placed for A's hash: where SUMMARY_PENDING lists the
    pairing under the kind of its request, declined summary-missing with no signer call; otherwise signed count
    times, returning A with, for a pairing at coverage none, the agreement's receipt for A's hash, and a payment check
    reads that hash from."""
    assert p.placed is not None
    doc = p.placed(HASH_A)
    signer = Recording(p.account, p.answer)
    out = run(
        lambda c: _terms.transact(
            doc, offered(p.binding), signer, c, approver=approve_all, resource_request=RESOURCE_REQUEST,
            inputs=p.inputs, ceilings=p.ceilings,
        ),
        serving(A),
    )  # fmt: skip
    if summary_pending(out):
        assert signer.requests == []
        return
    assert isinstance(out, Transacted), out
    assert len(signer.requests) == count
    assert out.atr_bytes == A and out.h == HASH_A
    assert out.agreement == (None if coverage_of(p.binding) == "full" else receipt(HASH_A))
    if out.signed is not None:
        assert check(A, out.signed, p.binding, out.landed) == Checked(h=HASH_A)


# THE PIECE-ONLY SET: the pairings a B6 test pays by the pairing's own steps alone, over abc, with no document placed for
# A's hash to pay them through the gate (Pairing.placed), each with why it has no gate-level run here. build_and_sign and
# confirms_only assert that a pairing they cannot place is listed, so none is skipped unseen; whoever places one removes
# it.
_NO_RUN = "not placed for A: no gate-level run yet"
PIECE_ONLY: Mapping[str, str] = {
    "ack/payment-request": "K2's Payment Request token is signed with the id of H(abc), which the read holds the legal context to",
    "card/mastercard-vi/autonomous": "C7's agent chain is signed over the checkout mandate for H(abc); none is published for another H",
    "card/mastercard-vi/immediate": "C6's user credential is signed over the checkout mandate for H(abc); none is published for another H",
    "card/seller-reference": _NO_RUN,
    "card/visa-tap": "C2's TAP answer signs a nonce built for H(abc); no answer signed for another H is published",
    "mpp/charge/card": _NO_RUN,
    "mpp/charge/evm/authorization": _NO_RUN,
    "mpp/charge/evm/permit2": _NO_RUN,
    "mpp/charge/lcp/hedera": _NO_RUN,
    "mpp/charge/lightning": "L3's invoice commits to H(abc), and the protocol package refuses to place it again for another H",
    "mpp/charge/nearintents": _NO_RUN,
    "mpp/charge/solana": _NO_RUN,
    "mpp/charge/solana/unsponsored": "no Python summary of solana-message yet; paid through the gate in TypeScript",
    "mpp/charge/stripe": _NO_RUN,
    "mpp/charge/usdc/evm": _NO_RUN,
    "mpp/charge/usdc/gateway": _NO_RUN,
    "mpp/charge/usdc/solana": _NO_RUN,
    "mpp/charge/usdc/stacks": _NO_RUN,
    "mpp/charge/xrpl": _NO_RUN,
    "mpp/subscription/solana": "nothing to sign: its confirm-only gate path over A runs in test_solcharge.py",
    "mpp/session/evm": _NO_RUN,
    "mpp/session/lightning": "the deposit invoice commits to H(abc), and the protocol package refuses to place it again for another H",
    "mpp/session/tempo": _NO_RUN,
    "mpp/session/xrpl": _NO_RUN,
    "mpp/subscription/stripe": _NO_RUN,
    "mpp/subscription/tempo": _NO_RUN,
    "ucp/checkout/agent-signed": "the bound rows' signed request bodies carry H(abc); none is published for another H",
    "x402/batch-settlement/eip155": _NO_RUN,
    "x402/batch-settlement/solana": _NO_RUN,
    "x402/exact/algorand": _NO_RUN,
    "x402/exact/cardano": "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H",
    "x402/exact/cardano/lock": _NO_RUN,
    "x402/exact/ccd": "D3's recorded transaction is bound to H(abc); no signer here makes one for another H",
    "x402/exact/hedera": _NO_RUN,
    "x402/exact/hedera/transfer-executor": _NO_RUN,
    "x402/exact/near": _NO_RUN,
    "x402/exact/polkadot/lcp-assets-remark": "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H",
    "x402/exact/solana": _NO_RUN,
    "x402/exact/starknet": "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H",
    "x402/exact/stellar/precondition": "no Python summary of stellar-precondition yet; paid through the gate in TypeScript",
    "x402/exact/sui": "the vectors' recorded payment is bound to H(abc); no signer here makes one for another H",
    "x402/exact/tron/lcp-trc20-memo": _NO_RUN,
    "x402/exact/tvm": _NO_RUN,
    "x402/exact/xrpl": _NO_RUN,
    "x402/upto/solana": _NO_RUN,
}


def build_and_sign(p: Pairing, inspect: Callable[[Any], None]) -> tuple[dict[str, Any], Any]:
    """B6, by the pairing's own steps with no gate: the build with the vectors' H gives the request, which inspect
    checks against the vectors; the test signer's answers complete a payment whose bound hash is H, the signer called
    once per step; check confirms that payment against abc and declines it against abd. Where the pairing gives placed,
    it is then paid through the gate over A (through_gate); where it gives none, PIECE_ONLY lists it. Returns the
    payment and the request."""
    confirmed = piece_confirm(p.doc, offered(p.binding), p.account, p.inputs)
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.h == H
    assert confirmed.request is not None, "nothing to sign"
    inspect(confirmed.request)

    signer = Recording(p.account, p.answer)
    done = asyncio.run(_gate.pay(p.binding, copy.deepcopy(confirmed.chosen), signer, ABC))
    assert isinstance(done, Finished), done
    assert done.h == H
    assert signer.requests[0] == confirmed.request

    # What the buyer holds to confirm later: the payment, with the landed receipt beside it, if any.
    assert check(ABC, done.signed, p.binding, done.landed) == Checked(h=H)
    assert code(check(ABD, done.signed, p.binding, done.landed)) == "signed-not-bound"
    if p.placed is not None:
        through_gate(p, len(signer.requests))
    else:
        assert p.binding.id in PIECE_ONLY, f"{p.binding.id} is paid by its own steps alone and PIECE_ONLY does not list it"
    return done.signed, confirmed.request


def confirms_only(p: Pairing) -> Confirmed:
    """B6 for a pairing with nothing for the buyer to sign, by its own steps with no gate: the build with the vectors' H
    gives request None, and the payment gives nothing signed without calling the signer. Where the pairing gives
    placed, it is then paid through the gate over A (through_gate); where it gives none, PIECE_ONLY lists it."""
    confirmed = piece_confirm(p.doc, offered(p.binding), p.account, p.inputs)
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.h == H and confirmed.request is None
    signer = Recording(p.account, p.answer)
    assert asyncio.run(_gate.pay(p.binding, confirmed.chosen, signer, ABC)) is None
    assert signer.requests == []
    if p.placed is not None:
        through_gate(p, 0)
    else:
        assert p.binding.id in PIECE_ONLY, f"{p.binding.id} is paid by its own steps alone and PIECE_ONLY does not list it"
    return confirmed


def link_calls(p: Pairing, account: str, doc: Any = None) -> tuple[Any, int]:
    """confirm with the given account (and document), and how many times the link was fetched."""
    link = serving(ABC)
    out = run(lambda c: confirm(p.doc if doc is None else doc, p.binding, account, c, p.inputs), link)
    return out, link.calls


def never(request: Any) -> Any:
    raise AssertionError("the signer was called")
