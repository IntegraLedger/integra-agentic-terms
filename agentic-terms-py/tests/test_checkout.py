"""The checkout pairings' buyer halves and pieces against @integraledger/lcp's rows for them. From
ap2-checkout-mandate-x402.json: ap2/checkout-mandate/x402's bound rows, each payment presented beside
ap2-checkout-mandate.json's mandate M and checkout JWT J, as the protocol package's own test presents it. From
ucp-checkout-agent-signed.json: ucp/checkout/agent-signed's bound and build rows. Each piece by its own steps: the
request handed to the signer is the build over the file's checkout, and the file's payment, given as the signer's
answer, completes a payment bound to the file's H; the x402 route is also paid through the gate over its file's ATR,
its approver shown the checkout's summary. AP2's push funding: a payment the payer's side already sent, with
broadcaster.json's Payment Receipt, is kept as moved when finish declines it. The summaries of the checkout requests:
summary-checkout.json's rows, which the TypeScript tests run too. Every expected value is the files'."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from breadth import Recording, offered, run, unpaid_receipt
from support import load, serving, transact

from integraledger_terms import (
    AP2_CHECKOUT_MANDATE,
    AP2_CHECKOUT_MANDATE_X402,
    UCP_CHECKOUT_AGENT_SIGNED,
    Advertised,
    Binding,
    Declined,
    Finished,
    Moved,
    Refusal,
    ToSign,
    Transacted,
    finish,
)
from integraledger_terms._core import atr_hash
from integraledger_terms._summary import summary_of
from integraledger_terms._types import Payee, Summary, Validity
from integraledger_terms.pieces import PIECES

AP2 = load("ap2-checkout-mandate.json")
X402 = load("ap2-checkout-mandate-x402.json")
AGENT = load("ucp-checkout-agent-signed.json")
RECEIPT = next(
    k for k in load("broadcaster.json")["kinds"] if k["pairing"] == "ap2/checkout-mandate" and k["expect"] == "payer"
)["presented"]["payment_receipt"]


def row(file: dict[str, Any], pairing: str, name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(r for r in file["buyer"]["rows"] if r["pairing"] == pairing and r["name"] == name)
    return found


ACCOUNT: str = row(X402, "ap2/checkout-mandate/x402", "B2")["input"]["account"]


def expected(r: dict[str, Any]) -> Any:
    return Refusal(r["expectRefusal"]) if "expectRefusal" in r else r["expect"]


@pytest.mark.parametrize("r", X402["bound"], ids=[r["case"] for r in X402["bound"]])
def test_ap2_checkout_mandate_x402_bound_rows(r: dict[str, Any]) -> None:
    presented = {"checkout_mandate": AP2["built"]["M"], "checkout_jwt": AP2["built"]["J"], "payment": r["payment"]}
    assert AP2_CHECKOUT_MANDATE_X402.bound(presented) == expected(r)


@pytest.mark.parametrize("r", AGENT["bound"], ids=[r["case"] for r in AGENT["bound"]])
def test_ucp_checkout_agent_signed_bound_rows(r: dict[str, Any]) -> None:
    assert UCP_CHECKOUT_AGENT_SIGNED.bound(copy.deepcopy(r["presented"])) == expected(r)


@pytest.mark.parametrize("r", AGENT["build"], ids=[r["case"] for r in AGENT["build"]])
def test_ucp_checkout_agent_signed_build_rows(r: dict[str, Any]) -> None:
    assert UCP_CHECKOUT_AGENT_SIGNED.build({"checkout": AGENT["fixed"]["checkout"]}, r["h"]) == expected(r)


def by_steps(binding: Binding, doc: Any, atr: bytes, answer: Any) -> tuple[Any, Any]:
    """The request the piece hands the signer for the file's checkout, built with the hash of atr, and finish over the
    answer given."""
    read = offered(binding).read(doc)
    assert isinstance(read, Advertised), read
    piece = PIECES[binding.id]
    chosen = piece.choose(read, ACCOUNT, {}, 0, "r" * 32, doc)
    assert not isinstance(chosen, Refusal), chosen
    request = piece.request(piece.build(binding, piece.choice(chosen, atr), atr_hash(atr)))
    return request, finish(atr, copy.deepcopy(chosen), answer, binding)


def test_ap2_checkout_mandate_x402_by_its_own_steps() -> None:
    b6 = row(X402, "ap2/checkout-mandate/x402", "B6")
    presented = b6["input"]["presented"]
    atr = bytes.fromhex(b6["input"]["check"][0]["bytesHex"])
    answer = {"checkout_mandate": presented["checkout_mandate"], "payment": presented["payment"]}
    request, done = by_steps(AP2_CHECKOUT_MANDATE_X402, presented["checkout_jwt"], atr, answer)
    content = {"vct": AP2["V4"]["expectVct"], "checkout_jwt": presented["checkout_jwt"], "checkout_hash": AP2["V4"]["expectCheckoutHash"]}
    assert request == {"kind": "ap2-checkout-mandate", "content": content}
    h = b6["expect"][0]["h"]
    assert done == Finished(signed=presented, h=h)

    # Through the gate over the same ATR, one JSON text: the approver is shown the checkout's charge, and the request
    # names no expiry, so the payment signs no end (profile buyer-gate.md, rule 8) and the caller raises the ceiling.
    shown: list[ToSign] = []

    def approver(t: ToSign) -> bool:
        shown.append(t)
        return True

    signer = Recording(ACCOUNT, lambda r: answer)
    binding = offered(AP2_CHECKOUT_MANDATE_X402)
    ceilings = {"ap2/checkout-mandate/x402": "no-end"}
    whole = run(
        lambda c: transact(presented["checkout_jwt"], binding, signer, c, approver=approver, ceilings=ceilings),
        serving(atr),
    )
    assert whole == Transacted(signed=presented, atr_bytes=atr, h=h, agreement=unpaid_receipt(h))
    assert signer.requests == [request]
    expected = Summary(
        amount="19900", payees=(), asset="USD", network=None, validity=Validity(None, None, "seconds"), atr=atr
    )
    assert [(t.act, t.request, t.summary) for t in shown] == [("payment", request, expected)]


def test_ucp_checkout_agent_signed_by_its_own_steps() -> None:
    doc = row(AGENT, "ucp/checkout/agent-signed", "B2")["input"]["doc"]
    answer = AGENT["bound"][0]["presented"]
    request, done = by_steps(UCP_CHECKOUT_AGENT_SIGNED, doc, b"abc", answer)
    assert request == {"kind": "ucp-legal-context", "checkout": doc, "legal_context": AGENT["build"][0]["expect"]["legal_context"]}
    assert done == Finished(signed=answer, h=AGENT["fixed"]["H"])


AP2_B6 = row(AP2, "ap2/checkout-mandate", "B6")
AP2_ATR = bytes.fromhex(AP2_B6["input"]["check"][0]["bytesHex"])
AP2_J: str = AP2_B6["input"]["presented"]["checkout_jwt"]


def test_ap2_push_funding_b6_mandate_with_the_receipt_completes_the_push_presentation() -> None:
    answer = {"checkout_mandate": AP2_B6["input"]["presented"]["checkout_mandate"], "payment_receipt": RECEIPT}
    _, done = by_steps(AP2_CHECKOUT_MANDATE, AP2_J, AP2_ATR, answer)
    assert done == Finished(signed={**AP2_B6["input"]["presented"], "payment_receipt": RECEIPT}, h=AP2_B6["expect"][0]["h"])


def test_ap2_push_funding_a_pushed_payment_for_another_checkout_is_declined_and_kept_as_moved() -> None:
    answer = {"checkout_mandate": AP2["V6"]["token"], "payment_receipt": RECEIPT}
    _, done = by_steps(AP2_CHECKOUT_MANDATE, AP2_J, AP2_ATR, answer)
    signed = {"checkout_mandate": AP2["V6"]["token"], "checkout_jwt": AP2_J, "payment_receipt": RECEIPT}
    assert isinstance(done, Declined) and done.code == "signed-not-bound"
    assert done.moved == Moved(signed, AP2_ATR, AP2_B6["expect"][0]["h"])


SHARED: dict[str, Any] = json.loads(
    (Path(__file__).resolve().parents[2] / "agentic-terms" / "test" / "summary-checkout.json").read_text("utf-8")
)


def resolved(v: Any, file: Any) -> Any:
    """A row's request, each {"$ref": pointer} replaced by the value at that JSON Pointer (RFC 6901) in file."""
    if isinstance(v, list):
        return [resolved(x, file) for x in v]
    if not isinstance(v, dict):
        return v
    if isinstance(v.get("$ref"), str):
        at = file
        for k in v["$ref"].split("/")[1:]:
            k = k.replace("~1", "/").replace("~0", "~")
            at = at[int(k)] if isinstance(at, list) else at[k]
        return at
    return {k: resolved(x, file) for k, x in v.items()}


def summary(e: dict[str, Any]) -> Summary:
    """The row's expect as the Python summary, its ATR's bytes empty."""
    v = e["validity"]
    return Summary(
        amount=e.get("amount"),
        maximum=e.get("maximum"),
        payees=tuple(Payee(account=p["account"], amount=p["amount"]) for p in e["payees"]),
        asset=e["asset"],
        network=e["network"],
        validity=Validity(not_before=v["notBefore"], not_after=v["notAfter"], unit=v["unit"]),
        atr=b"",
    )


@pytest.mark.parametrize("r", SHARED["rows"], ids=[f"{r['pairing']} {r['file']}" for r in SHARED["rows"]])
def test_checkout_summaries(r: dict[str, Any]) -> None:
    request = resolved(r["request"], load(r["file"]))
    assert summary_of(r["pairing"], request, b"", r["network"]) == summary(r["expect"])
