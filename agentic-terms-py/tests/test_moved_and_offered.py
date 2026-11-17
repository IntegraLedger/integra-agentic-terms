"""The buyer's rules once money may move, through the gate, as the TypeScript gate's tests run them. Expected
values: a pairing with no public proof, offered with no agreement URL, is agreement-not-offered before any signer call;
MPP's Lightning session ("returnInvoice: REQUIRED. BOLT11 invoice with no encoded amount", draft-lightning-session-00),
checked before the node pays; and the EVM account form. The offers and payers are the vector files'."""

import asyncio

import pytest

import integraledger_terms as terms
from integraledger_terms import (
    MPP_SESSION_LIGHTNING,
    X402_EXACT_EIP155_EIP3009,
    X402_EXACT_EIP155_ERC7710,
    Declined,
    Finished,
)
from support import confirm, transact
from integraledger_terms import _gate
from integraledger_terms.bindings._codec import b64u_encode, js_json

from breadth import ABC, ABD, H, LINK, Recording, code, offered, run, x402_doc
from mpp_docs import placed_doc
from support import ACCOUNT, HASH_A, A, D, load, piece_transact, serving

NOW = 1_790_000_000


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def test_erc7710_offered_with_no_agreement_url_is_agreement_not_offered_and_the_signer_is_never_called() -> None:
    e = load("x402-exact-eip155-erc7710.json")["fixed"]
    # Placed for the hash of A, an ATR that is one JSON text, which the gate parses before it asks for the agreement URL.
    doc = x402_doc(e["option"], e["resource"], HASH_A)
    account = f"{e['option']['network']}:{e['payer']}"
    signer = Recording(account, lambda r: (_ for _ in ()).throw(AssertionError("no signer call")))
    assert code(run(lambda c: transact(doc, X402_EXACT_EIP155_ERC7710, signer, c), serving(A))) == "agreement-not-offered"
    assert code(run(lambda c: confirm(doc, X402_EXACT_EIP155_ERC7710, account, c), serving(A))) == "agreement-not-offered"
    assert signer.requests == []


LN_S = load("mpp-session-lightning.json")
LN_S_DOC = placed_doc({**LN_S["S1"]["challenge"], "request": b64u_encode(js_json(LN_S["S1"]["request"]).encode("utf-8"))}, H, LINK)
LN_MAIN = f"lnbtc:000000000019d6689c085ae165831e93:{load('mpp-charge-lightning.json')['fixed']['payee']}"
def test_a_lightning_return_invoice_with_no_amount_the_node_pays_once() -> None:
    """Paid by the pairing's own steps over abc, with no gate: the invoice commits to the vectors' H."""
    node = Recording(LN_MAIN, lambda r: LN_S["fixed"]["preimage"])
    out = asyncio.run(piece_transact(LN_S_DOC, offered(MPP_SESSION_LIGHTNING), node, {"returnInvoice": LN_S["fixed"]["returnInvoice"]}))
    assert isinstance(out, Finished), out
    assert len(node.requests) == 1


@pytest.mark.parametrize(
    "return_invoice",
    [r["returnInvoice"] for r in LN_S["S1"]["returnInvoiceRows"] if isinstance(r["returnInvoice"], str)],
    ids=[r["case"] for r in LN_S["S1"]["returnInvoiceRows"] if isinstance(r["returnInvoice"], str)],
)
def test_a_lightning_return_invoice_that_is_not_amountless_is_declined_before_the_node_is_asked(return_invoice: str) -> None:
    node = Recording(LN_MAIN, lambda r: LN_S["fixed"]["preimage"])
    out = asyncio.run(piece_transact(LN_S_DOC, offered(MPP_SESSION_LIGHTNING), node, {"returnInvoice": return_invoice}))
    assert isinstance(out, Declined) and out.detail == "ln/return-invoice-malformed"
    assert node.requests == []


def test_an_account_with_a_caip10_escape_is_no_payable_option_before_any_fetch() -> None:
    link = serving(ABC)
    account = "eip155:84532:0x%66" + ACCOUNT.split(":")[-1][3:]
    p2 = load("x402-exact-eip155-permit2.json")["fixed"]
    for doc, binding in ((D, X402_EXACT_EIP155_EIP3009), (x402_doc(p2["option"], p2["resource"]), terms.X402_EXACT_EIP155_PERMIT2)):
        assert code(run(lambda c: confirm(doc, binding, account, c), link)) == "no-payable-option"
    assert link.calls == 0
