"""The buyer's rules once money may move, through the gate, as the TypeScript gate's tests run them. Expected
values: a pairing with no public proof, offered with no agreement URL, is agreement-not-offered before any signer call;
a payment the signer moved whose check fails after the signer returns keeps it as moved, never a bare decline; MPP's
Lightning session ("returnInvoice: REQUIRED. BOLT11 invoice with no encoded amount", draft-lightning-session-00),
checked before the node pays; the Hedera session's {openTx, signature} after the broadcast; MPP's Hedera charge
("Clients MUST reject challenges whose chainId does not match their configured network"), with a challenge with no
chainId read on the signer account's own network; the EVM account form; and the pairings with no public proof. The
offers and payers are the vector files'."""

import copy
from typing import Any

import pytest

import integraledger_terms as terms
from integraledger_terms import (
    MPP_CHARGE_HEDERA,
    MPP_SESSION_HEDERA,
    MPP_SESSION_LIGHTNING,
    X402_EXACT_EIP155_EIP3009,
    X402_EXACT_EIP155_ERC7710,
    X402_EXACT_LNBTC,
    Confirmed,
    Declined,
    Transacted,
    confirm,
    transact,
)
from integraledger_terms import _gate
from integraledger_terms.bindings._codec import b64u_encode, js_json

from breadth import ABC, ABD, H, LINK, Recording, code, offered, run, x402_doc
from mpp_docs import issued, placed_doc
from support import ACCOUNT, D, load, serving, sign_typed

NOW = 1_790_000_000


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def test_erc7710_offered_with_no_agreement_url_is_agreement_not_offered_and_the_signer_is_never_called() -> None:
    e = load("x402-exact-eip155-erc7710.json")["fixed"]
    doc = x402_doc(e["option"], e["resource"])
    account = f"{e['option']['network']}:{e['payer']}"
    assert X402_EXACT_EIP155_ERC7710.public_proof is False
    signer = Recording(account, lambda r: (_ for _ in ()).throw(AssertionError("no signer call")))
    assert code(run(lambda c: transact(doc, X402_EXACT_EIP155_ERC7710, signer, c), serving(ABC))) == "agreement-not-offered"
    assert code(run(lambda c: confirm(doc, X402_EXACT_EIP155_ERC7710, account, c), serving(ABC))) == "agreement-not-offered"
    assert signer.requests == []


LN = load("x402-exact-lnbtc.json")["fixed"]
LN_DOC = x402_doc(LN["O"], LN["resource"])
LN_ACCOUNT = f"{LN['O']['network']}:{LN['payee']}"


# The buyer's own request: x402's lnbtc example, GET of the vector's resource with an empty body.
LN_REQUEST = {"request": {"method": "GET", "url": "https://api.example.com/article/A"}}


def test_the_node_paid_and_answered_no_preimage_the_decline_keeps_what_it_answered() -> None:
    node = Recording(LN_ACCOUNT, lambda r: "not-a-preimage")
    out = run(lambda c: transact(LN_DOC, offered(X402_EXACT_LNBTC), node, c, inputs=LN_REQUEST), serving(ABC))
    assert [r["kind"] for r in node.requests] == ["bolt11-pay"]
    assert isinstance(out, Declined) and out.code == "signed-not-bound"
    assert out.moved is not None
    assert (out.moved.signed, out.moved.atr_bytes, out.moved.h) == ("not-a-preimage", ABC, H)


def test_a_plant_is_a_bare_decline_before_the_node_is_asked() -> None:
    node = Recording(LN_ACCOUNT, lambda r: LN["preimage"])
    out = run(lambda c: transact(LN_DOC, offered(X402_EXACT_LNBTC), node, c, inputs=LN_REQUEST), serving(ABD))
    assert isinstance(out, Declined) and out.code == "hash-mismatch" and out.moved is None
    assert node.requests == []


LN_S = load("mpp-session-lightning.json")
LN_S_DOC = placed_doc({**LN_S["S1"]["challenge"], "request": b64u_encode(js_json(LN_S["S1"]["request"]).encode("utf-8"))}, H, LINK)
LN_MAIN = f"lnbtc:000000000019d6689c085ae165831e93:{load('mpp-charge-lightning.json')['fixed']['payee']}"


def test_a_lightning_return_invoice_with_no_amount_the_node_pays_once() -> None:
    node = Recording(LN_MAIN, lambda r: LN_S["fixed"]["preimage"])
    out = run(lambda c: transact(LN_S_DOC, offered(MPP_SESSION_LIGHTNING), node, c, inputs={"returnInvoice": LN_S["fixed"]["returnInvoice"]}), serving(ABC))
    assert isinstance(out, Transacted), out
    assert len(node.requests) == 1


@pytest.mark.parametrize(
    "return_invoice",
    [r["returnInvoice"] for r in LN_S["S1"]["returnInvoiceRows"] if isinstance(r["returnInvoice"], str)],
    ids=[r["case"] for r in LN_S["S1"]["returnInvoiceRows"] if isinstance(r["returnInvoice"], str)],
)
def test_a_lightning_return_invoice_that_is_not_amountless_is_declined_before_the_node_is_asked(return_invoice: str) -> None:
    node = Recording(LN_MAIN, lambda r: LN_S["fixed"]["preimage"])
    out = run(lambda c: transact(LN_S_DOC, offered(MPP_SESSION_LIGHTNING), node, c, inputs={"returnInvoice": return_invoice}), serving(ABC))
    assert isinstance(out, Declined) and out.detail == "ln/return-invoice-malformed"
    assert node.requests == []


HS = load("mpp-session-hedera-solana-xrpl.json")


def test_a_hedera_session_signer_answering_open_tx_and_signature_after_broadcasting_keeps_the_open_credential() -> None:
    doc = placed_doc(HS["SS1"]["hedera"]["challenge"], H, LINK)
    account = f"hedera:testnet:{HS['fixed']['payer']}"
    signer = Recording(account, lambda r: {"openTx": HS["HS3"]["txHash"], "signature": sign_typed(r["voucher"])})
    out = run(lambda c: transact(doc, offered(MPP_SESSION_HEDERA), signer, c, inputs={"deposit": HS["HS2"]["deposit"]}), serving(ABC))
    assert [r["kind"] for r in signer.requests] == ["hedera-session-open"]
    assert isinstance(out, Declined) and out.code == "signed-not-bound" and out.moved is not None
    assert out.moved.h == H and out.moved.atr_bytes == ABC
    assert sorted(out.moved.signed) == ["challenge", "payload"]
    assert out.moved.signed["payload"]["txHash"] == HS["HS3"]["txHash"]
    assert out.moved.signed["payload"]["channelId"] == HS["HS1"]["expectChannelId"]


HC = load("mpp-charge-hedera.json")["fixed"]
HC_INPUTS = {"node": HC["node"], "validStart": HC["validStart"], "maxFee": HC["maxFee"]}


def hedera_doc(request: dict[str, Any]) -> list[dict[str, Any]]:
    return placed_doc(issued("hedera", "charge", js_json(request), realm=HC["realm"], expires=HC["expires"]), H, LINK)


@pytest.mark.parametrize("net", ["testnet", "mainnet"])
def test_a_hedera_charge_with_no_chain_id_is_read_on_the_accounts_own_network(net: str) -> None:
    request = copy.deepcopy(HC["request"])
    del request["methodDetails"]["chainId"]
    out = run(lambda c: confirm(hedera_doc(request), MPP_CHARGE_HEDERA, f"hedera:{net}:{HC['payer']}", c, HC_INPUTS), serving(ABC))
    assert isinstance(out, Confirmed), out
    assert out.request is not None and out.request["kind"] == "hedera-body"


def test_a_hedera_chain_id_naming_testnet_has_no_payable_option_for_a_mainnet_account() -> None:
    link = serving(ABC)
    out = run(lambda c: confirm(hedera_doc(HC["request"]), MPP_CHARGE_HEDERA, f"hedera:mainnet:{HC['payer']}", c, HC_INPUTS), link)
    assert code(out) == "no-payable-option"
    assert link.calls == 0


def test_an_account_with_a_caip10_escape_is_no_payable_option_before_any_fetch() -> None:
    link = serving(ABC)
    account = "eip155:84532:0x%66" + ACCOUNT.split(":")[-1][3:]
    p2 = load("x402-exact-eip155-permit2.json")["fixed"]
    for doc, binding in ((D, X402_EXACT_EIP155_EIP3009), (x402_doc(p2["option"], p2["resource"]), terms.X402_EXACT_EIP155_PERMIT2)):
        assert code(run(lambda c: confirm(doc, binding, account, c), link)) == "no-payable-option"
    assert link.calls == 0


# The pairings whose payment is not a public proof, so the agreement step applies.
NO_PUBLIC_PROOF = {
    "card/visa-tap", "card/mastercard-vi/immediate", "card/mastercard-vi/autonomous", "card/seller-reference",
    "ap2/checkout-mandate", "ucp/checkout/ap2-mandate", "ucp/checkout/unsigned", "ucp/booking/ap2-mandate",
    "ucp/booking/unsigned", "acp/checkout/delegated", "acp/checkout/undelegated", "ack/payment-request",
    "x402/exact/lnbtc", "x402/exact/lnbtc/invoice-named", "mpp/charge/lightning", "mpp/session/lightning",
    "mpp/charge/card", "mpp/charge/stripe", "mpp/subscription/stripe", "mpp/charge/nearintents",
    "mpp/charge/evm/transaction", "mpp/charge/evm/hash", "x402/exact/aptos", "x402/exact/eip155/erc7710",
    "x402/exact/hedera/transfer-executor", "x402/batch-settlement/cloudflare",
}  # fmt: skip


def test_every_pairings_public_proof_is_x1s() -> None:
    bindings = [v for v in vars(terms).values() if isinstance(getattr(v, "id", None), str) and hasattr(v, "public_proof")]
    ids = {b.id for b in bindings}
    assert NO_PUBLIC_PROOF <= ids
    for b in bindings:
        assert b.public_proof is (b.id not in NO_PUBLIC_PROOF), b.id
