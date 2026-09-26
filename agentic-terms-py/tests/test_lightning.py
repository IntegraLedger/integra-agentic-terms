"""B2 and B6 for the Lightning pairings on x402, with their vector rows for the buyer half. Every expected value is the
vector files' (x402-exact-lnbtc.json and x402-exact-lnbtc-invoice-named.json); the node answers with the preimage they
publish."""

import copy
import dataclasses
import hashlib
import json
from typing import Any

import pytest
from breadth import ABD, H, LINK, Pairing, Recording, build_and_sign, code, offered, plant, run, x402_doc
from support import load, serving

from integraledger_terms import (
    MPP_CHARGE_LIGHTNING,
    MPP_SESSION_LIGHTNING,
    X402_EXACT_LNBTC,
    X402_EXACT_LNBTC_INVOICE_NAMED,
    Advertised,
    Chosen,
    Confirmed,
    Finished,
    Refusal,
    _gate,
    confirm,
    finish,
    transact,
)
from integraledger_terms.bindings._bolt11 import Bolt11, decode, invoice_h
from integraledger_terms.bindings._channel import ChannelRef
from integraledger_terms.bindings._codec import b64u_encode, canonical_json
from integraledger_terms.bindings.lightning import atr_names_invoice
from mpp_docs import placed_doc

NOW = 1_790_000_000
V = load("x402-exact-lnbtc.json")
N = load("x402-exact-lnbtc-invoice-named.json")
F = V["fixed"]
FN = N["fixed"]


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def refusal(expect: dict[str, Any]) -> Refusal:
    assert expect["refused"] is True
    return Refusal(expect["code"])


def required(option: dict[str, Any]) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepts": [option]}


def with_set(base: Any, changes: dict[str, Any]) -> Any:
    """A copy of base with each dotted path set to its value."""
    out = copy.deepcopy(base)
    for path, value in changes.items():
        keys = path.split(".")
        at = out
        for k in keys[:-1]:
            at = at[k]
        at[keys[-1]] = value
    return out


def decoded(invoice: str) -> Bolt11:
    b = decode(invoice)
    assert isinstance(b, Bolt11), b
    return b


# ── x402/exact/lnbtc ──

# The buyer's own request: x402's lnbtc example, GET of the vector's resource with an empty body.
REQUEST = {"request": {"method": "GET", "url": "https://api.example.com/article/A"}}
LNBTC = Pairing(
    X402_EXACT_LNBTC, x402_doc(F["O"], F["resource"]), f"{F['O']['network']}:{F['payee']}", lambda r: F["preimage"], REQUEST
)

def test_x402_exact_lnbtc_b6_the_node_pays_the_option_invoice_whose_m_is_h() -> None:
    def inspect(request: Any) -> None:
        assert request == {"kind": "bolt11-pay", "invoice": F["O"]["extra"]["invoice"]}

    build_and_sign(LNBTC, inspect)


def test_bolt11_l1_published_h_example() -> None:
    b = decoded(V["L1"]["invoice"])
    assert b.description_hash is not None and b.description_hash.hex() == V["L1"]["expectDescriptionHash"]
    assert hashlib.sha256(V["L1"]["description"].encode("utf-8")).hexdigest() == V["L1"]["expectDescriptionHash"]


def test_bolt11_l4_request_hash_in_h_and_h_in_m() -> None:
    b = decoded(V["L4"]["invoice"])
    e = V["L4"]["expect"]
    assert {
        "currency": b.currency,
        "amountMsat": None if b.amount_msat is None else str(b.amount_msat),
        "timestamp": b.timestamp,
        "expiry": b.expiry,
        "paymentHash": b.payment_hash.hex(),
        "descriptionHash": None if b.description_hash is None else b.description_hash.hex(),
        "metadata": None if b.metadata is None else b.metadata.hex(),
        "description": b.description,
    } == e
    assert invoice_h(b, "m") == F["H"]
    assert invoice_h(b, "h") == "0x" + e["descriptionHash"]


def test_x402_exact_lnbtc_l5_read_build_complete_and_bound() -> None:
    o = F["O"]
    doc = x402_doc(o, F["resource"], F["H"], F["link"])
    r = X402_EXACT_LNBTC.read(doc)
    assert r == Advertised(h=F["H"], link=F["link"], offer={"required": doc, "options": [o]})
    binding: Any = X402_EXACT_LNBTC
    unsigned = binding.build({"required": required(o), "accepted": o}, F["H"])
    assert unsigned.request == {"kind": "bolt11-pay", "invoice": V["L4"]["invoice"]}
    payment = unsigned.complete(F["preimage"])
    assert payment == V["L5"]["payment"]
    assert X402_EXACT_LNBTC.bound(payment) == V["L5"]["expectBound"]


@pytest.mark.parametrize(
    "row", [r for r in V["refusals"]["rows"] if r["fn"] in ("complete", "bound")], ids=lambda r: str(r["case"])
)
def test_x402_exact_lnbtc_refusal_rows(row: dict[str, Any]) -> None:
    o = F["O"]
    if row["fn"] == "complete":
        binding: Any = X402_EXACT_LNBTC
        unsigned = binding.build({"required": required(o), "accepted": o}, F["H"])
        assert unsigned.complete(row["preimage"]) == refusal(row["expect"])
    else:
        option = with_set(o, row.get("optionSet", {}))
        assert X402_EXACT_LNBTC.bound(with_set(V["L5"]["payment"], {"accepted": option})) == refusal(row["expect"])


@pytest.mark.parametrize(
    "row", [r for r in V["refusals"]["rows"] if r["fn"] == "advertise"], ids=lambda r: str(r["case"])
)
def test_x402_exact_lnbtc_option_checks_refuse_in_build(row: dict[str, Any]) -> None:
    """The option checks advertise makes, which build repeats on the chosen option."""
    option = with_set(F["O"], row.get("optionSet", {}))
    binding: Any = X402_EXACT_LNBTC
    assert binding.build({"required": required(option), "accepted": option}, F["H"]) == refusal(row["expect"])


def test_x402_exact_lnbtc_build_with_another_h_is_no_metadata() -> None:
    row = next(r for r in V["refusals"]["rows"] if r["fn"] == "advertiseOtherH")
    binding: Any = X402_EXACT_LNBTC
    assert binding.build({"required": required(F["O"]), "accepted": F["O"]}, row["h"]) == refusal(row["expect"])


# ── x402/exact/lnbtc/invoice-named ──


def atr_n() -> bytes:
    """The core's bytes for the vectors' id and the x402 slot {accepts: [O_N], request}, members in that order."""
    slot = {"accepts": [FN["O_N"]], "request": FN["request"]}
    text = '{"atrVersion":"1","id":' + json.dumps(FN["atrId"]) + ',"x402":' + json.dumps(slot, separators=(",", ":"), ensure_ascii=False) + "}"
    return text.encode("utf-8")


def test_x402_exact_lnbtc_invoice_named_l6_the_invoice_and_the_atr_that_names_it() -> None:
    b = decoded(N["L6"]["invoice"])
    assert {
        "currency": b.currency,
        "amountMsat": None if b.amount_msat is None else str(b.amount_msat),
        "expiry": b.expiry,
        "paymentHash": b.payment_hash.hex(),
        "descriptionHash": None if b.description_hash is None else b.description_hash.hex(),
        "metadata": None if b.metadata is None else b.metadata.hex(),
    } == N["L6"]["expectDecoded"]
    atr = atr_n()
    assert len(atr) == N["L6"]["expectAtrLength"]
    assert "0x" + hashlib.sha256(atr).hexdigest() == N["L6"]["expectH_N"]
    assert atr_names_invoice(atr, N["L6"]["invoice"]) is N["L6"]["expectAtrNamesInvoice"]

def test_x402_exact_lnbtc_invoice_named_l6_build_and_bound() -> None:
    atr = atr_n()
    on = FN["O_N"]
    binding: Any = X402_EXACT_LNBTC_INVOICE_NAMED
    unsigned = binding.build({"required": required(on), "accepted": on, "atr": atr}, N["L6"]["expectH_N"])
    assert unsigned.request == N["L6"]["expectBuild"]
    payment = N["L6"]["payment"]
    assert binding.bound(payment) == N["L6"]["expectBound"]
    with_l4 = with_set(payment, {"accepted.extra.invoice": FN["L4"]})
    assert binding.bound(with_l4) == refusal(N["L6"]["withL4"]["expect"])
    bare = {k: v for k, v in payment.items() if k != "extensions"}
    assert binding.bound(bare) == refusal(N["L6"]["withoutExtensions"]["expect"])


def test_x402_exact_lnbtc_invoice_named_plant2_never_pays_an_invoice_its_atr_does_not_name() -> None:
    atr = atr_n()
    offered = with_set(FN["O_N"], {"extra.invoice": N["plant2"]["invoice"]})
    binding: Any = X402_EXACT_LNBTC_INVOICE_NAMED
    out = binding.build({"required": required(offered), "accepted": offered, "atr": atr}, N["L6"]["expectH_N"])
    assert out == refusal(N["plant2"]["expect"])


def test_x402_lightning_9a_each_read_serves_only_its_own_options() -> None:
    doc_m = x402_doc(F["O"], F["resource"])
    doc_n = x402_doc(FN["O_N"], FN["resource"])
    assert X402_EXACT_LNBTC_INVOICE_NAMED.read(doc_m) == Refusal("x402/no-payable-option")
    assert X402_EXACT_LNBTC.read(doc_n) == Refusal("x402/no-payable-option")
    assert H == F["H"] and LINK.endswith(F["H"])


# ── mpp/charge/lightning and mpp/session/lightning ──

C = load("mpp-charge-lightning.json")
S = load("mpp-session-lightning.json")
LN_ACCOUNT = f"lnbtc:000000000019d6689c085ae165831e93:{C['fixed']['payee']}"


def ln_challenges(row: dict[str, Any], h: str = H, link: str = LINK) -> list[dict[str, Any]]:
    """The seller's challenge list: the row's challenge with its request as base64url of its JSON text, placed."""
    issued = {**row["challenge"], "request": b64u_encode(json.dumps(row["request"], separators=(",", ":")).encode("utf-8"))}
    return placed_doc(issued, h, link)


CHARGE = Pairing(MPP_CHARGE_LIGHTNING, ln_challenges(C["L3"]), LN_ACCOUNT, lambda r: C["fixed"]["preimage"])
SESSION = Pairing(
    MPP_SESSION_LIGHTNING,
    ln_challenges(S["S1"]),
    LN_ACCOUNT,
    lambda r: S["fixed"]["preimage"],
    {"returnInvoice": S["fixed"]["returnInvoice"]},
)

def test_mpp_charge_lightning_b6_the_node_pays_l3_invoice() -> None:
    def inspect(request: Any) -> None:
        assert request == {"kind": "bolt11-pay", "invoice": C["L3"]["request"]["methodDetails"]["invoice"]}

    build_and_sign(CHARGE, inspect)


def test_mpp_session_lightning_b6_the_deposit_invoice_and_the_return_invoice_in_the_open() -> None:
    def inspect(request: Any) -> None:
        assert request == {"kind": "bolt11-pay", "invoice": S["S1"]["request"]["depositInvoice"]}

    signed, _ = build_and_sign(SESSION, inspect)
    assert signed["payload"] == {"action": "open", "preimage": S["fixed"]["preimage"], "returnInvoice": S["fixed"]["returnInvoice"]}


def test_mpp_lightning_b16_no_return_invoice_or_another_namespace() -> None:
    link = serving(b"abc")
    session = run(lambda c: confirm(SESSION.doc, MPP_SESSION_LIGHTNING, LN_ACCOUNT, c), link)
    charge = run(
        lambda c: confirm(CHARGE.doc, MPP_CHARGE_LIGHTNING, "eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", c), link
    )
    assert code(session) == "no-payable-option" and code(charge) == "no-payable-option"
    assert link.calls == 0


# The MPP Lightning vectors' rows for the buyer half: requests as base64url of their RFC 8785 form.


def challenge_of(row: dict[str, Any], request_set: dict[str, Any] | None = None) -> dict[str, Any]:
    request = with_set(row["request"], request_set or {})
    return {**row["challenge"], "request": b64u_encode(canonical_json(request).encode("utf-8"))}


def placed(row: dict[str, Any], link: str) -> dict[str, Any]:
    return placed_doc(challenge_of(row), H, link)[0]


def _without(base: dict[str, Any], dotted: str) -> dict[str, Any]:
    out = copy.deepcopy(base)
    keys = dotted.split(".")
    at = out
    for k in keys[:-1]:
        at = at[k]
    del at[keys[-1]]
    return out


def test_mpp_charge_lightning_l2_invoice_carries_h_as_its_description_hash() -> None:
    b = decoded(C["L2"]["invoice"])
    assert {
        "currency": b.currency,
        "amountMsat": None if b.amount_msat is None else str(b.amount_msat),
        "timestamp": b.timestamp,
        "expiry": b.expiry,
        "paymentHash": b.payment_hash.hex(),
        "descriptionHash": None if b.description_hash is None else b.description_hash.hex(),
        "metadata": None if b.metadata is None else b.metadata.hex(),
    } == C["L2"]["expect"]


def test_mpp_charge_lightning_l3_build_complete_and_bound() -> None:
    challenge = placed(C["L3"], C["fixed"]["link"])
    assert challenge["id"] == C["L3"]["expectId"]
    binding: Any = MPP_CHARGE_LIGHTNING
    unsigned = binding.build({"challenge": challenge}, H)
    assert unsigned.request == {"kind": "bolt11-pay", "invoice": C["L2"]["invoice"]}
    credential = unsigned.complete(C["fixed"]["preimage"])
    assert credential == {"challenge": challenge, "payload": {"preimage": C["fixed"]["preimage"]}}
    assert binding.bound(credential) == C["L3"]["expectBound"]


@pytest.mark.parametrize("row", C["L3"]["refusals"], ids=lambda r: str(r["case"]))
def test_mpp_charge_lightning_l3_checks_refuse_in_build(row: dict[str, Any]) -> None:
    """The checks of what the seller's node wrote, which build repeats on the challenge received."""
    challenge = placed(C["L3"], C["fixed"]["link"])
    changes = row.get("requestSet", {})
    request = C["L3"]["request"]
    for path, value in changes.items():
        request = _without(request, path) if value is None else with_set(request, {path: value})
    bad = {**with_set(challenge, row.get("challengeSet", {})), "request": b64u_encode(canonical_json(request).encode("utf-8"))}
    binding: Any = MPP_CHARGE_LIGHTNING
    assert binding.build({"challenge": bad}, H) == refusal(row["expect"])


def test_mpp_charge_lightning_plant1_an_echo_whose_invoice_does_not_carry_the_hash_is_never_bound() -> None:
    challenge = placed(C["L3"], C["fixed"]["link"])
    request = with_set(C["L3"]["request"], {"methodDetails.invoice": C["plant"]["invoice"]})
    echoed = {**challenge, "request": b64u_encode(canonical_json(request).encode("utf-8"))}
    credential = {"challenge": echoed, "payload": {"preimage": C["fixed"]["preimage"]}}
    assert MPP_CHARGE_LIGHTNING.bound(credential) == refusal(C["plant"]["expect"])


def test_mpp_session_lightning_the_open_action_pays_the_deposit_invoice_and_binds_h() -> None:
    challenge = placed(S["S1"], S["fixed"]["link"])
    binding: Any = MPP_SESSION_LIGHTNING
    unsigned = binding.build({"challenge": challenge, "returnInvoice": S["fixed"]["returnInvoice"]}, H)
    credential = unsigned.complete(S["fixed"]["preimage"])
    assert credential["payload"] == {
        "action": "open",
        "preimage": S["fixed"]["preimage"],
        "returnInvoice": S["fixed"]["returnInvoice"],
    }
    assert binding.bound(credential) == S["S1"]["expectBound"]


@pytest.mark.parametrize("row", S["S1"]["rows"], ids=lambda r: str(r["case"]))
def test_mpp_session_lightning_rows(row: dict[str, Any]) -> None:
    out = MPP_SESSION_LIGHTNING.bound({"challenge": placed(S["S1"], S["fixed"]["link"]), "payload": row["payload"]})
    expect = row["expect"]
    assert out == (refusal(expect) if isinstance(expect, dict) else expect)


@pytest.mark.parametrize("row", S["S1"]["returnInvoiceRows"], ids=lambda r: str(r["case"]))
def test_mpp_session_lightning_build_refuses_a_return_invoice_the_open_action_cannot_carry(row: dict[str, Any]) -> None:
    challenge = placed(S["S1"], S["fixed"]["link"])
    choice = {"challenge": challenge} if row["returnInvoice"] is None else {"challenge": challenge, "returnInvoice": row["returnInvoice"]}
    out = MPP_SESSION_LIGHTNING.build(choice, H)
    assert row["expectRefused"] is True
    assert out == Refusal(row["expectCode"])


# mpp/session/lightning's channel members, from draft-lightning-session-00's actions: open opens the session; bearer
# and topUp act within it; close ends it. The session is named by the open's paymentHash and every later sessionId.
def test_mpp_session_lightning_channel_kind() -> None:
    binding: Any = MPP_SESSION_LIGHTNING
    ph = S["fixed"]["paymentHash"]
    pre = S["fixed"]["preimage"]

    def k(payload: dict[str, Any]) -> Any:
        return binding.channel_kind({"challenge": placed(S["S1"], S["fixed"]["link"]), "payload": payload})

    assert k({"action": "open", "preimage": pre}) == "open"
    assert k({"action": "bearer", "sessionId": ph, "preimage": pre}) == "within"
    assert k({"action": "topUp", "sessionId": ph, "topUpPreimage": pre}) == "within"
    assert k({"action": "close", "sessionId": ph, "preimage": pre}) == "close"
    assert k({"action": "renew"}) == Refusal("mpp/session-action")


def test_mpp_session_lightning_channel_ref_names_one_channel_for_the_open_and_later_actions() -> None:
    binding: Any = MPP_SESSION_LIGHTNING
    ph = S["fixed"]["paymentHash"]
    opened = binding.channel_ref(
        {"challenge": placed(S["S1"], S["fixed"]["link"]), "payload": {"action": "open", "preimage": S["fixed"]["preimage"]}}
    )
    later_request = b64u_encode(canonical_json({"amount": "2", "currency": "sat", "paymentHash": "00" * 32}).encode("utf-8"))
    bearer = binding.channel_ref(
        {
            "challenge": {**S["S1"]["challenge"], "id": "x", "request": later_request},
            "payload": {"action": "bearer", "sessionId": ph.upper(), "preimage": S["fixed"]["preimage"]},
        }
    )
    assert opened == bearer == ChannelRef("lightning", ph.lower())


def test_mpp_session_lightning_bound_within_refuses() -> None:
    binding: Any = MPP_SESSION_LIGHTNING
    bearer = {
        "challenge": placed(S["S1"], S["fixed"]["link"]),
        "payload": {"action": "bearer", "sessionId": S["fixed"]["paymentHash"], "preimage": S["fixed"]["preimage"]},
    }
    assert binding.bound_within(bearer) == Refusal("mpp/not-bound-within")
    assert not hasattr(MPP_CHARGE_LIGHTNING, "channel_kind")
