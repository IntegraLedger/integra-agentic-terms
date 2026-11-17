"""The card pieces of card/visa-vic, card/mastercard-agent-pay and Verifiable Intent's Immediate checkout payload, the
TAP and Agent Pay carriers they share, and the VI signer's rule. Every request, answer and hash is a vector file's:
card.json's (T2, T3, T6, T7, V10, C2, C5, C6 and the VI strings) and terms' vi-signer.json, whose rows Python's json
module computed."""

import base64
import dataclasses
import json
import secrets
from pathlib import Path
from typing import Any

import pytest
from breadth import ABC, ABD, H, LINK, Pairing, through_gate
from support import load

from integraledger_terms._summary import summary_of
from integraledger_terms._types import Ceilings, Summary, Validity
from integraledger_terms import (
    CARD_MASTERCARD_AGENT_PAY,
    CARD_MASTERCARD_VI_AUTONOMOUS,
    CARD_MASTERCARD_VI_IMMEDIATE,
    CARD_VISA_TAP,
    CARD_VISA_VIC,
    Advertised,
    Chosen,
    Declined,
    Finished,
    Refusal,
    finish,
    vi_json,
)
from integraledger_terms.bindings import card as card_binding
from integraledger_terms.pieces import PIECES

CARD = load("card.json")
RULE = json.loads((Path(__file__).resolve().parents[2] / "agentic-terms" / "vectors" / "vi-signer.json").read_bytes())
BUYER = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
CJ: str = CARD["vi"]["CJ"]
CJ_PAYLOAD = json.loads(base64.urlsafe_b64decode(CJ.split(".")[1] + "=" * (-len(CJ.split(".")[1]) % 4)))
SHOWN = {"legalContext": CJ_PAYLOAD["legalContext"]}


def expected(e: str) -> Any:
    """A row's hash, or its refusal code as a Refusal."""
    return Refusal(e) if e.startswith("card/") else e


def built(binding: Any, doc: Any, inputs: dict[str, Any] | None = None) -> tuple[Chosen, Any]:
    """The pairing's own steps over abc with no gate: the choice kept as JSON, and the request handed to the signer."""
    piece = PIECES[binding.id]
    chosen = piece.choose(Advertised(h=H, link=LINK, offer={}), BUYER, inputs or {}, 1790000000, "r" * 32, doc)
    assert isinstance(chosen, Chosen), chosen
    kept = Chosen(**json.loads(json.dumps(dataclasses.asdict(chosen))))
    unsigned = piece.build(binding, piece.choice(kept, ABC), H)
    assert not isinstance(unsigned, Refusal), unsigned
    return kept, piece.request(unsigned)


@pytest.mark.parametrize("row", RULE["rows"], ids=[r["case"] for r in RULE["rows"]])
def test_the_vi_signer_rule(row: dict[str, Any]) -> None:
    assert vi_json(json.loads(row["json"])) == row["expect"]


# ── card/visa-vic ──


def test_vic_t7_build_and_bound() -> None:
    t7 = CARD["T7"]
    assert card_binding.vic_build(t7["build"]["h"]) == t7["build"]["expect"]
    assert CARD_VISA_VIC.bound(t7["bound"]["presented"]) == t7["bound"]["expect"]


@pytest.mark.parametrize("row", CARD["T7"]["refusals"], ids=[r["case"] for r in CARD["T7"]["refusals"]])
def test_vic_t7_refusals(row: dict[str, Any]) -> None:
    assert CARD_VISA_VIC.bound(row["presented"]) == Refusal(row["expect"])


def test_vic_the_request_is_the_reference_and_the_reference_returned_completes_a_payment_bound_to_h() -> None:
    t7 = CARD["T7"]
    kept, request = built(CARD_VISA_VIC, SHOWN)
    assert request == {"kind": "vic-reference", **t7["build"]["expect"]}
    assert finish(ABC, kept, dict(t7["bound"]["presented"]), CARD_VISA_VIC) == Finished(signed=t7["bound"]["presented"], h=H)
    out = finish(ABD, kept, dict(t7["bound"]["presented"]), CARD_VISA_VIC)
    assert isinstance(out, Declined) and out.code == "signed-not-bound"


def test_vic_through_the_gate_over_buyer_jsons_atr_a_once_the_caller_lifts_the_ceiling() -> None:
    """The document the seller shows for A's hash, as lcp's profile card-visa-tap.md rule 1 states it; the agent's
    credential client writes the reference it is handed, and the credential payload returns it."""
    p = Pairing(
        CARD_VISA_VIC,
        SHOWN,
        BUYER,
        lambda r: {"transactionReferenceId": r["transactionReferenceId"]},
        placed=lambda h: {"legalContext": {**SHOWN["legalContext"], "value": h}},
        ceilings={"card/visa-vic": "no-end"},
    )
    through_gate(p, 1)


# ── card/mastercard-agent-pay, and the TAP carrier it shares ──


@pytest.mark.parametrize("row", CARD["T6"]["rows"], ids=[r["case"] for r in CARD["T6"]["rows"]])
def test_agent_pay_t6(row: dict[str, Any]) -> None:
    presented = {"signatureInput": row["signatureInput"], "signature": row["signature"]}
    assert CARD_MASTERCARD_AGENT_PAY.bound(presented) == expected(row["expect"])


def test_agent_pay_t6_published_playbook_request() -> None:
    p = CARD["T6"]["published"]
    presented = {k: p[k] for k in ("signatureInput", "signature", "path")}
    assert CARD_MASTERCARD_AGENT_PAY.bound(presented) == p["expect"]
    assert CARD_VISA_TAP.bound(presented) == Refusal(p["visaTapExpect"])


@pytest.mark.parametrize("row", CARD["T2"]["rows"] + CARD["T3"]["rows"], ids=lambda r: r.get("case") or r["name"])
def test_tap_t2_t3(row: dict[str, Any]) -> None:
    presented = {k: row[k] for k in ("signatureInput", "signature", "path") if k in row}
    assert CARD_VISA_TAP.bound(presented) == expected(row["expect"])


def test_agent_pay_the_nonce_is_c2s_and_agent_pay_signatures_over_it_complete_a_payment_bound_to_h(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    random = bytes.fromhex(CARD["C2"]["random"])
    monkeypatch.setattr(card_binding, "token_bytes", lambda n: random if n == 32 else secrets.token_bytes(n))
    kept, request = built(CARD_MASTERCARD_AGENT_PAY, SHOWN)
    assert request == {"kind": "tap-field", "nonce": CARD["C2"]["nonce"]}
    rows = [r for r in CARD["T6"]["rows"] if r["expect"] == H]
    assert rows
    for row in rows:
        assert f'nonce="{CARD["C2"]["nonce"]}"' in row["signatureInput"]
        answer = {"signatureInput": row["signatureInput"], "signature": row["signature"]}
        assert finish(ABC, kept, answer, CARD_MASTERCARD_AGENT_PAY) == Finished(signed=answer, h=H)


# ── Verifiable Intent ──


def test_vi_v10_views_and_immediate_read_and_build() -> None:
    v = CARD["V10"]
    assert CARD_MASTERCARD_VI_AUTONOMOUS.bound({"l1": v["L1"], "l2": v["merchantView"], "l3b": v["L3b"]}) == v["expect"]["merchantView"]
    assert CARD_MASTERCARD_VI_AUTONOMOUS.bound({"l1": v["L1"], "l2": v["roleView"], "l3b": v["L3b"]}) == Refusal(v["expect"]["roleView"])
    assert CARD_MASTERCARD_VI_IMMEDIATE.bound({"l2": v["fullL2"]}) == Refusal(v["expect"]["fullL2UnderImmediate"])
    read = CARD_MASTERCARD_VI_IMMEDIATE.read(v["immediateRead"]["doc"])
    assert isinstance(read, Advertised) and (read.h, read.link) == (v["immediateRead"]["expect"]["h"], v["immediateRead"]["expect"]["link"])
    assert CARD_MASTERCARD_VI_IMMEDIATE.build(v["immediateBuild"]["choice"], H) == v["immediateBuild"]["expect"]


def test_vi_immediate_the_agents_payload_with_the_shown_legal_context_is_the_request() -> None:
    choice = CARD["V10"]["immediateBuild"]["choice"]
    _, request = built(CARD_MASTERCARD_VI_IMMEDIATE, choice["shown"], {"checkout": choice["checkout"]})
    assert request == {"kind": "vi-checkout", **CARD["V10"]["immediateBuild"]["expect"]}


def test_vi_immediate_cj_signs_the_payload_then_c5s_mandate_and_c6s_l2_complete_a_payment_bound_to_h() -> None:
    checkout = {k: v for k, v in CJ_PAYLOAD.items() if k != "legalContext"}
    kept, request = built(CARD_MASTERCARD_VI_IMMEDIATE, SHOWN, {"checkout": checkout})
    assert vi_json(request["checkout"]) == base64.urlsafe_b64decode(CJ.split(".")[1] + "==").decode("ascii")
    # The mandate, the later step, is held to its ceiling: the request names no end, so the caller lifts it.
    held = finish(ABC, kept, {"checkout_jwt": CJ}, CARD_MASTERCARD_VI_IMMEDIATE)
    assert isinstance(held, Declined) and held.code == "no-end"
    ceilings: Ceilings = {"card/mastercard-vi/immediate": "no-end"}
    step = finish(ABC, kept, {"checkout_jwt": CJ}, CARD_MASTERCARD_VI_IMMEDIATE, ceilings=ceilings)
    assert not isinstance(step, (Declined, Finished)) and step.next == {"kind": "vi-checkout-mandate", **CARD["C5"]["build"]["expect"]}
    l2 = CARD["C6"]["bound"]["presented"]["l2"]
    done = finish(ABC, kept, [{"checkout_jwt": CJ}, {"l2": l2}], CARD_MASTERCARD_VI_IMMEDIATE)
    assert done == Finished(signed={"l2": l2}, h=H)


def test_vi_immediate_a_checkout_jwt_over_another_payload_completes_nothing() -> None:
    choice = CARD["V10"]["immediateBuild"]["choice"]
    kept, _ = built(CARD_MASTERCARD_VI_IMMEDIATE, choice["shown"], {"checkout": choice["checkout"]})
    out = finish(ABC, kept, {"checkout_jwt": CJ}, CARD_MASTERCARD_VI_IMMEDIATE)
    assert isinstance(out, Declined) and (out.code, out.detail) == ("signed-not-bound", "card/signature-malformed")


# ── The summaries, of the requests lcp's build vectors give ──

def nothing_named(grant: Any = None) -> Summary:
    """No amount, payee or currency named, no ledger, and no end signed, over abc."""
    return Summary(payees=(), asset="", network=None, validity=Validity(not_before=None, not_after=None, unit="seconds"), grant=grant, atr=ABC)


def test_tap_field_and_vic_reference_name_no_amount_payee_or_currency_and_no_ledger_and_sign_no_end() -> None:
    tap = {"kind": "tap-field", "nonce": CARD["C2"]["nonce"]}
    assert summary_of("card/visa-tap", tap, ABC) == nothing_named()
    assert summary_of("card/mastercard-agent-pay", tap, ABC) == nothing_named()
    vic = {"kind": "vic-reference", **CARD["T7"]["build"]["expect"]}
    assert summary_of("card/visa-vic", vic, ABC) == nothing_named()


def test_vi_checkout_grants_the_payload_and_the_mandate_the_payload_of_its_checkout_jwt() -> None:
    payload = CARD["V10"]["immediateBuild"]["expect"]["checkout"]
    assert summary_of("card/mastercard-vi/immediate", {"kind": "vi-checkout", "checkout": payload}, ABC) == nothing_named(payload)
    mandate = {"kind": "vi-checkout-mandate", **CARD["C5"]["build"]["expect"]}
    for pairing in ("card/mastercard-vi/immediate", "card/mastercard-vi/autonomous"):
        assert summary_of(pairing, mandate, ABC) == nothing_named(CJ_PAYLOAD)
