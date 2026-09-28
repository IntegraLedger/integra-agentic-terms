"""The gate's rows, as the TypeScript gate's tests run them, for MPP's confirm-only pairings: card, Stripe charge and
Stripe subscription (pairings-b7.test.ts), and NEAR Intents (pairings-mpp2.test.ts). Expected values are the vector
files'."""

import json
from typing import Any

import pytest

from integraledger_terms.bindings._codec import b64u_decode
from integraledger_terms import (
    MPP_CHARGE_CARD,
    MPP_CHARGE_NEARINTENTS,
    MPP_CHARGE_STRIPE,
    MPP_SUBSCRIPTION_STRIPE,
    Binding,
    Checked,
    Confirmed,
    check,
    confirm,
)

from breadth import ABC, ABD, H, LINK, Pairing, code, confirms_only, never, plant, run
from mpp_docs import http_doc, issued, lcp_carrier, place_carrier
from support import load, serving

CARD = load("mpp-charge-card.json")
STRIPE = load("mpp-charge-stripe.json")
SUB = load("mpp-subscription-stripe.json")
NEAR = load("mpp-charge-nearintents.json")
AGREEMENT = f"https://pay.seller.example/agreement/{H}"
EVM_ACCOUNT = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"


def challenge_of(method: str, intent: str, request: Any) -> dict[str, Any]:
    text = request if isinstance(request, str) else json.dumps(request, separators=(",", ":"), ensure_ascii=False)
    return issued(method, intent, text, CARD["fixed"]["realm"], CARD["fixed"]["expires"])


def doc_of(c: dict[str, Any], occupied: str, agreement: str | None = None) -> list[dict[str, Any]]:
    placed = place_carrier([c], H, LINK, c, lcp_carrier(H, occupied), agreement)
    assert isinstance(placed, list), placed
    return placed


CONFIRM_ONLY = [
    (MPP_CHARGE_CARD, challenge_of("card", "charge", CARD["M1"]["request"])),
    (MPP_CHARGE_STRIPE, challenge_of("stripe", "charge", STRIPE["M2"]["request"])),
    (MPP_SUBSCRIPTION_STRIPE, challenge_of("stripe", "subscription", SUB["S1"]["request"])),
]
IDS = ["mpp/charge/card", "mpp/charge/stripe", "mpp/subscription/stripe"]


def pairing(binding: Binding, c: dict[str, Any]) -> Pairing:
    return Pairing(binding=binding, doc=doc_of(c, "mpp/carrier-occupied"), account=EVM_ACCOUNT, answer=never)

@pytest.mark.parametrize(("binding", "c"), CONFIRM_ONLY, ids=IDS)
def test_mpp_card_stripe_b6_nothing_handed_to_the_signer(binding: Binding, c: dict[str, Any]) -> None:
    confirms_only(pairing(binding, c))


@pytest.mark.parametrize(("binding", "c"), CONFIRM_ONLY, ids=IDS)
def test_mpp_card_stripe_the_agreement_url_reaches_the_buyer(binding: Binding, c: dict[str, Any]) -> None:
    doc: Any = doc_of(c, "mpp/carrier-occupied", AGREEMENT)
    confirmed = run(lambda client: confirm(doc, binding, EVM_ACCOUNT, client), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    assert (confirmed.chosen.agreement, confirmed.request, confirmed.h) == (AGREEMENT, None, H)


def test_mpp_card_stripe_placed_carriers_are_the_vectors() -> None:
    card = doc_of(CONFIRM_ONLY[0][1], "mpp/carrier-occupied")
    assert json.loads(_decoded(card[0]["request"]))["externalId"] == CARD["M1"]["expectExternalId"]
    sub = doc_of(CONFIRM_ONLY[2][1], "mpp/carrier-occupied")
    assert json.loads(_decoded(sub[0]["request"]))["methodDetails"]["metadata"] == SUB["S1"]["expectMetadata"]


def _decoded(request: str) -> str:
    raw = b64u_decode(request)
    assert raw is not None
    return raw.decode("utf-8")


# ── mpp/charge/nearintents.

REFUND_TO: str = NEAR["fixed"]["request"]["methodDetails"]["refundTo"]
NEAR_P = Pairing(
    binding=MPP_CHARGE_NEARINTENTS,
    doc=doc_of(NEAR["challenge"], "near/carrier-occupied"),
    account=f"{NEAR['fixed']['request']['methodDetails']['originNetwork']}:{REFUND_TO}",
    answer=never,
)


def test_mpp_charge_nearintents_the_placed_challenge_is_the_vectors() -> None:
    assert NEAR_P.doc == [NEAR["place"]["expect"]]

def test_mpp_charge_nearintents_b6_confirm_only_and_the_hash_credential_checks() -> None:
    confirms_only(NEAR_P)
    credential = {"challenge": NEAR["place"]["expect"], "payload": NEAR["bound"]["payload"]}
    assert check(ABC, credential, NEAR_P.binding) == Checked(h=NEAR["bound"]["expect"])
    assert code(check(ABD, credential, NEAR_P.binding)) == "signed-not-bound"


def test_mpp_charge_nearintents_b10_http_link_before_any_fetch() -> None:
    link = serving(ABC)
    doc: Any = http_doc(NEAR_P.doc)
    out = run(lambda c: confirm(doc, NEAR_P.binding, NEAR_P.account, c), link)
    assert (code(out), getattr(out, "detail", None)) == ("offer-unreadable", "mpp/link-not-https")
    assert link.calls == 0


def test_mpp_charge_nearintents_b16_other_namespace_and_network() -> None:
    others = [f"near:mainnet:{NEAR['fixed']['request']['methodDetails']['destinationRecipient']}", f"eip155:1:{REFUND_TO}"]
    for acct in others:
        link = serving(ABC)
        assert code(run(lambda c: confirm(NEAR_P.doc, NEAR_P.binding, acct, c), link)) == "no-payable-option"
        assert link.calls == 0
