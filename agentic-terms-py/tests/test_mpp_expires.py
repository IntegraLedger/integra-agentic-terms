"""expires, read per pairing. The core draft makes expires a SHOULD for servers (draft-httpauth-payment-01 L324), and
the charge intent's "REQUIRED for blockchain methods" is an example of a method elevating it
(draft-payment-intent-charge-00 L143-145). A pairing needs it where its build writes it into what the payer signs: the
EIP-3009 validBefore, the Permit2 deadline and the session openings' deadline; and on NEAR Intents, whose draft says expires "MUST be set to the 1Click quote
deadline" (draft-nearintents-charge-01 L414-415), and on the XRP Ledger charge, whose draft says "The server MUST reject
a credential whose challenge carries no expires" (draft-xrpl-charge-00 L391-392). Without expires those pairings are
left out, and a challenge left with none is mpp/expires-required, as the protocol package's pairingsOf answers."""

import json
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_EVM_AUTHORIZATION, MPP_CHARGE_EVM_TRANSACTION, Refusal
from integraledger_terms.bindings._mpp import NEEDS_EXPIRES, MppUnsigned, pairings_of

from mpp_docs import MC, issued, place, placed_doc
from support import PENDING, VECTORS, load, migrating

REQUIRED = Refusal("mpp/expires-required")
H: str = MC["fixed"]["H"]
LINK: str = MC["fixed"]["link"]
FROM = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
TOKEN_DOMAIN = {"name": "USD Coin", "version": "2"}
# Each vector file's first buyer row that presents a credential, whose echoed challenge is the file's challenge as
# placed; the files of pairings this package has no binding for yet (PENDING) are left out.
ROWS: list[tuple[str, dict[str, Any]]] = [
    (f.name, row)
    for f in sorted(VECTORS.glob("mpp-*.json"))
    for row in [next((r for r in load(f.name).get("buyer", {}).get("rows", []) if "challenge" in r["input"].get("presented", {})), None)]
    if row is not None and row["pairing"] not in PENDING
]


def without_expires(c: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in c.items() if k != "expires"}


@pytest.mark.parametrize(
    "row", [pytest.param(row, id=file, marks=migrating(row["pairing"])) for file, row in ROWS]
)
def test_each_vector_files_challenge_without_expires_offers_its_pairings_that_do_not_need_it(row: dict[str, Any]) -> None:
    offer = {k: v for k, v in row["input"]["presented"]["challenge"].items() if k not in ("id", "opaque")}
    named = pairings_of(offer)
    assert isinstance(named, tuple) and named
    kept = tuple(p for p in named if p not in NEEDS_EXPIRES)
    assert pairings_of(without_expires(offer)) == (kept or REQUIRED)
    assert pairings_of({**offer, "expires": "tomorrow"}) == REQUIRED


def test_card_stripe_and_the_evm_transaction_and_hash_charges_need_none() -> None:
    card = without_expires(issued("card", "charge", json.dumps(load("mpp-charge-card.json")["M1"]["request"])))
    assert pairings_of(card) == ("mpp/charge/card",)
    stripe = without_expires(issued("stripe", "charge", json.dumps(load("mpp-charge-stripe.json")["M2"]["request"])))
    assert pairings_of(stripe) == ("mpp/charge/stripe",)
    subscription = load("mpp-subscription-stripe.json")["S1"]["request"]
    assert pairings_of(without_expires(issued("stripe", "subscription", json.dumps(subscription)))) == (
        "mpp/subscription/stripe",
    )
    evm = without_expires(issued("evm", "charge", load("mpp-charge-evm-transaction.json")["fixed"]["R_ENoTypes"]))
    assert pairings_of(evm) == ("mpp/charge/evm/transaction", "mpp/charge/evm/hash")


def test_pairings_of_place_and_build_read_alike() -> None:
    r = json.loads(MC["fixed"]["R_E"])
    mixed = {**r, "methodDetails": {**r["methodDetails"], "credentialTypes": ["authorization", "transaction"]}}
    offer = without_expires(issued("evm", "charge", json.dumps(mixed)))
    assert pairings_of(offer) == ("mpp/charge/evm/transaction",)
    placed = placed_doc(offer, H, LINK)[0]
    assert "expires" not in placed
    choice = {"challenge": placed, "from": FROM, "now": 0, "tokenDomain": TOKEN_DOMAIN}
    assert MPP_CHARGE_EVM_AUTHORIZATION.build(choice, H) == Refusal("mpp/not-this-pairing")
    built = MPP_CHARGE_EVM_TRANSACTION.build({"challenge": placed, "from": FROM, "now": 0}, H)
    assert isinstance(built, MppUnsigned) and built.request["kind"] == "evm-call"
    both = without_expires(issued("evm", "charge", MC["fixed"]["R_E"]))
    assert place([both], H, LINK, both) == REQUIRED
    unexpired = without_expires(placed_doc(issued("evm", "charge", MC["fixed"]["R_E"]), H, LINK)[0])
    choice = {"challenge": unexpired, "from": FROM, "now": 0, "tokenDomain": TOKEN_DOMAIN}
    assert MPP_CHARGE_EVM_AUTHORIZATION.build(choice, H) == REQUIRED
