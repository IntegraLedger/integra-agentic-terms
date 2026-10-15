"""A placed MPP challenge that the protocol package's checks do not name for a pairing offers that pairing nothing, so
the gate has no challenge it can pay: it declines no-payable-option, mpp/no-payable-option, before any fetch and with no
signer call, as buyer.json's BX1 answers for a placed challenge those checks refuse. The subjects are each vector file's
boundChallenge rows, each a challenge placed with the id and opaque of the file's B2 document and not named for the
row's pairing, given as the sole challenge with that B2 row's account, inputs and time. The card and Stripe files hold
no such rows: their subjects are B2's challenge with the member each pairing's checks read set to a value they refuse
(card: externalId, absent or a string; Stripe: methodDetails.metadata, an object within Stripe's bounds). The link
serves abc, whose SHA-256 (FIPS 180-2 B.1) is each document's H. Every expected value is lcp's: BX1's decline and
pairings_of's answer for the changed card and Stripe challenges. The TypeScript gate runs the same subjects
(mpp-refused-challenge.test.ts)."""

import copy
import json
from collections.abc import Callable
from typing import Any

import pytest
from breadth import ABC, Recording, code, run
from support import VECTORS, load, serving

import integraledger_terms as terms
from integraledger_terms import Refusal, _gate, confirm, transact
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode, canonical_json
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.pieces._mpp import pairings_of_placed

BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.startswith("MPP_") and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}
DECLINE = ("no-payable-option", "mpp/no-payable-option")


def b2_of(file: str, pairing: str) -> dict[str, Any]:
    rows = [r for r in load(file).get("buyer", {}).get("rows", []) if r["name"] == "B2" and r["pairing"] == pairing]
    assert len(rows) == 1, (file, pairing)
    row: dict[str, Any] = rows[0]
    return row


def issued(c: dict[str, Any]) -> dict[str, Any]:
    """The challenge as the seller issued it: no id and no opaque."""
    return {k: v for k, v in c.items() if k not in ("id", "opaque")}


def offered_alone(b2: dict[str, Any], challenge: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """The gate given challenge as the sole challenge, with the B2 row's account, inputs and time."""
    given = b2["input"]
    if "now" in given:
        monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    binding = BINDINGS[b2["pairing"]]
    inputs = given.get("inputs", {})
    link = serving(ABC)

    def never(request: Any) -> Any:
        raise AssertionError("the signer was called")

    signer = Recording(given["account"], never)
    out = run(lambda c: transact([copy.deepcopy(challenge)], binding, signer, c, inputs=inputs), link)
    assert (code(out), getattr(out, "detail", None)) == DECLINE, out
    assert signer.requests == []
    confirmed = run(lambda c: confirm([copy.deepcopy(challenge)], binding, given["account"], c, inputs), link)
    assert (code(confirmed), getattr(confirmed, "detail", None)) == DECLINE, confirmed
    assert link.calls == 0


ROWS: list[tuple[str, dict[str, Any]]] = [
    (f.name, row) for f in sorted(VECTORS.glob("mpp-*.json")) for row in load(f.name).get("boundChallenge", {}).get("rows", [])
]


def test_the_bound_challenge_rows_are_read() -> None:
    assert len(ROWS) > 0


@pytest.mark.parametrize(("file", "row"), ROWS, ids=[f"{f}: {r['case']}" for f, r in ROWS])
def test_a_challenge_the_filter_does_not_name_for_the_pairing_is_no_payable_option(
    file: str, row: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    b2 = b2_of(file, row["pairing"])
    own = b2["input"]["doc"][0]
    assert (row["challenge"]["id"], row["challenge"]["opaque"]) == (own["id"], own["opaque"])
    assert row["pairing"] in pairings_of_placed(own)
    assert row["pairing"] not in pairings_of_placed(row["challenge"])
    offered_alone(b2, row["challenge"], monkeypatch)


def set_metadata(r: dict[str, Any]) -> None:
    r["methodDetails"]["metadata"] = "abc"


def set_external_id(r: dict[str, Any]) -> None:
    r["externalId"] = 5


CHANGED: list[tuple[str, str, str, Callable[[dict[str, Any]], None], str]] = [
    ("mpp-charge-card.json", "mpp/charge/card", "externalId 5", set_external_id, "mpp/request-malformed"),
    ("mpp-charge-stripe.json", "mpp/charge/stripe", "methodDetails.metadata a string", set_metadata, "mpp/metadata-malformed"),
    ("mpp-subscription-stripe.json", "mpp/subscription/stripe", "methodDetails.metadata a string", set_metadata, "mpp/metadata-malformed"),
]


@pytest.mark.parametrize(("file", "pairing", "case", "change", "refused"), CHANGED, ids=[f"{p}: {c}" for _, p, c, _, _ in CHANGED])
def test_a_card_or_stripe_challenge_its_checks_refuse_is_no_payable_option(
    file: str, pairing: str, case: str, change: Callable[[dict[str, Any]], None], refused: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    b2 = b2_of(file, pairing)
    own = b2["input"]["doc"][0]
    assert pairing in pairings_of_placed(own)
    raw = b64u_decode(own["request"], 8192)
    assert raw is not None
    request: dict[str, Any] = json.loads(raw)
    change(request)
    challenge = {**own, "request": b64u_encode(canonical_json(request).encode("utf-8"))}
    assert pairings_of(issued(challenge)) == Refusal(refused)
    assert pairings_of_placed(challenge) == ()
    offered_alone(b2, challenge, monkeypatch)
