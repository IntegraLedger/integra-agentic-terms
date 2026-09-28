"""An mpp/session/xrpl challenge's amount is the first claim's cumulative total in drops: a u64 written in decimal, with
no sign, point or leading zero (the XRP Ledger's Currency Formats: an XRP amount is a string of whole drops; the claim
signs it as a big-endian u64). The rail check refuses any other amount with mpp/request-malformed, so no challenge
offers the pairing and the gate declines before anything is signed, as the TypeScript gate does. Each document is
mpp-session-hedera-solana-xrpl.json's B2 document for this pairing with only request.amount replaced, the request
re-encoded as compact JSON in unpadded base64url (RFC 4648 section 5)."""

import base64
import json
from typing import Any

import pytest

from integraledger_terms import MPP_SESSION_XRPL, Confirmed, Declined, Refusal, confirm, transact
from integraledger_terms.bindings._mpp import pairings_of

from breadth import ABC, Recording, run
from support import load, serving

B2: dict[str, Any] = next(
    r["input"]
    for r in load("mpp-session-hedera-solana-xrpl.json")["buyer"]["rows"]
    if r["name"] == "B2" and r["pairing"] == "mpp/session/xrpl"
)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def with_amount(amount: object) -> list[dict[str, Any]]:
    """B2's document with request.amount replaced."""
    c = B2["doc"][0]
    request = json.loads(base64.urlsafe_b64decode(c["request"] + "=" * (-len(c["request"]) % 4)))
    request["amount"] = amount
    return [{**c, "request": b64url(json.dumps(request, separators=(",", ":")).encode("utf-8"))}]


def issued(doc: list[dict[str, Any]]) -> dict[str, Any]:
    """The challenge as issued: without the opaque that carries the legal context."""
    return {k: v for k, v in doc[0].items() if k != "opaque"}


REFUSED: list[tuple[str, object]] = [
    ("the JSON number 1000", 1000),
    ("the JSON number 0", 0),
    ("an empty array", []),
    ("a nested array", [[]]),
    ("true", True),
    ("a decimal fraction", "1.5"),
    ("a negative number", "-1"),
    ("a leading zero", "0100"),
    ("2^64, one above the largest u64", "18446744073709551616"),
]
ACCEPTED = [("B2's own 100", "100"), ("2^64 - 1, the largest u64", "18446744073709551615")]


def never(request: Any) -> Any:
    raise AssertionError("the signer is never called")


@pytest.mark.parametrize(("name", "amount"), REFUSED, ids=[n for n, _ in REFUSED])
def test_an_amount_that_is_not_a_u64_of_drops_is_declined_before_the_signer(name: str, amount: object) -> None:
    doc = with_amount(amount)
    assert pairings_of(issued(doc)) == Refusal("mpp/request-malformed")
    signer = Recording(B2["account"], never)
    out = run(lambda c: transact(doc, MPP_SESSION_XRPL, signer, c, inputs=B2["inputs"]), serving(ABC))
    assert isinstance(out, Declined) and (out.code, out.detail) == ("no-payable-option", "mpp/no-payable-option")
    assert signer.requests == []
    confirmed = run(lambda c: confirm(doc, MPP_SESSION_XRPL, B2["account"], c, B2["inputs"]), serving(ABC))
    assert isinstance(confirmed, Declined)
    assert (confirmed.code, confirmed.detail) == ("no-payable-option", "mpp/no-payable-option")


@pytest.mark.parametrize(("name", "amount"), ACCEPTED, ids=[n for n, _ in ACCEPTED])
def test_a_u64_of_drops_is_offered_and_the_opening_reaches_the_signer(name: str, amount: str) -> None:
    doc = with_amount(amount)
    assert pairings_of(issued(doc)) == ("mpp/session/xrpl",)
    out = run(lambda c: confirm(doc, MPP_SESSION_XRPL, B2["account"], c, B2["inputs"]), serving(ABC))
    assert isinstance(out, Confirmed), out
    assert out.request is not None and out.request["kind"] == "xrpl-session-open"
