"""Every x402 pairing's bound holds a presented payment's accepted to the option filter its own read applies.

The payments are the ones @integraledger/lcp's x402 vector files hold, and the pairings are the ones those files'
boundAccepted rows name. x402 v2's PaymentPayload carries accepted, the PaymentRequirements object the payer chose
(specs/x402-specification-v2.md at x402-foundation/x402 e95b06661e), and the protocol package's refusal list gives
x402/payload-malformed for a presented payment whose accepted is not an object."""

from collections.abc import Iterator
from typing import Any

import pytest

import integraledger_terms
from integraledger_terms import Refusal

from support import VECTORS, load

X402_FILES = sorted(path.name for path in VECTORS.glob("x402-*.json"))
BINDINGS: dict[str, Any] = {
    binding.id: binding
    for binding in (getattr(integraledger_terms, name) for name in integraledger_terms.__all__)
    if isinstance(getattr(binding, "id", None), str) and binding.id.startswith("x402/")
}


def payments_in(value: Any) -> Iterator[dict[str, Any]]:
    """Every x402 v2 payment in a vector file: an object with x402Version 2, an object accepted and an object
    payload."""
    if isinstance(value, list):
        for item in value:
            yield from payments_in(item)
    elif isinstance(value, dict):
        if value.get("x402Version") == 2 and isinstance(value.get("accepted"), dict) and isinstance(value.get("payload"), dict):
            yield value
        for item in value.values():
            yield from payments_in(item)


PAYMENTS = [payment for name in X402_FILES for payment in payments_in(load(name))]


def test_the_x402_bindings_are_the_pairings_the_vector_files_name() -> None:
    named = {row["pairing"] for name in X402_FILES for row in load(name).get("boundAccepted", {}).get("rows", [])}
    assert named, "the x402 vector files hold no boundAccepted rows"
    assert set(BINDINGS) == named


_REMOVED = object()
NOT_AN_OBJECT: list[tuple[str, object]] = [
    ("null", None),
    ("a string", "exact"),
    ("a number", 2),
    ("an array", []),
    ("removed", _REMOVED),
]


@pytest.mark.parametrize("pairing", sorted(BINDINGS))
def test_a_presented_payment_whose_accepted_is_not_an_object_is_payload_malformed(pairing: str) -> None:
    """A vector payment the pairing's bound binds, with accepted replaced by each value that is not an object, or
    removed: bound refuses it x402/payload-malformed."""
    binding = BINDINGS[pairing]
    payment = next((p for p in PAYMENTS if not isinstance(binding.bound(p), Refusal)), None)
    assert payment is not None, f"no vector payment that {pairing}'s bound binds"
    for what, value in NOT_AN_OBJECT:
        presented = {k: v for k, v in payment.items() if k != "accepted"}
        if value is not _REMOVED:
            presented["accepted"] = value
        assert (what, binding.bound(presented)) == (what, Refusal("x402/payload-malformed"))


def at(doc: Any, pointer: str) -> Any:
    """The value at a JSON Pointer (RFC 6901) into doc."""
    for token in pointer.split("/")[1:]:
        key = token.replace("~1", "/").replace("~0", "~")
        doc = doc[int(key)] if isinstance(doc, list) else doc[key]
    return doc


def offering(option: Any) -> dict[str, Any]:
    """A document offering the option alone, with a legal context."""
    info = {"type": "sha256", "value": "0x" + "00" * 32, "legalContextUrl": "https://pairing.invalid/"}
    return {
        "x402Version": 2,
        "resource": {"url": "https://pairing.invalid/"},
        "accepts": [option],
        "extensions": {"legalContext": {"info": info}},
    }


ROWS = [
    (name, i, row, at(load(name), row["payment"]))
    for name in X402_FILES
    for i, row in enumerate(load(name).get("boundAccepted", {}).get("rows", []))
]


def test_the_x402_vector_files_hold_a_bound_accepted_row_for_every_pairing() -> None:
    assert ROWS, "the x402 vector files hold no boundAccepted rows"
    assert {row["pairing"] for _, _, row, _ in ROWS} == set(BINDINGS)


@pytest.mark.parametrize(("name", "i", "row", "payment"), ROWS, ids=[f"{n} boundAccepted.rows[{i}]" for n, i, _, _ in ROWS])
def test_a_bound_accepted_row_is_refused_with_its_code(name: str, i: int, row: dict[str, Any], payment: dict[str, Any]) -> None:
    """The file's payment, which the row's pairing binds, presented under the row's option, which its read does not
    offer: bound refuses it with the row's code."""
    binding = BINDINGS[row["pairing"]]
    assert not isinstance(binding.bound(payment), Refusal), row["case"]
    assert binding.bound({**payment, "accepted": row["accepted"]}) == Refusal(row["expect"]), row["case"]
    assert binding.read(offering(row["accepted"])) == Refusal("x402/no-payable-option"), row["case"]


def test_the_aptos_payment_the_rows_present_is_bound() -> None:
    """x402-exact-aptos.json holds no signed payment, so its boundAccepted section carries one, whose transaction bound
    reads only as a string: under its own option bound gives the echoed legal context's hash."""
    v = load("x402-exact-aptos.json")
    payment = v["boundAccepted"]["payment"]
    rows = [row for _, _, row, _ in ROWS if row["pairing"] == "x402/exact/aptos"]
    assert rows and all(row["payment"] == "/boundAccepted/payment" for row in rows)
    h = payment["extensions"]["legalContext"]["info"]["value"]
    assert BINDINGS["x402/exact/aptos"].bound(payment) == h


@pytest.mark.parametrize(
    ("name", "pairing"),
    [
        ("x402-auth-capture-eip155-eip3009.json", "x402/auth-capture/eip155/eip3009"),
        ("x402-auth-capture-eip155-permit2.json", "x402/auth-capture/eip155/permit2"),
    ],
)
def test_an_auth_capture_payment_with_a_salt_nonce_under_an_unbound_option_is_salt_not_bound(name: str, pairing: str) -> None:
    """The auth-capture EVM scheme (scheme_auth_capture_evm.md at x402-foundation/x402 e95b06661e, "Payment
    identity"): with receiverAuthorizer and policy both absent or zero the payload's salt is the client's random 32
    bytes and it carries no saltNonce. A bound payment presented under its option with no receiver authorizer, which
    read offers, is refused with the row's code rather than answered with its salt."""
    row = load(name)["unboundSaltNonce"]
    payment = at(load(name), row["payment"])
    binding = BINDINGS[pairing]
    assert isinstance(binding.bound(payment), str)
    assert not isinstance(binding.read(offering(row["accepted"])), Refusal)
    assert binding.bound({**payment, "accepted": row["accepted"]}) == Refusal(row["expect"])
