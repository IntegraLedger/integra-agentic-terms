"""Every binding's broadcaster against @integraledger/lcp's broadcaster.json: who puts what a payer presents on its
rail, "payer" or "payee", and, for a payment of a type, kind or shape the pairing does not take, the refusal of what
reads it. Each pairings and kinds row's source names the specification its answer is read from.

The file's pairings rows give each pairing once, with its answer where every payment it takes has the same one and
null where it answers by kind; its kinds rows give answers for credentials of each kind; its refusals rows give the
code bound and broadcaster each give, or, where a row carries bound, the code bound gives and the code channel_kind
and broadcaster each give. A value {"$repeat": [s, n]} in a row stands for s repeated n times. The payments each
pairing takes are read from the protocol package's own vector files."""

from collections.abc import Iterator
from typing import Any

import pytest

import integraledger_terms as terms
from integraledger_terms import Refusal
from integraledger_terms.bindings._mpp import Held

from support import VECTORS, load

FILE = load("broadcaster.json")
BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.isupper() and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}


def rows(name: str, exact: int) -> list[dict[str, Any]]:
    """The file's rows of name, which must number exact."""
    found: list[dict[str, Any]] = FILE[name]
    assert len(found) == exact, f"broadcaster.json {name}: {len(found)} rows, {exact} expected"
    return found


PAIRINGS = rows("pairings", 67)
KINDS = rows("kinds", 35)
REFUSALS = rows("refusals", 37)
ANSWER: dict[str, str | None] = {row["pairing"]: row["broadcaster"] for row in PAIRINGS}
BY_KIND = sorted(pairing for pairing, answer in ANSWER.items() if answer is None)


def expand(value: Any) -> Any:
    """A row's value with each {"$repeat": [s, n]} replaced by s repeated n times."""
    if isinstance(value, list):
        return [expand(item) for item in value]
    if not isinstance(value, dict):
        return value
    repeat = value.get("$repeat")
    if isinstance(repeat, list):
        text: str = repeat[0] * repeat[1]
        return text
    return {key: expand(item) for key, item in value.items()}


def code(value: object) -> object:
    """A refusal's code, or the answer itself."""
    return value.code if isinstance(value, Refusal) else value


def test_every_binding_has_broadcaster_and_the_file_names_every_pairing_once() -> None:
    assert len(BINDINGS) == 67
    assert [row["pairing"] for row in PAIRINGS] == list(ANSWER)
    assert sorted(ANSWER) == sorted(BINDINGS)
    assert [p for p, b in sorted(BINDINGS.items()) if not callable(getattr(b, "broadcaster", None))] == []
    assert set(ANSWER.values()) == {"payer", "payee", None}


def test_each_pairing_that_answers_by_kind_has_a_credential_of_each_answer() -> None:
    assert len(BY_KIND) == 9
    for pairing in BY_KIND:
        answers = sorted({row["expect"] for row in KINDS if row["pairing"] == pairing})
        assert (pairing, answers) == (pairing, ["payee", "payer"])


@pytest.mark.parametrize("index", range(len(KINDS)), ids=[row["case"] for row in KINDS])
def test_kinds(index: int) -> None:
    """Each kinds row's answer, and the same answer for the credential with a read held for it in Held, as the
    protocol package holds one under the payment's own FETCHED member."""
    row = KINDS[index]
    answer = ANSWER[row["pairing"]]
    if answer is not None:
        assert row["expect"] == answer
    binding = BINDINGS[row["pairing"]]
    presented = expand(row["presented"])
    assert binding.broadcaster(presented) == row["expect"]
    assert binding.broadcaster(Held(presented, {"transaction": "x"})) == row["expect"]


@pytest.mark.parametrize("index", range(len(REFUSALS)), ids=[row["case"] for row in REFUSALS])
def test_refusals(index: int) -> None:
    """Each refusals row's code from bound and broadcaster; where the row carries bound, the action is one bound does
    not read, and channel_kind gives the row's code."""
    row = REFUSALS[index]
    binding = BINDINGS[row["pairing"]]
    presented = expand(row["presented"])
    assert (code(binding.bound(presented)), code(binding.broadcaster(presented))) == (
        row.get("bound", row["expectRefusal"]),
        row["expectRefusal"],
    )
    if "bound" in row:
        assert code(binding.channel_kind(presented)) == row["expectRefusal"]


# The pairings whose bound binds nothing, each with the code it gives every payment within its gates: a payment that
# reaches that code is one the pairing takes.
BINDS_NOTHING = {
    "mpp/charge/evm/transaction": "mpp/no-signed-place",
    "mpp/charge/evm/hash": "mpp/no-signed-place",
    "mpp/charge/card": "mpp/no-signed-place",
    "mpp/charge/stripe": "mpp/no-signed-place",
    "mpp/subscription/stripe": "mpp/no-signed-place",
    "ack/payment-request": "ack/no-signed-place",
    "acp/checkout/undelegated": "acp/not-buyer-signed",
    "ucp/checkout/unsigned": "ucp/not-buyer-signed",
    "ucp/booking/unsigned": "ucp/not-buyer-signed",
    "card/seller-reference": "card/no-signed-place",
}
PRESENTED_KEYS = ("payload", "allowance", "checkout_mandate", "signatureInput", "l2")


def presented_in(value: Any, depth: int = 0) -> Iterator[dict[str, Any]]:
    """Every object in a vector file that can be presented: one carrying a payload, an allowance, a checkout mandate,
    a TAP signature input or a VI L2."""
    if depth > 14:
        return
    if isinstance(value, dict):
        if any(key in value for key in PRESENTED_KEYS):
            yield value
        for item in value.values():
            yield from presented_in(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from presented_in(item, depth + 1)


CANDIDATES = [
    p
    for path in sorted(VECTORS.glob("*.json"))
    if path.name != "broadcaster.json"
    for p in presented_in(load(path.name))
] + [row["presented"] for row in KINDS]


def taken(binding: Any) -> list[Any]:
    """Up to four vector payments the pairing takes: bound binds each, gives it the code it gives every payment, or
    gives it a .../read-first code, which bound gives a payment the payer broadcast until the seller's read is held."""
    found: list[Any] = []
    for c in CANDIDATES:
        if len(found) == 4:
            break
        b = binding.bound(c)
        if not isinstance(b, Refusal) or b.code == BINDS_NOTHING.get(binding.id) or b.code.endswith("/read-first"):
            found.append(c)
    return found


@pytest.mark.parametrize("pairing", list(ANSWER))
def test_pairings(pairing: str) -> None:
    """broadcaster answers each payment the pairing takes: the pairings row's answer where it has one, and an answer
    by kind where it has none, the same with a read held for the payment."""
    binding = BINDINGS[pairing]
    payments = taken(binding)
    assert payments, f"{pairing}: no vector payment the pairing takes"
    for presented in payments:
        answer = binding.broadcaster(presented)
        assert answer in ("payer", "payee"), (pairing, answer)
        if ANSWER[pairing] is not None:
            assert answer == ANSWER[pairing]
        if isinstance(presented, dict):
            assert binding.broadcaster(Held(presented, {"transaction": "x"})) == answer
