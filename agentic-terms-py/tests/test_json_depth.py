"""One JSON nesting cap of 64 levels for every read of JSON text by a binding: core-vectors.json's jsonDepth rows, read
and written as the protocol package writes JSON, binding reads of text nested 64 and 65 levels deep, and the ACP, UCP and ACK reads, which measure a document as
JSON.stringify writes it, the document being level 1. core-vectors.json's jsonNumbers rows: an integer literal of any
length reads as JSON.parse reads it. The binding codes are those @integraledger/lcp's same reads give
for the same inputs: its ACK and AP2 read, usdcRequestHash, atrNamesInvoice, and jsonBytes, which measures a value
nested past 64 levels as over every size limit and writes an integer past the double range, which JSON.parse reads as
Infinity, as null."""

import base64
import json
from typing import Any

import pytest
from support import load

from integraledger_terms import (
    ACK_PAYMENT_REQUEST,
    ACP_CHECKOUT_DELEGATED,
    AP2_CHECKOUT_MANDATE,
    UCP_CHECKOUT_UNSIGNED,
    Advertised,
    Binding,
    Refusal,
)
from integraledger_terms.bindings._codec import MAX_JSON_DEPTH, js_json
from integraledger_terms.bindings._jose import UNPARSED, json_bytes, json_within_depth, parse_json, within_depth
from integraledger_terms.bindings.lightning import atr_names_invoice
from integraledger_terms.bindings.mpp_charge_usdc import usdc_request_hash

CORE = load("core-vectors.json")
ACK = load("ack-payment-request.json")
AP2 = load("ap2-checkout-mandate.json")
ACP = load("acp-checkout.json")
UCP = load("ucp.json")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def arrays(levels: int, broken: bool = False) -> str:
    return "[" * levels + ("," if broken else "") + "]" * levels


def with_deep(object_text: str, levels: int, broken: bool = False) -> str:
    """A JSON object's text with a member holding levels - 1 nested arrays, so the object nests levels deep."""
    return object_text[:-1] + ',"deep":' + arrays(levels - 1, broken) + "}"


def test_json_depth_rows() -> None:
    assert MAX_JSON_DEPTH == CORE["jsonDepth"]["max"] == 64
    rows = CORE["jsonDepth"]["rows"]
    assert [r["name"] for r in rows] == [f"JD{i}" for i in range(1, 8)]
    for row in rows:
        assert json_within_depth(row["text"]) is row["accept"], row["name"]
        assert (parse_json(row["text"]) is not UNPARSED) is row["accept"], row["name"]
        parsed = json.loads(row["text"]) if row["accept"] else None
        if parsed is not None:
            assert within_depth(parsed), row["name"]


def test_a_value_within_depth_64_levels_counted_as_its_json_text_is() -> None:
    # within_depth measures the lists, tuples and dicts json.dumps writes as arrays and objects, without recursion, as
    # json_within_depth measures the text: 64 levels hold and 65 do not, at any depth and on any shape, a cycle
    # included, which json.dumps would not write.
    def nested(levels: int, inner: object) -> object:
        v: object = inner
        for i in range(levels):
            v = [v] if i % 2 else {"n": v}
        return v

    for levels in (1, 63, 64, 65, 100_000):
        inner: object
        for inner in (0, [], {}):
            value = nested(levels, inner)
            deep = levels + (1 if isinstance(inner, (list, dict)) else 0)
            assert within_depth(value) is (deep <= MAX_JSON_DEPTH), (levels, inner)
            if deep <= 2 * MAX_JSON_DEPTH:
                assert json_within_depth(json.dumps(value)) is within_depth(value), (levels, inner)
    assert within_depth(0) and within_depth("[[[") and within_depth(()) and not within_depth(nested(65, ()))
    cycle: list[object] = []
    cycle.append(cycle)
    assert not within_depth(cycle)


def as_tuples(value: Any) -> Any:
    if isinstance(value, list):
        return tuple(as_tuples(v) for v in value)
    if isinstance(value, dict):
        return {k: as_tuples(v) for k, v in value.items()}
    return value


def test_js_json_writes_what_the_json_depth_rows_accept() -> None:
    # Each jsonDepth row's value, read without the cap, is written as its text when the row accepts it and raises when
    # it does not, as a list and as a tuple.
    for row in CORE["jsonDepth"]["rows"]:
        value = json.loads(row["text"])
        for form in (value, as_tuples(value)):
            if row["accept"]:
                assert js_json(form) == row["text"], row["name"]
            else:
                with pytest.raises(ValueError):
                    js_json(form)


@pytest.mark.parametrize(
    "nested",
    [
        lambda n: "[" * n + "]" * n,
        lambda n: "[" * n + "0" + "]" * n,
        lambda n: '{"a":' * (n - 1) + "{}" + "}" * (n - 1),
        lambda n: '{"a":' * n + "null" + "}" * n,
    ],
    ids=["arrays", "arrays-holding-a-number", "objects", "objects-holding-null"],
)
def test_js_json_writes_64_levels_and_refuses_65(nested: Any) -> None:
    # The protocol package writes no array or object at depth 64 or more, counted from 0 at the value: 64 levels are
    # written, 65 raise, whether the innermost container is empty or holds a value.
    assert js_json(json.loads(nested(64))) == nested(64)
    with pytest.raises(ValueError):
        js_json(json.loads(nested(65)))
    with pytest.raises(ValueError):
        js_json(as_tuples(json.loads(nested(65))))


def test_json_numbers_rows() -> None:
    # Every row that gives a text and what JSON.stringify writes for its JSON.parse value: the text reads as JSON.parse
    # reads it, and is written, and measured, as JSON.stringify writes it. At least one row is read.
    rows = [
        r
        for r in CORE.get("jsonNumbers", {}).get("rows", [])
        if isinstance(r.get("text"), str) and isinstance(r.get("stringified"), str)
    ]
    assert rows, "no jsonNumbers row gives a text and its stringified form"
    for row in rows:
        value = parse_json(row["text"])
        assert value is not UNPARSED, row["name"]
        assert js_json(value, null_non_finite=True) == row["stringified"], row["name"]
        assert json_bytes(value) == len(row["stringified"].encode("utf-8")), row["name"]


def test_ack_token_payload_nested_past_64_is_token_malformed() -> None:
    head, body, sig = ACK["K2"]["body"]["paymentRequestToken"].split(".")
    text = unb64u(body).decode("utf-8")

    def read(levels: int, broken: bool = False) -> Any:
        token = f"{head}.{b64u(with_deep(text, levels, broken).encode())}.{sig}"
        return ACK_PAYMENT_REQUEST.read({**ACK["K2"]["body"], "paymentRequestToken": token})

    assert isinstance(read(64), Advertised)
    for levels, broken in ((65, False), (1000, False), (1000, True)):
        assert read(levels, broken) == Refusal("ack/token-malformed"), levels


def test_ap2_checkout_payload_nested_past_64_is_too_large() -> None:
    head, body, sig = AP2["built"]["J"].split(".")
    text = unb64u(body).decode("utf-8")

    def read(levels: int, broken: bool = False) -> Any:
        return AP2_CHECKOUT_MANDATE.read(f"{head}.{b64u(with_deep(text, levels, broken).encode())}.{sig}")

    assert isinstance(read(64), Advertised)
    assert read(65) == Refusal("ap2/too-large")
    assert read(1000) == Refusal("ap2/too-large")
    assert read(100_000) == Refusal("ap2/too-large")
    assert read(1000, broken=True) == Refusal("ap2/jws-malformed")
    assert read(100_000, broken=True) == Refusal("ap2/jws-malformed")


def test_mpp_usdc_request_nested_past_64_is_request_malformed() -> None:
    assert isinstance(usdc_request_hash(b64u(('{"a":' + arrays(63) + "}").encode())), str)
    assert usdc_request_hash(b64u(('{"a":' + arrays(64) + "}").encode())) == Refusal("mpp/request-malformed")


def test_lightning_atr_nested_past_64_is_not_read() -> None:
    def atr(levels: int) -> bytes:
        head = '{"atrVersion":"1","id":"i","x402":{"accepts":[{"extra":{"invoice":"lnbc1"}}]},"z":'
        text = head + arrays(levels - 1) + "}"
        return text.encode("utf-8")

    assert atr_names_invoice(atr(64), "lnbc1") is True
    assert atr_names_invoice(atr(65), "lnbc1") is False
    assert json.loads(atr(64))["x402"]["accepts"][0]["extra"]["invoice"] == "lnbc1"


def nested_arrays(count: int) -> list[Any]:
    """count arrays, each holding the next."""
    value: list[Any] = []
    for _ in range(count - 1):
        value = [value]
    return value


MEASURED = [
    (ACP_CHECKOUT_DELEGATED, ACP["V2"]["expectSession"], "acp/too-large"),
    (UCP_CHECKOUT_UNSIGNED, UCP["V2"]["expectCheckout"], "ucp/too-large"),
    (ACK_PAYMENT_REQUEST, ACK["K2"]["body"], "ack/too-large"),
]


@pytest.mark.parametrize(("binding", "doc", "too_large"), MEASURED, ids=lambda v: getattr(v, "id", ""))
def test_a_document_nested_past_64_levels_is_too_large(binding: Binding, doc: dict[str, Any], too_large: str) -> None:
    assert isinstance(binding.read({**doc, "x": nested_arrays(63)}), Advertised)
    assert binding.read({**doc, "x": nested_arrays(64)}) == Refusal(too_large)
    assert binding.read({**doc, "x": nested_arrays(99_999)}) == Refusal(too_large)


@pytest.mark.parametrize(("binding", "doc"), [(b, d) for b, d, _ in MEASURED], ids=lambda v: getattr(v, "id", ""))
def test_a_document_holding_an_integer_past_the_double_range_is_read(binding: Binding, doc: dict[str, Any]) -> None:
    assert isinstance(binding.read({**doc, "n": 10**399}), Advertised)
    assert isinstance(binding.read({**doc, "n": -(10**399)}), Advertised)
