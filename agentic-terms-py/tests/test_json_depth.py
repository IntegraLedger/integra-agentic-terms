"""One JSON nesting cap of 64 levels for every read of JSON text by a binding: core-vectors.json's jsonDepth rows,
binding reads of text nested 64 and 65 levels deep, and the ACP, UCP and ACK reads, which measure a document as
JSON.stringify writes it, the document being level 1. core-vectors.json's jsonNumbers rows: an integer literal of any
length reads as JSON.parse reads it. The binding codes are those @integraledger/lcp's same reads give
for the same inputs: its ACK and AP2 read, usdcRequestHash, atrNamesInvoice, and jsonBytes, which measures a value
nested past 64 levels as over every size limit and writes an integer past the double range, which JSON.parse reads as
Infinity, as null."""

import base64
import json
import math
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
from integraledger_terms.bindings._jose import MAX_JSON_DEPTH, UNPARSED, json_bytes, json_within_depth, parse_json
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


def test_json_numbers_rows() -> None:
    rows = CORE["jsonNumbers"]["rows"]
    assert [len(r["text"]) - len('{"n":}') for r in rows] == [4301, 400]
    for row in rows:
        assert json_within_depth(row["text"]) is True, row["name"]
        value = parse_json(row["text"])
        assert value == {"n": math.inf}, row["name"]
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
