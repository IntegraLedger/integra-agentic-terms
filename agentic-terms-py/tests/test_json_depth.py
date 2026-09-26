"""One JSON nesting cap of 64 levels for every read of JSON text by a binding: core-vectors.json's jsonDepth rows, and
binding reads of text nested 64 and 65 levels deep. The binding codes are those @integraledger/lcp's same reads give
for the same inputs: its ACK and AP2 read, usdcRequestHash and atrNamesInvoice."""

import base64
import json
from typing import Any

from support import load

from integraledger_terms import ACK_PAYMENT_REQUEST, AP2_CHECKOUT_MANDATE, Advertised, Refusal
from integraledger_terms.bindings._jose import MAX_JSON_DEPTH, UNPARSED, json_within_depth, parse_json
from integraledger_terms.bindings.lightning import atr_names_invoice
from integraledger_terms.bindings.mpp_charge_usdc import usdc_request_hash

CORE = load("core-vectors.json")
ACK = load("ack-payment-request.json")
AP2 = load("ap2-checkout-mandate.json")


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
        text = '{"x402":{"accepts":[{"extra":{"invoice":"lnbc1"}}]},"z":' + arrays(levels - 1) + "}"
        return text.encode("utf-8")

    assert atr_names_invoice(atr(64), "lnbc1") is True
    assert atr_names_invoice(atr(65), "lnbc1") is False
    assert json.loads(atr(64))["x402"]["accepts"][0]["extra"]["invoice"] == "lnbc1"
