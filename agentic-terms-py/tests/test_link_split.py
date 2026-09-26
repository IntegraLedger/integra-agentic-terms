"""The link beside the hash takes the agreement URL's split at every reading: link-not-https only for a string of at
most 2048 characters that parses as an absolute URL whose scheme is not https, and legal-context-malformed for every
other value the https-link rule refuses. Expected values are core-vectors.json's links rows (refusedAs), and each
document is its vector file's with the link replaced."""

import base64
import json
from typing import Any

import pytest
from support import load

from integraledger_terms import (
    CARD_VISA_TAP,
    MPP_CHARGE_NEARINTENTS,
    UCP_CHECKOUT_UNSIGNED,
    X402_EXACT_EIP155_EIP3009,
    Refusal,
)
from integraledger_terms.bindings._lcp import is_hash_with_non_https_link
from integraledger_terms.bindings._x402 import legal_context_of

LINKS: list[dict[str, Any]] = load("core-vectors.json")["links"]["rows"]
X = load("x402-exact-eip155-eip3009.json")["fixed"]
CARD = load("card.json")
UCP = load("ucp.json")
NI = load("mpp-charge-nearintents.json")


def _replaced(doc: Any, old: str, new: str) -> Any:
    return json.loads(json.dumps(doc, ensure_ascii=False).replace(json.dumps(old)[1:-1], json.dumps(new, ensure_ascii=False)[1:-1]))


def _opaque(h: str, link: str) -> str:
    text = json.dumps({"legalContext": f"lcp:sha256:{h}", "legalContextUrl": link}, separators=(",", ":"), ensure_ascii=False)
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def _outcome(got: object, h: str) -> tuple[str, str] | str:
    if isinstance(got, Refusal):
        return got.code
    if isinstance(got, tuple):
        return got[0], got[1]
    return got.h, got.link  # type: ignore[attr-defined]


def test_the_rows_cover_each_kind_of_refused_value() -> None:
    assert {r["refusedAs"] for r in LINKS} == {"accepted", "link-not-https", "legal-context-malformed"}
    assert [r["accept"] for r in LINKS] == [r["refusedAs"] == "accepted" for r in LINKS]


@pytest.mark.parametrize("row", LINKS, ids=[r["name"] for r in LINKS])
def test_each_reading_splits_the_link(row: dict[str, Any]) -> None:
    link, fault = row["link"], row["refusedAs"]

    def expect(ns: str, h: str) -> tuple[str, str] | str:
        return (h, link) if fault == "accepted" else f"{ns}/{fault}"

    h = X["H"]
    info = {"type": "sha256", "value": h, "legalContextUrl": link}
    assert is_hash_with_non_https_link({"type": "sha256", "value": h, "legal_context_url": link}) is (fault == "link-not-https")
    assert _outcome(legal_context_of({"legalContext": {"info": info}}), h) == expect("x402", h)
    doc = {"x402Version": 2, "resource": X["resource"], "accepts": [X["O"]], "extensions": {"legalContext": {"info": info}}}
    assert _outcome(X402_EXACT_EIP155_EIP3009.read(doc), h) == expect("x402", h)

    ch = CARD["fixed"]["H"]
    values = _replaced(CARD["C1"]["advertise"]["expect"], CARD["fixed"]["link"], link)
    assert _outcome(CARD_VISA_TAP.read(values), ch) == expect("card", ch)

    uh = UCP["V2"]["advertise"]["h"]
    checkout = _replaced(UCP["V2"]["expectCheckout"], UCP["V2"]["advertise"]["link"], link)
    assert _outcome(UCP_CHECKOUT_UNSIGNED.read(checkout), uh) == expect("ucp", uh)

    nh = NI["fixed"]["H"]
    challenge = {**NI["place"]["expect"], "opaque": _opaque(nh, link)}
    assert _outcome(MPP_CHARGE_NEARINTENTS.read([challenge]), nh) == expect("mpp", nh)


ACP = load("acp-checkout.json")
AP2 = load("ap2-checkout-mandate.json")
ACK = load("ack-payment-request.json")
LONG = "https://atr.seller.example/" + "a" * (2049 - len("https://atr.seller.example/"))


def _b64u(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def test_an_https_link_over_2048_characters_is_malformed_at_every_reading() -> None:
    from integraledger_terms import ACK_PAYMENT_REQUEST, ACP_CHECKOUT_DELEGATED, AP2_CHECKOUT_MANDATE

    assert len(LONG) == 2049
    got = {}
    doc = {"x402Version": 2, "resource": X["resource"], "accepts": [X["O"]]}
    doc["extensions"] = {"legalContext": {"info": {"type": "sha256", "value": X["H"], "legalContextUrl": LONG}}}
    got["x402"] = X402_EXACT_EIP155_EIP3009.read(doc)
    got["card"] = CARD_VISA_TAP.read(_replaced(CARD["C1"]["advertise"]["expect"], CARD["fixed"]["link"], LONG))
    got["ucp"] = UCP_CHECKOUT_UNSIGNED.read(_replaced(UCP["V2"]["expectCheckout"], UCP["V2"]["advertise"]["link"], LONG))
    got["mpp"] = MPP_CHARGE_NEARINTENTS.read([{**NI["place"]["expect"], "opaque": _opaque(NI["fixed"]["H"], LONG)}])
    got["acp"] = ACP_CHECKOUT_DELEGATED.read(_replaced(ACP["V2"]["expectSession"], ACP["V2"]["advertise"]["link"], LONG))
    payload = _replaced(AP2["V2"]["expectPayload"], AP2["V2"]["advertise"]["link"], LONG)
    jws = f"{_b64u(AP2['fixed']['jwtHeader'])}.{_b64u(json.dumps(payload))}.{AP2['fixed']['signature']}"
    got["ap2"] = AP2_CHECKOUT_MANDATE.read(jws)
    lc = _replaced(ACK["K1"]["expect"]["legalContext"], ACK["K1"]["advertise"]["link"], LONG)
    got["ack"] = ACK_PAYMENT_REQUEST.read({**ACK["K2"]["body"], "legalContext": lc})
    assert {k: getattr(v, "code", v) for k, v in got.items()} == {k: f"{k}/legal-context-malformed" for k in got}
