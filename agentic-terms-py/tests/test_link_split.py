"""The link beside the hash takes the agreement URL's split at the x402, UCP and MPP readings: link-not-https only for a
string of at most 2048 characters that parses as an absolute URL whose scheme is not https, and legal-context-malformed
for every other value the https-link rule refuses. Card's, ACK's and AP2's readings give legal-context-malformed for
every value the rule refuses. Expected values are core-vectors.json's links rows (refusedAs, and the rule its about
states), and each document is its vector file's with the link replaced; for the links of other schemes below, whether
the WHATWG URL Standard's basic URL parser reads them."""

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
    assert len(LINKS) == 32
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
    assert _outcome(CARD_VISA_TAP.read(values), ch) == ((ch, link) if fault == "accepted" else "card/legal-context-malformed")

    uh = UCP["V2"]["advertise"]["h"]
    checkout = _replaced(UCP["V2"]["expectCheckout"], UCP["V2"]["advertise"]["link"], link)
    assert _outcome(UCP_CHECKOUT_UNSIGNED.read(checkout), uh) == expect("ucp", uh)

    nh = NI["fixed"]["H"]
    challenge = {**NI["place"]["expect"], "opaque": _opaque(nh, link)}
    assert _outcome(MPP_CHARGE_NEARINTENTS.read([challenge]), nh) == expect("mpp", nh)


# The WHATWG URL Standard's basic URL parser reads a file URL's whole authority as its host, with no user information
# or port, and a Windows drive letter there as the path's first segment; in every authority it fails an empty host
# after user information or before a port.
@pytest.mark.parametrize(
    ("link", "fault"),
    [
        ("file://atr.seller.example:443/x", "legal-context-malformed"),
        ("file://user@atr.seller.example/x", "legal-context-malformed"),
        ("file://C|/x", "link-not-https"),
        ("file:///x", "link-not-https"),
        ("file://[::1]/x", "link-not-https"),
        ("file://[::g]/x", "legal-context-malformed"),
        ("foo://:443/x", "legal-context-malformed"),
        ("foo://user@/x", "legal-context-malformed"),
        ("foo://atr.seller.example:443/x", "link-not-https"),
    ],
)
def test_a_link_of_another_scheme_is_one_the_whatwg_parser_reads(link: str, fault: str) -> None:
    h = X["H"]
    info = {"type": "sha256", "value": h, "legalContextUrl": link}
    assert is_hash_with_non_https_link(info) is (fault == "link-not-https")
    assert _outcome(legal_context_of({"legalContext": {"info": info}}), h) == f"x402/{fault}"


ACP = load("acp-checkout.json")
AP2 = load("ap2-checkout-mandate.json")
ACK = load("ack-payment-request.json")
LONG = "https://atr.seller.example/" + "a" * (2049 - len("https://atr.seller.example/"))


def _b64u(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def test_an_https_link_over_2048_characters_is_too_large_or_malformed() -> None:
    """ACP, UCP and AP2 read a link over 2048 characters as too large, as acp-checkout.json's agreed refusal for it and
    @integraledger/lcp's UCP and AP2 reads answer; the other readings give legal-context-malformed."""
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
    row = next(r for r in ACP["agreedRefusals"]["rows"] if r["case"] == "read of a legal_context link over 2048 characters")
    assert row["expect"] == {"refused": True, "code": "acp/too-large"}
    too_large = {"acp", "ucp", "ap2"}
    assert {k: getattr(v, "code", v) for k, v in got.items()} == {
        k: f"{k}/too-large" if k in too_large else f"{k}/legal-context-malformed" for k in got
    }
