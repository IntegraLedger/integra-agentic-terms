"""x402 lnbtc: the buyer recomputes the request hash from its own request and requires the option's extra.requestHash
and the invoice's description hash to equal it, before the node is asked to pay. MPP Lightning: the challenge's invoice
is paid only on the account's own network, read through its BOLT11 currency.

Expected values: x402's scheme_exact_lnbtc.md, "Request Binding Test Vectors" (HTTP article A and B; MCP article A, B,
delete_article and another server; a bound metadata member absent and present as null), and its client check 4.
BOLT11's currency prefixes (bc mainnet, tb testnet, tbs signet, bcrt regtest), with tb for testnet3 and testnet4
accounts, and MPP Lightning's network names (mainnet bc, signet tbs, regtest bcrt); the lnbtc CAIP-2 reference is the first 32 hex characters of the network's genesis block hash, as x402's lnbtc scheme
defines it, the genesis hashes being those of each network's genesis block header hashed with double SHA-256. The MPP
invoices are the session vector's deposit invoice with its human-readable part's currency changed and its BIP-173
checksum recomputed; the decoder verifies no signature."""

import json
from typing import Any

import pytest
from breadth import ABC, H, LINK, offered, run, x402_doc
from mpp_docs import placed_doc
from support import load, serving

from integraledger_terms import (
    MPP_CHARGE_LIGHTNING,
    MPP_SESSION_LIGHTNING,
    X402_EXACT_LNBTC,
    Confirmed,
    Declined,
    Refusal,
    _gate,
    confirm,
)
from integraledger_terms.bindings._codec import b64u_encode
from integraledger_terms.pieces._lnbtc_request import binding_of, request_hash_of

NOW = 1_790_000_000
HTTP_A = "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018"
HTTP_B = "4a99860f75eed1ea8178a5db488e044173bc570c8a6210f2c8590cdf8622d509"
MCP_A = "03941bfedc6af8a09b2f459fe83470284a76a8c75801caa9e1487a9276a693f4"
MCP_B = "b3e425970d64cd4f08fc4d57a11b76da59ce6a5760d92687398c91f063120678"
MCP_DELETE = "3a52bbf19dda8b5765a27246b12e805770298273b48526956c421f02fe043455"
MCP_OTHER_SERVER = "96903c29186c6aabc95e48abafd8ce3ad32b4060f5d5bf22cf75f3fbfe816e45"
META_ABSENT = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
META_NULL = "c58dcb77cee9027d1f4b3207bd876d232e61f79ee9f9dbd4e6d834778da78b16"
ARTICLE_A = "https://api.example.com/article/A"
ARTICLE_B = "https://api.example.com/article/B"
SERVER = "https://api.example.com/mcp"

V = load("x402-exact-lnbtc.json")
F = V["fixed"]


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def test_http_article_a_and_b_are_the_specifications_digests() -> None:
    http: dict[str, Any] = {"headers": []}
    assert request_hash_of("http:1", http, {"method": "GET", "url": ARTICLE_A}, ARTICLE_A) == HTTP_A
    assert request_hash_of("http:1", http, {"method": "GET", "url": ARTICLE_B}, ARTICLE_B) == HTTP_B
    assert request_hash_of("http:1", http, {"method": "GET", "url": ARTICLE_A, "body": "0x"}, ARTICLE_A) == HTTP_A
    assert request_hash_of("http:1", http, {"method": "POST", "url": ARTICLE_A}, ARTICLE_A) != HTTP_A
    assert request_hash_of("http:1", http, {"method": "GET", "url": ARTICLE_A, "body": "0x78"}, ARTICLE_A) != HTTP_A


def test_mcp_article_a_and_its_three_changes_are_the_specifications_digests() -> None:
    params = {"server": SERVER, "metadata": []}
    call = {"server": SERVER, "name": "get_article", "arguments": {"article": "A"}}
    assert request_hash_of("mcp:1", params, call, None) == MCP_A
    assert request_hash_of("mcp:1", params, {**call, "arguments": {"article": "B"}}, None) == MCP_B
    assert request_hash_of("mcp:1", params, {**call, "name": "delete_article"}, None) == MCP_DELETE
    other = "https://other.example.com/mcp"
    assert request_hash_of("mcp:1", {**params, "server": other}, {**call, "server": other}, None) == MCP_OTHER_SERVER


def test_mcp_metadata_absent_and_null_hash_as_the_specifications() -> None:
    params = {"server": SERVER, "metadata": ["m"]}
    call = {"server": SERVER, "name": "get_article", "arguments": {"article": "A"}}
    absent = binding_of("mcp:1", params, call, None)
    present = binding_of("mcp:1", params, {**call, "meta": {"m": None}}, None)
    assert isinstance(absent, dict) and absent["metadata"] == [{"name": "m", "valueHash": META_ABSENT}]
    assert isinstance(present, dict) and present["metadata"] == [{"name": "m", "valueHash": META_NULL}]


@pytest.mark.parametrize(
    ("case", "profile", "params", "request_", "expected"),
    [
        ("an unknown profile", "http:2", {"headers": []}, {"method": "GET", "url": ARTICLE_A}, "ln/request-profile-mismatch"),
        ("http:1 for an MCP tool call", "http:1", {"headers": []}, {"server": SERVER, "name": "get_article"}, "ln/request-profile-mismatch"),
        ("an unknown parameter", "http:1", {"headers": [], "extra": 1}, {"method": "GET", "url": ARTICLE_A}, "ln/request-binding-malformed"),
        ("headers out of order", "http:1", {"headers": ["range", "accept"]}, {"method": "GET", "url": ARTICLE_A}, "ln/request-binding-malformed"),
        ("payment-signature bound", "http:1", {"headers": ["payment-signature"]}, {"method": "GET", "url": ARTICLE_A}, "ln/request-binding-malformed"),
        ("a URL with a fragment", "http:1", {"headers": []}, {"method": "GET", "url": ARTICLE_A + "#x"}, "ln/request-binding-malformed"),
        ("a URL with user information", "http:1", {"headers": []}, {"method": "GET", "url": "https://u@api.example.com/article/A"}, "ln/request-binding-malformed"),
        # The WHATWG URL Standard's basic URL parser fails each of these three: a port past 65535, an IPv4 address with a
        # part past 255, and an IPv4 address of five parts.
        ("a URL with port 65536", "http:1", {"headers": []}, {"method": "GET", "url": "https://api.example.com:65536/article/A"}, "ln/request-binding-malformed"),
        ("a URL whose host is 256.1.1.1", "http:1", {"headers": []}, {"method": "GET", "url": "https://256.1.1.1/article/A"}, "ln/request-binding-malformed"),
        ("a URL whose host is 1.2.3.4.5", "http:1", {"headers": []}, {"method": "GET", "url": "https://1.2.3.4.5/article/A"}, "ln/request-binding-malformed"),
        ("x402/payment bound", "mcp:1", {"server": SERVER, "metadata": ["x402/payment"]}, {"server": SERVER, "name": "get_article"}, "ln/request-binding-malformed"),
        ("null arguments", "mcp:1", {"server": SERVER, "metadata": []}, {"server": SERVER, "name": "get_article", "arguments": None}, "ln/request-binding-malformed"),
        # The WHATWG URL Standard's basic URL parser fails a port past 65535.
        ("an MCP server with port 65536", "mcp:1", {"server": "https://api.example.com:65536/mcp", "metadata": []}, {"server": "https://api.example.com:65536/mcp", "name": "get_article"}, "ln/request-binding-malformed"),
        ("another server", "mcp:1", {"server": "https://other.example.com/mcp", "metadata": []}, {"server": SERVER, "name": "get_article"}, "ln/request-server-mismatch"),
    ],
)
def test_malformed_bindings_are_refused(case: str, profile: str, params: Any, request_: Any, expected: str) -> None:
    out = request_hash_of(profile, params, request_, ARTICLE_A)
    assert isinstance(out, object) and getattr(out, "code", None) == expected, (case, out)


DOC = x402_doc(F["O"], F["resource"])
ACCOUNT = f"{F['O']['network']}:{F['payee']}"


def test_the_buyers_get_of_article_a_hands_the_invoice_to_the_node() -> None:
    out = run(lambda c: confirm(DOC, offered(X402_EXACT_LNBTC), ACCOUNT, c, {"request": {"method": "GET", "url": ARTICLE_A}}), serving(ABC))
    assert isinstance(out, Confirmed), out
    assert out.request == {"kind": "bolt11-pay", "invoice": F["O"]["extra"]["invoice"]}


@pytest.mark.parametrize(
    ("request_", "detail"),
    [
        ({"method": "POST", "url": ARTICLE_A}, "ln/request-hash-mismatch"),
        ({"method": "GET", "url": ARTICLE_A, "body": "0x78"}, "ln/request-hash-mismatch"),
        ({"method": "GET", "url": ARTICLE_B}, "ln/request-resource-mismatch"),
        ({"server": SERVER, "name": "get_article"}, "ln/request-profile-mismatch"),
        (None, "x402/input-missing"),
    ],
)
def test_another_request_is_no_payable_option_before_any_fetch(request_: Any, detail: str) -> None:
    link = serving(ABC)
    inputs = {} if request_ is None else {"request": request_}
    out = run(lambda c: confirm(DOC, offered(X402_EXACT_LNBTC), ACCOUNT, c, inputs), link)
    assert out == Declined("no-payable-option", detail)
    assert link.calls == 0


def test_an_option_whose_request_hash_is_article_bs_over_article_as_invoice_is_refused() -> None:
    option = {**F["O"], "extra": {**F["O"]["extra"], "requestHash": HTTP_B}}
    doc = x402_doc(option, {"url": ARTICLE_B})
    link = serving(ABC)
    out = run(lambda c: confirm(doc, offered(X402_EXACT_LNBTC), ACCOUNT, c, {"request": {"method": "GET", "url": ARTICLE_B}}), link)
    assert out == Declined("no-payable-option", "ln/request-hash-mismatch")
    assert link.calls == 0


# ── MPP Lightning: the account's network through the invoice's BOLT11 currency ──

INVOICES = {
    "tb": "lntb250n1p4tzwuqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5hfupd0u0q8875s2pgr09mt3zywcqxcdrjcth4895zrlkrusqzkksxqzfv9qrsgq00s4xjxtrutvzp7yzmdyyqpykvvnnxg6vacmn44nqlqqsepw6vy8kjvq5s8jrxq8ayy3pa7xrwz0zx8angk20ttn0awxumjskmaxf0qq432lkn",
    "tbs": "lntbs250n1p4tzwuqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5hfupd0u0q8875s2pgr09mt3zywcqxcdrjcth4895zrlkrusqzkksxqzfv9qrsgq00s4xjxtrutvzp7yzmdyyqpykvvnnxg6vacmn44nqlqqsepw6vy8kjvq5s8jrxq8ayy3pa7xrwz0zx8angk20ttn0awxumjskmaxf0qqcmqsva",
    "bcrt": "lnbcrt250n1p4tzwuqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5hfupd0u0q8875s2pgr09mt3zywcqxcdrjcth4895zrlkrusqzkksxqzfv9qrsgq00s4xjxtrutvzp7yzmdyyqpykvvnnxg6vacmn44nqlqqsepw6vy8kjvq5s8jrxq8ayy3pa7xrwz0zx8angk20ttn0awxumjskmaxf0qq7wjywa",
}
NETWORKS = {
    "mainnet": "lnbtc:000000000019d6689c085ae165831e93",
    "testnet3": "lnbtc:000000000933ea01ad0ee984209779ba",
    "testnet4": "lnbtc:00000000da84f2bafbbc53dee25a72ae",
    "signet": "lnbtc:00000008819873e925422c1ff0f99f7c",
    "regtest": "lnbtc:0f9188f13cb7b2c71f2a335e3a4fc328",
}
C = load("mpp-charge-lightning.json")
S = load("mpp-session-lightning.json")
SESSION_INPUTS = {"returnInvoice": S["fixed"]["returnInvoice"]}
MAINNET_INVOICE = S["S1"]["request"]["depositInvoice"]


def challenge_with(deposit_invoice: str) -> dict[str, Any]:
    row = S["S1"]
    request = {**row["request"], "depositInvoice": deposit_invoice}
    issued = {**row["challenge"], "request": b64u_encode(json.dumps(request, separators=(",", ":")).encode("utf-8"))}
    placed: dict[str, Any] = placed_doc(issued, H, LINK)[0]
    return placed


def account(network: str) -> str:
    return f"{network}:{C['fixed']['payee']}"


@pytest.mark.parametrize(
    ("network", "currency"),
    [("mainnet", "bc"), ("testnet3", "tb"), ("testnet4", "tb"), ("signet", "tbs"), ("regtest", "bcrt")],
)
def test_an_account_pays_the_invoice_of_its_networks_currency(network: str, currency: str) -> None:
    doc = [challenge_with(i) for i in (MAINNET_INVOICE, INVOICES["tb"], INVOICES["tbs"], INVOICES["bcrt"])]
    out = run(lambda c: confirm(doc, offered(MPP_SESSION_LIGHTNING), account(NETWORKS[network]), c, SESSION_INPUTS), serving(ABC))
    assert isinstance(out, Confirmed), out
    expected = MAINNET_INVOICE if currency == "bc" else INVOICES[currency]
    assert out.request == {"kind": "bolt11-pay", "invoice": expected}


@pytest.mark.parametrize(
    ("network", "invoices"),
    [
        (NETWORKS["mainnet"], [INVOICES["tb"], INVOICES["bcrt"]]),
        (NETWORKS["signet"], [MAINNET_INVOICE]),
        (NETWORKS["signet"], [INVOICES["tb"]]),
        (NETWORKS["testnet4"], [INVOICES["tbs"]]),
        (NETWORKS["testnet3"], [INVOICES["bcrt"]]),
        (NETWORKS["regtest"], [INVOICES["tb"]]),
        ("lnbtc:00000000000000000000000000000000", [MAINNET_INVOICE]),
    ],
)
def test_no_invoice_on_the_accounts_network_is_no_payable_option_before_any_fetch(network: str, invoices: list[str]) -> None:
    link = serving(ABC)
    doc = [challenge_with(i) for i in invoices]
    out = run(lambda c: confirm(doc, offered(MPP_SESSION_LIGHTNING), account(network), c, SESSION_INPUTS), link)
    assert out == Declined("no-payable-option", "mpp/no-payable-option")
    assert link.calls == 0


# ── MPP Lightning: bound holds the echoed challenge's network to the invoice, as build does ──

# draft-lightning-charge-00's network: "MUST be one of "mainnet", "regtest", or "signet". If present, MUST match the
# network implied by the invoice's human-readable prefix." draft-lightning-session-00 names no network, so the session
# reads methodDetails.network by the charge's rule. A methodDetails that is not an object has no network to read: bound
# and build answer it mpp/request-malformed. The echo keeps the placed id and opaque, so only the request differs.
OPEN = {"action": "open", "preimage": S["fixed"]["preimage"], "returnInvoice": S["fixed"]["returnInvoice"]}
NAMED_NETWORK_ROWS = [
    ("network bogus", {"network": "bogus"}, "ln/currency-network"),
    ("network 5", {"network": 5}, "ln/currency-network"),
    ("network testnet, which MPP Lightning does not name", {"network": "testnet"}, "ln/currency-network"),
    ("network signet for an lnbc invoice", {"network": "signet"}, "ln/currency-network"),
    ("network regtest for an lnbc invoice", {"network": "regtest"}, "ln/currency-network"),
]


def echoed(placed: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    return {**placed, "request": b64u_encode(json.dumps(request, separators=(",", ":")).encode("utf-8"))}


@pytest.mark.parametrize(
    ("case", "details", "expected"),
    [*NAMED_NETWORK_ROWS, ("methodDetails the string mainnet", "mainnet", "mpp/request-malformed")],
)
def test_mpp_session_lightning_bound_and_build_read_the_named_network_alike(case: str, details: object, expected: str) -> None:
    challenge = echoed(challenge_with(MAINNET_INVOICE), {**S["S1"]["request"], "methodDetails": details})
    assert MPP_SESSION_LIGHTNING.bound({"challenge": challenge, "payload": OPEN}) == Refusal(expected)
    binding: Any = MPP_SESSION_LIGHTNING
    assert binding.build({"challenge": challenge, **SESSION_INPUTS}, H) == Refusal(expected)


def test_mpp_session_lightning_a_regtest_invoice_echoed_naming_regtest_binds_h() -> None:
    request = {**S["S1"]["request"], "depositInvoice": INVOICES["bcrt"], "methodDetails": {"network": "regtest"}}
    challenge = echoed(challenge_with(MAINNET_INVOICE), request)
    assert MPP_SESSION_LIGHTNING.bound({"challenge": challenge, "payload": OPEN}) == H


def charge_placed() -> dict[str, Any]:
    row = C["L3"]
    issued = {**row["challenge"], "request": b64u_encode(json.dumps(row["request"], separators=(",", ":")).encode("utf-8"))}
    placed: dict[str, Any] = placed_doc(issued, H, LINK)[0]
    return placed


@pytest.mark.parametrize(
    ("case", "details", "expected"),
    [*NAMED_NETWORK_ROWS, ("methodDetails the string mainnet", "mainnet", "mpp/request-malformed")],
)
def test_mpp_charge_lightning_bound_and_build_read_the_named_network_alike(case: str, details: object, expected: str) -> None:
    md = C["L3"]["request"]["methodDetails"]
    request = {**C["L3"]["request"], "methodDetails": {**md, **details} if isinstance(details, dict) else details}
    challenge = echoed(charge_placed(), request)
    assert MPP_CHARGE_LIGHTNING.bound({"challenge": challenge, "payload": {"preimage": C["fixed"]["preimage"]}}) == Refusal(expected)
    binding: Any = MPP_CHARGE_LIGHTNING
    assert binding.build({"challenge": challenge}, H) == Refusal(expected)


def test_mpp_charge_lightning_with_no_network_binds_h() -> None:
    md = {k: v for k, v in C["L3"]["request"]["methodDetails"].items() if k != "network"}
    challenge = echoed(charge_placed(), {**C["L3"]["request"], "methodDetails": md})
    assert MPP_CHARGE_LIGHTNING.bound({"challenge": challenge, "payload": {"preimage": C["fixed"]["preimage"]}}) == H
