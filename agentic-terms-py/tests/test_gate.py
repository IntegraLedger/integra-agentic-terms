"""The buyer rows B1-B17 and B2b against the gate."""

import asyncio
import json
import re
import time
from typing import Any

import httpx
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import (
    MAX_ATR_BYTES,
    Advertised,
    Checked,
    Confirmed,
    Declined,
    Finished,
    Transacted,
    _gate,
    atr_hash,
    check,
    confirm,
    finish,
    transact,
)

from integraledger_terms.bindings._lcp import is_https_link
from support import (
    A,
    ACCOUNT,
    C,
    D,
    HASH_A,
    HASH_C,
    LINK_A,
    NOW,
    O,
    Chunks,
    CountingSigner,
    EthAccountSigner,
    Link,
    StubBinding,
    digest,
    document,
    load,
    recover,
    row,
    serving,
)


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def run_transact(doc: dict[str, Any], link: Link, signer: Any = None, binding: Any = BINDING) -> Any:
    async def go() -> Any:
        async with link.client() as client:
            return await transact(doc, binding, signer or CountingSigner(), client)

    return asyncio.run(go())


def run_confirm(doc: dict[str, Any], link: Link, account: str = ACCOUNT, binding: Any = BINDING) -> Any:
    async def go() -> Any:
        async with link.client() as client:
            return await confirm(doc, binding, account, client)

    return asyncio.run(go())


def declined(result: Any, code: str) -> bool:
    return isinstance(result, Declined) and result.code == code


def test_b1_hash_of_a() -> None:
    assert atr_hash(A) == row("B1")["expect"]["h"]
    assert atr_hash(C) == HASH_C


def test_b2_plant_link_serves_c() -> None:
    expect = row("B2")["expect"]
    signer = CountingSigner()
    assert declined(run_transact(document(), serving(C), signer), expect["decline"])
    assert len(signer.requests) == expect["signCalls"]


def test_b2b_core_plant() -> None:
    b2b = row("B2b")
    signer = CountingSigner()
    result = run_transact(b2b["input"]["doc"], serving(bytes.fromhex(b2b["input"]["servesHex"])), signer)
    assert declined(result, b2b["expect"]["decline"])
    assert len(signer.requests) == b2b["expect"]["signCalls"]


def test_b3_python_reserialisation_is_a_mismatch() -> None:
    b3 = row("B3")
    body = bytes.fromhex(b3["input"]["servesHex"])
    assert json.dumps(json.loads(A)).encode() == body
    assert atr_hash(body) == b3["servedHash"]
    signer = CountingSigner()
    assert declined(run_transact(document(), serving(body), signer), b3["expect"]["decline"])
    assert len(signer.requests) == b3["expect"]["signCalls"]


def test_b4_javascript_reserialisation_is_a_mismatch() -> None:
    b4 = row("B4")
    body = bytes.fromhex(b4["input"]["servesHex"])
    assert atr_hash(body) == b4["servedHash"]
    signer = CountingSigner()
    assert declined(run_transact(document(), serving(body), signer), b4["expect"]["decline"])
    assert len(signer.requests) == b4["expect"]["signCalls"]


def test_b5_upper_case_advertised_hash_matches_and_build_gets_lower_case() -> None:
    b5 = row("B5")
    stub = StubBinding(BINDING, read_answer=Advertised(h=b5["input"]["stubRead"]["h"], link=LINK_A,
                                                       offer={"required": document(), "options": [O]}))
    result = run_confirm(document(), serving(A), binding=stub)
    assert isinstance(result, Confirmed)
    assert result.h == b5["expect"]["h"]
    assert stub.built == [b5["expect"]["buildReceives"]]


def test_b6_confirm_sign_finish() -> None:
    b6 = row("B6")["expect"]
    confirmed = run_confirm(document(), serving(A))
    assert isinstance(confirmed, Confirmed) and confirmed.request is not None
    typed = confirmed.request["typedData"]
    assert confirmed.request["kind"] == "eip712"
    assert {key: str(value) for key, value in typed["message"].items()} == b6["message"]
    assert digest(typed) == b6["digest"]
    # The signer receives the build's request exactly as given; the domain's verifyingContract is the option's asset,
    # in the case the option wrote.
    assert typed["domain"]["verifyingContract"] == D["accepts"][0]["asset"]
    sig = asyncio.run(EthAccountSigner().sign(confirmed.request))
    assert sig == b6["signature"]
    finished = finish(A, confirmed.chosen, sig, BINDING)
    assert isinstance(finished, Finished)
    assert finished.signed["payload"]["authorization"]["nonce"] == b6["signedNonce"]
    assert finished.signed["payload"]["signature"] == b6["signature"]
    assert recover(typed, finished.signed["payload"]["signature"]) == b6["recovers"]
    assert confirmed.atr_bytes == A


def test_b6_transact_with_the_eth_account_signer() -> None:
    b6 = row("B6")["expect"]
    signer = EthAccountSigner()
    result = run_transact(document(), serving(A), signer)
    assert isinstance(result, Transacted)
    assert signer.calls == 1
    assert result.h == b6["signedNonce"]
    assert result.atr_bytes == A
    assert result.signed is not None and result.signed["payload"]["signature"] == b6["signature"]


def test_b7_check() -> None:
    expect = row("B7")["expect"]
    result = run_transact(document(), serving(A), EthAccountSigner())
    assert isinstance(result, Transacted) and result.signed is not None
    assert check(A, result.signed, BINDING) == Checked(h=expect[0]["h"])
    assert declined(check(C, result.signed, BINDING), expect[1]["decline"])


def test_b8_payment_identifier() -> None:
    expect = row("B8")["expect"]
    advertised: dict[str, Any] = {"payment-identifier": {"info": {}, "schema": {}}}
    ids = []
    for _ in range(2):
        result = run_transact(document(extensions=advertised), serving(A), EthAccountSigner())
        assert isinstance(result, Transacted)
        assert result.signed is not None
        ids.append(result.signed["extensions"]["payment-identifier"]["info"]["id"])
    assert all(re.search(expect["paymentIdentifierPattern"], value) for value in ids)
    assert (ids[0] != ids[1]) == expect["differsBetweenRuns"]
    plain = run_transact(document(), serving(A), EthAccountSigner())
    assert isinstance(plain, Transacted)
    assert plain.signed is not None and "payment-identifier" not in plain.signed.get("extensions", {})


def test_b9_signed_not_bound() -> None:
    b9 = row("B9")
    assert b9["input"]["stubBound"] == "hashC"
    signer = CountingSigner()
    result = run_transact(document(), serving(A), signer, StubBinding(BINDING, bound_answer=HASH_C))
    assert declined(result, b9["expect"]["decline"])
    assert len(signer.requests) == b9["expect"]["signCalls"]


def test_b10_http_link() -> None:
    b10 = row("B10")
    link = serving(A)
    result = run_confirm(document(link="http://atr.seller.example/" + HASH_A), link)
    assert result == Declined(b10["expect"][0]["decline"], b10["expect"][0]["detail"])
    stub = StubBinding(BINDING, read_answer=Advertised(h=HASH_A, link=b10["input"][1]["stubRead"]["link"],
                                                       offer={"required": document(), "options": [O]}))
    assert declined(run_confirm(document(), link, binding=stub), b10["expect"][1]["decline"])
    assert link.calls == b10["expect"][0]["fetches"] + b10["expect"][1]["fetches"]


def test_b11_redirect_404_and_rejection() -> None:
    b11 = row("B11")
    assert [answer.get("status") for answer in b11["input"]["fetch"]] == [302, 404, None]

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    redirect = Link(lambda request: httpx.Response(302, headers={"location": LINK_A}))
    signer = CountingSigner()

    async def followed() -> Any:
        async with redirect.client(follow_redirects=True) as client:
            return await transact(document(), BINDING, signer, client)

    assert declined(asyncio.run(followed()), b11["expect"]["decline"])
    assert redirect.calls == 1
    for link in (Link(lambda request: httpx.Response(404)), Link(refuse)):
        assert declined(run_transact(document(), link, signer), b11["expect"]["decline"])
    assert len(signer.requests) == b11["expect"]["signCalls"]


def test_b12_exactly_the_bound_passes_the_size_check() -> None:
    b12 = row("B12")
    result = run_transact(document(), serving(b"x" * b12["input"]["bodyLength"]))
    assert declined(result, b12["expect"]["decline"])


def test_b13_one_byte_over_the_bound() -> None:
    b13 = row("B13")
    streamed_input, declared_input = b13["input"]
    assert MAX_ATR_BYTES == row("B12")["input"]["bodyLength"]
    signer = CountingSigner()
    stream = Chunks(streamed_input["bodyLength"])
    streamed = Link(lambda request: httpx.Response(200, stream=stream))
    assert declined(run_transact(document(), streamed, signer), b13["expect"]["decline"])
    assert stream.closed == b13["expect"]["streamCancelled"]
    declared_stream = Chunks(0)
    declared = Link(lambda request: httpx.Response(
        200, headers={"content-length": str(declared_input["contentLength"])}, stream=declared_stream))
    assert declined(run_transact(document(), declared, signer), b13["expect"]["decline"])
    assert declared_stream.sent == 0
    assert declared_stream.closed == b13["expect"]["streamCancelled"]
    assert len(signer.requests) == b13["expect"]["signCalls"]


def test_b13_an_endless_body_is_cut_at_the_bound() -> None:
    stream = Chunks(10 * MAX_ATR_BYTES)
    assert declined(run_transact(document(), Link(lambda request: httpx.Response(200, stream=stream))),
                    row("B13")["expect"]["decline"])
    assert stream.closed
    assert stream.sent < 2 * MAX_ATR_BYTES


def test_b14_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "FETCH_DEADLINE_S", 0.05)

    async def never(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(3600)
        return httpx.Response(200, content=A)

    started = time.monotonic()
    result = run_transact(document(), Link(never))
    elapsed = time.monotonic() - started
    assert declined(result, row("B14")["expect"]["decline"])
    assert elapsed < 1.0


def test_b15_signer_rejects() -> None:
    assert declined(run_transact(document(), serving(A), CountingSigner(fail=True)), row("B15")["expect"]["decline"])


def test_b16_no_payable_option() -> None:
    b16 = row("B16")
    link = serving(A)
    for account in b16["input"]["accounts"]:
        assert declined(run_confirm(document(), link, account=account), b16["expect"]["decline"])
    assert link.calls == b16["expect"]["fetches"]


def test_b17_pairing_not_supported() -> None:
    b17 = row("B17")
    stub = StubBinding(BINDING, id=b17["input"]["stubBindingId"])
    assert declined(run_transact(document(), serving(A), binding=stub), b17["expect"]["decline"])


# The one https-link rule, over core-vectors.json's shared links rows: an accepted link is fetched, a refused one is
# link-not-https before any fetch.
LINKS = load("core-vectors.json")["links"]["rows"]


@pytest.mark.parametrize("case", LINKS, ids=[r["name"] for r in LINKS])
def test_the_https_link_rule(case: dict[str, Any]) -> None:
    assert is_https_link(case["link"]) is case["accept"]
    link = serving(A)
    stub = StubBinding(BINDING, read_answer=Advertised(h=HASH_A, link=case["link"], offer={"required": document(), "options": [O]}))
    result = run_confirm(document(), link, binding=stub)
    if case["accept"]:
        assert link.calls == 1
    else:
        assert result == Declined("link-not-https", f"x402/{case['refusedAs']}")
        assert link.calls == 0


@pytest.mark.parametrize(
    "link",
    [
        "https://256.1.1.1/x",
        "https://1.2.3.4.5/x",
        "https://09.1.1.1/x",
        "https://1.2.3.08/x",
        "https://[::::]/x",
        "https://atr.seller.example:65536/x",
        "https://atr.seller.example/\ud800",
    ],
)
def test_links_a_whatwg_parser_refuses(link: str) -> None:
    # An IPv4 number out of range, with five parts or an invalid octal part, an invalid IPv6 literal, a port above
    # 65535, and a lone surrogate: lcp's isHttpsLink refuses each.
    assert is_https_link(link) is False


def test_links_a_whatwg_parser_reads_as_ipv4_or_as_a_domain() -> None:
    # lcp's isHttpsLink accepts each.
    assert is_https_link("https://1.2.3/x") is True
    assert is_https_link("https://0x1g.example/x") is True
    assert is_https_link("https://0x7f.1/x") is True
    assert is_https_link("https://atr.seller.example.:8443/x") is True
