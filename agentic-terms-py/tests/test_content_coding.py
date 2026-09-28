"""The gate's requests ask for the identity coding, a 200 that names any content coding is declined with its body unread,
and every body is read as sent, bounded before anything could decode it. Sources: RFC 9110 section 8.4 (a content coding
is applied to the representation's bytes, and Content-Encoding lists the codings applied, in order) and section 12.5.3
("identity" is a synonym for "no encoding"; Accept-Encoding: identity asks for the bytes with no coding applied). The ATR,
its hash and the agreement exchange's inputs are @integraledger/lcp's vectors/buyer.json; each gzip body is written by
Python's zlib."""

import asyncio
import base64
import json
import zlib
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import Confirmed, Declined, _gate, agree, confirm, transact

from support import A, ACCOUNT, BUYER, D, HASH_A, NOW, Chunks, CountingSigner, EthAccountSigner, Link

AG: dict[str, Any] = BUYER["fixed"]["agreement"]
URL: str = AG["url"]
RECEIPT = json.dumps(AG["receipt"]).encode("utf-8")
IDENTITY_DETAIL = "The link served a content coding other than identity."
AGREEMENT_DETAIL = "The agreement URL served a content coding other than identity."
MAX_ANSWER_BYTES = 65_536

# Content-Encoding values that name a coding: RFC 9110's registered codings, a stacked list, and an unregistered one.
CODINGS = ["gzip", "x-gzip", "deflate", "br", "compress", "zstd", "gzip, gzip", "identity, gzip", "unknown"]


def gzip(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    return compressor.compress(data) + compressor.flush()


def layered(size: int, layers: int) -> bytes:
    """size zero bytes under gzip, then gzip again, layers times in all."""
    data = gzip(bytes(size))
    for _ in range(layers - 1):
        data = gzip(data)
    return data


# 64 MiB of zeros under three layers of gzip: a body of a few hundred bytes that inflates to 64 MiB.
LAYERED = layered(64 * 1024 * 1024, 3)


class Served(httpx.AsyncByteStream):
    """A response body of the given bytes, recording how many were read and whether it was closed."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.sent = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.sent += len(self.data)
        yield self.data

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class Recording:
    """Answers each request with answer, recording the requests."""

    answer: Callable[[httpx.Request], httpx.Response]
    requests: list[httpx.Request] = field(default_factory=list)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.answer(request)

    def run(self, go: Callable[[httpx.AsyncClient], Awaitable[Any]]) -> Any:
        async def main() -> Any:
            async with Link(self.handle).client() as client:
                return await go(client)

        return asyncio.run(main())


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def unpaid_402() -> httpx.Response:
    required = base64.b64encode(json.dumps(AG["required"]).encode("utf-8")).decode("ascii")
    return httpx.Response(402, headers={"payment-required": required})


# ── The ATR fetch ────────────────────────────────────────────────────────────────────────────────────────────────


def test_the_atr_fetch_asks_for_the_identity_coding() -> None:
    seller = Recording(lambda request: httpx.Response(200, content=A))
    out = seller.run(lambda c: confirm(D, BINDING, ACCOUNT, c))
    assert isinstance(out, Confirmed) and out.h == HASH_A
    assert seller.requests[0].headers["accept-encoding"] == "identity"


@pytest.mark.parametrize("coding", ["identity", " IDENTITY ", ""])
def test_a_200_naming_no_coding_is_read_as_sent(coding: str) -> None:
    seller = Recording(lambda request: httpx.Response(200, headers={"content-encoding": coding}, stream=Served(A)))
    out = seller.run(lambda c: confirm(D, BINDING, ACCOUNT, c))
    assert isinstance(out, Confirmed) and out.h == HASH_A and out.atr_bytes == A


@pytest.mark.parametrize("coding", CODINGS)
def test_a_200_naming_a_coding_is_atr_unfetchable_unread_and_nothing_is_signed(coding: str) -> None:
    body = Served(gzip(A))
    seller = Recording(lambda request: httpx.Response(200, headers={"content-encoding": coding}, stream=body))
    signer = CountingSigner()
    out = seller.run(lambda c: transact(D, BINDING, signer, c))
    assert out == Declined("atr-unfetchable", IDENTITY_DETAIL)
    assert body.sent == 0 and body.closed
    assert signer.requests == []


def test_gzip_bytes_served_with_no_coding_are_hashed_as_sent() -> None:
    seller = Recording(lambda request: httpx.Response(200, stream=Served(gzip(A))))
    out = seller.run(lambda c: confirm(D, BINDING, ACCOUNT, c))
    assert isinstance(out, Declined) and out.code == "hash-mismatch"


# ── The agreement exchange ───────────────────────────────────────────────────────────────────────────────────────


def test_the_agreement_exchange_asks_for_the_identity_coding_unpaid_and_paid() -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        return unpaid_402() if "payment-signature" not in request.headers else httpx.Response(200, content=RECEIPT)

    seller = Recording(answer)
    out = seller.run(lambda c: agree(HASH_A, URL, EthAccountSigner(), c, atr_bytes=A))
    assert not isinstance(out, Declined)
    assert [r.headers["accept-encoding"] for r in seller.requests] == ["identity", "identity"]
    assert "payment-signature" in seller.requests[1].headers


@pytest.mark.parametrize("coding", CODINGS)
def test_an_unpaid_200_naming_a_coding_is_agreement_failed_unread_and_nothing_is_signed(coding: str) -> None:
    body = Served(gzip(RECEIPT))
    seller = Recording(lambda request: httpx.Response(200, headers={"content-encoding": coding}, stream=body))
    signer = CountingSigner()
    out = seller.run(lambda c: agree(HASH_A, URL, signer, c, atr_bytes=A))
    assert out == Declined("agreement-failed", AGREEMENT_DETAIL)
    assert body.sent == 0 and body.closed
    assert signer.requests == []


def test_a_paid_200_naming_a_coding_is_agreement_failed_with_the_sent_payment_kept_as_moved() -> None:
    body = Served(gzip(RECEIPT))

    def answer(request: httpx.Request) -> httpx.Response:
        if "payment-signature" not in request.headers:
            return unpaid_402()
        return httpx.Response(200, headers={"content-encoding": "gzip"}, stream=body)

    seller = Recording(answer)
    out = seller.run(lambda c: agree(HASH_A, URL, EthAccountSigner(), c, atr_bytes=A))
    assert isinstance(out, Declined) and (out.code, out.detail) == ("agreement-failed", AGREEMENT_DETAIL)
    assert out.moved is not None and out.moved.h == HASH_A and out.moved.atr_bytes == A
    sent = seller.requests[1].headers["payment-signature"]
    assert json.loads(base64.b64decode(sent)) == out.moved.signed
    assert body.sent == 0


def test_a_layered_gzip_body_is_declined_unread_and_never_inflated() -> None:
    assert len(LAYERED) < 1024
    body = Served(LAYERED)
    seller = Recording(
        lambda request: httpx.Response(200, headers={"content-encoding": "gzip, gzip, gzip"}, stream=body)
    )
    out = seller.run(lambda c: agree(HASH_A, URL, CountingSigner(), c, atr_bytes=A))
    assert out == Declined("agreement-failed", AGREEMENT_DETAIL)
    assert body.sent == 0


def test_a_layered_gzip_body_served_with_no_coding_is_read_as_its_own_bytes() -> None:
    body = Served(LAYERED)
    seller = Recording(lambda request: httpx.Response(200, stream=body))
    out = seller.run(lambda c: agree(HASH_A, URL, CountingSigner(), c, atr_bytes=A))
    assert out == Declined("agreement-failed", "The agreement URL answered 200 without a JSON receipt.")
    assert body.sent == len(LAYERED)


def test_the_receipt_read_stops_at_64_kib_of_bytes_as_sent() -> None:
    stream = Chunks(100 * MAX_ANSWER_BYTES, size=4096)
    seller = Recording(lambda request: httpx.Response(200, stream=stream))
    out = seller.run(lambda c: agree(HASH_A, URL, CountingSigner(), c, atr_bytes=A))
    assert out == Declined("agreement-failed", "The agreement receipt is larger than 64 KiB.")
    assert MAX_ANSWER_BYTES < stream.sent <= MAX_ANSWER_BYTES + 4096
    assert stream.closed
