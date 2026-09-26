"""The fetch's bound on decoded bytes (1 MiB): the gate asks for an unencoded body, and a gzip or
deflate body counts against the bound as it is decoded."""

import asyncio
import gzip
import zlib
from collections.abc import AsyncIterator
from typing import Any

import httpx

from integraledger_terms import MAX_ATR_BYTES, Declined, _gate

from support import A, Link


class Encoded(httpx.AsyncByteStream):
    """A body sent as the given encoded bytes, in chunks, recording how many bytes were read."""

    def __init__(self, data: bytes, size: int = 16384) -> None:
        self.data = data
        self.size = size
        self.sent = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while self.sent < len(self.data):
            chunk = self.data[self.sent : self.sent + self.size]
            self.sent += len(chunk)
            yield chunk

    async def aclose(self) -> None:
        return None


def fetched(link: Link) -> Any:
    async def go() -> Any:
        async with link.client() as client:
            return await _gate._fetch(client, "https://atr.seller.example/a")

    return asyncio.run(go())


def encoded(encoding: str, data: bytes) -> Link:
    return Link(lambda request: httpx.Response(200, headers={"content-encoding": encoding}, stream=Encoded(data)))


def test_the_gate_asks_for_an_unencoded_body() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("accept-encoding"))
        return httpx.Response(200, content=A)

    assert fetched(Link(handler)) == A
    assert seen == ["identity"]


def test_a_gzip_body_is_hashed_as_decoded() -> None:
    assert fetched(encoded("gzip", gzip.compress(A))) == A


def test_a_deflate_body_zlib_or_raw_is_hashed_as_decoded() -> None:
    assert fetched(encoded("deflate", zlib.compress(A))) == A
    raw = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    assert fetched(encoded("deflate", raw.compress(A) + raw.flush())) == A


def test_a_gzip_body_of_exactly_the_bound_passes() -> None:
    body = b"x" * MAX_ATR_BYTES
    assert fetched(encoded("gzip", gzip.compress(body))) == body


def test_a_gzip_bomb_is_cut_at_the_bound_before_it_is_read_whole() -> None:
    bomb = gzip.compress(b"\0" * (64 * MAX_ATR_BYTES))
    stream = Encoded(bomb)
    out = fetched(Link(lambda request: httpx.Response(200, headers={"content-encoding": "gzip"}, stream=stream)))
    assert isinstance(out, Declined) and out.code == "atr-too-large"
    assert stream.sent < len(bomb)


def test_one_decoded_byte_over_the_bound_is_too_large() -> None:
    out = fetched(encoded("gzip", gzip.compress(b"x" * (MAX_ATR_BYTES + 1))))
    assert isinstance(out, Declined) and out.code == "atr-too-large"


def test_an_encoding_the_gate_does_not_decode_is_unfetchable() -> None:
    out = fetched(encoded("br", b"\x0b\x01\x80abc\x03"))
    assert isinstance(out, Declined) and out.code == "atr-unfetchable"


def test_a_corrupt_gzip_body_is_unfetchable() -> None:
    out = fetched(encoded("gzip", b"\x1f\x8b not gzip"))
    assert isinstance(out, Declined) and out.code == "atr-unfetchable"
