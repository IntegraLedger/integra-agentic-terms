"""The agreement exchange reads the seller's answers as the protocol package reads JSON text. PAYMENT-REQUIRED is padded
standard base64 (RFC 4648 section 4; x402's HTTP transport carries it base64-encoded, and RFC 4648 section 3.2 keeps
the pad characters), whose final character's unused bits are zero (RFC 4648 section 3.5). Every body and header decodes
as UTF-8 whose leading byte order mark is kept as a character, and no JSON text begins with one (RFC 8259 section 8.1).
So buyer.json's BA13 header (requiredUnpadded), a header whose final character carries a non-zero unused bit, and a
header whose JSON follows a byte order mark leave the 402 unread: agreement-failed after one fetch, with nothing signed.
A paid 200 whose receipt follows a byte order mark is agreement-failed, with the sent agreement payment kept as moved.
buyer.json's BA17 and BA18 rows give the byte order mark cases and a padded header with a space inside, built here as
those rows build receiptBomLed, requiredBomLed and requiredInnerSpace from required and receipt (JSON text with no
spaces), and each row's expected decline. The same cases run through the TypeScript gate in
agreement-decoding.test.ts."""

import asyncio
import base64
import json
from typing import Any

import httpx
import pytest

from integraledger_terms import Agreed, Declined, ToApprove, agree

from support import A, BUYER, EthAccountSigner

AG: dict[str, Any] = BUYER["fixed"]["agreement"]
BOM = b"\xef\xbb\xbf"
REQUIRED = json.dumps(AG["required"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
CANONICAL = base64.b64encode(REQUIRED).decode("ascii")
RECEIPT = json.dumps(AG["receipt"], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def non_canonical(b64: str) -> str:
    """The header with its final character's lowest unused bit set: the same bytes, written another way."""
    pads = 2 if b64.endswith("==") else 1 if b64.endswith("=") else 0
    assert pads > 0, "the header has no unused bits"
    at = len(b64) - pads - 1
    return b64[:at] + _ALPHABET[_ALPHABET.index(b64[at]) | 1] + b64[at + 1 :]


def exchange(header: str, paid: bytes) -> tuple[Any, int, int]:
    fetches = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal fetches
        fetches += 1
        if "payment-signature" not in request.headers:
            return httpx.Response(402, headers={"payment-required": header})
        return httpx.Response(200, content=paid)

    signer = EthAccountSigner()

    async def go() -> Any:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            first = await agree(A, AG["url"], signer, client)
            if not isinstance(first, ToApprove):
                return first
            return await agree(A, AG["url"], signer, client, approved=first.approve)

    out = asyncio.run(go())
    return out, fetches, signer.calls


def test_the_canonical_header_and_a_receipt_with_no_byte_order_mark_give_the_receipt() -> None:
    assert non_canonical(CANONICAL) != CANONICAL
    assert base64.b64decode(non_canonical(CANONICAL)) == base64.b64decode(CANONICAL)
    out, _, calls = exchange(CANONICAL, RECEIPT)
    assert isinstance(out, Agreed), out
    assert out.receipt.atr_hash == AG["receipt"]["atrHash"]
    assert calls == 1


@pytest.mark.parametrize(
    "header",
    [
        AG["requiredUnpadded"],
        non_canonical(CANONICAL),
        base64.b64encode(BOM + REQUIRED).decode("ascii"),
        CANONICAL[:4] + " " + CANONICAL[4:],
    ],
    ids=[
        "BA13's unpadded header",
        "a header whose final character carries a non-zero unused bit",
        "BA18: a header whose JSON follows a byte order mark",
        "BA18: the padded header with a space after its fourth character",
    ],
)
def test_an_unreadable_payment_required_is_agreement_failed_after_one_fetch_with_nothing_signed(header: str) -> None:
    out, fetches, calls = exchange(header, RECEIPT)
    assert isinstance(out, Declined) and out.code == "agreement-failed", out
    assert out.moved is None
    assert (fetches, calls) == (1, 0)


def test_ba17_a_paid_200_whose_receipt_follows_a_byte_order_mark_is_agreement_failed_with_moved() -> None:
    out, _, calls = exchange(CANONICAL, BOM + RECEIPT)
    assert isinstance(out, Declined) and out.code == "agreement-failed", out
    assert out.moved is not None
    assert calls == 1
