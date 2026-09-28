"""The agreement payment: ask the agreement URL for its challenge, pay it through the buyer piece of the pairing that
placed it, a pairing whose payment is itself a public proof of the ATR hash, and return the resource's receipt once the
payment is recorded. Nothing is signed when the challenge advertises another hash, and nothing is sent unless what was
signed carries the hash. Once sent, the same signed payment is sent again after each 202, 5xx or timeout, each paid
request bounded by min(maxTimeoutSeconds, 120) + 60 + 10 seconds and the whole exchange by the agreement option's
maxTimeoutSeconds + 180 seconds; no second agreement payment is signed, and every decline after it was sent carries it
as moved."""

import asyncio
import base64
import binascii
import json
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

import httpx

from . import _gate
from ._core import AtrHash, hash_equals, is_hash
from .bindings._jose import UNPARSED, parse_json
from .bindings._lcp import is_https_link, is_other_scheme_link
from ._types import Advertised, AgreementReceipt, Agreed, Binding, Declined, Inputs, Moved, Refusal, Signer

UNPAID_DEADLINE_S = 10.0
EXCHANGE_CAP_S = 120
SETTLE_S = 60
VERIFY_S = 10
WINDOW_EXTRA_S = 180
MAX_ANSWER_BYTES = 65_536
RETRY_DEFAULT_S = 2
RETRY_MIN_S = 1

_DECIMAL = re.compile(r"[0-9]{1,9}")


def _clock() -> float:
    return time.monotonic()


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


@dataclass(frozen=True, slots=True)
class _Answer:
    status: int
    payment_required: str | None
    retry_after: str | None
    body: bytes | None


@dataclass(frozen=True, slots=True)
class _Unanswered:
    """A request that reached no answer: its deadline passed, or the URL could not be reached."""


def _failed(detail: str, moved: Moved | None = None) -> Declined:
    return Declined("agreement-failed", detail, moved)


def _server_error(status: int) -> bool:
    """A 5xx answer to the paid request, which is read as a timeout: the same payment is sent again."""
    return 500 <= status <= 599


def _to_base64(value: object) -> str:
    """Standard base64 of the UTF-8 bytes of the compact JSON of value."""
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _from_base64_json(header: str) -> object | None:
    """The JSON value a base64 header carries, or None when it is not base64 of UTF-8 JSON."""
    if len(header) > MAX_ANSWER_BYTES:
        return None
    try:
        loaded: object = parse_json(base64.b64decode(header, validate=True).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return None if loaded is UNPARSED else loaded


def _retry_seconds(header: str | None) -> int:
    """retry-after in whole seconds, at least 1; 2 when absent or not a number of seconds."""
    value = header.strip() if header is not None else None
    if value is None or _DECIMAL.fullmatch(value) is None:
        return RETRY_DEFAULT_S
    return max(RETRY_MIN_S, int(value))


async def _get(
    fetch: httpx.AsyncClient, url: str, signature: str | None, seconds: float
) -> _Answer | _Unanswered | Declined:
    """One GET of the agreement URL, asking for the identity coding, with no redirect and a deadline of seconds over
    headers and body. A 200 whose Content-Encoding names any coding is agreement-failed with its body unread; a 200
    body is read as sent, up to 64 KiB, and nothing is decoded; any other body is left unread."""
    headers = dict(_gate.IDENTITY) if signature is None else {**_gate.IDENTITY, "PAYMENT-SIGNATURE": signature}
    too_large = _failed("The agreement receipt is larger than 64 KiB.")
    try:
        async with asyncio.timeout(seconds):
            async with fetch.stream("GET", url, headers=headers, follow_redirects=False) as response:
                answer = _Answer(
                    status=response.status_code,
                    payment_required=response.headers.get("payment-required"),
                    retry_after=response.headers.get("retry-after"),
                    body=None,
                )
                if response.status_code != 200:
                    return answer
                if not _gate.is_identity(response.headers.get("content-encoding")):
                    return _failed("The agreement URL served a content coding other than identity.")
                declared = response.headers.get("content-length")
                if declared is not None and declared.strip().isdigit() and int(declared) > MAX_ANSWER_BYTES:
                    return too_large
                if response.is_stream_consumed:
                    return too_large if len(response.content) > MAX_ANSWER_BYTES else replace(answer, body=response.content)
                body = bytearray()
                async for chunk in response.aiter_raw():
                    body += chunk
                    if len(body) > MAX_ANSWER_BYTES:
                        return too_large
                return replace(answer, body=bytes(body))
    except Exception:
        return _Unanswered()


def _receipt(body: bytes | None, h: AtrHash) -> Agreed | Declined:
    """The receipt a 200 carries, when it is the agreement receipt for h."""
    try:
        parsed: object = parse_json((body or b"").decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _failed("The agreement URL answered 200 without a JSON receipt.")
    if parsed is UNPARSED or not isinstance(parsed, Mapping):
        return _failed("The agreement URL answered 200 without a JSON receipt.")
    atr_hash = parsed.get("atrHash")
    if not isinstance(atr_hash, str) or not is_hash(atr_hash) or not hash_equals(atr_hash, h):
        return _failed("The agreement receipt names another ATR hash.")
    network = parsed.get("network")
    transaction = parsed.get("transaction")
    if parsed.get("agreed") is not True or not isinstance(network, str) or not isinstance(transaction, str):
        return _failed("The agreement receipt is not a recorded agreement.")
    return Agreed(AgreementReceipt(atr_hash=atr_hash, agreed=True, network=network, transaction=transaction))


def _x402_bindings() -> tuple[Binding, ...]:
    """The x402 pairings the gate serves, in the protocol package's order."""
    from . import (
        X402_AUTH_CAPTURE_EIP155_EIP3009,
        X402_AUTH_CAPTURE_EIP155_PERMIT2,
        X402_BATCH_SETTLEMENT_CLOUDFLARE,
        X402_BATCH_SETTLEMENT_EIP155,
        X402_BATCH_SETTLEMENT_SOLANA,
        X402_EXACT_ALGORAND,
        X402_EXACT_APTOS,
        X402_EXACT_CARDANO,
        X402_EXACT_CASPER,
        X402_EXACT_CCD,
        X402_EXACT_EIP155_EIP3009,
        X402_EXACT_EIP155_ERC7710,
        X402_EXACT_EIP155_ERC7710_SALT,
        X402_EXACT_EIP155_PERMIT2,
        X402_EXACT_HEDERA,
        X402_EXACT_HEDERA_TRANSFER_EXECUTOR,
        X402_EXACT_LNBTC,
        X402_EXACT_LNBTC_INVOICE_NAMED,
        X402_EXACT_NEAR,
        X402_EXACT_POLKADOT_LCP_ASSETS_REMARK,
        X402_EXACT_SOLANA,
        X402_EXACT_STARKNET,
        X402_EXACT_STELLAR,
        X402_EXACT_SUI,
        X402_EXACT_TRON_LCP_TRC20_MEMO,
        X402_EXACT_TVM,
        X402_EXACT_XRPL,
        X402_UPTO_EIP155_PERMIT2,
        X402_UPTO_SOLANA,
    )

    return (
        X402_EXACT_EIP155_EIP3009,
        X402_AUTH_CAPTURE_EIP155_EIP3009,
        X402_AUTH_CAPTURE_EIP155_PERMIT2,
        X402_BATCH_SETTLEMENT_CLOUDFLARE,
        X402_BATCH_SETTLEMENT_EIP155,
        X402_BATCH_SETTLEMENT_SOLANA,
        X402_EXACT_ALGORAND,
        X402_EXACT_APTOS,
        X402_EXACT_CARDANO,
        X402_EXACT_CASPER,
        X402_EXACT_CCD,
        X402_EXACT_EIP155_ERC7710,
        X402_EXACT_EIP155_ERC7710_SALT,
        X402_EXACT_EIP155_PERMIT2,
        X402_EXACT_HEDERA,
        X402_EXACT_HEDERA_TRANSFER_EXECUTOR,
        X402_EXACT_LNBTC,
        X402_EXACT_LNBTC_INVOICE_NAMED,
        X402_EXACT_NEAR,
        X402_EXACT_POLKADOT_LCP_ASSETS_REMARK,
        X402_EXACT_SOLANA,
        X402_EXACT_STARKNET,
        X402_EXACT_STELLAR,
        X402_EXACT_SUI,
        X402_EXACT_TRON_LCP_TRC20_MEMO,
        X402_EXACT_TVM,
        X402_EXACT_XRPL,
        X402_UPTO_EIP155_PERMIT2,
        X402_UPTO_SOLANA,
    )


def _agreement_pairing(required: Mapping[str, Any]) -> tuple[Binding, Advertised, Mapping[str, Any]] | Declined:
    """The pairing that placed the agreement option, when its payment is itself a public proof, with its read and the
    option."""
    accepts = required.get("accepts")
    if not isinstance(accepts, Sequence) or isinstance(accepts, str) or not accepts or not isinstance(accepts[0], Mapping):
        return Declined("offer-unreadable", "x402/no-payable-option")
    for binding in _x402_bindings():
        try:
            read = binding.read(required)
        except Exception:
            continue
        if isinstance(read, Advertised):
            if getattr(binding, "public_proof", False) is not True:
                return Declined("pairing-not-supported", f"The agreement pairing {binding.id} is not itself a public proof.")
            return binding, read, accepts[0]
    return Declined("pairing-not-supported", "The agreement option names no pairing the gate serves.")


def _bounds(option: Mapping[str, Any]) -> tuple[int, int] | None:
    """The paid request's deadline and the whole exchange's, in seconds, from the option's maxTimeoutSeconds."""
    t = option.get("maxTimeoutSeconds")
    if isinstance(t, bool) or not isinstance(t, int) or t <= 0 or t > 2**53 - 1:
        return None
    return min(t, EXCHANGE_CAP_S) + SETTLE_S + VERIFY_S, t + WINDOW_EXTRA_S


async def agree(
    h: AtrHash,
    url: str,
    signer: Signer,
    fetch: httpx.AsyncClient,
    *,
    atr_bytes: bytes,
    inputs: Inputs | None = None,
    ns: str | None = None,
) -> Agreed | Declined:
    """Pay the agreement for h at url with signer, and return its receipt once recorded. atr_bytes are the ATR the
    gate compared, for a pairing whose build reads them; inputs are the buyer's own chain values; ns is the namespace
    of the pairing whose offer named the URL, which a refused URL's detail carries with the protocol package's code."""
    if not is_https_link(url):
        if ns is None:
            return Declined("link-not-https", "The agreement URL is not an https URL.")
        fault = "link-not-https" if is_other_scheme_link(url) else "legal-context-malformed"
        return Declined("link-not-https", f"{ns}/{fault}")

    unpaid = await _get(fetch, url, None, UNPAID_DEADLINE_S)
    if isinstance(unpaid, Declined):
        return unpaid
    if isinstance(unpaid, _Unanswered):
        return _failed("The agreement URL could not be reached.")
    if unpaid.status == 200:
        return _receipt(unpaid.body, h)
    if unpaid.status == 202:
        return Declined("agreement-pending", "An agreement payment for this ATR is already settling.")
    if unpaid.status != 402:
        return _failed(f"The agreement URL answered status {unpaid.status}.")

    required = None if unpaid.payment_required is None else _from_base64_json(unpaid.payment_required)
    if not isinstance(required, Mapping):
        return _failed("The agreement URL answered 402 without a readable PAYMENT-REQUIRED.")
    found = _agreement_pairing(required)
    if isinstance(found, Declined):
        return found
    binding, read, option = found
    limits = _bounds(option)
    if limits is None:
        return Declined("offer-unreadable", "x402/option-malformed")
    if not hash_equals(read.h, h):
        return Declined("hash-mismatch", "The agreement challenge advertises another ATR hash.")

    paid = await _gate.pay(binding, read, required, signer, inputs if isinstance(inputs, Mapping) else {}, atr_bytes)
    if isinstance(paid, Declined):
        return paid
    if paid is None:
        return Declined("offer-unreadable", "The agreement payment gave nothing to sign.")
    payment = _to_base64(paid.signed)
    moved = Moved(paid.signed, atr_bytes, h)
    pending = Declined("agreement-pending", "The agreement payment was sent and is not yet recorded.", moved)

    request_s, exchange_s = limits
    end = _clock() + exchange_s
    while True:
        remaining = end - _clock()
        if remaining <= 0:
            return pending
        answer = await _get(fetch, url, payment, min(request_s, remaining))
        if isinstance(answer, Declined):
            return replace(answer, moved=moved)
        wait = float(RETRY_DEFAULT_S)
        if isinstance(answer, _Answer) and not _server_error(answer.status):
            if answer.status == 200:
                receipt = _receipt(answer.body, h)
                return replace(receipt, moved=moved) if isinstance(receipt, Declined) else receipt
            if answer.status != 202:
                return _failed(f"The agreement URL answered status {answer.status} to the payment.", moved)
            wait = float(_retry_seconds(answer.retry_after))
        await _sleep(max(0.0, min(wait, end - _clock())))
