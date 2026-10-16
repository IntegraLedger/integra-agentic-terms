"""What the x402 batch-settlement pairings share: the scheme's name, the withdraw delay's range, an option build can
pay, the payload of a presented payment of one pairing, who broadcasts a payment of the channel, and the EVM hex
signature."""

import re
from collections.abc import Callable, Mapping
from typing import Any

from .._types import Broadcaster, Refusal
from ._lcp import is_object, safe_int
from ._x402 import OptionFilter, accepted_by, is_amount, timeout_seconds, x402_shape

SCHEME = "batch-settlement"
MIN_DELAY = 900
MAX_DELAY = 2_592_000
MAX_SIGNATURE_HEX = 2 + 2 * 8192
U128_LIMIT = 1 << 128
DECIMAL = re.compile(r"[0-9]{1,39}")
_SIGNATURE = re.compile(r"0x(?:[0-9a-fA-F]{2})+")


def is_delay(value: object) -> bool:
    """An integer from 900 to 2 592 000 seconds."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return MIN_DELAY <= value <= MAX_DELAY


def is_decimal(value: object) -> bool:
    return isinstance(value, str) and DECIMAL.fullmatch(value) is not None


def payable(option: Mapping[str, Any]) -> bool:
    """An option whose amount is "0" or a positive amount (is_amount) below 2^128, and whose maxTimeoutSeconds is a
    positive safe integer. The EVM and Solana batch-settlement schemes take a zero price: their facilitator validates
    amount as a non-negative base-10 integer string. On EVM a zero price opens no channel: the opening's build refuses
    an option under it."""
    amount = option.get("amount")
    return (
        (amount == "0" or is_amount(amount))
        and is_decimal(amount)
        and int(amount) < U128_LIMIT
        and timeout_seconds(option.get("maxTimeoutSeconds")) is not None
    )


def payload_of(presented: object, check: OptionFilter) -> tuple[Mapping[str, Any], Mapping[str, Any]] | Refusal:
    """A presented x402 v2 payment of the pairing: its accepted option, held to the pairing's filter by accepted_by,
    and its payload object."""
    if not is_object(presented) or safe_int(presented.get("x402Version")) != 2 or isinstance(
        presented.get("x402Version"), bool
    ):
        return Refusal("x402/not-v2")
    accepted = accepted_by(presented.get("accepted"), check)
    if isinstance(accepted, Refusal):
        return accepted
    payload = presented.get("payload")
    if not is_object(payload):
        return Refusal("x402/payload-malformed")
    return accepted, payload


def batch_broadcaster(presented: object, kind: Callable[[Mapping[str, Any]], object]) -> Broadcaster | Refusal:
    """The broadcaster of a batch-settlement channel: "payee", for a payment within x402_shape's gate whose payload
    kind, the payload read of the pairing's channel_kind, takes. A payment of a type kind refuses
    x402/channel-kind-unknown gets x402/not-an-opening, as bound refuses it. bound reads a deposit alone, so kind is the
    reader of every other type: a payment it refuses for its content, such as a refund whose amount the channel contract
    does not take, gets kind's refusal. A deposit's content is bound's to read. kind reads no option, so which option
    accepted is does not change the answer."""
    shape = x402_shape(presented)
    if isinstance(shape, Refusal):
        return shape
    assert is_object(presented)
    payload = presented["payload"]
    k = kind(payload)
    if not isinstance(k, Refusal):
        return "payee"
    if k.code == "x402/channel-kind-unknown":
        return Refusal("x402/not-an-opening")
    return "payee" if payload.get("type") == "deposit" else k


def is_hex_signature(value: object) -> bool:
    """0x and at least one byte of hex, at most 8 KiB."""
    return isinstance(value, str) and len(value) <= MAX_SIGNATURE_HEX and _SIGNATURE.fullmatch(value) is not None
