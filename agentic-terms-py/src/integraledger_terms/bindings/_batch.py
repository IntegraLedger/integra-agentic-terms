"""What the x402 batch-settlement pairings share: the scheme's name, the withdraw delay's range, an option build can
pay, the payload of a presented payment of one pairing, and the EVM hex signature."""

import re
from collections.abc import Callable, Mapping
from typing import Any

from .._types import Refusal
from ._lcp import is_object, safe_int

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
    """An option whose amount is a decimal below 2^128 and whose maxTimeoutSeconds is a positive safe integer."""
    amount = option.get("amount")
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    return isinstance(amount, str) and is_decimal(amount) and int(amount) < U128_LIMIT and timeout is not None and timeout > 0


def payload_of(
    presented: object, is_pairing: Callable[[Mapping[str, Any]], bool]
) -> tuple[Mapping[str, Any], Mapping[str, Any]] | Refusal:
    """A presented x402 v2 payment of the pairing: its accepted option and its payload object."""
    if not is_object(presented) or safe_int(presented.get("x402Version")) != 2 or isinstance(
        presented.get("x402Version"), bool
    ):
        return Refusal("x402/not-v2")
    accepted = presented.get("accepted")
    if not is_object(accepted) or not is_pairing(accepted):
        return Refusal("x402/option-not-this-pairing")
    payload = presented.get("payload")
    if not is_object(payload):
        return Refusal("x402/payload-malformed")
    return accepted, payload


def is_hex_signature(value: object) -> bool:
    """0x and at least one byte of hex, at most 8 KiB."""
    return isinstance(value, str) and len(value) <= MAX_SIGNATURE_HEX and _SIGNATURE.fullmatch(value) is not None
