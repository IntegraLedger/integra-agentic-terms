"""The buyer half of the pairing x402/upto/xrpl: x402's upto scheme on the XRP Ledger, at coverage none. The payer opens
a payment channel to the option's payTo itself and presents the channel and its own account, so nothing it signs
carries the ATR hash and the protocol package builds nothing; the payment follows an agreement on the same network.
read offers the options the scheme defines (specs/schemes/upto/scheme_upto_xrpl.md at x402-foundation/x402 88b66dd4),
bound holds a presented payment to that filter and to its form before it finds no signed place for H, and broadcaster
answers payer. Nothing here fetches or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Refusal
from ._lcp import MAX_SAFE_INTEGER, is_object, safe_int
from ._x402 import presented_with, read_for, timeout_seconds, x402_broadcaster
from ._xrpl import is_xrpl_network
from ._xrpl_codec import account_id_of

ID = "x402/upto/xrpl"
# Drops of XRP: a positive integer in canonical decimal below 10^17, the most an XRP amount holds.
_DROPS = re.compile(r"[1-9][0-9]{0,16}")
_HASH256 = re.compile(r"[0-9A-Fa-f]{64}")
# The largest SettleDelay a PaymentChannelCreate carries, a UInt32 field.
_MAX_SETTLE_DELAY = 0xFFFFFFFF
_ABSENT = object()


def _optional_count(value: object, maximum: int) -> bool:
    """Absent, null, or a non-negative safe integer no greater than maximum: the scheme's optional extra integers."""
    if value is _ABSENT or value is None:
        return True
    n = safe_int(value)
    return n is not None and 0 <= n <= maximum


def _payable(option: Mapping[str, Any]) -> bool:
    """True when the option can be paid as the scheme defines it: amount drops of XRP, payTo a classic address whose
    checksum holds, a positive safe-integer maxTimeoutSeconds, extra.areFeesSponsored false, and extra.minSettleDelay
    and extra.validAfter each absent, null, or a non-negative integer, minSettleDelay within a UInt32
    (scheme_upto_xrpl.md:144-150, :236-243)."""
    amount = option.get("amount")
    if not isinstance(amount, str) or _DROPS.fullmatch(amount) is None:
        return False
    if account_id_of(option.get("payTo")) is None or timeout_seconds(option.get("maxTimeoutSeconds")) is None:
        return False
    extra = option.get("extra")
    if not is_object(extra) or extra.get("areFeesSponsored", _ABSENT) is not False:
        return False
    return _optional_count(extra.get("minSettleDelay", _ABSENT), _MAX_SETTLE_DELAY) and _optional_count(
        extra.get("validAfter", _ABSENT), MAX_SAFE_INTEGER
    )


def option_filter(option: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """The pairing's option filter, which read and bound apply: an upto option on an XRPL network is this pairing's. One
    whose asset is not XRP is xrpl/currency-not-xrp, a payment channel holding XRP alone (scheme_upto_xrpl.md:62-66);
    one _payable refuses is x402/option-malformed; any other option is not this pairing's."""
    if option.get("scheme") != "upto" or not is_xrpl_network(option.get("network")):
        return None
    if option.get("asset") != "XRP":
        return Refusal("xrpl/currency-not-xrp")
    return True if _payable(option) else Refusal("x402/option-malformed")


_read = read_for(option_filter)


@dataclass(frozen=True, slots=True)
class X402UptoXrpl:
    id: str = ID
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "same-network"

    def read(self, doc: Any) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Any, h: AtrHash, act: Act | None = None) -> Refusal:
        """The protocol package builds nothing for this pairing: the payer's own client opens the channel."""
        return Refusal("x402/nothing-to-sign")

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """Nothing the payer signs carries H at coverage none, neither the channel's create nor its claim: once the
        payment's accepted passes the filter and its payload names a channel, 64 hex digits, and a payer, a classic
        address whose checksum holds (else x402/payload-malformed), x402/no-signed-place. The act changes nothing."""
        p = presented_with(presented, option_filter)
        if isinstance(p, Refusal):
            return p
        payload = p[1]
        channel, payer = payload.get("channelId"), payload.get("payer")
        if not isinstance(channel, str) or _HASH256.fullmatch(channel) is None or account_id_of(payer) is None:
            return Refusal("x402/payload-malformed")
        return Refusal("x402/no-signed-place")

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payer: its client submits the channel's create before it presents the payment, which names that
        channel."""
        return x402_broadcaster(presented, "payer")
