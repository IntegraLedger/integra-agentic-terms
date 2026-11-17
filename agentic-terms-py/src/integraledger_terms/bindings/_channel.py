"""What a channel pairing's binding gives the buyer's channel steps: the kind of a payment in its channel, the
channel's identifier, and the several signing requests a payment signed in order carries."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .._types import Refusal

ChannelKind = Literal["open", "within", "close"]


@dataclass(frozen=True, slots=True)
class ChannelRef:
    """The channel's network and identifier: a read key only."""

    network: str
    channel: str


@dataclass(frozen=True, slots=True)
class BatchUnsigned:
    """Several signing requests, signed in order; complete takes one answer per request. config, on an x402
    batch-settlement EVM opening, is the channel's configuration, whose batch_channel_id under the requests' chain id is
    the channelId the deposit authorization and the voucher sign; no other build gives it."""

    requests: Sequence[dict[str, Any]]
    complete: Callable[[Sequence[str]], dict[str, Any] | Refusal]
    config: Mapping[str, Any] | None = None
