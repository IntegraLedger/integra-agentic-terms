"""What a channel pairing's binding gives the buyer's channel steps: the kind of a payment in its channel, the
channel's identifier, the hash a later payment is signed under, and the several signing requests a payment signed in
order carries."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from .._core import AtrHash
from .._types import Advertised, Json, Refusal

ChannelKind = Literal["open", "within", "close"]


@dataclass(frozen=True, slots=True)
class ChannelRef:
    """The channel's network and identifier: a read key only."""

    network: str
    channel: str


@dataclass(frozen=True, slots=True)
class BatchUnsigned:
    """Several signing requests, signed in order; complete takes one answer per request."""

    requests: Sequence[dict[str, Any]]
    complete: Callable[[Sequence[str]], dict[str, Any] | Refusal]


class ChannelBinding(Protocol):
    """A channel pairing's binding: every binding's id, read and bound, and the channel members the buyer's channel
    steps call. A pairing whose later payments are not signed under H refuses bound_within with a code ending
    /not-bound-within."""

    @property
    def id(self) -> str: ...

    def read(self, doc: Json) -> Advertised | Refusal: ...

    def bound(self, presented: Json) -> AtrHash | Refusal: ...

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal: ...

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal: ...

    def bound_within(self, presented: Json) -> AtrHash | Refusal: ...

    def build_within(self, w: Mapping[str, Any], h: AtrHash) -> BatchUnsigned | Refusal: ...
