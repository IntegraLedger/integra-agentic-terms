"""The buyer piece for mpp/charge/nearintents: the first challenge offering the pairing whose originNetwork is the
account's network. Nothing the buyer deposits carries the hash, so the gate's comparison is the whole of the buyer's
step."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.mpp_charge_nearintents import ID
from ._base import BasePiece
from ._mpp import MppRail, rail_choose


def _nothing_to_sign(*_: Any) -> Refusal:
    return Refusal("mpp/nothing-to-sign")


def _no_inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any]:
    return {}


_RAIL = MppRail(
    pairing=ID,
    namespace=None,
    address=re.compile(r".+", re.DOTALL),
    payer=None,
    now=False,
    inputs=_no_inputs,
    revive=lambda c: c,
    complete=_nothing_to_sign,
)


class MppChargeNearIntentsPiece(BasePiece):
    pairing = ID

    def __init__(self) -> None:
        self._choose = rail_choose(_RAIL)

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        return self._choose(read, account, inputs, now, ref, doc)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Refusal:
        return _nothing_to_sign()

    def request(self, unsigned: Any) -> Refusal:
        return _nothing_to_sign()

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> Refusal:
        return _nothing_to_sign()


PIECE = MppChargeNearIntentsPiece()
