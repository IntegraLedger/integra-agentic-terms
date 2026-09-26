"""The buyer half of mpp/charge/nearintents: the ATR hash in LCP string form as the request's externalId, inside the
challenge the seller's server binds. The buyer's deposit carries nothing of this pairing, so nothing is built for the
buyer to sign."""

from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Refusal
from ._lcp import from_lcp_string
from ._mpp import echoed_for, read

ID = "mpp/charge/nearintents"


@dataclass(frozen=True, slots=True)
class MppChargeNearIntents:
    id: str = ID
    public_proof: bool = False

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> Refusal:
        """The deposit is not built here: there is nothing for the buyer to sign."""
        return Refusal("mpp/nothing-to-sign")

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """H from the echoed challenge's externalId, for a push credential (type "hash") whose challenge names that
        H."""
        e = echoed_for(presented, ID)
        if isinstance(e, Refusal):
            return e
        if e.payload.get("type") != "hash":
            return Refusal("near/not-hash-credential")
        ext = e.checked.request.get("externalId")
        h = from_lcp_string(ext) if isinstance(ext, str) else None
        if h is None:
            return Refusal("near/memo-not-lcp")
        if not hash_equals(h, e.h):
            return Refusal("mpp/carrier-not-challenge")
        return e.h
