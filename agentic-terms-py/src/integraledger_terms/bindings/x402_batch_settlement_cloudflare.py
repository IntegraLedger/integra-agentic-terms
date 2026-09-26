"""The buyer half of x402/batch-settlement/cloudflare: read, build and bound.

The ATR hash rides the challenge's extensions.legalContext, echoed in the payment. The build is itself the payment;
the agent's HTTP message signature covers the header that carries it, and Cloudflare verifies that signature. There is
no channel. Nothing here fetches, hashes an ATR or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._batch import SCHEME
from ._lcp import is_object, normal_hash, safe_int
from ._x402 import chosen, filter_of, legal_context_of, read_for

ID = "x402/batch-settlement/cloudflare"
NETWORK = "cloudflare:402"
_CURRENCY = re.compile(r"[A-Z]{3}")


def is_pairing(option: Mapping[str, Any]) -> bool:
    """The option names x402/batch-settlement/cloudflare: scheme batch-settlement on cloudflare:402, payTo merchant,
    a three-letter currency as asset, and extra.version present."""
    if not is_object(option) or option.get("scheme") != SCHEME or not is_object(option.get("extra")):
        return False
    if option.get("network") != NETWORK or option.get("payTo") != "merchant":
        return False
    asset = option.get("asset")
    return isinstance(asset, str) and _CURRENCY.fullmatch(asset) is not None and "version" in option["extra"]


_FILTER = filter_of(is_pairing)


@dataclass(frozen=True, slots=True)
class X402BatchSettlementCloudflare:
    id: str = ID
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when the legal context names one, and the options this pairing can pay."""
        return read_for(_FILTER)(doc)

    def build(self, c: Json, h: AtrHash) -> dict[str, Any] | Refusal:
        """The request's payment document: the option's amount and asset, with the challenge's extensions echoed,
        when the challenge's legal context carries h."""
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _FILTER)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        lc = legal_context_of(required.get("extensions"))
        if isinstance(lc, Refusal):
            return lc
        if lc[0] != normal_hash(h):
            return Refusal("x402/legal-context-conflict")
        return {
            "x402Version": 2,
            "payload": {"amount": accepted.get("amount"), "asset": accepted.get("asset")},
            "accepted": accepted,
            "extensions": required["extensions"],
        }

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The echoed extensions.legalContext hash. The agent's HTTP message signature is not verified here."""
        version = presented.get("x402Version") if is_object(presented) else None
        if not is_object(presented) or isinstance(version, bool) or safe_int(version) != 2:
            return Refusal("x402/not-v2")
        accepted = presented.get("accepted")
        if not is_object(accepted) or not is_pairing(accepted):
            return Refusal("x402/option-not-this-pairing")
        lc = legal_context_of(presented.get("extensions"))
        return lc if isinstance(lc, Refusal) else lc[0]
