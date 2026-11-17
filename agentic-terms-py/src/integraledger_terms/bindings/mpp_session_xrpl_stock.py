"""The buyer half of mpp/session/xrpl/stock, the stock XRPL session, at coverage none: the stock client opens the channel
itself, out of band, with no memo, and presents vouchers that name it, so nothing the payer signs carries the ATR hash,
and the protocol package builds nothing. bound finds no signed place for H in a voucher or close that names its
channel, and refuses an open, which the stock server would submit with no memo; broadcaster answers payee, the seller's
server redeeming the vouchers and submitting the close. Nothing here fetches or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Refusal
from ._channel import ChannelKind
from ._mpp import credential_shape, read, session_broadcaster
from ._mpp_checks import xrpl_network_of
from ._session_within import action_kind, echoed_details

ID = "mpp/session/xrpl/stock"
_HASH256 = re.compile(r"[0-9A-Fa-f]{64}")


def _kind(presented: object) -> ChannelKind | Refusal:
    """A voucher is within the channel and a close closes it. An open, which the stock server would submit with no
    memo, is mpp/session-action before anything is submitted, as any other action is."""
    k = action_kind(presented, ("voucher",))
    return Refusal("mpp/session-action") if k == "open" else k


def _channel(presented: Mapping[str, Any]) -> tuple[str, str] | Refusal:
    """The network and channel a voucher or close names: the echoed challenge's methodDetails, read as the stock
    server's later challenges are (echoed_details), its network, and the payload's channelId, 64 hex digits, in upper
    case, else mpp/credential-malformed. An open is mpp/session-action."""
    details = echoed_details(presented, "xrpl")
    if isinstance(details, Refusal):
        return details
    k = _kind(presented)
    if isinstance(k, Refusal):
        return k
    network = xrpl_network_of(details)
    if isinstance(network, Refusal):
        return network
    channel = presented["payload"].get("channelId")
    if not isinstance(channel, str) or _HASH256.fullmatch(channel) is None:
        return Refusal("mpp/credential-malformed")
    return network, channel.upper()


@dataclass(frozen=True, slots=True)
class MppSessionXrplStock:
    id: str = ID
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "same-network"

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash, act: Act | None = None) -> Refusal:
        """The protocol package builds nothing for this pairing: the buyer's stock client opens the channel itself."""
        return Refusal("mpp/nothing-to-sign")

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """Nothing the payer signs carries H at coverage none: once the credential passes the shape gate and is a
        voucher or a close naming its channel, mpp/no-signed-place. The act changes nothing."""
        credential = credential_shape(presented)
        if isinstance(credential, Refusal):
            return credential
        held = _channel(credential)
        return held if isinstance(held, Refusal) else Refusal("mpp/no-signed-place")

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payee for a voucher and for a close: the seller's server redeems the vouchers and submits the close's
        PaymentChannelClaim; mpp/session-action for an open or any other action."""
        return session_broadcaster(presented, _kind, lambda c: "payee", "mpp/session-action")
