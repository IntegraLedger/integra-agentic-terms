"""The buyer half of mpp/session/hedera/stock, MPP's session intent with the stock method hedera, at coverage none: the
stock client sends the escrow's approve and open itself, with a random salt, so nothing the payer signs carries the ATR
hash, and the protocol package builds nothing. bound finds no signed place for H in an opening whose echoed challenge
the pairing takes, and broadcaster names who sends each action. Nothing here fetches or signs."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Refusal
from ._mpp import credential_of, echoed_for, read, session_broadcaster
from ._session_within import action_kind, echoed_details

ID = "mpp/session/hedera/stock"
# draft-hedera-session-00's actions within the channel, beside open and close.
WITHIN_ACTIONS = ("voucher", "topUp")


def _broadcasts(credential: Mapping[str, Any]) -> Broadcaster | Refusal:
    """Who broadcasts a stock session payment, as draft-hedera-session-00 has it: the payer an opening or a top-up, each
    a transaction it sends itself and names by txHash; the resource server a voucher, which it redeems when it closes,
    and the close, which it sends."""
    action = credential["payload"].get("action")
    if action in ("open", "topUp"):
        return "payer"
    return "payee" if action in ("voucher", "close") else Refusal("mpp/session-action")


@dataclass(frozen=True, slots=True)
class MppSessionHederaStock:
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
        """Nothing the payer signs carries H at coverage none: once the credential is an opening whose echoed challenge
        the pairing takes, mpp/no-signed-place; another action is mpp/session-action. The act changes nothing."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        e = echoed_for(credential, ID)
        if isinstance(e, Refusal):
            return e
        return Refusal("mpp/no-signed-place" if e.payload.get("action") == "open" else "mpp/session-action")

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payer for an opening and a top-up, which the buyer's client sends; the payee for a voucher and the close;
        mpp/session-action for any other action, and credential_shape's refusal for a credential outside its gate."""
        return session_broadcaster(
            presented,
            lambda c: action_kind(c, WITHIN_ACTIONS),
            _broadcasts,
            "mpp/session-action",
            lambda c: echoed_details(c, "hedera"),
        )
