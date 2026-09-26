"""What the protocol-group pieces (card, AP2, UCP, ACP, ACK) share: the buyer's CAIP-10 account, which names the
buyer, the object choice revived from Chosen, and the piece of a pairing whose build has nothing for the buyer to
sign."""

from collections.abc import Callable
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ._base import BasePiece
from ._common import account_of, choice_of

# The pairing's build input as the piece stores it in Chosen, or the refusal that names why there is none.
Choose = Callable[[Advertised, str, Inputs, int, str, Json], "dict[str, Any] | Refusal"]


def unnamed_buyer(account: object, ns: str) -> Refusal | None:
    """A refusal <ns>/no-payable-option unless the account is CAIP-10."""
    return Refusal(f"{ns}/no-payable-option") if account_of(account) is None else None


def object_choice(chosen: Chosen, ns: str) -> dict[str, Any] | Refusal:
    """The choice object of chosen, or <ns>/choice-malformed."""
    choice = choice_of(chosen)
    return choice if choice is not None else Refusal(f"{ns}/choice-malformed")


class ConfirmOnlyPiece(BasePiece):
    """The piece of a pairing whose build refuses no-signed-place or nothing-to-sign: it chooses, and the gate
    confirms only. Nothing is handed to a signer, and nothing completes."""

    def __init__(self, pairing: str, choose: Choose) -> None:
        self.pairing = pairing
        self._ns = pairing.split("/")[0]
        self._choose = choose

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        choice = self._choose(read, account, inputs, now, ref, doc)
        if isinstance(choice, Refusal):
            return choice
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return object_choice(chosen, self._ns)

    def request(self, unsigned: Any) -> Refusal:
        return Refusal(f"{self._ns}/nothing-to-sign")

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> Refusal:
        return Refusal(f"{self._ns}/nothing-to-sign")
