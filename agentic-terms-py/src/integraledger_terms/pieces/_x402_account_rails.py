"""What the x402 pieces on account rails share: the option on the account's network, with the account's address
percent-decoded as CAIP-10 writes it, the payment identifier on the completed payment, and the piece for pairings
where the payer's wallet builds and signs the rail's own payment around what the build hands it."""

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .._types import Advertised, Chosen, Inputs, Refusal, Signature
from ._base import BasePiece
from ._common import FirstOption, account_of, choice_of, first_option, with_payment_identifier

NO_OPTION = "x402/no-payable-option"


def rail_option(
    read: Advertised, account: str, namespaces: Sequence[str], pairing: str, address: Callable[[str], bool]
) -> FirstOption | Refusal:
    """The first option on the account's network, for an account in one of namespaces whose decoded address passes
    address. The address is returned decoded."""
    a = account_of(account)
    if a is None or a.namespace not in namespaces:
        return Refusal(NO_OPTION)
    if not address(a.address):
        return Refusal(NO_OPTION)
    o = first_option(read, account, a.namespace, pairing)
    if isinstance(o, Refusal):
        return Refusal(NO_OPTION)
    return o


def identified(signed: object, chosen: Chosen) -> dict[str, Any] | Refusal:
    """The x402 payment with the payment identifier appended where the challenge advertises it."""
    if isinstance(signed, Refusal):
        return signed
    assert isinstance(signed, dict)
    choice = choice_of(chosen)
    return with_payment_identifier(signed, choice.get("required") if choice is not None else None, chosen.ref)


def chosen_choice(chosen: Chosen) -> dict[str, Any] | Refusal:
    """Chosen's choice object, or x402/choice-malformed."""
    choice = choice_of(chosen)
    return choice if choice is not None else Refusal("x402/choice-malformed")


class WalletBuiltPiece(BasePiece):
    """The buyer piece for an x402 pairing whose build takes only the challenge and the chosen option, and whose
    request the payer's wallet answers with the payment's own fields: each a string, passed to the build's complete as
    one object."""

    def __init__(
        self, pairing: str, namespaces: Sequence[str], address: Callable[[str], bool], fields: Sequence[str]
    ) -> None:
        self.pairing = pairing
        self._namespaces = tuple(namespaces)
        self._address = address
        self._fields = tuple(fields)

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Any) -> Chosen | Refusal:
        o = rail_option(read, account, self._namespaces, self.pairing, self._address)
        if isinstance(o, Refusal):
            return o
        return Chosen(pairing=self.pairing, choice={"required": o.required, "accepted": o.accepted}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return chosen_choice(chosen)

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, Mapping):
            return Refusal("x402/signature-malformed")
        signed: dict[str, str] = {}
        for field in self._fields:
            value = signature.get(field)
            if not isinstance(value, str):
                return Refusal("x402/signature-malformed")
            signed[field] = value
        return identified(unsigned.complete(signed), chosen)
