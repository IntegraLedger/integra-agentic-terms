"""The buyer pieces for Lightning on x402 and MPP: the buyer's node pays exactly the invoice the build names, and its
answer is the payment preimage, as the build's complete takes it. The node moves the payment, so a decline keeps
it."""

from typing import Any

from collections.abc import Mapping

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings._bolt11 import decode
from ..bindings.lightning import LNBTC, MPP_CHARGE, MPP_SESSION, NAMED
from ._base import BasePiece
from ._common import InputKind, account_of, choice_of, first_option, inputs_of, with_payment_identifier
from ._lnbtc_request import check_request_hash
from ._mpp import challenges_of, pairings_of_placed, request_of

# The BOLT11 currency of each lnbtc network, the CAIP-2 reference being the first 32 hex characters of the network's
# genesis block hash: bc mainnet; tb testnet3 and testnet4; tbs signet; bcrt regtest.
_LN_CURRENCY = {
    "lnbtc:000000000019d6689c085ae165831e93": "bc",
    "lnbtc:000000000933ea01ad0ee984209779ba": "tb",
    "lnbtc:00000000da84f2bafbbc53dee25a72ae": "tb",
    "lnbtc:00000008819873e925422c1ff0f99f7c": "tbs",
    "lnbtc:0f9188f13cb7b2c71f2a335e3a4fc328": "bcrt",
}


def _invoice_of(challenge: object, session: bool) -> object:
    """The invoice a Lightning challenge asks the node to pay: a charge's methodDetails.invoice, a session's
    deposit."""
    request = request_of(challenge)
    if request is None:
        return None
    if session:
        return request.get("depositInvoice")
    details = request.get("methodDetails")
    return details.get("invoice") if isinstance(details, Mapping) else None


class LnbtcPiece(BasePiece):
    """The first option on the account's lnbtc network, whose request hash, recomputed from the buyer's own request
    (the request input), equals both the option's extra.requestHash and the invoice's description hash. With named, the
    build reads the ATR the gate compared, which rides beside the choice as the bytes the gate passes."""

    def __init__(self, pairing: str, named: bool) -> None:
        self.pairing = pairing
        self._named = named

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        o = first_option(read, account, "lnbtc", self.pairing)
        if isinstance(o, Refusal):
            return Refusal("x402/no-payable-option")
        request = inputs.get("request") if isinstance(inputs, Mapping) else None
        if request is None:
            return Refusal("x402/input-missing")
        resource = o.required.get("resource") if isinstance(o.required, Mapping) else None
        url = resource.get("url") if isinstance(resource, Mapping) else None
        checked = check_request_hash(o.accepted, url, request)
        if isinstance(checked, Refusal):
            return checked
        return Chosen(pairing=self.pairing, choice={"required": o.required, "accepted": o.accepted}, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = choice_of(chosen)
        if c is None:
            return Refusal("x402/choice-malformed")
        return {**c, "atr": atr_bytes} if self._named else c

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        """The paid payment, with the payment identifier where the challenge advertises it."""
        if not isinstance(signature, str):
            return Refusal("ln/preimage-malformed")
        signed = unsigned.complete(signature)
        if isinstance(signed, Refusal):
            return signed
        c = choice_of(chosen)
        return with_payment_identifier(signed, c.get("required") if c is not None else None, chosen.ref)

    def moves(self, request: Json) -> bool:
        return True


class LnMppPiece(BasePiece):
    """The first challenge offering the pairing whose invoice's BOLT11 currency is the account's lnbtc network's. A
    session's return invoice is the buyer's input, and rides in the build's choice."""

    def __init__(self, pairing: str, session: bool) -> None:
        self.pairing = pairing
        self._session = session
        self._spec: dict[str, InputKind] = {"returnInvoice": "string"} if session else {}

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        a = account_of(account)
        currency = _LN_CURRENCY.get(a.network) if a is not None else None
        if a is None or a.namespace != "lnbtc" or currency is None:
            return Refusal("mpp/no-payable-option")
        challenge = next(
            (c for c in challenges_of(read) if self.pairing in pairings_of_placed(c) and self._currency(c) == currency),
            None,
        )
        if challenge is None:
            return Refusal("mpp/no-payable-option")
        given = inputs_of(inputs, self.pairing, self._spec)
        if isinstance(given, Refusal):
            return given
        return Chosen(pairing=self.pairing, choice={"challenge": challenge, **given}, ref=ref)

    def _currency(self, challenge: object) -> str | None:
        invoice = _invoice_of(challenge, self._session)
        b = decode(invoice) if isinstance(invoice, str) else None
        return b.currency if b is not None and not isinstance(b, Refusal) else None

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = choice_of(chosen)
        return Refusal("mpp/choice-malformed") if c is None else c

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, str):
            return Refusal("ln/preimage-malformed")
        signed: dict[str, Any] | Refusal = unsigned.complete(signature)
        return signed

    def moves(self, request: Json) -> bool:
        return True


LNBTC_PIECE = LnbtcPiece(LNBTC, False)
NAMED_PIECE = LnbtcPiece(NAMED, True)
MPP_CHARGE_PIECE = LnMppPiece(MPP_CHARGE, False)
MPP_SESSION_PIECE = LnMppPiece(MPP_SESSION, True)
