"""The buyer pieces for Lightning: the buyer's node pays exactly the invoice the build names, and its answer is the
payment preimage, as the build's complete takes it. The node moves the payment, so a decline keeps it."""

import re
from typing import Any

from collections.abc import Mapping

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings._bolt11 import decode
from ..bindings._mpp import pairings_of
from ..bindings.lightning import LNBTC, MPP_CHARGE, MPP_SESSION
from ._base import BasePiece
from ._common import InputKind, account_of, bytes_of, choice_of, inputs_of
from ._mpp import challenges_of, pairings_of_placed, request_of
from ._x402_rail import Rail, RailPiece

# The BOLT11 currency of each lnbtc network, the CAIP-2 reference being the first 32 hex characters of the network's
# genesis block hash: bc mainnet; tb testnet3 and testnet4; tbs signet; bcrt regtest.
LN_CURRENCY = {
    "lnbtc:000000000019d6689c085ae165831e93": "bc",
    "lnbtc:000000000933ea01ad0ee984209779ba": "tb",
    "lnbtc:00000000da84f2bafbbc53dee25a72ae": "tb",
    "lnbtc:00000008819873e925422c1ff0f99f7c": "tbs",
    "lnbtc:0f9188f13cb7b2c71f2a335e3a4fc328": "bcrt",
}


# The BOLT11 currency of each network MPP Lightning names in methodDetails.network, as the protocol package's checks of a
# challenge read it: mainnet bc, signet tbs, regtest bcrt.
_MPP_LN_CURRENCY = {"mainnet": "bc", "signet": "tbs", "regtest": "bcrt"}


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


class LnMppPiece(BasePiece):
    """The first challenge offering the pairing whose BOLT11 currency is the account's lnbtc network's (_currency). A
    session's return invoice is the buyer's input, and rides in the build's choice."""

    def __init__(self, pairing: str, session: bool) -> None:
        self.pairing = pairing
        self._session = session
        self._spec: dict[str, InputKind] = {"returnInvoice": "string"} if session else {}

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        a = account_of(account)
        currency = LN_CURRENCY.get(a.network) if a is not None else None
        if a is None or a.namespace != "lnbtc" or currency is None:
            return Refusal("mpp/no-payable-option")
        challenge = next((c for c in challenges_of(read) if self._currency(c) == currency), None)
        if challenge is None:
            return Refusal("mpp/no-payable-option")
        given = inputs_of(inputs, self.pairing, self._spec)
        if isinstance(given, Refusal):
            return given
        return Chosen(pairing=self.pairing, choice={"challenge": challenge, **given}, ref=ref)

    def _currency(self, challenge: object) -> str | None:
        """The BOLT11 currency a challenge offering the pairing is paid in. A placed challenge, which pairings_of_placed
        names the pairing for: its invoice's. A challenge as issued, which the ATR's binding slot holds without the
        invoice the seller's node writes after H (lcp profile mpp-charge.md, rule 5), and which pairings_of names the
        pairing for (it refuses a challenge whose opaque carries H, so no challenge the seller placed is read so): the
        currency of the network its methodDetails.network names. None for any other, an issued challenge naming no
        network among them."""
        invoice = _invoice_of(challenge, self._session)
        if self.pairing in pairings_of_placed(challenge):
            b = decode(invoice) if isinstance(invoice, str) else None
            return b.currency if b is not None and not isinstance(b, Refusal) else None
        if invoice is not None:
            return None
        named = pairings_of(challenge)
        if isinstance(named, Refusal) or self.pairing not in named:
            return None
        request = request_of(challenge)
        details = request.get("methodDetails") if request is not None else None
        network = details.get("network") if isinstance(details, Mapping) else None
        return _MPP_LN_CURRENCY.get(network) if isinstance(network, str) else None

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


MPP_CHARGE_PIECE = LnMppPiece(MPP_CHARGE, False)
MPP_SESSION_PIECE = LnMppPiece(MPP_SESSION, True)


# ── x402/exact/lnbtc/payment-hash ──


def _lnbtc_inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any]:
    """The buyer's request, where inputs gives it as an object; else nothing, the build declining it."""
    request = given.get("request") if isinstance(given, Mapping) else None
    return {"request": request} if isinstance(request, Mapping) else {}


def _lnbtc_revive(c: dict[str, Any]) -> dict[str, Any] | Refusal:
    """The choice as the build takes it: the request's body, on http:1, as bytes; a choice without the request, or
    with a body that is not 0x hex, is x402/input-missing."""
    request = c.get("request")
    if not isinstance(request, Mapping):
        return Refusal("x402/input-missing")
    if request.get("profile") != "http:1":
        return c
    body = bytes_of(request["body"] if "body" in request else "0x")
    return Refusal("x402/input-missing") if body is None else {**c, "request": {**request, "body": body}}


def _preimage(signature: Signature) -> str | Refusal:
    return signature if isinstance(signature, str) else Refusal("ln/preimage-malformed")


class LnbtcPaymentHashPiece(RailPiece):
    """x402/exact/lnbtc/payment-hash: the buyer signs nothing; its node pays the BOLT 11 invoice the seller's node
    issued after the agreement for the payment hash the ATR commits, and its answer is the payment preimage. The
    binding's build makes the client's checks of the option and its invoice before it hands over the invoice to pay
    (lcp profile x402-exact-lnbtc.md, rules 6 and 7). The buyer's request is the input request, the request the buyer
    means to make: over HTTP {profile: "http:1", method, url, body?, headers?}, body the content bytes as 0x hex (absent
    for no body); over MCP {profile: "mcp:1", server, name, arguments?, meta?}. It is read at the build, once the ATR's
    hash is held, so an offer is chosen without it. The node moves the payment, so a decline after it keeps it."""

    def moves(self, request: Json) -> bool:
        return True


LNBTC_PIECE = LnbtcPaymentHashPiece(
    Rail(
        pairing=LNBTC,
        namespace="lnbtc",
        # The payer is named in nothing the node pays, so the account's address is not read.
        address=re.compile(r".*", re.DOTALL),
        payer=None,
        now=True,
        inputs=_lnbtc_inputs,
        revive=_lnbtc_revive,
        answer=_preimage,
    )
)
