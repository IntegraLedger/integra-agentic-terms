"""The buyer half of the pairing x402/exact/stellar: read, build with complete, and bound.

The challenge's extensions.legalContext carries the ATR hash, and its first 8 bytes ride as the muxed id of the
option's payTo, which the payer signs as the Soroban transfer's to. Nothing here fetches or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from . import _stellar
from ._lcp import is_object, safe_int
from ._x402 import chosen, filter_of, legal_context_of, read_for

ID = "x402/exact/stellar"

_AMOUNT = re.compile(r"[1-9][0-9]{0,37}")
_I128_LIMIT = 1 << 127


def pairing_of(option: object) -> str | None:
    """This pairing's id for an option it can pay: scheme exact, a Stellar network, a contract asset, a G or M payTo,
    and fees sponsored."""
    if not is_object(option) or option.get("scheme") != "exact" or not _stellar.is_stellar_network(option.get("network")):
        return None
    pay_to = option.get("payTo")
    if not _stellar.is_contract(option.get("asset")) or not (_stellar.is_account(pay_to) or _stellar.is_muxed(pay_to)):
        return None
    extra = option.get("extra")
    if not is_object(extra) or extra.get("areFeesSponsored") is not True:
        return None
    return ID


def _is_this(option: Mapping[str, Any]) -> bool:
    return pairing_of(option) is not None


_THIS = filter_of(_is_this)


def _payable(option: Mapping[str, Any]) -> bool:
    """True when the amount is a positive i128 in decimal and the timeout a positive safe integer."""
    amount = option.get("amount")
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    return (
        isinstance(amount, str)
        and _AMOUNT.fullmatch(amount) is not None
        and int(amount) < _I128_LIMIT
        and timeout is not None
        and timeout > 0
    )


@dataclass(frozen=True, slots=True)
class X402ExactStellar:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(_THIS)(doc)

    def build(self, choice: Json, h: AtrHash) -> _stellar.StellarUnsigned | Refusal:
        """The authorization preimage for the payer to sign, from the buyer's simulated transaction, with the entry's
        expiration at currentLedger + ceil(maxTimeoutSeconds / 5). The option's payTo must carry muxed_id(h) and
        equal the simulated to."""
        c: Mapping[str, Any] = choice if is_object(choice) else {}
        ok = chosen(c.get("required"), c.get("accepted"), _THIS)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        accepted = c["accepted"]
        if not _payable(accepted):
            return Refusal("x402/option-malformed")
        ledger = safe_int(c.get("currentLedger"))
        if ledger is None or ledger < 0:
            return Refusal("stellar/tx-malformed")
        m = _stellar.unmux(accepted["payTo"])
        if m is None or m.id != _stellar.muxed_id(h):
            return Refusal("stellar/carrier-mismatch")
        timeout = safe_int(accepted["maxTimeoutSeconds"])
        assert timeout is not None
        expiration = ledger + -(-timeout // 5)
        s = _stellar.signing_for(c.get("simulatedXdr"), accepted["network"], expiration, False)
        if isinstance(s, Refusal):
            return s
        if s.payment.to != accepted["payTo"]:
            return Refusal("stellar/carrier-mismatch")
        if not s.agrees:
            return Refusal("stellar/not-one-transfer")
        return s.unsigned

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The echoed challenge's hash, when the to of the invocation the payer's entry signs is the option's muxed
        payTo whose id is the hash's first 8 bytes, and the operation invokes exactly that. The authorization's
        signature is not verified here."""
        if not is_object(presented) or presented.get("x402Version") != 2 or isinstance(presented.get("x402Version"), bool):
            return Refusal("x402/not-v2")
        accepted = presented.get("accepted")
        if not is_object(accepted) or not _is_this(accepted):
            return Refusal("x402/option-not-this-pairing")
        lc = legal_context_of(presented.get("extensions"))
        if isinstance(lc, Refusal):
            return lc
        payload = presented.get("payload")
        if not is_object(payload):
            return Refusal("x402/payload-malformed")
        signed = _stellar.read_signed_transfer(payload.get("transaction"), accepted["network"])
        if isinstance(signed, Refusal):
            return signed
        payment = signed.payment
        if payment.to_id is None:
            return Refusal("stellar/no-carrier")
        if payment.to != accepted["payTo"] or payment.to_id != _stellar.muxed_id(lc[0]):
            return Refusal("stellar/carrier-mismatch")
        if not signed.agrees:
            return Refusal("stellar/not-one-transfer")
        return lc[0]
