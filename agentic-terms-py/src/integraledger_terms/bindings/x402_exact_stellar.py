"""The buyer half of the pairing x402/exact/stellar: read, build with complete, and bound.

The challenge's extensions.legalContext carries the ATR hash, and its first 8 bytes ride as the muxed id of the
option's payTo, which the payer signs as the Soroban transfer's to. Nothing here fetches or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from . import _stellar
from ._lcp import is_object, normal_hash, safe_int
from ._x402 import (
    accepted_by,
    chosen,
    filter_of,
    is_amount,
    legal_context_of,
    read_for,
    timeout_seconds,
    x402_broadcaster,
)

ID = "x402/exact/stellar"

_AMOUNT = re.compile(r"0|[1-9][0-9]{0,38}")
_I128_LIMIT = 1 << 127
_UINT32_MAX = (1 << 32) - 1


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


def _payable(option: Mapping[str, Any]) -> bool:
    """True when the amount is a positive i128 in decimal (is_amount) and the timeout a positive safe integer of at most
    5 * (2^32 - 1) seconds: build sets the authorization entry's expiration ledger, a uint32, to the current ledger
    plus ceil(maxTimeoutSeconds / 5)."""
    amount = option.get("amount")
    timeout = timeout_seconds(option.get("maxTimeoutSeconds"))
    return (
        is_amount(amount)
        and _AMOUNT.fullmatch(amount) is not None
        and int(amount) < _I128_LIMIT
        and timeout is not None
        and -(-timeout // 5) <= _UINT32_MAX
    )


# The pairing's one option filter, which read, build and bound apply: an option of this pairing that build can pay
# (_payable), else x402/option-malformed.
_THIS = filter_of(_is_this, _payable)


@dataclass(frozen=True, slots=True)
class X402ExactStellar:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(_THIS)(doc)

    def build(self, choice: Json, h: AtrHash) -> _stellar.StellarUnsigned | Refusal:
        """The authorization preimage for the payer to sign, from the buyer's simulated transaction, with the entry's
        expiration at currentLedger + ceil(maxTimeoutSeconds / 5). The option's payTo must carry muxed_id(h) and
        equal the to of the invocation the payer's entry signs, and the operation must invoke exactly that. That
        invocation's token contract must then be the option's asset, its amount the option's amount exactly, and its
        from the choice's payer. Nothing reaches the signer unless every one holds. H is checked first, then the choice
        members whose form needs no document: the current ledger (stellar/tx-malformed) and the payer, which must be a
        G, C or M strkey (stellar/payer-mismatch, as no other value can equal a transfer's from). Then the document and
        the option, then the payTo carrier, then the simulated transaction's form (signing_input), then the
        transaction."""
        if normal_hash(h) is None:
            return Refusal("x402/payload-malformed")
        if not is_object(choice):
            return Refusal("x402/not-v2")
        c: Mapping[str, Any] = choice
        ledger = safe_int(c.get("currentLedger"))
        if ledger is None or ledger < 0:
            return Refusal("stellar/tx-malformed")
        if not _stellar.is_payer(c.get("payer")):
            return Refusal("stellar/payer-mismatch")
        ok = chosen(c.get("required"), c.get("accepted"), _THIS)
        if ok is not True:
            return ok
        accepted = c["accepted"]
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
        if s.payment.asset != accepted["asset"]:
            return Refusal("stellar/asset-mismatch")
        if s.payment.amount != int(accepted["amount"]):
            return Refusal("stellar/amount-mismatch")
        if s.payment.source != c.get("payer"):
            return Refusal("stellar/payer-mismatch")
        return s.unsigned

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The echoed challenge's hash, when the to of the invocation the payer's entry signs is the option's muxed
        payTo whose id is the hash's first 8 bytes, and the operation invokes exactly that. Every check that reads no
        transaction comes before the transaction is read: the option, the legal context, the payload, and the option's
        payTo carrying the echoed hash's muxed id, else stellar/carrier-mismatch, as build checks it. The
        authorization's signature is not verified here."""
        if not is_object(presented) or presented.get("x402Version") != 2 or isinstance(presented.get("x402Version"), bool):
            return Refusal("x402/not-v2")
        accepted = accepted_by(presented.get("accepted"), _THIS)
        if isinstance(accepted, Refusal):
            return accepted
        lc = legal_context_of(presented.get("extensions"))
        if isinstance(lc, Refusal):
            return lc
        payload = presented.get("payload")
        if not is_object(payload):
            return Refusal("x402/payload-malformed")
        m = _stellar.unmux(accepted["payTo"])
        if m is None or m.id != _stellar.muxed_id(lc[0]):
            return Refusal("stellar/carrier-mismatch")
        signed = _stellar.read_signed_transfer(payload.get("transaction"), accepted["network"], False)
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

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's facilitator submits the Soroban transfer the payer authorized. The payment
        is held to x402_shape's gate, the one bound applies first; any other gets its refusal."""
        return x402_broadcaster(presented, "payee")
