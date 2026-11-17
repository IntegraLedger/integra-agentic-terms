"""The buyer half of the pairing x402/exact/stellar/precondition, the agreement on Stellar and never a charge: read,
build with complete, bound and broadcaster.

The buyer signs a Soroban authorization of transfer(buyer, payTo, amount) and the 40-byte payload of H and that
authorization's nonce, which the transaction carries as a signed-payload precondition (CAP-40); the settler submits the
transaction as its source. Nothing here fetches or signs.
"""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._lcp import is_object, normal_hash
from ._stellar import (
    PreconditionEnvelope,
    is_account,
    is_contract,
    is_stellar_network,
    precondition_signing_for,
    read_precondition,
    read_signed_payload,
    unmux,
)
from ._x402 import chosen, payment_with, presented_with, read_for, timeout_seconds, x402_broadcaster

ID = "x402/exact/stellar/precondition"

# The option's amount: zero, or a decimal integer with no sign and no leading zero, below 2^127 (a transfer's i128).
_AMOUNT = re.compile(r"0|[1-9][0-9]{0,38}")
_I128_LIMIT = 2**127
_U32_MAX = 0xFFFFFFFF


def _filter(option: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """An option is this pairing's where it is exact on a Stellar network with extra.assetTransferMethod
    "lcp-precondition". It is served where extra.areFeesSponsored is true, asset is a contract strkey, payTo an account
    strkey, amount zero or a positive decimal below 2^127, and maxTimeoutSeconds a positive safe integer whose fifth,
    rounded up, is a ledger count; a muxed payTo is stellar/option-malformed, and any other failure
    x402/option-malformed."""
    if not is_object(option) or option.get("scheme") != "exact" or not is_stellar_network(option.get("network")):
        return None
    extra = option.get("extra")
    if not is_object(extra) or extra.get("assetTransferMethod") != "lcp-precondition":
        return None
    if extra.get("areFeesSponsored") is not True:
        return Refusal("x402/option-malformed")
    if unmux(option.get("payTo")) is not None:
        return Refusal("stellar/option-malformed")
    if not is_contract(option.get("asset")) or not is_account(option.get("payTo")):
        return Refusal("x402/option-malformed")
    amount = option.get("amount")
    if not isinstance(amount, str) or _AMOUNT.fullmatch(amount) is None or int(amount) >= _I128_LIMIT:
        return Refusal("x402/option-malformed")
    seconds = timeout_seconds(option.get("maxTimeoutSeconds"))
    if seconds is None or math.ceil(seconds / 5) > _U32_MAX:
        return Refusal("x402/option-malformed")
    return True


def _ledger(value: object) -> int | None:
    """A ledger sequence, an integer from 0 to 2^32 - 1 (a JSON number with an integral value reads as it), or
    None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    return int(value) if 0 <= value <= _U32_MAX else None


@dataclass(frozen=True, slots=True)
class StellarPreconditionUnsigned:
    """What the buyer signs, with one key: SHA-256 of the request's preimage, the authorization entry's HashIDPreimage,
    and its payload itself, the 40 bytes of the signed-payload precondition; and how the two signatures complete the
    payment."""

    request: dict[str, Any]
    _written: Any
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signatures: object) -> dict[str, Any] | Refusal:
        """The x402 payment: signatures {entry, payload}, each 64 bytes, the entry's written as a Stellar account's and
        the payload's as a decorated signature of the envelope. A signature that is not 64 bytes is
        stellar/tx-malformed, and a signed envelope over 8,192 characters stellar/tx-too-large."""
        transaction = self._written(signatures)
        if isinstance(transaction, Refusal):
            return transaction
        return payment_with(self._required, self._accepted, {"transaction": transaction})


def _carried(presented: object) -> tuple[Mapping[str, Any], PreconditionEnvelope, AtrHash] | Refusal:
    """The option a payment answers, its envelope and H, or the refusal that names what is wrong: the option through
    the filter, then the envelope (its size, form, one transfer and the buyer's address entry), then the operation
    invoking exactly the transfer the entry signs (stellar/not-one-transfer), a buyer that is an account
    (stellar/no-address-auth), exactly one signed-payload signer (stellar/no-carrier), its payload 40 bytes whose last 8
    are the entry's nonce and its key one whose signature the entry carries (stellar/carrier-mismatch), and a transfer
    whose from is not the option's payTo (stellar/payee-mismatch)."""
    pw = presented_with(presented, _filter)
    if isinstance(pw, Refusal):
        return pw
    accepted, payload, _ = pw
    tx = payload.get("transaction")
    if not isinstance(tx, str):
        return Refusal("x402/payload-malformed")
    p = read_precondition(tx, accepted["network"], False)
    if isinstance(p, Refusal):
        return p
    if not p.agrees:
        return Refusal("stellar/not-one-transfer")
    if not is_account(p.payment.source):
        return Refusal("stellar/no-address-auth")
    if len(p.signers) != 1:
        return Refusal("stellar/no-carrier")
    signer = p.signers[0]
    read = read_signed_payload(signer.payload)
    if isinstance(read, Refusal):
        return read
    if read.value != p.payment.auth.nonce or signer.key not in p.entry_keys:
        return Refusal("stellar/carrier-mismatch")
    if p.payment.source == accepted["payTo"]:
        return Refusal("stellar/payee-mismatch")
    return accepted, p, read.h


# The agreement this pairing's payment is, as @integraledger/lcp's registry states it: offered as an agreement only.
AGREEMENT = AgreementData(floor="0", only=True)


@dataclass(frozen=True, slots=True)
class X402ExactStellarPrecondition:
    id: str = ID
    coverage: Coverage = "full"
    agreement: AgreementData | None = AGREEMENT

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(_filter)(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> StellarPreconditionUnsigned | Refusal:
        """What the buyer signs, from its simulated transaction: the entry's expiration ledger set to the current ledger
        plus ceil(maxTimeoutSeconds / 5), and the preconditions set to one signed-payload signer, the buyer's key with
        the payload of H and the entry's nonce. Nothing reaches the signer unless the operation invokes exactly the
        transfer the entry signs, on the option's asset, for its amount exactly, from the choice's payer, to the
        option's payTo, which is not the payer. H is checked first, then the current ledger (stellar/tx-malformed) and
        the payer, an account strkey (else stellar/payer-mismatch), then the document and the option, then the
        simulated transaction. The single-use value is the entry's nonce, so the act changes nothing."""
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        if not is_object(choice):
            return Refusal("x402/not-v2")
        c: Mapping[str, Any] = choice
        current = _ledger(c.get("currentLedger"))
        if current is None:
            return Refusal("stellar/tx-malformed")
        payer = c.get("payer")
        if not is_account(payer):
            return Refusal("stellar/payer-mismatch")
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _filter)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        expiration = current + math.ceil(accepted["maxTimeoutSeconds"] / 5)
        s = precondition_signing_for(c.get("simulatedXdr"), accepted["network"], expiration, nh)
        if isinstance(s, Refusal):
            return s
        payment = s.payment
        if not s.agrees:
            return Refusal("stellar/not-one-transfer")
        if payment.asset != accepted["asset"]:
            return Refusal("stellar/asset-mismatch")
        if payment.amount != int(accepted["amount"]):
            return Refusal("stellar/amount-mismatch")
        if payment.source != payer:
            return Refusal("stellar/payer-mismatch")
        if payment.to != accepted["payTo"] or payment.source == accepted["payTo"]:
            return Refusal("stellar/payee-mismatch")
        request = {"kind": "stellar-precondition", "preimage": s.preimage, "payload": s.payload}
        return StellarPreconditionUnsigned(request, s.written, required, accepted)

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H, the first 32 bytes of the presented transaction's signed-payload precondition, once _carried's checks
        hold. The signatures are not verified here: the network verifies the entry's when it is used and the payload's
        at submission."""
        r = _carried(presented)
        return r if isinstance(r, Refusal) else r[2]

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's settler submits the transaction as its source."""
        return x402_broadcaster(presented, "payee")
