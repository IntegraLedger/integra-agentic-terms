"""bolt11-pay, the BOLT 11 invoice the buyer's node pays (x402/exact/lnbtc/payment-hash, mpp/charge/lightning,
mpp/session/lightning; terms' profile buyer-gate.md, rule 13), read with the strict decoder the bindings share: the
amount and the one payee's part are the invoice's amount, in millisatoshis; the payee is the key that signed the
invoice, its n field's where it has one and otherwise the key the signature recovers, as 66 lowercase hex digits; the
asset is BTC; the network is the signer's account's lnbtc network, where the invoice's currency is that network's
(BOLT 11's prefix: bc mainnet, tb testnet3 and testnet4, tbs signet, bcrt regtest); and the validity is the invoice's
creation time to that time plus its expiry, in seconds. An invoice the decoder refuses, one that names no amount, which
the node would pay at an amount the request does not state, and one whose currency is not the account's network's give
no summary. A session's deposit invoice is also its deposit."""

from collections.abc import Mapping
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ._types import Payee, Refusal, Summary, Validity
from .bindings._bolt11 import decode
from .pieces.lightning import LN_CURRENCY

if TYPE_CHECKING:
    from ._summary import Opened


def bolt11_pay(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """The invoice a charge's node pays."""
    invoice = request.get("invoice")
    if request.get("kind") != "bolt11-pay" or not isinstance(invoice, str) or network is None:
        return None
    b = decode(invoice)
    if isinstance(b, Refusal) or b.amount_msat is None or LN_CURRENCY.get(network) != b.currency:
        return None
    amount = str(b.amount_msat)
    return Summary(
        amount=amount,
        payees=(Payee(account=b.signer, amount=amount),),
        asset="BTC",
        network=network,
        validity=Validity(not_before=str(b.timestamp), not_after=str(b.timestamp + b.expiry), unit="seconds"),
        atr=b"",
    )


def bolt11_deposit(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """A Lightning session's deposit invoice: as a charge's, its amount also the session's deposit."""
    shown = bolt11_pay(request, network, opened)
    return None if shown is None else replace(shown, deposit=shown.amount)
