"""The summary of a gateway-burn-intent request, the buyer's signing of mpp/charge/usdc/gateway (terms' profile
buyer-gate.md, rules 13 and 14; lcp profile mpp-charge.md, rule 8), as summary/gateway-burn-intent.ts reads it in the
TypeScript package. The buyer's Gateway client signs a Circle Gateway burn intent whose TransferSpec salt commits to the
request's preimage, whose requestHash is the keccak-256 of the challenge's request as issued. The request carries that
request as challengeRequest, so the summary recomputes the hash with the pairing's binding's usdc_request_hash and shows
the challenge's terms only where it is preimage.requestHash: the amount the recipient is paid, the currency, the network
the recipient is paid on and the cap on Gateway's fee, which the payer pays beside the amount from the same balance
(draft-usdc-charge-00, Gateway Transfer Profile: "Clients SHOULD present amount + maxFee as the payer's worst-case
spend"). The burn intent's maxBlockHeight is counted in the blocks of the network it spends from, the signer's
account's."""

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from ._types import Payee, Refusal, Summary, Validity
from .bindings._mpp_checks import decode_object
from .bindings.mpp_charge_usdc import usdc_request_hash

if TYPE_CHECKING:
    from ._summary import Opened

# A CAIP-2 network id, as the summary's network names one.
_CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
_DECIMAL = re.compile(r"[0-9]{1,78}")


def _is_decimal(v: object) -> bool:
    return isinstance(v, str) and _DECIMAL.fullmatch(v) is not None


def gateway_burn_intent(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """gateway-burn-intent: where usdc_request_hash(challengeRequest) is preimage.requestHash, the challenge's request
    r shows the amount and the one payee's part, r.amount, the payee r.recipient, which must be the preimage's, the asset
    r.currency, and, as the grant, r.methodDetails.gateway's destinationNetwork and maxFee; the network is the signer's
    account's, the EVM network the burn intent spends from, which the request does not name; and the validity is none to
    maxBlockHeight, in that network's blocks. Any other request has no summary."""
    preimage, challenge_request, until = request.get("preimage"), request.get("challengeRequest"), request.get("maxBlockHeight")
    if request.get("kind") != "gateway-burn-intent" or not isinstance(preimage, Mapping) or not isinstance(challenge_request, str):
        return None
    if not isinstance(network, str) or _CAIP2.fullmatch(network) is None or not network.startswith("eip155:"):
        return None
    if not isinstance(until, str) or not _is_decimal(until):
        return None
    digest = usdc_request_hash(challenge_request)
    if isinstance(digest, Refusal) or digest != preimage.get("requestHash"):
        return None
    r = decode_object(challenge_request)
    details = None if r is None else r.get("methodDetails")
    gateway = details.get("gateway") if isinstance(details, Mapping) else None
    if r is None or not isinstance(gateway, Mapping):
        return None
    amount, currency, recipient = r.get("amount"), r.get("currency"), r.get("recipient")
    destination, max_fee = gateway.get("destinationNetwork"), gateway.get("maxFee")
    if not isinstance(amount, str) or not _is_decimal(amount) or not isinstance(currency, str):
        return None
    if not isinstance(recipient, str) or recipient != preimage.get("recipient"):
        return None
    if not isinstance(destination, str) or _CAIP2.fullmatch(destination) is None or not _is_decimal(max_fee):
        return None
    return Summary(
        amount=amount,
        payees=(Payee(account=recipient, amount=amount),),
        asset=currency,
        network=network,
        validity=Validity(not_before=None, not_after=until, unit="block"),
        grant={"destinationNetwork": destination, "maxFee": max_fee},
        atr=b"",
    )
