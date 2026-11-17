"""eip712 requests signing Circle Gateway's batched payment: an EIP-3009 TransferWithAuthorization in the Gateway Wallet's
GatewayWalletBatched domain (profile buyer-gate.md, rule 13; lcp profile x402-exact-eip155-gateway-batched.md, rules 4, 5
and 7). The verifying contract is the Gateway Wallet, not the token: at version "2" the domain's salt names the token,
its address left-padded to 32 bytes; at version "1" the domain names none, and Circle's client signs it only for the
network's USDC. The summary reads only what the typed data signs, under the types the request names."""

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from ._types import Payee, Summary, Validity
from .bindings.x402_exact_eip155_gateway_batched import BATCHED_NAME, NETWORKS

if TYPE_CHECKING:
    from ._summary import Opened

_DECIMAL = re.compile(r"[0-9]{1,78}")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_SALTED = re.compile(r"0x0{24}([0-9a-fA-F]{40})")
_DOMAIN = (("name", "string"), ("version", "string"), ("chainId", "uint256"), ("verifyingContract", "address"))
_DOMAIN_WITH_SALT = (*_DOMAIN, ("salt", "bytes32"))
_TRANSFER_WITH_AUTHORIZATION = (
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
)


def _decimal(v: object) -> str | None:
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v) if v >= 0 else None
    return v if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


def _type_is(members: object, fields: Sequence[tuple[str, str]]) -> bool:
    """Whether an EIP-712 struct type's members are exactly fields, each (name, type), in that order."""
    if not isinstance(members, Sequence) or isinstance(members, str) or len(members) != len(fields):
        return False
    return all(
        isinstance(m, Mapping) and len(m) == 2 and m.get("name") == name and m.get("type") == kind
        for m, (name, kind) in zip(members, fields)
    )


def gateway_batched(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """TransferWithAuthorization in the GatewayWalletBatched domain whose verifyingContract is the Gateway Wallet on
    d.chainId's network: the amount and the one payee's part are m.value, the payee m.to, the asset the token d.salt
    names at version "2" or the network's USDC at version "1", the network eip155: and d.chainId, and the validity
    m.validAfter to m.validBefore, in seconds. Another domain, version or verifying contract, a salt that is not a padded
    address, or types other than these gives no summary."""
    typed = request.get("typedData")
    if request.get("kind") != "eip712" or not isinstance(typed, Mapping):
        return None
    types, d, m = typed.get("types"), typed.get("domain"), typed.get("message")
    if typed.get("primaryType") != "TransferWithAuthorization" or not isinstance(types, Mapping):
        return None
    if not isinstance(d, Mapping) or not isinstance(m, Mapping) or d.get("name") != BATCHED_NAME:
        return None
    if not _type_is(types.get("TransferWithAuthorization"), _TRANSFER_WITH_AUTHORIZATION):
        return None
    chain = _decimal(d.get("chainId"))
    found = None if chain is None else NETWORKS.get(int(chain))
    wallet = d.get("verifyingContract")
    if found is None or not isinstance(wallet, str) or _ADDRESS.fullmatch(wallet) is None or wallet.lower() != found[0]:
        return None
    asset: str | None = None
    if d.get("version") == "1" and _type_is(types.get("EIP712Domain"), _DOMAIN) and "salt" not in d:
        asset = found[1]
    elif d.get("version") == "2" and _type_is(types.get("EIP712Domain"), _DOMAIN_WITH_SALT) and isinstance(d.get("salt"), str):
        salted = _SALTED.fullmatch(d["salt"])
        asset = None if salted is None else "0x" + salted.group(1)
    value, after, before = (_decimal(m.get(k)) for k in ("value", "validAfter", "validBefore"))
    to = m.get("to")
    if asset is None or value is None or after is None or before is None:
        return None
    if not isinstance(to, str) or _ADDRESS.fullmatch(to) is None:
        return None
    return Summary(
        amount=value,
        payees=(Payee(account=to, amount=value),),
        asset=asset,
        network=f"eip155:{chain}",
        validity=Validity(not_before=after, not_after=before, unit="seconds"),
        atr=b"",
    )
