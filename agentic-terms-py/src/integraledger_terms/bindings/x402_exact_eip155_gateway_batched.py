"""The buyer half of the pairing x402/exact/eip155/gateway-batched: read, build with complete, bound and broadcaster.

Circle Gateway's batched payment: the payer signs an EIP-3009 TransferWithAuthorization in the Gateway Wallet's
GatewayWalletBatched domain with the ATR hash, all of it, as its nonce, and the resource server hands it to Circle
Gateway, which settles it in batches (lcp profile x402-exact-eip155-gateway-batched.md). No public ledger shows the
authorization, so the pairing is at coverage none, taken only after an agreement on the payment's own network. Nothing
here fetches, hashes or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash, is_hash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._lcp import chain_id_of, is_address, safe_int, uint256_of
from ._x402 import (
    MAX_SIGNATURE_BYTES,
    accepted_by,
    chosen,
    is_amount,
    legal_context_of,
    payment_with,
    read_for,
    timeout_seconds,
    x402_broadcaster,
)

ID = "x402/exact/eip155/gateway-batched"
BATCHED_NAME = "GatewayWalletBatched"
# validAfter is the signing time less 600 seconds; Circle's margin over the served minimum validity is 100 seconds.
_VALID_BEFORE_SIGNING = 600
_VALIDITY_MARGIN = 100
_SIGNATURE_BYTES = 65
_HEX_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*")

_MAINNET_WALLET = "0x77777777dcc4d5a8b6e418fd04d8997ef11000ee"
_TESTNET_WALLET = "0x0077777d7eba4688bdef3e311b846f25870a19b9"

# The Gateway Wallet and USDC on each network, by chain id, as @circle-fin/x402-batching 4.0.0 configures them
# (src/config.ts:110-116, :121-360), lower-case.
NETWORKS: Mapping[int, tuple[str, str]] = {
    1: (_MAINNET_WALLET, "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"),
    10: (_MAINNET_WALLET, "0x0b2c639c533813f4aa9d7837caf62653d097ff85"),
    130: (_MAINNET_WALLET, "0x078d782b760474a361dda0af3839290b0ef57ad6"),
    137: (_MAINNET_WALLET, "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359"),
    146: (_MAINNET_WALLET, "0x29219dd400f2bf60e5a23d13be72b486d4038894"),
    480: (_MAINNET_WALLET, "0x79a02482a880bce3f13e09da970dc34db4cd24d1"),
    999: (_MAINNET_WALLET, "0xb88339cb7199b77e23db6e890353e22632ba630f"),
    1329: (_MAINNET_WALLET, "0xe15fc38f6d8c56af07bbcbe3baf5708a2bf42392"),
    5042: (_MAINNET_WALLET, "0x3600000000000000000000000000000000000000"),
    8453: (_MAINNET_WALLET, "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"),
    42161: (_MAINNET_WALLET, "0xaf88d065e77c8cc2239327c5edb3a432268e5831"),
    43114: (_MAINNET_WALLET, "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e"),
    998: (_TESTNET_WALLET, "0x2b3370ee501b4a559b57d449569354196457d8ab"),
    1301: (_TESTNET_WALLET, "0x31d0220469e10c4e71834a79b1f276d740d3768f"),
    1328: (_TESTNET_WALLET, "0x4fcf1784b31630811181f670aea7a7bef803eaed"),
    4801: (_TESTNET_WALLET, "0x66145f38cbac35ca6f1dfb4914df98f1614aea88"),
    14601: (_TESTNET_WALLET, "0x0ba304580ee7c9a980cf72e55f5ed2e9fd30bc51"),
    43113: (_TESTNET_WALLET, "0x5425890298aed601595a70ab815c96711a31bc65"),
    80002: (_TESTNET_WALLET, "0x41e94eb019c0762f9bfcf9fb1e58725bfb0e7582"),
    84532: (_TESTNET_WALLET, "0x036cbd53842c5426634e7929541ec2318f3dcf7e"),
    421614: (_TESTNET_WALLET, "0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d"),
    5042002: (_TESTNET_WALLET, "0x3600000000000000000000000000000000000000"),
    11155111: (_TESTNET_WALLET, "0x1c7d4b196cb0c7b01d743fbc6116a902379c7238"),
    11155420: (_TESTNET_WALLET, "0x5fd84259d66cd46123540766be93dfe6d43130d7"),
}

_DOMAIN_FIELDS = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
_SALT_FIELD = {"name": "salt", "type": "bytes32"}
_AUTHORIZATION_FIELDS = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]


def _version_of(extra: Mapping[str, Any]) -> Literal["1", "2"] | None:
    """The option's domain version: extra.version, "1" where it has none, or None for any other value."""
    v = extra.get("version", "1")
    return "1" if v == "1" else "2" if v == "2" else None


def _filter(o: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """True for an exact option on an eip155 network whose extra.name is GatewayWalletBatched and whose
    extra.assetTransferMethod is absent or eip3009, where it can be paid; None for any other option. Of those, a
    non-empty extra.splits is x402/splits-not-carried; another extra.version than "1" and "2", an
    extra.verifyingContract that is not the Gateway Wallet on the option's network, at version "1" an asset other than
    that network's USDC, or an asset, payTo, amount or maxTimeoutSeconds the payment cannot carry is
    x402/option-malformed."""
    if o.get("scheme") != "exact":
        return None
    chain = chain_id_of(o.get("network"))
    extra = o.get("extra")
    if chain is None or not isinstance(extra, Mapping) or extra.get("name") != BATCHED_NAME:
        return None
    if extra.get("assetTransferMethod", "eip3009") != "eip3009":
        return None
    if "splits" in extra and extra["splits"] != []:
        return Refusal("x402/splits-not-carried")
    network = NETWORKS.get(chain)
    version = _version_of(extra)
    wallet, asset = extra.get("verifyingContract"), o.get("asset")
    payable = (
        network is not None
        and version is not None
        and is_address(wallet)
        and wallet.lower() == network[0]
        and is_address(asset)
        and (version == "2" or asset.lower() == network[1])
        and is_address(o.get("payTo"))
        and is_amount(o.get("amount"))
        and uint256_of(o.get("amount")) is not None
        and timeout_seconds(o.get("maxTimeoutSeconds")) is not None
    )
    return True if payable else Refusal("x402/option-malformed")


def is_gateway_batched(option: object) -> bool:
    """Whether the pairing's filter serves an option."""
    return isinstance(option, Mapping) and _filter(option) is True


_READ = read_for(_filter)


def _typed_data(option: Mapping[str, Any], message: dict[str, Any]) -> dict[str, Any]:
    """The typed data for an option the filter serves: its domain by extra.version, the message as given."""
    extra = option["extra"]
    version = _version_of(extra)
    domain: dict[str, Any] = {
        "name": BATCHED_NAME,
        "version": version,
        "chainId": chain_id_of(option["network"]),
        "verifyingContract": extra["verifyingContract"],
    }
    fields = [dict(f) for f in _DOMAIN_FIELDS]
    if version == "2":
        domain["salt"] = "0x" + "00" * 12 + option["asset"][2:].lower()
        fields.append(dict(_SALT_FIELD))
    return {
        "domain": domain,
        "types": {"EIP712Domain": fields, "TransferWithAuthorization": [dict(f) for f in _AUTHORIZATION_FIELDS]},
        "primaryType": "TransferWithAuthorization",
        "message": message,
    }


def _is_hex_bytes(s: object, least: int, most: int) -> bool:
    return isinstance(s, str) and _HEX_BYTES.fullmatch(s) is not None and least <= (len(s) - 2) // 2 <= most


@dataclass(frozen=True, slots=True)
class _Unsigned:
    typed_data: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _authorization: Mapping[str, str]

    def complete(self, signature: str) -> dict[str, Any] | Refusal:
        """The PaymentPayload for this authorization, every member of it a string, with a 65-byte signature."""
        if not _is_hex_bytes(signature, _SIGNATURE_BYTES, _SIGNATURE_BYTES):
            return Refusal("x402/signature-malformed")
        return payment_with(self._required, self._accepted, {"signature": signature, "authorization": dict(self._authorization)})


def _payment_of(presented: object) -> Mapping[str, Any] | Refusal:
    """The payment's shape as this pairing requires it, or the refusal that names what is wrong."""
    if not isinstance(presented, Mapping) or safe_int(presented.get("x402Version")) != 2:
        return Refusal("x402/not-v2")
    if "refused" in presented:
        return Refusal("x402/payload-malformed")
    accepted = accepted_by(presented.get("accepted"), _filter)
    if isinstance(accepted, Refusal):
        return accepted
    payload = presented.get("payload")
    a = payload.get("authorization") if isinstance(payload, Mapping) else None
    if not isinstance(payload, Mapping) or not isinstance(a, Mapping):
        return Refusal("x402/payload-malformed")
    if any(not isinstance(a.get(k), str) for k in ("from", "to", "value", "validAfter", "validBefore", "nonce")):
        return Refusal("x402/payload-malformed")
    if not _is_hex_bytes(payload.get("signature"), 1, MAX_SIGNATURE_BYTES):
        return Refusal("x402/signature-malformed")
    return presented


@dataclass(frozen=True, slots=True)
class X402ExactEip155GatewayBatched:
    id: str = ID
    coverage: Coverage = "none"
    agreement: AgreementData | None = None
    agreement_on: str | None = "same-network"

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when the legal context names one, and the options the pairing's filter
        serves, in document order."""
        return _READ(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> _Unsigned | Refusal:
        """The TransferWithAuthorization the payer signs for the chosen option, with H as its nonce: validAfter 600
        seconds before now, and validBefore now plus the greater of the option's maxTimeoutSeconds and
        minValiditySeconds, the minimum validity Circle Gateway's /supported serves for the network, plus 100. H is
        checked first, then the choice's from, now (at least 600) and minValiditySeconds (a positive safe integer), then
        its document and option. The payment is never an agreement, so the act changes nothing."""
        if not is_hash(h):
            return Refusal("x402/payload-malformed")
        if not isinstance(choice, Mapping):
            return Refusal("x402/not-v2")
        payer, now = choice.get("from"), safe_int(choice.get("now"))
        if not is_address(payer) or now is None or now < _VALID_BEFORE_SIGNING:
            return Refusal("x402/option-malformed")
        minimum = safe_int(choice.get("minValiditySeconds"))
        if minimum is None or minimum <= 0:
            return Refusal("x402/option-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        served = chosen(required, accepted, _filter)
        if isinstance(served, Refusal):
            return served
        assert isinstance(required, Mapping) and isinstance(accepted, Mapping)
        timeout = timeout_seconds(accepted["maxTimeoutSeconds"])
        value = uint256_of(accepted["amount"])
        assert timeout is not None and value is not None
        window = max(timeout, minimum + _VALIDITY_MARGIN)
        valid_after, valid_before = now - _VALID_BEFORE_SIGNING, now + window
        nonce = h.lower()
        message = {"from": payer, "to": accepted["payTo"], "value": value, "validAfter": valid_after, "validBefore": valid_before, "nonce": nonce}
        authorization = {
            "from": payer,
            "to": accepted["payTo"],
            "value": accepted["amount"],
            "validAfter": str(valid_after),
            "validBefore": str(valid_before),
            "nonce": nonce,
        }
        return _Unsigned(_typed_data(accepted, message), required, accepted, authorization)

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H as the authorization's nonce, lower-case. Where the payment echoes an extensions.legalContext that
        decodes, its H must be the nonce, else x402/signed-not-bound. The signature is not verified here; Circle
        verifies it."""
        p = _payment_of(presented)
        if isinstance(p, Refusal):
            return p
        nonce = p["payload"]["authorization"]["nonce"]
        if not is_hash(nonce):
            return Refusal("x402/payload-malformed")
        assert isinstance(nonce, str)
        echoed = legal_context_of(p.get("extensions"))
        if not isinstance(echoed, Refusal) and echoed[0].lower() != nonce.lower():
            return Refusal("x402/signed-not-bound")
        return nonce.lower()

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the resource server hands the authorization the payer signed to Circle Gateway, which
        settles it. A payment that carries a refused member is x402/payload-malformed."""
        return x402_broadcaster(presented, "payee", refused="x402/payload-malformed")
