"""The buyer half of the pairing x402/exact/eip155/eip3009: read, build with complete, and bound.

The ATR hash rides as the nonce of an EIP-3009 TransferWithAuthorization. Nothing here fetches, hashes or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, is_hash
from .._types import Advertised, Json, Refusal
from ._lcp import chain_id_of, is_address, safe_int, uint256_of
from ._x402 import accepted_by, chosen, filter_of, is_amount, read_for, timeout_seconds

ID = "x402/exact/eip155/eip3009"

MIN_SIGNATURE_BYTES = 65
MAX_SIGNATURE_BYTES = 8192

_HEX_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*")

_EIP712_DOMAIN = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
_TRANSFER_WITH_AUTHORIZATION = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]


def passes(option: object) -> bool:
    """The pairing's filter: scheme exact, an eip155 network, EIP-3009 as the transfer method, a known flow."""
    if not isinstance(option, Mapping):
        return False
    if option.get("scheme") != "exact":
        return False
    if chain_id_of(option.get("network")) is None:
        return False
    extra = option.get("extra", {})
    if not isinstance(extra, Mapping):
        return False
    if "assetTransferMethod" in extra and extra["assetTransferMethod"] != "eip3009":
        return False
    if "paymentFlow" in extra and extra["paymentFlow"] not in ("authorization", "upfront"):
        return False
    return True


def _payable(option: Mapping[str, Any]) -> bool:
    """True for an option build can turn into typed data: the token's EIP-712 name and version, the asset and payee
    addresses, a positive amount (is_amount) below 2^256, and a time bound that is a safe integer above zero."""
    extra = option.get("extra")
    if not isinstance(extra, Mapping):
        return False
    name, version = extra.get("name"), extra.get("version")
    return (
        isinstance(name, str)
        and name != ""
        and isinstance(version, str)
        and version != ""
        and is_address(option.get("asset"))
        and is_address(option.get("payTo"))
        and is_amount(option.get("amount"))
        and uint256_of(option.get("amount")) is not None
        and timeout_seconds(option.get("maxTimeoutSeconds")) is not None
    )


# The pairing's one option filter, which read, build and bound apply: an option the pairing names and build can pay.
_FILTER = filter_of(passes, _payable)
_READ = read_for(_FILTER)


@dataclass(frozen=True, slots=True)
class _Unsigned:
    typed_data: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _authorization: Mapping[str, str]

    def complete(self, signature: str) -> dict[str, Any] | Refusal:
        """The PaymentPayload for this authorization: its value is the option's amount as written, and the other
        numbers are decimal strings."""
        if not isinstance(signature, str) or _HEX_BYTES.fullmatch(signature) is None:
            return Refusal("x402/signature-malformed")
        size = (len(signature) - 2) // 2
        if size < MIN_SIGNATURE_BYTES or size > MAX_SIGNATURE_BYTES:
            return Refusal("x402/signature-malformed")
        payload: dict[str, Any] = {"x402Version": 2}
        if "resource" in self._required:
            payload["resource"] = self._required["resource"]
        payload["accepted"] = self._accepted
        payload["payload"] = {"signature": signature, "authorization": dict(self._authorization)}
        if "extensions" in self._required:
            payload["extensions"] = self._required["extensions"]
        return payload


@dataclass(frozen=True, slots=True)
class X402ExactEip155Eip3009:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when the legal context names one, and the options the pairing's filter
        serves, in document order."""
        return _READ(doc)

    def build(self, choice: Json, h: AtrHash) -> _Unsigned | Refusal:
        """The EIP-712 TransferWithAuthorization request whose nonce is h."""
        if not isinstance(choice, Mapping):
            return Refusal("x402/not-v2")
        required = choice.get("required")
        accepted = choice.get("accepted")
        served = chosen(required, accepted, _FILTER)
        if isinstance(served, Refusal):
            return served
        assert isinstance(required, Mapping) and isinstance(accepted, Mapping)
        payer = choice.get("from")
        now = safe_int(choice.get("now"))
        if not is_address(payer) or now is None or now < 0:
            return Refusal("x402/option-malformed")
        if not is_hash(h):
            return Refusal("x402/payload-malformed")
        extra = accepted["extra"]
        name, version = extra["name"], extra["version"]
        asset, pay_to, amount = accepted["asset"], accepted["payTo"], accepted["amount"]
        chain_id = chain_id_of(accepted["network"])
        value = uint256_of(amount)
        max_timeout = safe_int(accepted["maxTimeoutSeconds"])
        assert chain_id is not None and value is not None and max_timeout is not None
        typed_data: dict[str, Any] = {
            "domain": {"name": name, "version": version, "chainId": chain_id, "verifyingContract": asset},
            "types": {
                "EIP712Domain": [dict(field) for field in _EIP712_DOMAIN],
                "TransferWithAuthorization": [dict(field) for field in _TRANSFER_WITH_AUTHORIZATION],
            },
            "primaryType": "TransferWithAuthorization",
            "message": {
                "from": payer,
                "to": pay_to,
                "value": value,
                "validAfter": 0,
                "validBefore": now + max_timeout,
                "nonce": h.lower(),
            },
        }
        authorization = {
            "from": payer,
            "to": pay_to,
            "value": amount,
            "validAfter": "0",
            "validBefore": str(now + max_timeout),
            "nonce": h.lower(),
        }
        return _Unsigned(typed_data=typed_data, _required=required, _accepted=accepted, _authorization=authorization)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The authorization's nonce, as a lower-case hash, from a payment whose accepted the pairing's filter serves
        (accepted_by). A payment that carries a refused member, the member refusals use, is x402/payload-malformed. The
        signature is not verified here."""
        if not isinstance(presented, Mapping) or safe_int(presented.get("x402Version")) != 2:
            return Refusal("x402/not-v2")
        if "refused" in presented:
            return Refusal("x402/payload-malformed")
        accepted = accepted_by(presented.get("accepted"), _FILTER)
        if isinstance(accepted, Refusal):
            return accepted
        payload = presented.get("payload")
        if not isinstance(payload, Mapping):
            return Refusal("x402/payload-malformed")
        authorization = payload.get("authorization")
        if not isinstance(authorization, Mapping):
            return Refusal("x402/payload-malformed")
        for member in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
            if not isinstance(authorization.get(member), str):
                return Refusal("x402/payload-malformed")
        signature = payload.get("signature")
        if (
            not isinstance(signature, str)
            or _HEX_BYTES.fullmatch(signature) is None
            or not 1 <= (len(signature) - 2) // 2 <= MAX_SIGNATURE_BYTES
        ):
            return Refusal("x402/signature-malformed")
        nonce = authorization["nonce"]
        if not is_hash(nonce):
            return Refusal("x402/payload-malformed")
        assert isinstance(nonce, str)
        return nonce.lower()
