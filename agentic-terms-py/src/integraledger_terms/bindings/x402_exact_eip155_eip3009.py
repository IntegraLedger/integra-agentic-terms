"""The buyer half of the pairing x402/exact/eip155/eip3009: read, build with complete, and bound.

The ATR hash rides as the nonce of an EIP-3009 TransferWithAuthorization. Nothing here fetches, hashes or signs.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeGuard

from .._core import AtrHash, is_hash
from .._types import Advertised, Json, Refusal
from ._lcp import AgreementFault, agreement_in, is_https_link, is_other_scheme_link

ID = "x402/exact/eip155/eip3009"

MAX_OPTIONS = 32
MAX_LINK_CHARS = 2048
MIN_SIGNATURE_BYTES = 65
MAX_SIGNATURE_BYTES = 8192
_MAX_SAFE_INTEGER = 2**53 - 1
_UINT256_DIGITS = len(str(2**256 - 1))

_NETWORK = re.compile(r"eip155:([0-9]{1,32})")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_DIGITS = re.compile(r"[0-9]+")
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


def _safe_int(value: object) -> int | None:
    """The value as an int when it is a JSON number holding a safe integer; None otherwise."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    else:
        return None
    return number if -_MAX_SAFE_INTEGER <= number <= _MAX_SAFE_INTEGER else None


def _uint256(value: object) -> int | None:
    """The value as an int when it is a string of decimal digits below 2^256; None otherwise."""
    if not isinstance(value, str) or _DIGITS.fullmatch(value) is None:
        return None
    significant = value.lstrip("0") or "0"
    if len(significant) > _UINT256_DIGITS:
        return None
    number = int(significant)
    return number if number < 2**256 else None


def _is_list(value: object) -> TypeGuard[Sequence[Any]]:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def passes(option: object) -> bool:
    """The pairing's filter: scheme exact, an eip155 network, EIP-3009 as the transfer method, a known flow."""
    if not isinstance(option, Mapping):
        return False
    if option.get("scheme") != "exact":
        return False
    network = option.get("network")
    if not isinstance(network, str) or _NETWORK.fullmatch(network) is None:
        return False
    extra = option.get("extra", {})
    if not isinstance(extra, Mapping):
        return False
    if "assetTransferMethod" in extra and extra["assetTransferMethod"] != "eip3009":
        return False
    if "paymentFlow" in extra and extra["paymentFlow"] not in ("authorization", "upfront"):
        return False
    return True


def _legal_context(info: object) -> tuple[AtrHash, str] | Refusal:
    """H and the https link from a legalContext's info."""
    if not isinstance(info, Mapping):
        return Refusal("x402/legal-context-malformed")
    camel = info.get("legalContextUrl")
    snake = info.get("legal_context_url")
    if camel is not None and snake is not None and camel != snake:
        return Refusal("x402/legal-context-malformed")
    link = camel if camel is not None else snake
    if info.get("type") != "sha256" or not is_hash(info.get("value")) or not isinstance(link, str):
        return Refusal("x402/legal-context-malformed")
    if not is_https_link(link) or len(link) > MAX_LINK_CHARS:
        return Refusal("x402/link-not-https" if is_other_scheme_link(link) else "x402/legal-context-malformed")
    value = info["value"]
    assert isinstance(value, str)
    return value.lower(), link


@dataclass(frozen=True, slots=True)
class _Unsigned:
    typed_data: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signature: str) -> dict[str, Any] | Refusal:
        """The PaymentPayload for this authorization, with the numbers as decimal strings."""
        if not isinstance(signature, str) or _HEX_BYTES.fullmatch(signature) is None:
            return Refusal("x402/signature-malformed")
        size = (len(signature) - 2) // 2
        if size < MIN_SIGNATURE_BYTES or size > MAX_SIGNATURE_BYTES:
            return Refusal("x402/signature-malformed")
        message = self.typed_data["message"]
        payload: dict[str, Any] = {"x402Version": 2}
        if "resource" in self._required:
            payload["resource"] = self._required["resource"]
        payload["accepted"] = self._accepted
        payload["payload"] = {
            "signature": signature,
            "authorization": {
                "from": message["from"],
                "to": message["to"],
                "value": str(message["value"]),
                "validAfter": str(message["validAfter"]),
                "validBefore": str(message["validBefore"]),
                "nonce": message["nonce"],
            },
        }
        if "extensions" in self._required:
            payload["extensions"] = self._required["extensions"]
        return payload


@dataclass(frozen=True, slots=True)
class X402ExactEip155Eip3009:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        if not isinstance(doc, Mapping) or _safe_int(doc.get("x402Version")) != 2:
            return Refusal("x402/not-v2")
        accepts = doc.get("accepts")
        if not _is_list(accepts) or len(accepts) > MAX_OPTIONS:
            return Refusal("x402/option-malformed")
        extensions = doc.get("extensions")
        if not isinstance(extensions, Mapping) or "legalContext" not in extensions:
            return Refusal("x402/no-legal-context")
        legal_context = extensions["legalContext"]
        if not isinstance(legal_context, Mapping):
            return Refusal("x402/legal-context-malformed")
        decoded = _legal_context(legal_context.get("info"))
        if isinstance(decoded, Refusal):
            return decoded
        h, link = decoded
        agreement = agreement_in(legal_context.get("info"))
        if isinstance(agreement, AgreementFault):
            return Refusal(f"x402/{agreement.fault}")
        options = [option for option in accepts if passes(option)]
        if not options:
            return Refusal("x402/no-payable-option")
        offer = {"required": doc, "options": options}
        return Advertised(h=h, link=link, offer=offer, agreement=agreement if isinstance(agreement, str) else None)

    def build(self, choice: Json, h: AtrHash) -> _Unsigned | Refusal:
        """The EIP-712 TransferWithAuthorization request whose nonce is h."""
        if not isinstance(choice, Mapping):
            return Refusal("x402/option-malformed")
        required = choice.get("required")
        accepted = choice.get("accepted")
        if not isinstance(required, Mapping) or _safe_int(required.get("x402Version")) != 2:
            return Refusal("x402/not-v2")
        accepts = required.get("accepts")
        if not _is_list(accepts) or len(accepts) > MAX_OPTIONS:
            return Refusal("x402/option-malformed")
        if accepted not in accepts:
            return Refusal("x402/option-not-in-document")
        if not passes(accepted):
            return Refusal("x402/option-not-this-pairing")
        assert isinstance(accepted, Mapping)
        extra = accepted.get("extra", {})
        assert isinstance(extra, Mapping)
        name = extra.get("name")
        version = extra.get("version")
        if not isinstance(name, str) or name == "" or not isinstance(version, str) or version == "":
            return Refusal("x402/option-malformed")
        asset = accepted.get("asset")
        pay_to = accepted.get("payTo")
        payer = choice.get("from")
        for address in (asset, pay_to, payer):
            if not isinstance(address, str) or _ADDRESS.fullmatch(address) is None:
                return Refusal("x402/option-malformed")
        assert isinstance(asset, str) and isinstance(pay_to, str) and isinstance(payer, str)
        value = _uint256(accepted.get("amount"))
        max_timeout = _safe_int(accepted.get("maxTimeoutSeconds"))
        if value is None or max_timeout is None or max_timeout <= 0:
            return Refusal("x402/option-malformed")
        now = _safe_int(choice.get("now"))
        if now is None or now < 0:
            return Refusal("x402/option-malformed")
        if not is_hash(h):
            return Refusal("x402/payload-malformed")
        network = _NETWORK.fullmatch(accepted["network"])
        assert network is not None
        chain_id = int(network.group(1))
        if chain_id > _MAX_SAFE_INTEGER:
            return Refusal("evm/network-malformed")
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
        return _Unsigned(typed_data=typed_data, _required=required, _accepted=accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The authorization's nonce, as a lower-case hash. A payment that carries a refused member, the member
        refusals use, is x402/payload-malformed. The signature is not verified here."""
        if not isinstance(presented, Mapping) or _safe_int(presented.get("x402Version")) != 2:
            return Refusal("x402/not-v2")
        if "refused" in presented:
            return Refusal("x402/payload-malformed")
        accepted = presented.get("accepted")
        if not isinstance(accepted, Mapping):
            return Refusal("x402/payload-malformed")
        if not passes(accepted):
            return Refusal("x402/option-not-this-pairing")
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
