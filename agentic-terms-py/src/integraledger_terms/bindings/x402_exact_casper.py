"""The buyer half of the pairing x402/exact/casper: read, build with complete, and bound.

The ATR hash rides as the 32-byte nonce of a CEP-3009 TransferWithAuthorization. Nothing here fetches, hashes or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._lcp import is_object, normal_hash, safe_int, uint256_of
from ._x402 import chosen, filter_of, payment_with, read_for

ID = "x402/exact/casper"

UINT256_LIMIT = 1 << 256
_NETWORK = re.compile(r"casper:[a-z0-9-]{1,64}")
_PACKAGE = re.compile(r"[0-9a-fA-F]{64}")
_ADDRESS = re.compile(r"0[01][0-9a-fA-F]{64}")
_NONCE = re.compile(r"(0x)?[0-9a-fA-F]{64}")
_TAGGED = re.compile(r"0[12](?:[0-9a-fA-F]{2})+")
MAX_NAME = 64
MAX_PUBLIC_KEY_HEX = 68
MAX_SIGNATURE_HEX = 132


def _utf16_length(text: str) -> int:
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def _is_address(value: object) -> bool:
    return isinstance(value, str) and _ADDRESS.fullmatch(value) is not None


def _is_name(value: object) -> bool:
    return isinstance(value, str) and 0 < _utf16_length(value) <= MAX_NAME


def _is_tagged(value: object, max_hex: int) -> bool:
    return isinstance(value, str) and len(value) <= max_hex and _TAGGED.fullmatch(value) is not None


def casper_option(option: object) -> bool:
    """The pairing's filter: an exact option on a casper: network that build can turn into typed data."""
    if not is_object(option):
        return False
    extra = option.get("extra")
    network = option.get("network")
    asset = option.get("asset")
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    return (
        option.get("scheme") == "exact"
        and isinstance(network, str)
        and _NETWORK.fullmatch(network) is not None
        and isinstance(asset, str)
        and _PACKAGE.fullmatch(asset) is not None
        and _is_address(option.get("payTo"))
        and uint256_of(option.get("amount")) is not None
        and is_object(extra)
        and _is_name(extra.get("name"))
        and _is_name(extra.get("version"))
        and timeout is not None
        and timeout > 0
    )


CHECK = filter_of(casper_option)


def cep3009_typed_data(
    network: str, asset: str, name: str, version: str, from_: str, to: str, value: str, valid_before: int, nonce: AtrHash
) -> dict[str, Any] | Refusal:
    """The CEP-3009 typed data for TransferWithAuthorization, with validAfter 0 and the hash as the nonce."""
    if _NETWORK.fullmatch(network) is None:
        return Refusal("casper/network-malformed")
    if _PACKAGE.fullmatch(asset) is None:
        return Refusal("casper/option-malformed")
    if not _is_name(name) or not _is_name(version):
        return Refusal("casper/option-malformed")
    if not _is_address(from_) or not _is_address(to):
        return Refusal("casper/address-malformed")
    amount = uint256_of(value)
    if amount is None:
        return Refusal("casper/amount-malformed")
    if valid_before < 0 or valid_before >= UINT256_LIMIT:
        return Refusal("casper/option-malformed")
    h = normal_hash(nonce)
    if h is None:
        return Refusal("casper/payload-malformed")
    return {
        "domain": {"name": name, "version": version, "chain_name": network, "contract_package_hash": asset},
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chain_name", "type": "string"},
                {"name": "contract_package_hash", "type": "bytes32"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "message": {"from": from_, "to": to, "value": amount, "validAfter": 0, "validBefore": valid_before, "nonce": h[2:]},
    }


@dataclass(frozen=True, slots=True)
class CasperUnsigned:
    """The typed data the payer's key signs, and the payment its public key and signature complete."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _authorization: dict[str, str]

    def complete(self, public_key: str, signature: str) -> dict[str, Any] | Refusal:
        """The payment, for a public key and a signature each in hex with its one-byte algorithm tag."""
        if not _is_tagged(public_key, MAX_PUBLIC_KEY_HEX) or not _is_tagged(signature, MAX_SIGNATURE_HEX):
            return Refusal("casper/signature-malformed")
        if public_key[:2] != signature[:2]:
            return Refusal("casper/key-tag-mismatch")
        payload = {"authorization": dict(self._authorization), "publicKey": public_key, "signature": signature}
        return payment_with(self._required, self._accepted, payload)


def _payment_of(presented: object) -> Mapping[str, Any] | Refusal:
    """The payment's shape as this pairing requires it, or casper/payload-malformed."""
    malformed = Refusal("casper/payload-malformed")
    if not is_object(presented) or safe_int(presented.get("x402Version")) != 2:
        return malformed
    if not casper_option(presented.get("accepted")):
        return malformed
    payload = presented.get("payload")
    if not is_object(payload):
        return malformed
    a = payload.get("authorization")
    if not is_object(a):
        return malformed
    for k in ("from", "to", "value", "validAfter", "validBefore", "nonce"):
        if not isinstance(a.get(k), str):
            return malformed
    if _NONCE.fullmatch(a["nonce"]) is None:
        return malformed
    if not _is_tagged(payload.get("publicKey"), MAX_PUBLIC_KEY_HEX) or not _is_tagged(
        payload.get("signature"), MAX_SIGNATURE_HEX
    ):
        return malformed
    return presented


@dataclass(frozen=True, slots=True)
class X402ExactCasper:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(CHECK)(doc)

    def build(self, choice: Json, h: AtrHash) -> CasperUnsigned | Refusal:
        """The CEP-3009 authorization the payer signs for the chosen option, with the hash as its nonce."""
        c = choice if is_object(choice) else {}
        required, accepted = c.get("required"), c.get("accepted")
        wrong = chosen(required, accepted, CHECK)
        if wrong is not True:
            return wrong if isinstance(wrong, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        from_ = c.get("from")
        if not _is_address(from_):
            return Refusal("casper/address-malformed")
        assert isinstance(from_, str)
        now = safe_int(c.get("now"))
        if now is None or now < 0:
            return Refusal("casper/option-malformed")
        timeout = safe_int(accepted["maxTimeoutSeconds"])
        assert timeout is not None
        valid_before = now + timeout
        extra = accepted["extra"]
        typed_data = cep3009_typed_data(
            accepted["network"], accepted["asset"], extra["name"], extra["version"], from_, accepted["payTo"],
            accepted["amount"], valid_before, h,
        )  # fmt: skip
        if isinstance(typed_data, Refusal):
            return typed_data
        authorization = {
            "from": from_,
            "to": accepted["payTo"],
            "value": accepted["amount"],
            "validAfter": "0",
            "validBefore": str(valid_before),
            "nonce": typed_data["message"]["nonce"],
        }
        return CasperUnsigned(
            request={"kind": "casper-eip712", "typedData": typed_data},
            _required=required,
            _accepted=accepted,
            _authorization=authorization,
        )

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """The hash inside what the payer signed: the authorization's nonce, lower-case. The signature is not
        verified here."""
        p = _payment_of(presented)
        if isinstance(p, Refusal):
            return p
        n: str = p["payload"]["authorization"]["nonce"]
        h = normal_hash(n if n.startswith("0x") else "0x" + n)
        assert h is not None
        return h
