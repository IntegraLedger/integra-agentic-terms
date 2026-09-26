"""The buyer half of the pairing x402/exact/starknet: read, build with complete, and bound.

The payer signs a SNIP-12 OutsideExecution (SNIP-9 v2) authorizing one token transfer; its Nonce is the ATR hash's
low 250 bits. Nothing here fetches, hashes or signs.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._codec import js_json_length
from ._lcp import from_legal_context, is_object, normal_hash, safe_int, uint256_of
from ._x402 import LEGAL_CONTEXT, OptionFilter, chosen, payment_with, presented_with, read_for

ID = "x402/exact/starknet"

FELT_P = 2**251 + 17 * 2**192 + 1
MASK_250 = 2**250 - 1
# The SNIP-9 any-caller sentinel, the short string ANY_CALLER.
ANY_CALLER = "0x414e595f43414c4c4552"
# sn_keccak("transfer")
SELECTOR_TRANSFER = "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"

NETWORKS = ("starknet:SN_MAIN", "starknet:SN_SEPOLIA")
_U128 = 1 << 128
_U256_LIMIT = 1 << 256
_MAX_SAFE_INTEGER = 2**53 - 1
MAX_SIGNATURE_FELTS = 32
MAX_TYPED_DATA_CHARS = 16_384
_FELT_TEXT = re.compile(r"0x[0-9a-fA-F]{1,64}")
_DECIMAL = re.compile(r"[0-9]{1,78}")


def felt_value(value: object) -> int | None:
    """The value of 0x and 1 to 64 hex digits below FELT_P, or None."""
    if not isinstance(value, str) or _FELT_TEXT.fullmatch(value) is None:
        return None
    v = int(value[2:], 16)
    return v if v < FELT_P else None


def felt_of(value: int) -> str:
    return hex(value)


def sn_nonce(h: AtrHash) -> str | Refusal:
    """The hash's low 250 bits as a felt. A value that is not a 32-byte hash is x402/payload-malformed."""
    nh = normal_hash(h)
    if nh is None:
        return Refusal("x402/payload-malformed")
    return felt_of(int(nh, 16) & MASK_250)


def _short_string(text: str) -> int | None:
    """A short string of 1 to 31 ASCII characters as a felt, or None."""
    if len(text) == 0 or len(text) > 31:
        return None
    v = 0
    for c in text:
        if ord(c) > 0x7F:
            return None
        v = (v << 8) | ord(c)
    return v


def chain_id_felt(network: str) -> str:
    """The network's reference as a short-string felt."""
    value = _short_string(network[len("starknet:") :])
    assert value is not None
    return felt_of(value)


def _chain_id_value(value: object) -> int | None:
    """A chain id as hex, decimal or the short string."""
    if not isinstance(value, str):
        return None
    if _FELT_TEXT.fullmatch(value) is not None:
        return felt_value(value)
    if _DECIMAL.fullmatch(value) is not None:
        return int(value)
    return _short_string(value)


def _is_int(value: object, n: int) -> bool:
    """The JSON number n or the string of its digits."""
    if isinstance(value, bool):
        return False
    return (isinstance(value, (int, float)) and value == n) or value == str(n)


def _check(option: Mapping[str, Any]) -> bool | Refusal | None:
    """The pairing's filter: scheme exact on a Starknet network, the default transfer and the authorization flow,
    felts for asset, payTo and a fee payer that is neither zero nor ANY_CALLER, an amount below 2^256 and a positive
    timeout."""
    if not is_object(option) or option.get("scheme") != "exact":
        return Refusal("x402/option-not-this-pairing")
    network = option.get("network")
    if not isinstance(network, str) or not network.startswith("starknet:"):
        return Refusal("x402/option-not-this-pairing")
    extra = option.get("extra")
    if not is_object(extra):
        return Refusal("starknet/option-malformed")
    if "assetTransferMethod" in extra and extra["assetTransferMethod"] != "default":
        return Refusal("x402/option-not-this-pairing")
    if "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return Refusal("x402/option-not-this-pairing")
    if network not in NETWORKS:
        return Refusal("starknet/network-malformed")
    fee_payer = felt_value(extra.get("feePayer"))
    if felt_value(option.get("asset")) is None or felt_value(option.get("payTo")) is None or fee_payer is None:
        return Refusal("starknet/felt-malformed")
    if fee_payer == 0 or fee_payer == int(ANY_CALLER, 16):
        return Refusal("starknet/caller-forbidden")
    if uint256_of(option.get("amount")) is None:
        return Refusal("starknet/option-malformed")
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    if timeout is None or timeout < 1:
        return Refusal("starknet/option-malformed")
    return True


CHECK: OptionFilter = _check


def outside_execution(
    network: str, fee_payer: str, asset: str, pay_to: str, amount: int, execute_before: int, nonce: str
) -> dict[str, Any] | Refusal:
    """x402's OutsideExecution for one transfer(payTo, amount) on asset, with the fee payer as Caller."""
    if network not in NETWORKS:
        return Refusal("starknet/network-malformed")
    caller, token, payee, n = (felt_value(v) for v in (fee_payer, asset, pay_to, nonce))
    if caller is None or token is None or payee is None or n is None:
        return Refusal("starknet/felt-malformed")
    if amount < 0 or amount >= _U256_LIMIT:
        return Refusal("starknet/option-malformed")
    if execute_before > _MAX_SAFE_INTEGER or execute_before < 2:
        return Refusal("starknet/option-malformed")
    return {
        "types": {
            "StarknetDomain": [
                {"name": "name", "type": "shortstring"},
                {"name": "version", "type": "shortstring"},
                {"name": "chainId", "type": "shortstring"},
                {"name": "revision", "type": "shortstring"},
            ],
            "OutsideExecution": [
                {"name": "Caller", "type": "ContractAddress"},
                {"name": "Nonce", "type": "felt"},
                {"name": "Execute After", "type": "u128"},
                {"name": "Execute Before", "type": "u128"},
                {"name": "Calls", "type": "Call*"},
            ],
            "Call": [
                {"name": "To", "type": "ContractAddress"},
                {"name": "Selector", "type": "selector"},
                {"name": "Calldata", "type": "felt*"},
            ],
        },
        "primaryType": "OutsideExecution",
        "domain": {"name": "Account.execute_from_outside", "version": 2, "chainId": chain_id_felt(network), "revision": 1},
        "message": {
            "Caller": felt_of(caller),
            "Nonce": felt_of(n),
            "Execute After": "1",
            "Execute Before": str(execute_before),
            "Calls": [
                {
                    "To": felt_of(token),
                    "Selector": SELECTOR_TRANSFER,
                    "Calldata": [felt_of(payee), felt_of(amount % _U128), felt_of(amount // _U128)],
                }
            ],
        },
    }


@dataclass(frozen=True, slots=True)
class StarknetUnsigned:
    """The typed data the account's key signs, and the payment its signature completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signature: Sequence[str]) -> dict[str, Any] | Refusal:
        """The payment, for a signature of 1 to 32 felts."""
        if not isinstance(signature, list) or not 1 <= len(signature) <= MAX_SIGNATURE_FELTS:
            return Refusal("starknet/signature-malformed")
        if not all(felt_value(s) is not None for s in signature):
            return Refusal("starknet/signature-malformed")
        payload = {
            "from": self.request["account"],
            "outsideExecution": {"typedData": self.request["typedData"], "signature": list(signature)},
        }
        return payment_with(self._required, self._accepted, payload)


@dataclass(frozen=True, slots=True)
class X402ExactStarknet:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(CHECK)(doc)

    def build(self, choice: Json, h: AtrHash) -> StarknetUnsigned | Refusal:
        """x402's typed data for the chosen option, with Nonce the hash's low 250 bits."""
        if not is_object(choice):
            return Refusal("starknet/option-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, CHECK)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        account = felt_value(choice.get("from"))
        if account is None:
            return Refusal("starknet/felt-malformed")
        fee_payer = accepted["extra"]["feePayer"]
        if account == felt_value(fee_payer):
            return Refusal("starknet/caller-forbidden")
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        now = safe_int(choice.get("now"))
        if now is None or now < 0:
            return Refusal("starknet/option-malformed")
        amount = uint256_of(accepted["amount"])
        timeout = safe_int(accepted["maxTimeoutSeconds"])
        assert amount is not None and timeout is not None
        nonce = sn_nonce(nh)
        if isinstance(nonce, Refusal):
            return nonce
        typed_data = outside_execution(
            accepted["network"], fee_payer, accepted["asset"], accepted["payTo"], amount, now + timeout, nonce
        )
        if isinstance(typed_data, Refusal):
            return typed_data
        request = {"kind": "starknet-snip12", "typedData": typed_data, "account": felt_of(account)}
        return StarknetUnsigned(request=request, _required=required, _accepted=accepted)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """The echoed hash whose low 250 bits are the nonce the payer signed. The signature is not verified here."""
        p = presented_with(presented, CHECK)
        if isinstance(p, Refusal):
            return p
        accepted, payload, extensions = p
        if felt_value(payload.get("from")) is None:
            return Refusal("starknet/felt-malformed")
        oe = payload.get("outsideExecution")
        td = oe.get("typedData") if is_object(oe) else None
        if not is_object(td) or js_json_length(td, MAX_TYPED_DATA_CHARS) is None:
            return Refusal("starknet/typed-data-malformed")
        domain, message = td.get("domain"), td.get("message")
        if td.get("primaryType") != "OutsideExecution" or not is_object(domain) or not is_object(message):
            return Refusal("starknet/typed-data-malformed")
        if domain.get("name") != "Account.execute_from_outside":
            return Refusal("starknet/typed-data-malformed")
        if not _is_int(domain.get("version"), 2) or not _is_int(domain.get("revision"), 1):
            return Refusal("starknet/typed-data-malformed")
        chain = _chain_id_value(domain.get("chainId"))
        if chain is None or chain != int(chain_id_felt(accepted["network"]), 16):
            return Refusal("starknet/typed-data-malformed")
        nonce = felt_value(message.get("Nonce"))
        if nonce is None:
            return Refusal("starknet/typed-data-malformed")
        lc = extensions.get(LEGAL_CONTEXT) if is_object(extensions) else None
        decoded = from_legal_context({"legalContext": lc.get("info") if is_object(lc) else None})
        if decoded is None:
            return Refusal("starknet/no-legal-context")
        if int(decoded[0], 16) & MASK_250 != nonce:
            return Refusal("starknet/nonce-not-bound")
        return decoded[0]
