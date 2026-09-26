"""The EVM values MPP's EVM and Tempo pairings build: ABI words, the ERC-20 transfer call, EIP-3009's
TransferWithAuthorization and ReceiveWithAuthorization typed data, and Permit2's typed data. Numbers in typed data are
ints."""

import re
from collections.abc import Mapping, Sequence
from typing import Any

from .._types import Refusal
from ._lcp import is_address, normal_hash, uint256_of

UINT256_LIMIT = 2**256
MAX_SAFE_INTEGER = 2**53 - 1
PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
TRANSFER_SELECTOR = "a9059cbb"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

_EIP155 = re.compile(r"eip155:([0-9]+)")
_WITNESS_TYPE_NAME = re.compile(r"[A-Z][A-Za-z0-9]{0,63}")

Field = dict[str, str]


def is_uint256(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < UINT256_LIMIT


def uint_word(value: int) -> bytes:
    return (value % UINT256_LIMIT).to_bytes(32, "big")


def address_word(address: str) -> bytes:
    return b"\0" * 12 + bytes.fromhex(address[2:])


def transfer_calldata(to: str, amount: int) -> str:
    """transfer(address,uint256) calldata, lower-case hex."""
    return "0x" + TRANSFER_SELECTOR + address_word(to).hex() + uint_word(amount).hex()


def eip3009_typed_data(
    network: str,
    asset: str,
    name: str,
    version: str,
    from_: str,
    to: str,
    value: str,
    valid_after: int,
    valid_before: int,
    nonce: str,
) -> dict[str, Any] | Refusal:
    """EIP-712 typed data for TransferWithAuthorization, with the field lists in ERC-3009's order. The domain's
    verifyingContract is the token."""
    match = _EIP155.fullmatch(network) if isinstance(network, str) else None
    chain_id = int(match.group(1)) if match is not None else None
    if chain_id is None or chain_id > MAX_SAFE_INTEGER:
        return Refusal("evm/network-malformed")
    amount = uint256_of(value)
    if amount is None:
        return Refusal("evm/amount-malformed")
    if not is_address(asset) or not is_address(from_) or not is_address(to):
        return Refusal("evm/field-malformed")
    if not is_uint256(valid_after) or not is_uint256(valid_before):
        return Refusal("evm/field-malformed")
    n = normal_hash(nonce)
    if n is None:
        return Refusal("evm/field-malformed")
    return {
        "domain": {"name": name, "version": version, "chainId": chain_id, "verifyingContract": asset},
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
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
        "message": {
            "from": from_,
            "to": to,
            "value": amount,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": n,
        },
    }


def receive_typed_data(**a: Any) -> dict[str, Any] | Refusal:
    """EIP-3009's ReceiveWithAuthorization: the same fields as TransferWithAuthorization."""
    t = eip3009_typed_data(**a)
    if isinstance(t, Refusal):
        return t
    return {
        "domain": t["domain"],
        "types": {
            "EIP712Domain": t["types"]["EIP712Domain"],
            "ReceiveWithAuthorization": t["types"]["TransferWithAuthorization"],
        },
        "primaryType": "ReceiveWithAuthorization",
        "message": t["message"],
    }


def permit2_typed_data(
    chain_id: int,
    permitted: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    spender: str,
    nonce: int,
    deadline: int,
    verifying_contract: str | None = None,
    witness: Mapping[str, Any] | None = None,
) -> dict[str, Any] | Refusal:
    """Permit2's typed data under its domain (name "Permit2", no version). No witness gives PermitTransferFrom; a
    witness {type, fields, value} gives PermitWitnessTransferFrom, or PermitBatchWitnessTransferFrom when permitted is
    a list."""
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or not 0 < chain_id <= MAX_SAFE_INTEGER:
        return Refusal("evm/network-malformed")
    contract = PERMIT2 if verifying_contract is None else verifying_contract
    if not is_address(contract) or not is_address(spender):
        return Refusal("evm/field-malformed")
    if not is_uint256(nonce) or not is_uint256(deadline):
        return Refusal("evm/field-malformed")
    listed = isinstance(permitted, list)
    entries: list[Mapping[str, Any]] = list(permitted) if isinstance(permitted, list) else [permitted]  # type: ignore[list-item]
    if not 1 <= len(entries) <= 32:
        return Refusal("evm/field-malformed")
    for p in entries:
        if not is_address(p.get("token")):
            return Refusal("evm/field-malformed")
        if not is_uint256(p.get("amount")):
            return Refusal("evm/amount-malformed")
    token_permissions = [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}]
    domain = {"name": "Permit2", "chainId": chain_id, "verifyingContract": contract}
    eip712_domain = [
        {"name": "name", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ]
    shaped: Any = (
        [{"token": p["token"], "amount": p["amount"]} for p in entries]
        if listed
        else {"token": entries[0]["token"], "amount": entries[0]["amount"]}
    )
    if witness is None:
        if listed:
            return Refusal("evm/field-malformed")
        return {
            "domain": domain,
            "types": {
                "EIP712Domain": eip712_domain,
                "TokenPermissions": token_permissions,
                "PermitTransferFrom": [
                    {"name": "permitted", "type": "TokenPermissions"},
                    {"name": "spender", "type": "address"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                ],
            },
            "primaryType": "PermitTransferFrom",
            "message": {"permitted": shaped, "spender": spender, "nonce": nonce, "deadline": deadline},
        }
    kind = witness["type"]
    if _WITNESS_TYPE_NAME.fullmatch(kind) is None or kind == "TokenPermissions" or kind.startswith("Permit"):
        return Refusal("evm/field-malformed")
    primary = "PermitBatchWitnessTransferFrom" if listed else "PermitWitnessTransferFrom"
    return {
        "domain": domain,
        "types": {
            "EIP712Domain": eip712_domain,
            "TokenPermissions": token_permissions,
            primary: [
                {"name": "permitted", "type": "TokenPermissions[]" if listed else "TokenPermissions"},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
                {"name": "witness", "type": kind},
            ],
            kind: [{"name": f["name"], "type": f["type"]} for f in witness["fields"]],
        },
        "primaryType": primary,
        "message": {
            "permitted": shaped,
            "spender": spender,
            "nonce": nonce,
            "deadline": deadline,
            "witness": dict(witness["value"]),
        },
    }
