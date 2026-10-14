"""The EVM values MPP's EVM and Tempo pairings build: ABI words, the ERC-20 transfer call, and EIP-3009's
TransferWithAuthorization and ReceiveWithAuthorization typed data. Numbers in typed data are ints."""

import re
from typing import Any

from .._types import Refusal
from ._lcp import is_address, normal_hash, uint256_of

UINT256_LIMIT = 2**256
MAX_SAFE_INTEGER = 2**53 - 1
TRANSFER_SELECTOR = "a9059cbb"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

_EIP155 = re.compile(r"eip155:([0-9]+)")


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
