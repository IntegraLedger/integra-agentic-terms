"""The x402 batch-settlement channel contract's EVM pieces: its addresses, the channel id (the EIP-712 digest of a
ChannelConfig under the "x402 Batch Settlement" domain), the ERC-3009 deposit nonce, and the voucher's typed data."""

import re
from collections.abc import Mapping
from typing import Any, TypeGuard

from .._keccak import keccak256
from .._types import Refusal
from ._evm import address_word, bytes32_word, hex_of, uint_word
from ._lcp import is_address, is_object, safe_int

BATCH_SETTLEMENT = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003"
ERC3009_DEPOSIT_COLLECTOR = "0x4020806089470a89826cB9fB1f4059150b550004"
PERMIT2_DEPOSIT_COLLECTOR = "0x4020425FAf3B746C082C2f942b4E5159887B0005"
CHANNEL_CONFIG_TYPEHASH = "0x1c9a06ceab9b0ebbd3301dc56c9111bb6d9af421356dc9ccb3b7084c755db308"
VOUCHER_TYPEHASH = "0x1e1bd6ff84c3e0d9029a292b212e039c0ca97ec497c55191a4a5874294609a69"

DOMAIN_NAME = "x402 Batch Settlement"
DOMAIN_VERSION = "1"
_DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_U40_LIMIT = 1 << 40
_HASH32 = re.compile(r"0x[0-9a-fA-F]{64}")
_ADDRESSES = ("payer", "payerAuthorizer", "receiver", "receiverAuthorizer", "token")


def is_hash32(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _HASH32.fullmatch(value) is not None


def is_channel_config(c: object) -> TypeGuard[Mapping[str, Any]]:
    """Five addresses, a withdrawDelay below 2^40, and a 32-byte salt."""
    if not is_object(c) or not all(is_address(c.get(k)) for k in _ADDRESSES):
        return False
    delay = safe_int(c.get("withdrawDelay"))
    return delay is not None and 0 <= delay < _U40_LIMIT and is_hash32(c.get("salt"))


def _domain_separator(chain_id: int) -> bytes:
    return keccak256(
        _DOMAIN_TYPEHASH
        + keccak256(DOMAIN_NAME.encode())
        + keccak256(DOMAIN_VERSION.encode())
        + uint_word(chain_id)
        + address_word(BATCH_SETTLEMENT)
    )


def batch_channel_id(chain_id: int, c: object) -> str | Refusal:
    """The channel id: keccak256(0x1901 ‖ domainSeparator ‖ keccak256(abi.encode(CHANNEL_CONFIG_TYPEHASH, payer,
    payerAuthorizer, receiver, receiverAuthorizer, token, withdrawDelay, salt)))."""
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or not 0 < chain_id <= 2**53 - 1:
        return Refusal("evm/network-malformed")
    if not is_channel_config(c):
        return Refusal("evm/field-malformed")
    delay = safe_int(c["withdrawDelay"])
    assert delay is not None
    struct_hash = keccak256(
        bytes32_word(CHANNEL_CONFIG_TYPEHASH)
        + b"".join(address_word(c[k]) for k in _ADDRESSES)
        + uint_word(delay)
        + bytes32_word(c["salt"])
    )
    return hex_of(keccak256(b"\x19\x01" + _domain_separator(chain_id) + struct_hash))


def erc3009_deposit_nonce(channel_id: object, auth_salt: object) -> str | Refusal:
    """The ERC-3009 deposit's nonce: keccak256(abi.encode(bytes32 channelId, uint256 authSalt))."""
    if not is_hash32(channel_id) or not is_hash32(auth_salt):
        return Refusal("evm/field-malformed")
    return hex_of(keccak256(bytes32_word(channel_id) + bytes32_word(auth_salt)))


def voucher_request(chain_id: int, channel_id: str, max_claimable_amount: int) -> dict[str, Any]:
    """The voucher the payer authorizer signs, Voucher(bytes32 channelId, uint128 maxClaimableAmount), with the amount
    as a decimal string."""
    return {
        "domain": {
            "name": DOMAIN_NAME,
            "version": DOMAIN_VERSION,
            "chainId": chain_id,
            "verifyingContract": BATCH_SETTLEMENT,
        },
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Voucher": [
                {"name": "channelId", "type": "bytes32"},
                {"name": "maxClaimableAmount", "type": "uint128"},
            ],
        },
        "primaryType": "Voucher",
        "message": {"channelId": channel_id, "maxClaimableAmount": str(max_claimable_amount)},
    }
