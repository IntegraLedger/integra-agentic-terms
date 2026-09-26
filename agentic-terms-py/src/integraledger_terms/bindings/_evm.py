"""The EVM rail pieces the x402 EVM pairings build with: the Permit2 proxies and collectors, the commerce-payments
escrow's deployments, MetaMask's reference DelegationManager, 32-byte ABI words, EIP-3009 and Permit2 typed data, the
escrow's salt commitment and payment hash, and a strict decoder of a permission context's delegations. Nothing here
throws on a caller's value: malformed input gives a Refusal or None."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._keccak import keccak256
from .._types import Refusal
from ._lcp import UINT256_LIMIT, chain_id_of, is_address, normal_hash, uint256_of

PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
EXACT_PERMIT2_PROXY = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"
UPTO_PERMIT2_PROXY = "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"
PAYMENT_INFO_TYPEHASH = "0xae68ac7ce30c86ece8196b61a7c486d8f0061f575037fbd34e7fe4e2820c6591"
SALT_BINDING_TYPEHASH = "0x8a2a7e41a0bda000ded071ff38b79401d2603e1826516ff2635b11fe9e30877f"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"


@dataclass(frozen=True, slots=True)
class Escrow:
    """One deployment of the commerce-payments escrow: the escrow and its two token collectors."""

    escrow: str
    eip3009_collector: str
    permit2_collector: str


ESCROW_V1_1 = Escrow(
    escrow="0xf96815976523E00e65Be8f34cA5e64b4f41EB19c",
    eip3009_collector="0x8612dfdc421f80336cd14E8EF9cb1E765dB5ab88",
    permit2_collector="0xD69831Aed5bfe262067ec4c751f4F830EcdD446e",
)
ESCROW_V1_0 = Escrow(
    escrow="0xBdEA0D1bcC5966192B070Fdf62aB4EF5b4420cff",
    eip3009_collector="0x0E3dF9510de65469C4518D7843919c0b8C7A7757",
    permit2_collector="0x992476B9Ee81d52a5BdA0622C333938D0Af0aB26",
)

# MetaMask's reference DelegationManager, v1.3.0, at one CREATE2 address, and the chain ids whose deployment record
# holds it there.
DELEGATION_MANAGER = "0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3"
DELEGATION_MANAGER_CHAINS: frozenset[int] = frozenset((
    1, 10, 56, 97, 100, 130, 137, 143, 146, 1155, 1301, 1328, 1329, 2020, 2021, 4114, 4217, 4663, 5000, 5003, 5042, 5115,
    6342, 6343, 8453, 10143, 10200, 13579, 14601, 42161, 42170, 42220, 42431, 46630, 50312, 57073, 59141, 59144, 80002,
    80069, 80094, 84532, 421614, 560048, 737373, 747474, 763373, 5042002, 11142220, 11155111, 11155420,
))  # fmt: skip

MAX_CONTEXT_BYTES = 32_768
MAX_DELEGATIONS = 8
MAX_CAVEATS = 16
MAX_ABI_BYTES = 8192

_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_WITNESS_TYPE_NAME = re.compile(r"[A-Z][A-Za-z0-9]{0,63}")

Field = dict[str, str]


def bytes_of(value: object, max_bytes: int | None = None) -> bytes | None:
    """The bytes of 0x and an even number of hex digits, at most max_bytes of them when named, or None."""
    if not isinstance(value, str) or (max_bytes is not None and len(value) > 2 + 2 * max_bytes):
        return None
    if _HEX.fullmatch(value) is None:
        return None
    return bytes.fromhex(value[2:])


def hex_of(data: bytes) -> str:
    return "0x" + data.hex()


def keccak_hex(data: bytes) -> str:
    return hex_of(keccak256(data))


def is_uint256(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < UINT256_LIMIT


def uint_word(value: int) -> bytes:
    """A uint256 as one 32-byte big-endian word."""
    return value.to_bytes(32, "big")


def address_word(address: str) -> bytes:
    """An address (0x + 40 hex) as one word, left-padded with zeros."""
    return bytes(12) + bytes.fromhex(address[2:])


def bytes32_word(value: str) -> bytes:
    """A 32-byte value (0x + 64 hex) as one word."""
    return bytes.fromhex(value[2:])


def address_of_word(word: bytes) -> str | None:
    """The address in a word whose first 12 bytes are zero, lower-case, or None."""
    if len(word) != 32 or any(word[:12]):
        return None
    return hex_of(word[12:])


_EIP712_DOMAIN: list[Field] = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]
_AUTHORIZATION_FIELDS: list[Field] = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]


def eip3009_typed_data(
    primary_type: str,
    network: object,
    asset: object,
    name: str,
    version: str,
    from_: object,
    to: object,
    value: object,
    valid_after: int,
    valid_before: int,
    nonce: object,
) -> dict[str, Any] | Refusal:
    """The EIP-712 typed data of an EIP-3009 authorization (TransferWithAuthorization or ReceiveWithAuthorization),
    with the fields in ERC-3009's order and the token as the domain's verifyingContract."""
    chain_id = chain_id_of(network)
    if chain_id is None:
        return Refusal("evm/network-malformed")
    amount = uint256_of(value)
    if amount is None:
        return Refusal("evm/amount-malformed")
    if not is_address(asset) or not is_address(from_) or not is_address(to):
        return Refusal("evm/field-malformed")
    if not is_uint256(valid_after) or not is_uint256(valid_before):
        return Refusal("evm/field-malformed")
    h = normal_hash(nonce)
    if h is None:
        return Refusal("evm/field-malformed")
    return {
        "domain": {"name": name, "version": version, "chainId": chain_id, "verifyingContract": asset},
        "types": {
            "EIP712Domain": [dict(f) for f in _EIP712_DOMAIN],
            primary_type: [dict(f) for f in _AUTHORIZATION_FIELDS],
        },
        "primaryType": primary_type,
        "message": {
            "from": from_,
            "to": to,
            "value": amount,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": h,
        },
    }


@dataclass(frozen=True, slots=True)
class Witness:
    type: str
    fields: Sequence[Field]
    value: Mapping[str, Any]


def permit2_typed_data(
    chain_id: int,
    permitted: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    spender: object,
    nonce: int,
    deadline: int,
    verifying_contract: object = PERMIT2,
    witness: Witness | None = None,
) -> dict[str, Any] | Refusal:
    """Permit2's typed data under its domain (name "Permit2", no version). No witness gives PermitTransferFrom; a
    witness gives PermitWitnessTransferFrom, or PermitBatchWitnessTransferFrom when permitted is a list."""
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or not 0 < chain_id <= 2**53 - 1:
        return Refusal("evm/network-malformed")
    if not is_address(verifying_contract) or not is_address(spender):
        return Refusal("evm/field-malformed")
    if not is_uint256(nonce) or not is_uint256(deadline):
        return Refusal("evm/field-malformed")
    batch = not isinstance(permitted, Mapping)
    entries: list[Mapping[str, Any]] = [permitted] if isinstance(permitted, Mapping) else list(permitted)
    if not 0 < len(entries) <= 32:
        return Refusal("evm/field-malformed")
    for entry in entries:
        if not isinstance(entry, Mapping) or not is_address(entry.get("token")):
            return Refusal("evm/field-malformed")
        if not is_uint256(entry.get("amount")):
            return Refusal("evm/amount-malformed")
    token_permissions: list[Field] = [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"}]
    domain = {"name": "Permit2", "chainId": chain_id, "verifyingContract": verifying_contract}
    eip712_domain: list[Field] = [
        {"name": "name", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ]
    copied = [{"token": e["token"], "amount": e["amount"]} for e in entries]
    message_permitted: Any = copied if batch else copied[0]
    if witness is None:
        if batch:
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
            "message": {"permitted": message_permitted, "spender": spender, "nonce": nonce, "deadline": deadline},
        }
    if (
        _WITNESS_TYPE_NAME.fullmatch(witness.type) is None
        or witness.type == "TokenPermissions"
        or witness.type.startswith("Permit")
    ):
        return Refusal("evm/field-malformed")
    primary_type = "PermitBatchWitnessTransferFrom" if batch else "PermitWitnessTransferFrom"
    return {
        "domain": domain,
        "types": {
            "EIP712Domain": eip712_domain,
            "TokenPermissions": token_permissions,
            primary_type: [
                {"name": "permitted", "type": "TokenPermissions[]" if batch else "TokenPermissions"},
                {"name": "spender", "type": "address"},
                {"name": "nonce", "type": "uint256"},
                {"name": "deadline", "type": "uint256"},
                {"name": "witness", "type": witness.type},
            ],
            witness.type: [{"name": f["name"], "type": f["type"]} for f in witness.fields],
        },
        "primaryType": primary_type,
        "message": {
            "permitted": message_permitted,
            "spender": spender,
            "nonce": nonce,
            "deadline": deadline,
            "witness": dict(witness.value),
        },
    }


@dataclass(frozen=True, slots=True)
class PaymentInfo:
    """The commerce-payments escrow's PaymentInfo."""

    operator: str
    payer: str
    receiver: str
    token: str
    max_amount: int
    pre_approval_expiry: int
    authorization_expiry: int
    refund_expiry: int
    min_fee_bps: int
    max_fee_bps: int
    fee_receiver: str
    salt: str


def bind_salt(receiver_authorizer: object, policy: object, h: object) -> str | Refusal:
    """keccak256(abi.encode(SALT_BINDING_TYPEHASH, receiverAuthorizer, policy, h))."""
    salt = normal_hash(h)
    if not is_address(receiver_authorizer) or not is_address(policy) or salt is None:
        return Refusal("evm/field-malformed")
    return keccak_hex(
        bytes32_word(SALT_BINDING_TYPEHASH)
        + address_word(receiver_authorizer)
        + address_word(policy)
        + bytes32_word(salt)
    )


def _within(value: object, bits: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 1 << bits


def payment_hash(chain_id: int, escrow: str, p: PaymentInfo) -> str | Refusal:
    """The escrow's getHash: keccak256(abi.encode(chainId, escrow, keccak256(abi.encode(PAYMENT_INFO_TYPEHASH, p)))).
    With payer zero it is x402's signatureNonce."""
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or not 0 < chain_id <= 2**53 - 1:
        return Refusal("evm/field-malformed")
    if not is_address(escrow):
        return Refusal("evm/field-malformed")
    for address in (p.operator, p.payer, p.receiver, p.token, p.fee_receiver):
        if not is_address(address):
            return Refusal("evm/field-malformed")
    if not _within(p.max_amount, 120):
        return Refusal("evm/amount-malformed")
    for expiry in (p.pre_approval_expiry, p.authorization_expiry, p.refund_expiry):
        if not _within(expiry, 48):
            return Refusal("evm/field-malformed")
    for fee in (p.min_fee_bps, p.max_fee_bps):
        if not _within(fee, 16):
            return Refusal("evm/field-malformed")
    salt = normal_hash(p.salt)
    if salt is None:
        return Refusal("evm/field-malformed")
    info = keccak256(
        bytes32_word(PAYMENT_INFO_TYPEHASH)
        + address_word(p.operator)
        + address_word(p.payer)
        + address_word(p.receiver)
        + address_word(p.token)
        + uint_word(p.max_amount)
        + uint_word(p.pre_approval_expiry)
        + uint_word(p.authorization_expiry)
        + uint_word(p.refund_expiry)
        + uint_word(p.min_fee_bps)
        + uint_word(p.max_fee_bps)
        + address_word(p.fee_receiver)
        + bytes32_word(salt)
    )
    return keccak_hex(uint_word(chain_id) + address_word(escrow) + info)


@dataclass(frozen=True, slots=True)
class Caveat:
    enforcer: str
    terms: str
    args: str


@dataclass(frozen=True, slots=True)
class Delegation:
    delegate: str
    delegator: str
    authority: str
    caveats: tuple[Caveat, ...]
    salt: str
    signature: str


def decode_permission_context(ctx: object) -> list[Delegation] | Refusal:
    """Decodes abi.encode(Delegation[]), strictly: every offset and length lies inside the input and is 32-byte
    aligned, address words carry 12 zero bytes, and there are at most 8 delegations, 16 caveats each, and 8 KiB per
    bytes. The list is returned in the input's order, leaf first. An empty array decodes to []."""
    data = bytes_of(ctx, MAX_CONTEXT_BYTES)
    if data is None or len(data) == 0 or len(data) % 32 != 0:
        return Refusal("evm/field-malformed")
    out = _Delegations(data).read()
    return out if out is not None else Refusal("evm/field-malformed")


class _Delegations:
    def __init__(self, data: bytes) -> None:
        self.b = data

    def word(self, pos: int) -> bytes | None:
        if pos % 32 != 0 or pos < 0 or pos + 32 > len(self.b):
            return None
        return self.b[pos : pos + 32]

    def num(self, pos: int) -> int | None:
        w = self.word(pos)
        if w is None:
            return None
        value = int.from_bytes(w, "big")
        return value if value < len(self.b) else None

    def offset(self, base: int, pos: int) -> int | None:
        o = self.num(pos)
        if o is None or o % 32 != 0:
            return None
        at = base + o
        return at if at < len(self.b) else None

    def address(self, pos: int) -> str | None:
        w = self.word(pos)
        return None if w is None else address_of_word(w)

    def bytes_at(self, at: int | None) -> str | None:
        if at is None:
            return None
        length = self.num(at)
        if length is None or length > MAX_ABI_BYTES:
            return None
        end = at + 32 + length
        if end > len(self.b):
            return None
        return hex_of(self.b[at + 32 : end])

    def read(self) -> list[Delegation] | None:
        array = self.offset(0, 0)
        if array is None:
            return None
        count = self.num(array)
        if count is None or count > MAX_DELEGATIONS:
            return None
        heads = array + 32
        out: list[Delegation] = []
        for i in range(count):
            t = self.offset(heads, heads + 32 * i)
            if t is None:
                return None
            delegate = self.address(t)
            delegator = self.address(t + 32)
            authority = self.word(t + 64)
            caveats_at = self.offset(t, t + 96)
            salt = self.word(t + 128)
            signature = self.bytes_at(self.offset(t, t + 160))
            if delegate is None or delegator is None or authority is None:
                return None
            if caveats_at is None or salt is None or signature is None:
                return None
            n = self.num(caveats_at)
            if n is None or n > MAX_CAVEATS:
                return None
            caveats: list[Caveat] = []
            for j in range(n):
                c = self.offset(caveats_at + 32, caveats_at + 32 + 32 * j)
                if c is None:
                    return None
                enforcer = self.address(c)
                terms = self.bytes_at(self.offset(c, c + 32))
                args = self.bytes_at(self.offset(c, c + 64))
                if enforcer is None or terms is None or args is None:
                    return None
                caveats.append(Caveat(enforcer, terms, args))
            out.append(Delegation(delegate, delegator, hex_of(authority), tuple(caveats), hex_of(salt), signature))
        return out


def is_reference_manager(manager: object, network: object) -> bool:
    """True for MetaMask's reference DelegationManager on a chain where it is deployed."""
    chain_id = chain_id_of(network)
    return (
        isinstance(manager, str)
        and manager.lower() == DELEGATION_MANAGER.lower()
        and chain_id is not None
        and chain_id in DELEGATION_MANAGER_CHAINS
    )


def as_hash(value: AtrHash) -> int:
    """A 32-byte hash as a uint256."""
    return int(value[2:], 16)
