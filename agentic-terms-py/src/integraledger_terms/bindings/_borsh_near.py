"""Borsh for NEP-366: a DelegateAction and a SignedDelegate, read and written, with the NEAR action, public-key and
signature enums. Integers are little-endian; a string or a byte vector is a u32 length and its bytes, strings read
byte for byte; an enum is a u8 index and its variant; an option is a u8 0 or 1."""

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

from ._codec import b58_decode, b58_encode

# The NEP-461 prefix for a delegate action: (1 << 30) + 366.
NEP461_DELEGATE = 1073742190
U64_LIMIT = 1 << 64
U128_LIMIT = 1 << 128

_KEY_TYPES = {"ed25519": 0, "secp256k1": 1}
_KEY_SIZES = (32, 64)
_SIGNATURE_SIZES = (64, 65)


@dataclass(frozen=True, slots=True)
class PublicKey:
    key_type: int
    data: bytes

    def text(self) -> str:
        return ("ed25519:" if self.key_type == 0 else "secp256k1:") + b58_encode(self.data)


def public_key_of(encoded: object) -> PublicKey | None:
    """<curve>:<base58> or <base58>. With no curve, or with ed25519, a 64-byte key is secp256k1 and any other is
    ed25519; the key must then be 32 or 64 bytes as its type says. None for anything else."""
    if not isinstance(encoded, str):
        return None
    parts = encoded.split(":")
    if len(parts) == 1:
        text, key_type = parts[0], 0
    elif len(parts) == 2:
        named = _KEY_TYPES.get(parts[0].lower())
        if named is None:
            return None
        text, key_type = parts[1], named
    else:
        return None
    data = b58_decode(text)
    if data is None:
        return None
    if key_type == 0:
        key_type = 1 if len(data) == _KEY_SIZES[1] else 0
    return PublicKey(key_type, data) if len(data) == _KEY_SIZES[key_type] else None


@dataclass(frozen=True, slots=True)
class FunctionCall:
    method_name: str
    args: bytes
    gas: int
    deposit: int


@dataclass(frozen=True, slots=True)
class DelegateAction:
    sender_id: str
    receiver_id: str
    # Each action as (enum index, value); a FunctionCall's value is a FunctionCall.
    actions: tuple[tuple[int, Any], ...]
    nonce: int
    max_block_height: int
    public_key: PublicKey


# ── write ─────────────────────────────────────────────────────────────────────────────────────────────────────────


def _u32(v: int) -> bytes:
    return struct.pack("<I", v)


def _u64(v: int) -> bytes:
    return v.to_bytes(8, "little")


def _u128(v: int) -> bytes:
    return v.to_bytes(16, "little")


def _bytes(b: bytes) -> bytes:
    return _u32(len(b)) + b


def _string(s: str) -> bytes:
    return _bytes(s.encode("latin-1"))


def _function_call(call: FunctionCall) -> bytes:
    return _string(call.method_name) + _bytes(call.args) + _u64(call.gas) + _u128(call.deposit)


def encode_delegate_action(da: DelegateAction) -> bytes:
    """Borsh of a DelegateAction whose actions are FunctionCalls."""
    actions = b"".join(bytes([index]) + _function_call(value) for index, value in da.actions)
    return (
        _string(da.sender_id)
        + _string(da.receiver_id)
        + _u32(len(da.actions))
        + actions
        + _u64(da.nonce)
        + _u64(da.max_block_height)
        + bytes([da.public_key.key_type])
        + da.public_key.data
    )


def delegate_hash(da: DelegateAction) -> bytes:
    """SHA-256 of the NEP-461 prefix (u32) and the DelegateAction: what the key signs."""
    return hashlib.sha256(_u32(NEP461_DELEGATE) + encode_delegate_action(da)).digest()


def encode_signed_delegate(da: DelegateAction, key_type: int, signature: bytes) -> bytes:
    return encode_delegate_action(da) + bytes([key_type]) + signature


# ── read ──────────────────────────────────────────────────────────────────────────────────────────────────────────


class _Malformed(Exception):
    """The bytes are not the borsh of the schema read."""


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise _Malformed
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def u128(self) -> int:
        return int.from_bytes(self.take(16), "little")

    def vec(self) -> bytes:
        return self.take(self.u32())

    def string(self) -> str:
        return self.vec().decode("latin-1")

    def enum(self, size: int) -> int:
        index = self.u8()
        if index >= size:
            raise _Malformed
        return index

    def public_key(self) -> PublicKey:
        key_type = self.enum(2)
        return PublicKey(key_type, self.take(_KEY_SIZES[key_type]))

    def option_u128(self) -> None:
        flag = self.u8()
        if flag == 1:
            self.u128()
        elif flag != 0:
            raise _Malformed

    def access_key(self) -> None:
        self.u64()
        if self.enum(2) == 0:
            self.option_u128()
            self.string()
            for _ in range(self.u32()):
                self.string()

    def action(self) -> tuple[int, Any]:
        """One of NEAR's eleven action variants; only a FunctionCall's value is kept."""
        index = self.enum(11)
        if index == 1:
            self.vec()
        elif index == 2:
            return index, FunctionCall(self.string(), self.vec(), self.u64(), self.u128())
        elif index == 3:
            self.u128()
        elif index == 4:
            self.u128()
            self.public_key()
        elif index == 5:
            self.public_key()
            self.access_key()
        elif index == 6:
            self.public_key()
        elif index in (7, 8):
            self.string()
        elif index == 9:
            self.vec()
            self.enum(2)
        elif index == 10:
            if self.enum(2) == 0:
                self.take(32)
            else:
                self.string()
        return index, None


def decode_signed_delegate(data: bytes) -> tuple[DelegateAction, int, bytes] | None:
    """The DelegateAction, the signature's key type and bytes of a SignedDelegate that is exactly its borsh; None
    otherwise. Every action takes at least one byte, so the actions read are bounded by the bytes given."""
    r = _Reader(data)
    try:
        sender_id = r.string()
        receiver_id = r.string()
        actions = tuple(r.action() for _ in range(r.u32()))
        nonce = r.u64()
        max_block_height = r.u64()
        public_key = r.public_key()
        key_type = r.enum(2)
        signature = r.take(_SIGNATURE_SIZES[key_type])
    except _Malformed:
        return None
    if r.at != len(data):
        return None
    return DelegateAction(sender_id, receiver_id, actions, nonce, max_block_height, public_key), key_type, signature
