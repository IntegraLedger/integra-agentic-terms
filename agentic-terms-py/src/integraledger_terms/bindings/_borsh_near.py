"""Borsh for NEP-366's DelegateAction and SignedDelegate, as nearcore defines them, for the one shape the NEAR pairing
reads and writes: a delegate action holding one FunctionCall action, under an Ed25519 or secp256k1 key, with a signature
of either type; and the NEAR account id rule its sender and receiver are read by. Integers are little-endian; a byte
vector is a u32 length and its bytes, and a string is the same with its bytes strict UTF-8, as borsh writes a String;
an enum is a u8 index and its variant. A Vec<Action> of one action is its u32 length 1, then the action's u8 variant
index, FunctionCall's 2, then the FunctionCall."""

import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Literal, TypeGuard

from ._codec import b58_decode, b58_encode

# The NEP-461 prefix for a delegate action: (1 << 30) + 366.
NEP461_DELEGATE = 1073742190
U64_LIMIT = 1 << 64
U128_LIMIT = 1 << 128

_KEY_TYPES = {"ed25519": 0, "secp256k1": 1}
_KEY_SIZES = (32, 64)
_SIGNATURE_SIZES = (64, 65)
_FUNCTION_CALL = 2
_ACCOUNT_ID_LENGTH = (2, 64)
_SEPARATORS = ("-", "_", ".")
_ASCII_LOWERCASE = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
# Base58 of 64 bytes is at most 88 characters, and a longer text always decodes to more.
_BASE58_KEY = re.compile(r"[1-9A-HJ-NP-Za-km-z]{1,88}")


@dataclass(frozen=True, slots=True)
class PublicKey:
    key_type: int
    data: bytes

    def text(self) -> str:
        return ("ed25519:" if self.key_type == 0 else "secp256k1:") + b58_encode(self.data)


def public_key_of(encoded: object) -> PublicKey | None:
    """A public key as nearcore's PublicKey::from_str reads it (core/crypto/src/signature.rs): the key type before the
    first ':', ed25519 or secp256k1, matched once its ASCII letters are lowercased (to_ascii_lowercase, so a letter
    outside ASCII matches none), or no ':', which is Ed25519; then the base58 of exactly that type's key size, 32 bytes
    or 64. None for anything else."""
    if not isinstance(encoded, str):
        return None
    named, colon, text = encoded.partition(":")
    if not colon:
        named, text = "ed25519", encoded
    key_type = _KEY_TYPES.get(named.translate(_ASCII_LOWERCASE))
    if key_type is None or _BASE58_KEY.fullmatch(text) is None:
        return None
    data = b58_decode(text)
    return PublicKey(key_type, data) if data is not None and len(data) == _KEY_SIZES[key_type] else None


def is_near_account_id(value: object) -> TypeGuard[str]:
    """True for a NEAR account id: what near-account-id 3.0.0, the version nearcore locks, reads as an AccountId
    (src/validation.rs: validate, MIN_LEN and MAX_LEN). Its borsh reader, through which nearcore reads a delegate
    action's sender and receiver, and its serde reader, through which a NEP-141 contract reads ft_transfer's
    receiver_id, each refuse any other string. An id is 2 to 64 characters, each a lowercase ASCII letter, a digit,
    '-', '_' or '.'; a separator ('-', '_' or '.') is never first, never last, and never follows another. The length
    bounds count bytes, and every character an id may hold is one byte, so counting characters gives the same answer.
    The typed forms the crate names (64 lowercase hex digits, or 0x, 0s or 0u and lowercase hex or base32 digits) are
    kinds of ids that meet these rules, and none changes which strings are ids."""
    if not isinstance(value, str) or not _ACCOUNT_ID_LENGTH[0] <= len(value) <= _ACCOUNT_ID_LENGTH[1]:
        return False
    after_separator = True
    for c in value:
        separator = c in _SEPARATORS
        if not separator and not ("a" <= c <= "z" or "0" <= c <= "9"):
            return False
        if separator and after_separator:
            return False
        after_separator = separator
    return not after_separator


@dataclass(frozen=True, slots=True)
class FunctionCall:
    method_name: str
    args: bytes
    gas: int
    deposit: int


@dataclass(frozen=True, slots=True)
class DelegateAction:
    """A delegate action holding one FunctionCall action."""

    sender_id: str
    receiver_id: str
    function_call: FunctionCall
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
    return _bytes(s.encode("utf-8"))


def _function_call(call: FunctionCall) -> bytes:
    return _string(call.method_name) + _bytes(call.args) + _u64(call.gas) + _u128(call.deposit)


def encode_delegate_action(da: DelegateAction) -> bytes:
    """Borsh of a DelegateAction whose one action is its FunctionCall."""
    return (
        _string(da.sender_id)
        + _string(da.receiver_id)
        + _u32(1)
        + bytes([_FUNCTION_CALL])
        + _function_call(da.function_call)
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
        try:
            return self.vec().decode("utf-8")
        except UnicodeDecodeError:
            raise _Malformed from None

    def enum(self, size: int) -> int:
        index = self.u8()
        if index >= size:
            raise _Malformed
        return index

    def public_key(self) -> PublicKey:
        key_type = self.enum(2)
        return PublicKey(key_type, self.take(_KEY_SIZES[key_type]))


DelegateRefused = Literal["malformed", "action-count", "not-function-call"]


def is_near_ed25519_signature(data: bytes) -> bool:
    """True when nearcore reads these bytes as an Ed25519 signature: 64 bytes whose last byte is below 0x20, the top
    three bits clear (core/crypto/src/signature.rs, Signature's borsh reader). The last 32 bytes are S, little-endian,
    and a valid signature's S is below the group order, under 2^253, so every valid signature is read."""
    return len(data) == _SIGNATURE_SIZES[0] and data[-1] < 0x20


def decode_signed_delegate(data: bytes) -> tuple[DelegateAction, int, bytes] | DelegateRefused:
    """The DelegateAction, the signature's key type and bytes of a SignedDelegate, read in the order nearcore reads its
    bytes. The sender and the receiver come first, each strict UTF-8 and a NEAR account id (is_near_account_id), as
    nearcore's AccountId reader requires, or the bytes are "malformed". Then a count of actions other than one is
    "action-count", and a first action whose variant index is not FunctionCall's is "not-function-call", the bytes
    after it unread. Otherwise the bytes must be exactly the borsh of the one-action delegate and its signature, each
    key and signature Ed25519 or secp256k1, and an Ed25519 signature one nearcore reads, or they are "malformed"."""
    r = _Reader(data)
    try:
        sender_id = r.string()
        receiver_id = r.string()
        if not is_near_account_id(sender_id) or not is_near_account_id(receiver_id):
            return "malformed"
        if r.u32() != 1:
            return "action-count"
        if r.u8() != _FUNCTION_CALL:
            return "not-function-call"
        call = FunctionCall(r.string(), r.vec(), r.u64(), r.u128())
        nonce = r.u64()
        max_block_height = r.u64()
        public_key = r.public_key()
        key_type = r.enum(2)
        signature = r.take(_SIGNATURE_SIZES[key_type])
    except _Malformed:
        return "malformed"
    if r.at != len(data) or (key_type == 0 and not is_near_ed25519_signature(signature)):
        return "malformed"
    return DelegateAction(sender_id, receiver_id, call, nonce, max_block_height, public_key), key_type, signature
