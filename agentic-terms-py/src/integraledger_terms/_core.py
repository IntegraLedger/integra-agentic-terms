"""SHA-256 of an ATR's bytes, and hash equality by decoded bytes."""

import hashlib
import re

AtrHash = str

MAX_ATR_BYTES: int = 1_048_576

_HASH = re.compile(r"0x[0-9a-fA-F]{64}")


def atr_hash(data: bytes) -> AtrHash:
    """SHA-256 over the bytes exactly as given, written 0x plus 64 lower-case hex digits."""
    return "0x" + hashlib.sha256(data).hexdigest()


def is_hash(value: object) -> bool:
    """True for 0x followed by 64 hex digits in either case."""
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def hash_equals(a: str, b: str) -> bool:
    """Decodes both values to 32 bytes and compares the bytes; False when either is malformed."""
    if not is_hash(a) or not is_hash(b):
        return False
    return bytes.fromhex(a[2:]) == bytes.fromhex(b[2:])
