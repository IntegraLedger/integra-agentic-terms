"""SHA-256 of an ATR's bytes, hash equality by decoded bytes, and the agreement's own value for a hash."""

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


# The agreement tag: the 16 ASCII bytes lcp-agreement-v1.
AGREEMENT_TAG = b"lcp-agreement-v1"


def agreement_value(h: AtrHash) -> AtrHash:
    """The agreement's own value for H: SHA-256 over the 16 ASCII bytes lcp-agreement-v1 followed by H's 32 bytes, as 0x
    and lowercase hex. On a pairing whose single-use value is H itself or H's low bits, an agreement carries this value,
    or its low bits as the pairing takes H's, where a payment carries H, so the two acts under one H never share a
    single-use value. Raises TypeError when h is not a 32-byte hash."""
    if not is_hash(h):
        raise TypeError("not a 32-byte hash")
    return "0x" + hashlib.sha256(AGREEMENT_TAG + bytes.fromhex(h[2:])).hexdigest()
