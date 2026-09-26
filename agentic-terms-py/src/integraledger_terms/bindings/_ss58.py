"""SS58 addresses in the simple format: one prefix byte 0-63, a 32-byte account, and a two-byte BLAKE2b-512
checksum over "SS58PRE" and the first 33 bytes."""

import hashlib

from ._codec import b58_decode

_SS58_PREFIX = b"SS58PRE"


def ss58_decode(address: object) -> bytes | None:
    """The 32-byte account of a simple-format SS58 address, or None."""
    if not isinstance(address, str) or len(address) > 64:
        return None
    raw = b58_decode(address)
    if raw is None or len(raw) != 35 or raw[0] > 63:
        return None
    checksum = hashlib.blake2b(_SS58_PREFIX + raw[:33], digest_size=64).digest()
    if checksum[:2] != raw[33:35]:
        return None
    return raw[1:33]
