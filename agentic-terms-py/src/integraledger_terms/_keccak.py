"""Keccak-256: the Keccak-f[1600] permutation (FIPS 202 §3) with rate 1088 bits and the original Keccak padding
(0x01 ... 0x80), which differs from SHA3-256's (0x06 ... 0x80)."""

_MASK = (1 << 64) - 1
_RATE = 136

_ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)  # fmt: skip

# The rotation offset of lane (x, y), indexed x + 5 * y.
_ROTATIONS = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)  # fmt: skip


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _permute(state: list[int]) -> None:
    """Keccak-f[1600] over 25 lanes, lane (x, y) at index x + 5 * y."""
    for constant in _ROUND_CONSTANTS:
        parity = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        for x in range(5):
            d = parity[(x - 1) % 5] ^ _rotl(parity[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                state[x + y] ^= d
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _ROTATIONS[x + 5 * y])
        for y in range(0, 25, 5):
            row = moved[y : y + 5]
            for x in range(5):
                state[x + y] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5])
        state[0] ^= constant


def keccak256(data: bytes) -> bytes:
    """The 32-byte Keccak-256 digest of data."""
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\0" * (-len(padded) % _RATE))
    padded[-1] |= 0x80
    state = [0] * 25
    for start in range(0, len(padded), _RATE):
        block = padded[start : start + _RATE]
        for i in range(_RATE // 8):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        _permute(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))
