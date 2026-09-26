"""The SCALE subset the Substrate bindings read and write: Compact<uN> in its shortest mode."""


def compact(v: int) -> bytes:
    """SCALE Compact<uN> of a non-negative integer, in its shortest mode."""
    if v < 1 << 6:
        return bytes([v << 2])
    if v < 1 << 14:
        return ((v << 2) | 1).to_bytes(2, "little")
    if v < 1 << 30:
        return ((v << 2) | 2).to_bytes(4, "little")
    body = v.to_bytes((v.bit_length() + 7) // 8, "little")
    return bytes([((len(body) - 4) << 2) | 3]) + body


def compact_at(b: bytes, at: int) -> tuple[int, int] | None:
    """A canonical Compact<uN> at index at: the value and the index after it, or None. At most 17 value bytes are
    read."""
    if at < 0 or at >= len(b):
        return None
    first = b[at]
    mode = first & 3
    if mode == 0:
        value, nxt = first >> 2, at + 1
    elif mode in (1, 2):
        size = 2 if mode == 1 else 4
        if at + size > len(b):
            return None
        value, nxt = int.from_bytes(b[at : at + size], "little") >> 2, at + size
    else:
        size = (first >> 2) + 4
        if size > 17 or at + 1 + size > len(b):
            return None
        value, nxt = int.from_bytes(b[at + 1 : at + 1 + size], "little"), at + 1 + size
    return (value, nxt) if compact(value) == b[at:nxt] else None
