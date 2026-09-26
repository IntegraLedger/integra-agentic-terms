"""Recursive-length prefix (RLP) encoding, strict and bounded. The decoder accepts only the canonical form: a single
byte below 0x80 stands for itself, a length uses the short form whenever it fits, and a long length has no leading
zero. Every decoded item keeps raw, its exact encoded bytes."""

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class RlpItem:
    """A byte string (items None) or a list (items set), with its exact encoded bytes."""

    raw: bytes
    data: bytes = b""
    items: list["RlpItem"] | None = field(default=None)

    @property
    def is_list(self) -> bool:
        return self.items is not None


def rlp_decode(data: bytes, max_depth: int) -> RlpItem | None:
    """The one item that spans all of data, the outermost list at depth 0, no list deeper than max_depth; None for
    anything that is not canonical RLP within that depth."""
    at = [0]
    item = _read(data, at, len(data), 0, max_depth)
    return item if item is not None and at[0] == len(data) else None


def _read(b: bytes, at: list[int], end: int, depth: int, max_depth: int) -> RlpItem | None:
    start = at[0]
    if start >= end:
        return None
    p = b[start]
    if p < 0x80:
        at[0] = start + 1
        return RlpItem(raw=b[start : start + 1], data=b[start : start + 1])
    if p <= 0xB7 or 0xC0 <= p <= 0xF7:
        length = p - 0x80 if p <= 0xB7 else p - 0xC0
        head = 1
    else:
        len_of_len = p - 0xB7 if p <= 0xBF else p - 0xF7
        if start + 1 + len_of_len > end or b[start + 1] == 0:
            return None
        length = 0
        for i in range(len_of_len):
            length = length * 256 + b[start + 1 + i]
            if length > end:
                return None
        if length <= 55:
            return None
        head = 1 + len_of_len
    body_start = start + head
    body_end = body_start + length
    if body_end > end:
        return None
    raw = b[start:body_end]
    if p < 0xC0:
        if length == 1 and b[body_start] < 0x80:
            return None
        at[0] = body_end
        return RlpItem(raw=raw, data=b[body_start:body_end])
    if depth > max_depth:
        return None
    items: list[RlpItem] = []
    at[0] = body_start
    while at[0] < body_end:
        item = _read(b, at, body_end, depth + 1, max_depth)
        if item is None:
            return None
        items.append(item)
    return RlpItem(raw=raw, items=items)


def rlp_uint(item: RlpItem | None) -> int | None:
    """The unsigned integer in a canonical RLP byte string (no leading zero; empty is zero), up to 32 bytes."""
    if item is None or item.is_list or len(item.data) > 32:
        return None
    if item.data and item.data[0] == 0:
        return None
    return int.from_bytes(item.data, "big")


def _prefix(base: int, length: int) -> bytes:
    if length <= 55:
        return bytes([base + length])
    size = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(size)]) + size


def rlp_bytes(b: bytes) -> bytes:
    """The encoding of a byte string."""
    if len(b) == 1 and b[0] < 0x80:
        return bytes(b)
    return _prefix(0x80, len(b)) + b


def rlp_uint_bytes(v: int) -> bytes:
    """The encoding of an unsigned integer: its big-endian bytes without leading zeros."""
    return rlp_bytes(v.to_bytes((v.bit_length() + 7) // 8, "big") if v > 0 else b"")


def rlp_list(encoded_items: list[bytes]) -> bytes:
    """The encoding of a list whose items are already encoded."""
    body = b"".join(encoded_items)
    return _prefix(0xC0, len(body)) + body
