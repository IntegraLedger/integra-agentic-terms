"""The TON cell layer: cells with their level, hashes and depths, a bit builder and a slice, bags of cells read and
written with CRC-32C, and the check that a HashmapE parses. An exotic cell is held as the bag gives it, and a slice of
one is Malformed, so each read refuses one where it parses it."""

import hashlib
import math
from collections.abc import Callable
from dataclasses import dataclass, field

MAX_BITS = 1023
MAX_REFS = 4

_BOC_MAGIC = 0xB5EE9C72
_BOC_MAGIC_IDX = 0x68FF65F3
_BOC_MAGIC_IDX_CRC = 0xACC3A728


class Malformed(Exception):
    """The bytes or the bits are not what is read from them."""


# ── CRC-32C ───────────────────────────────────────────────────────────────────────────────────────────────────────

_CASTAGNOLI = 0x82F63B78


def _crc_table() -> tuple[int, ...]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ _CASTAGNOLI if c & 1 else c >> 1
        table.append(c)
    return tuple(table)


_CRC_TABLE = _crc_table()


def crc32c(data: bytes) -> bytes:
    """CRC-32C (Castagnoli, RFC 3720 §B.4): reflected polynomial 0x82F63B78, initial and final value 0xFFFFFFFF,
    written little-endian."""
    crc = 0xFFFFFFFF
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF).to_bytes(4, "little")


# ── cells ─────────────────────────────────────────────────────────────────────────────────────────────────────────


def padded(value: int, length: int) -> bytes:
    """The bits, most significant first, as bytes; a length that is not a whole number of bytes is completed with a
    1 bit and then zeros."""
    rest = length % 8
    if rest:
        value = (value << (8 - rest)) | (1 << (7 - rest))
    return value.to_bytes(math.ceil(length / 8), "big") if length else b""


_PRUNED_BRANCH, _LIBRARY, _MERKLE_PROOF, _MERKLE_UPDATE = 1, 2, 3, 4


def _below(mask: int, level: int) -> int:
    """The level mask's bits below level."""
    return mask & ((1 << level) - 1)


def _hash_index(mask: int) -> int:
    return bin(mask).count("1")


@dataclass(frozen=True, slots=True, eq=False)
class Cell:
    """A cell: up to 1023 bits (value, most significant first, and length) and up to four references. An exotic cell
    is TVM's pruned branch, library, Merkle proof or Merkle update, its type in its first 8 bits, read as @ton/core
    reads one; one that is not in its type's form is Malformed. The level mask, and the hashes and depths at levels 0
    to 3, follow TVM's cell rules (ton-blockchain/ton crypto/vm/cells/DataCell.cpp); hash and depth are the
    representation's, at level 3."""

    value: int
    length: int
    refs: tuple["Cell", ...] = ()
    exotic: bool = False
    hash: bytes = field(init=False)
    depth: int = field(init=False)
    level_mask: int = field(init=False)
    hashes: tuple[bytes, ...] = field(init=False)
    depths: tuple[int, ...] = field(init=False)

    def __post_init__(self) -> None:
        if not 0 <= self.length or not 0 <= self.value < (1 << self.length):
            raise Malformed
        kind = 0
        pruned: list[tuple[bytes, int]] = []
        if not self.exotic:
            if self.length > MAX_BITS or len(self.refs) > MAX_REFS:
                raise Malformed
            mask = 0
            for r in self.refs:
                mask |= r.level_mask
        else:
            if self.length < 8:
                raise Malformed
            kind = self.value >> (self.length - 8)
            mask = self._exotic_mask(kind, pruned)
        merkle = kind in (_MERKLE_PROOF, _MERKLE_UPDATE)
        # A pruned branch computes only its own level's hash; its lower levels' hashes and depths are its data.
        offset = _hash_index(mask) if kind == _PRUNED_BRANCH else 0
        hashes: list[bytes] = []
        depths: list[int] = []
        hash_i = 0
        for level in range(mask.bit_length() + 1):
            if level != 0 and not (mask >> (level - 1)) & 1:
                continue
            if hash_i < offset:
                hash_i += 1
                continue
            data = padded(self.value, self.length) if hash_i == offset else hashes[hash_i - offset - 1]
            child = min(level + 1, 3) if merkle else level
            depth = max((r.depths[child] for r in self.refs), default=-1) + 1
            d1 = len(self.refs) + (8 if self.exotic else 0) + 32 * _below(mask, level)
            repr_ = bytes([d1, self.descriptor2()]) + data
            repr_ += b"".join(r.depths[child].to_bytes(2, "big") for r in self.refs)
            repr_ += b"".join(r.hashes[child] for r in self.refs)
            hashes.append(hashlib.sha256(repr_).digest())
            depths.append(depth)
            hash_i += 1
        at = [_hash_index(_below(mask, level)) for level in range(4)]
        if kind == _PRUNED_BRANCH:
            own = _hash_index(mask)
            by_level = [pruned[i] if i != own else (hashes[0], depths[0]) for i in at]
        else:
            by_level = [(hashes[i], depths[i]) for i in at]
        object.__setattr__(self, "level_mask", mask)
        object.__setattr__(self, "hashes", tuple(h for h, _ in by_level))
        object.__setattr__(self, "depths", tuple(d for _, d in by_level))
        object.__setattr__(self, "hash", by_level[3][0])
        object.__setattr__(self, "depth", by_level[3][1])

    def _exotic_mask(self, kind: int, pruned: list[tuple[bytes, int]]) -> int:
        """The level mask of an exotic cell in its type's form, after checking that form; a pruned branch's hashes and
        depths are appended to pruned. Malformed for any other form or type."""
        bits, refs = self.length, self.refs
        if kind == _PRUNED_BRANCH:
            if refs:
                raise Malformed
            if bits == 8 + 256 + 16:
                mask, at = 1, 8
            else:
                mask, at = (self.value >> (bits - 16)) & 0xFF, 16
                level = mask.bit_length()
                if not 1 <= level <= 3 or bits != 16 + (_hash_index(_below(mask, level - 1)) + 1) * (256 + 16):
                    raise Malformed
            level = mask.bit_length()
            if at + level * (256 + 16) > bits:
                raise Malformed
            rest = self.value & ((1 << (bits - at)) - 1)
            body = (rest >> (bits - at - level * (256 + 16))).to_bytes(level * (32 + 2), "big")
            for i in range(level):
                at_depth = 32 * level + 2 * i
                pruned.append((body[32 * i : 32 * i + 32], int.from_bytes(body[at_depth : at_depth + 2], "big")))
            return mask
        if kind == _LIBRARY:
            if bits != 8 + 256:
                raise Malformed
            return 0
        if kind == _MERKLE_PROOF:
            if bits != 8 + 256 + 16 or len(refs) != 1:
                raise Malformed
            body = padded(self.value, bits)
            if body[1:33] != refs[0].hashes[0] or int.from_bytes(body[33:35], "big") != refs[0].depths[0]:
                raise Malformed
            return refs[0].level_mask >> 1
        if kind == _MERKLE_UPDATE:
            if bits != 8 + 2 * (256 + 16) or len(refs) != 2:
                raise Malformed
            body = padded(self.value, bits)
            for i, r in enumerate(refs):
                depth = int.from_bytes(body[65 + 2 * i : 67 + 2 * i], "big")
                if body[1 + 32 * i : 33 + 32 * i] != r.hashes[0] or depth != r.depths[0]:
                    raise Malformed
            return (refs[0].level_mask | refs[1].level_mask) >> 1
        raise Malformed

    def descriptor1(self) -> int:
        return len(self.refs) + (8 if self.exotic else 0) + 32 * self.level_mask

    def descriptor2(self) -> int:
        return math.ceil(self.length / 8) + self.length // 8

    def equals(self, other: "Cell") -> bool:
        return self.hash == other.hash

    def slice(self) -> "Slice":
        """A slice of an ordinary cell; an exotic cell is not parsed (Malformed)."""
        if self.exotic:
            raise Malformed
        return Slice(self)


EMPTY = Cell(0, 0)


class Builder:
    def __init__(self) -> None:
        self.value = 0
        self.length = 0
        self.refs: list[Cell] = []

    def uint(self, v: int, bits: int) -> "Builder":
        if not 0 <= v < (1 << bits):
            raise ValueError("value out of range")
        self.value = (self.value << bits) | v
        self.length += bits
        return self

    def sint(self, v: int, bits: int) -> "Builder":
        if not -(1 << (bits - 1)) <= v < (1 << (bits - 1)):
            raise ValueError("value out of range")
        return self.uint(v % (1 << bits), bits)

    def bit(self, b: bool | int) -> "Builder":
        return self.uint(1 if b else 0, 1)

    def buf(self, data: bytes) -> "Builder":
        return self.uint(int.from_bytes(data, "big"), 8 * len(data))

    def coins(self, v: int) -> "Builder":
        """VarUInteger 16: the byte length in 4 bits, then the value."""
        if v < 0:
            raise ValueError("negative")
        size = math.ceil(v.bit_length() / 8)
        self.uint(size, 4)
        return self.uint(v, 8 * size)

    def ref(self, c: Cell) -> "Builder":
        if len(self.refs) >= MAX_REFS:
            raise ValueError("too many references")
        self.refs.append(c)
        return self

    def maybe_ref(self, c: Cell | None) -> "Builder":
        return self.bit(0) if c is None else self.bit(1).ref(c)

    def slice(self, s: "Slice") -> "Builder":
        """The slice's remaining bits and references."""
        rest = s.as_cell()
        self.uint(rest.value, rest.length)
        for r in rest.refs:
            self.ref(r)
        return self

    def end(self) -> Cell:
        if self.length > MAX_BITS:
            raise ValueError("bits overflow")
        return Cell(self.value, self.length, tuple(self.refs))


class Slice:
    def __init__(self, cell: Cell) -> None:
        self.cell = cell
        self.at = 0
        self.ref_at = 0

    @property
    def remaining_bits(self) -> int:
        return self.cell.length - self.at

    @property
    def remaining_refs(self) -> int:
        return len(self.cell.refs) - self.ref_at

    def preload_uint(self, bits: int, offset: int = 0) -> int:
        start = self.at + offset
        if bits < 0 or start + bits > self.cell.length:
            raise Malformed
        return (self.cell.value >> (self.cell.length - start - bits)) & ((1 << bits) - 1)

    def uint(self, bits: int) -> int:
        v = self.preload_uint(bits)
        self.at += bits
        return v

    def sint(self, bits: int) -> int:
        v = self.uint(bits)
        return v - (1 << bits) if bits and v >> (bits - 1) else v

    def bit(self) -> bool:
        return self.uint(1) == 1

    def buf(self, n: int) -> bytes:
        return self.uint(8 * n).to_bytes(n, "big")

    def coins(self) -> int:
        return self.uint(8 * self.uint(4))

    def ref(self) -> Cell:
        if self.ref_at >= len(self.cell.refs):
            raise Malformed
        self.ref_at += 1
        return self.cell.refs[self.ref_at - 1]

    def maybe_ref(self) -> Cell | None:
        return self.ref() if self.bit() else None

    def as_cell(self) -> Cell:
        """The remaining bits and references as a cell."""
        rest = self.remaining_bits
        return Cell(self.cell.value & ((1 << rest) - 1), rest, self.cell.refs[self.ref_at :])


# ── HashmapE ──────────────────────────────────────────────────────────────────────────────────────────────────────


def _label_length_bits(n: int) -> int:
    return math.ceil(math.log2(n + 1))


def _hashmap(s: Slice, n: int, value: Callable[[Slice], object]) -> None:
    """Parses one Hashmap node of key length n: its label (hml_short, hml_long or hml_same), then the value at a
    leaf or the two children at a fork, each child that is an ordinary cell. A label longer than the key is
    malformed."""
    if not s.bit():
        length = 0
        while s.bit():
            length += 1
        s.uint(length)
    elif not s.bit():
        length = s.uint(_label_length_bits(n))
        s.uint(length)
    else:
        s.bit()
        length = s.uint(_label_length_bits(n))
    if length > n:
        raise Malformed
    if n - length == 0:
        value(s)
        return
    for child in (s.ref(), s.ref()):
        if not child.exotic:
            _hashmap(child.slice(), n - length - 1, value)


def load_dict(s: Slice, key_bits: int, value: Callable[[Slice], object]) -> Cell | None:
    """A HashmapE: the root reference when one is present, after checking that the map's ordinary cells parse. An
    exotic cell in the map is not parsed, as @ton/core's Dictionary reads one."""
    root = s.maybe_ref()
    if root is not None and not root.exotic:
        _hashmap(root.slice(), key_bits, value)
    return root


# ── bags of cells ─────────────────────────────────────────────────────────────────────────────────────────────────


class _Bytes:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise Malformed
        self.at += n
        return self.data[self.at - n : self.at]

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")


def _hashes_count(level_mask: int) -> int:
    return bin(level_mask & 7).count("1") + 1


def parse_boc(src: bytes) -> list[Cell]:
    """The root cells of a bag of cells in any of its three magics, an exotic cell among them as an exotic Cell. Raises
    Malformed for anything else, for a failed CRC-32C, and for a cell that is not in its type's form."""
    r = _Bytes(src)
    magic = r.uint(4)
    if magic in (_BOC_MAGIC_IDX, _BOC_MAGIC_IDX_CRC):
        size, off_bytes = r.uint(1), r.uint(1)
        cells, _roots, _absent = r.uint(size), r.uint(size), r.uint(size)
        total = r.uint(off_bytes)
        r.take(cells * off_bytes)
        data = r.take(total)
        roots = [0]
        if magic == _BOC_MAGIC_IDX_CRC and crc32c(src[:-4]) != r.take(4):
            raise Malformed
    elif magic == _BOC_MAGIC:
        flags = r.uint(1)
        has_idx, has_crc = flags >> 7, (flags >> 6) & 1
        size = flags & 7
        off_bytes = r.uint(1)
        cells, root_count, _absent = r.uint(size), r.uint(size), r.uint(size)
        total = r.uint(off_bytes)
        roots = []
        for _ in range(root_count):
            roots.append(r.uint(size))
        if has_idx:
            r.take(cells * off_bytes)
        data = r.take(total)
        if has_crc and crc32c(src[:-4]) != r.take(4):
            raise Malformed
    else:
        raise Malformed

    d = _Bytes(data)
    raw: list[tuple[int, int, list[int], bool]] = []
    for _ in range(cells):
        d1, d2 = d.uint(1), d.uint(1)
        if d1 & 16:
            d.take(_hashes_count(d1 >> 5) * 34)
        size_bytes = math.ceil(d2 / 2)
        chunk = d.take(size_bytes)
        value, length = int.from_bytes(chunk, "big"), 8 * size_bytes
        if d2 % 2:
            if value == 0:
                raise Malformed
            trailing = (value & -value).bit_length()
            value >>= trailing
            length -= trailing
        raw.append((value, length, [d.uint(size) for _ in range(d1 % 8)], d1 & 8 != 0))

    built: list[Cell | None] = [None] * len(raw)
    for i in range(len(raw) - 1, -1, -1):
        value, length, refs, exotic = raw[i]
        children = []
        for ref in refs:
            child = built[ref] if 0 <= ref < len(built) else None
            if child is None:
                raise Malformed
            children.append(child)
        built[i] = Cell(value, length, tuple(children), exotic)
    out = []
    for root in roots:
        cell = built[root] if 0 <= root < len(built) else None
        if cell is None:
            raise Malformed
        out.append(cell)
    return out


def _topological(root: Cell) -> list[tuple[Cell, list[int]]]:
    """The cells under root, each once, parents before children, with each cell's references as indexes."""
    cells: dict[bytes, Cell] = {}
    pending = [root]
    while pending:
        current, pending = pending, []
        for c in current:
            if c.hash in cells:
                continue
            cells[c.hash] = c
            pending.extend(c.refs)
    not_placed = dict.fromkeys(cells)
    order: list[bytes] = []

    def visit(h: bytes) -> None:
        if h not in not_placed:
            return
        for ref in reversed(cells[h].refs):
            visit(ref.hash)
        order.append(h)
        del not_placed[h]

    while not_placed:
        visit(next(iter(not_placed)))
    index = {h: len(order) - 1 - i for i, h in enumerate(order)}
    return [(cells[h], [index[r.hash] for r in cells[h].refs]) for h in reversed(order)]


def serialize_boc(root: Cell, crc: bool = True) -> bytes:
    """One root cell as a bag of cells with magic b5ee9c72, no index, and a CRC-32C when crc is set."""
    cells = _topological(root)
    size_bytes = max(math.ceil(max(len(cells).bit_length(), 1) / 8), 1)
    total = sum(2 + math.ceil(c.length / 8) + len(c.refs) * size_bytes for c, _ in cells)
    off_bytes = max(math.ceil(max(total.bit_length(), 1) / 8), 1)
    out = bytearray(_BOC_MAGIC.to_bytes(4, "big"))
    out.append((0x40 if crc else 0) | size_bytes)
    out.append(off_bytes)
    for v in (len(cells), 1, 0):
        out += v.to_bytes(size_bytes, "big")
    out += total.to_bytes(off_bytes, "big")
    out += (0).to_bytes(size_bytes, "big")
    for c, refs in cells:
        out += bytes([c.descriptor1(), c.descriptor2()]) + padded(c.value, c.length)
        for ref in refs:
            out += ref.to_bytes(size_bytes, "big")
    if crc:
        out += crc32c(bytes(out))
    return bytes(out)
