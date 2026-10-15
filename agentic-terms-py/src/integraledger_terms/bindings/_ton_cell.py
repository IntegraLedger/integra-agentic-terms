"""The TON cell layer: cells with their level, hashes and depths, a bit builder and a slice, bags of cells read and
written with CRC-32C, and TL-B validation of a cell and a Hashmap as TON runs it. An exotic cell is held as the bag
gives it, and a slice of one is Malformed, so each read refuses one where it parses it."""

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
# The deepest a cell may be at any level (ton-blockchain/ton crypto/vm/cells/CellTraits.h, max_depth).
CELL_MAX_DEPTH = 1024


def _below(mask: int, level: int) -> int:
    """The level mask's bits below level."""
    return mask & ((1 << level) - 1)


def _hash_index(mask: int) -> int:
    return bin(mask).count("1")


@dataclass(frozen=True, slots=True, eq=False)
class Cell:
    """A cell as TON creates one (ton-blockchain/ton crypto/vm/cells/DataCell.cpp, CellChecker): up to 1023 bits
    (value, most significant first, and length) and up to four references. An exotic cell's first 8 bits are its type:
    a pruned branch (1: no references, a level mask from 1 to 7 in its next 8 bits, then a stored hash and a stored
    depth for each bit the mask sets, and nothing else), a library cell (2: 264 bits, no references), a Merkle proof
    (3: 280 bits, one reference) or a Merkle update (4: 552 bits, two references), each Merkle cell storing its
    children's level-0 hashes and depths. Any other type or form is Malformed, and so is a depth above 1,024 at any
    level. The level mask, and the hashes and depths at levels 0 to 3, are TON's: a pruned branch's at level i are the
    stored ones of the lowest bit of its mask at or above i, and above every bit its own representation hash and
    depth 0. hash and depth are the representation's, at level 3."""

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
        if self.length > MAX_BITS or len(self.refs) > MAX_REFS:
            raise Malformed
        kind = 0
        pruned: list[tuple[bytes, int]] = []
        if not self.exotic:
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
        if max(d for _, d in by_level) > CELL_MAX_DEPTH:
            raise Malformed
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
            if refs or bits < 16:
                raise Malformed
            mask = (self.value >> (bits - 16)) & 0xFF
            count = _hash_index(mask)
            if not 1 <= mask <= 7 or bits != (2 + count * (32 + 2)) * 8:
                raise Malformed
            body = padded(self.value, bits)
            for k in range(count):
                at_depth = 2 + 32 * count + 2 * k
                pruned.append((body[2 + 32 * k : 34 + 32 * k], int.from_bytes(body[at_depth : at_depth + 2], "big")))
            return mask
        if kind == _LIBRARY:
            if bits != 8 + 256 or refs:
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


def read_label(s: Slice, n: int) -> int:
    """The length of a TL-B HmLabel ~l n read from the slice: hml_short$0 (a unary length, then the bits), hml_long$10
    (the length in ceil(log2(n + 1)) bits, then the bits) or hml_same$11 (one bit, then the length). A label longer
    than n is Malformed, as is a read past the slice's end."""
    width = math.ceil(math.log2(n + 1))
    if not s.bit():
        length = 0
        while s.bit():
            length += 1
    elif not s.bit():
        length = s.uint(width)
    else:
        s.bit()
        length = s.uint(width)
        if length > n:
            raise Malformed
        return length
    if length > n:
        raise Malformed
    s.uint(length)
    return length


class Validation:
    """TL-B validation as TON runs it (ton-blockchain/ton crypto/tl/tlblib.cpp, TLB::validate_ref_internal): each cell
    ordinary and read to its end, with no bit or reference left over, and at most reads cells read in all. A read
    past a slice's end is Malformed."""

    def __init__(self, reads: int) -> None:
        self.left = reads

    def exact(self, c: Cell, read: Callable[[Slice], bool]) -> bool:
        """True when the cell is ordinary, within the reads left, and read reads it to its end."""
        if self.left <= 0 or c.exotic:
            return False
        self.left -= 1
        s = c.slice()
        return read(s) and s.remaining_bits == 0 and s.remaining_refs == 0

    def hashmap(self, c: Cell, n: int, value: Callable[[Slice], bool]) -> bool:
        """A TL-B Hashmap n X edge (hm_edge): a label of at most n bits, then at key length 0 the value, which value
        reads, else a fork of two edges, each cell counted each time a path reaches it."""

        def edge(s: Slice) -> bool:
            length = read_label(s, n)
            if length == n:
                return value(s)
            left, right = s.ref(), s.ref()
            return self.hashmap(left, n - length - 1, value) and self.hashmap(right, n - length - 1, value)

        return self.exact(c, edge)


# ── bags of cells ─────────────────────────────────────────────────────────────────────────────────────────────────


def _hashes_count(level_mask: int) -> int:
    return bin(level_mask & 7).count("1") + 1


def _cell_size(d1: int, d2: int, ref_size: int) -> int:
    """A serialized cell's byte length from its two descriptor bytes (CellSerializationInfo::init)."""
    stored = _hashes_count(d1 >> 5) if d1 & 16 else 0
    return 2 + stored * 34 + (d2 >> 1) + (d2 & 1) + (d1 & 7) * ref_size


def parse_boc(src: bytes) -> Cell:
    """The one root of a bag of cells as TON deserializes it (ton-blockchain/ton crypto/vm/boc.cpp,
    std_boc_deserialize); Malformed where TON refuses the bytes:
    - the header (parse_serialized_header): one of the three magics, cache bits only with an index, a reference size
      of 1 to 4 bytes and an offset size of 1 to 8, at least one cell, exactly one root, no more absent cells than
      cells, a data size within the cell count's bounds, and the bytes holding all of it;
    - with a CRC-32C, the input's last four bytes are the CRC-32C of every byte before them;
    - each cell's bytes: at most four references, each to a later cell, the bytes read exactly (the cells fill the
      data, or each index entry bounds one cell with no unused space), a partial last data byte holding a data bit
      before its completion tag, and with cache bits, each cell's flag set exactly when two or more references (the
      root's counted) name it;
    - each cell as Cell creates it, TON's CellChecker; the level mask its first byte gives equal to the one computed;
      and where it stores hashes and depths, each one equal to the computed one;
    - the root's level 0."""

    def at(offset: int, n: int) -> int:
        return int.from_bytes(src[offset : offset + n], "big")

    if len(src) < 6:
        raise Malformed
    magic = at(0, 4)
    if magic not in (_BOC_MAGIC, _BOC_MAGIC_IDX, _BOC_MAGIC_IDX_CRC):
        raise Malformed
    generic = magic == _BOC_MAGIC
    flags = src[4]
    indexed = not generic or flags & 0x80 != 0
    crc = flags & 0x40 != 0 if generic else magic == _BOC_MAGIC_IDX_CRC
    cache_bits = generic and flags & 0x20 != 0
    ref_size = flags & 7
    off_size = src[5]
    if (cache_bits and not indexed) or not 1 <= ref_size <= 4 or not 1 <= off_size <= 8:
        raise Malformed
    roots_at = 6 + 3 * ref_size + off_size
    if len(src) < roots_at:
        raise Malformed
    # TON reads the three counts into an int, so a count of 2^31 or more is negative there.
    cells, roots, absent = at(6, ref_size), at(6 + ref_size, ref_size), at(6 + 2 * ref_size, ref_size)
    data_size = at(6 + 3 * ref_size, off_size)
    if cells < 1 or cells >= 2**31 or roots != 1 or absent > cells:
        raise Malformed
    if data_size > cells * 1024 or data_size < cells * (2 + ref_size) - ref_size:
        raise Malformed
    index_at = roots_at + (ref_size if generic else 0)
    data_at = index_at + (cells * off_size if indexed else 0)
    if data_at + data_size + (4 if crc else 0) > len(src):
        raise Malformed
    if crc and crc32c(src[:-4]) != src[-4:]:
        raise Malformed
    root_index = at(roots_at, ref_size) if generic else 0
    if root_index >= cells:
        raise Malformed
    data = src[data_at : data_at + data_size]
    spans: list[tuple[int, int]] = []
    start = 0
    if indexed:
        for i in range(cells):
            raw = at(index_at + i * off_size, off_size)
            end = raw // 2 if cache_bits else raw
            if start > end or end > data_size:
                raise Malformed
            spans.append((start, end))
            start = end
    else:
        for _ in range(cells):
            if len(data) - start < 2 or data[start] & 7 > 4:
                raise Malformed
            size = _cell_size(data[start], data[start + 1], ref_size)
            if len(data) - start < size:
                raise Malformed
            spans.append((start, start + size))
            start += size
        if start != data_size:
            raise Malformed

    built: list[Cell] = [Cell(0, 0)] * cells
    named = [0] * cells
    named[root_index] = 1
    for i in range(cells - 1, -1, -1):
        s = data[spans[i][0] : spans[i][1]]
        if len(s) < 2:
            raise Malformed
        d1, d2 = s[0], s[1]
        if d1 & 7 > 4 or _cell_size(d1, d2, ref_size) != len(s):
            raise Malformed
        mask = d1 >> 5
        stored = _hashes_count(mask) if d1 & 16 else 0
        bits_at = 2 + stored * 34
        refs_at = bits_at + (d2 >> 1) + (d2 & 1)
        refs: list[Cell] = []
        for k in range(d1 & 7):
            r = int.from_bytes(s[refs_at + k * ref_size : refs_at + (k + 1) * ref_size], "big")
            if r <= i or r >= cells:
                raise Malformed
            refs.append(built[r])
            named[r] = min(named[r] + 1, 2)
        value, length = int.from_bytes(s[bits_at:refs_at], "big"), 8 * (refs_at - bits_at)
        if d2 & 1:
            last = s[refs_at - 1]
            if last & 0x7F == 0:
                raise Malformed
            tag = (last & -last).bit_length()
            value >>= tag
            length -= tag
        cell = Cell(value, length, tuple(refs), d1 & 8 != 0)
        if cell.level_mask != mask:
            raise Malformed
        if stored:
            hashes = [s[2 + 32 * k : 34 + 32 * k] for k in range(stored)]
            depths = [int.from_bytes(s[2 + 32 * stored + 2 * k : 4 + 32 * stored + 2 * k], "big") for k in range(stored)]
            levels = [level for level in range(4) if level == 0 or mask >> (level - 1) & 1]
            if [(cell.hashes[level], cell.depths[level]) for level in levels] != list(zip(hashes, depths)):
                raise Malformed
        built[i] = cell
    if cache_bits and any((named[i] > 1) != (at(index_at + i * off_size, off_size) % 2 == 1) for i in range(cells)):
        raise Malformed
    root = built[root_index]
    if root.level_mask != 0:
        raise Malformed
    return root


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
