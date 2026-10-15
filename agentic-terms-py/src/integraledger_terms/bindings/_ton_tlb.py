"""The TL-B the TON pairing reads and writes: raw addresses (MsgAddressInt addr_std, with anycast read), the
relaxed message (CommonMsgInfoRelaxed, Maybe StateInit, the body), StateInit, and currency collections."""

import re
from dataclasses import dataclass

from ._ton_cell import Builder, Cell, Malformed, Slice, Validation

_RAW_ADDRESS = re.compile(r"-?[0-9]{1,10}:[0-9a-fA-F]{64}")
# The cells TON's TL-B validation reads at most (ton-blockchain/ton crypto/tl/tlblib.hpp, default_validate_max_cells):
# of a message's state init, and of the action that sends a message.
STATE_INIT_MAX_READS = 1024


@dataclass(frozen=True, slots=True)
class Address:
    workchain: int
    hash: bytes


def raw_address(text: object) -> Address | None:
    """workchain:64 hex digits as an address, or None. The workchain must fit addr_std's workchain_id:int8, [-128,
    127]: outside it, no addr_std can hold it, and every address this pairing writes is an addr_std."""
    if not isinstance(text, str) or _RAW_ADDRESS.fullmatch(text) is None:
        return None
    workchain, hex_hash = text.split(":")
    if not -128 <= int(workchain) <= 127:
        return None
    return Address(int(workchain), bytes.fromhex(hex_hash))


def store_address(b: Builder, a: Address | None) -> None:
    """addr_none for None, else addr_std with no anycast."""
    if a is None:
        b.uint(0, 2)
        return
    b.uint(2, 2).uint(0, 1).sint(a.workchain, 8).buf(a.hash)


def _internal_address(s: Slice) -> Address:
    """addr_std, with an anycast rewrite prefix applied to the hash."""
    if s.preload_uint(2) != 2:
        raise Malformed
    depth: int | None = None
    prefix = 0
    if s.preload_uint(1, 2) != 0:
        depth = s.preload_uint(5, 3)
        prefix = s.preload_uint(depth, 8)
        s.at += 5 + depth
    workchain = s.preload_uint(8, 3)
    workchain = workchain - 256 if workchain >= 128 else workchain
    hash_value = s.preload_uint(256, 11)
    if depth is not None and depth > 0:
        shift = 256 - depth
        hash_value = (hash_value & ((1 << shift) - 1)) | (prefix << shift)
    s.at += 267
    return Address(workchain, hash_value.to_bytes(32, "big"))


def load_address(s: Slice) -> Address:
    if s.preload_uint(2) != 2:
        raise Malformed
    return _internal_address(s)


def load_maybe_address(s: Slice) -> Address | None:
    kind = s.preload_uint(2)
    if kind == 0:
        s.at += 2
        return None
    if kind == 2:
        return _internal_address(s)
    raise Malformed


def _extra_currency(s: Slice) -> bool:
    s.uint(8 * s.uint(5))
    return True


def _simple_lib(s: Slice) -> bool:
    """simple_lib public:Bool root:^Cell."""
    s.bit()
    s.ref()
    return True


def is_state_init(root: Cell) -> bool:
    """True when the cell is exactly one StateInitWithLibs, the type in which TON validates a message's state init
    (ton-blockchain/ton crypto/block/transaction.cpp, try_action_send_msg and unpack_input_msg): fixed_prefix_length,
    special, code, data and library:(HashmapE 256 SimpleLib), each cell this reads validated as TON validates it
    (Validation), with at most 1,024 cells read: the state init's, then each dictionary cell each time a path reaches
    it. The code, the data and each library's root are any cells and are not read."""
    v = Validation(STATE_INIT_MAX_READS)

    def fields(s: Slice) -> bool:
        if s.bit():
            s.uint(5)
        if s.bit():
            s.uint(2)
        s.maybe_ref()
        s.maybe_ref()
        library = s.maybe_ref()
        return library is None or v.hashmap(library, 256, _simple_lib)

    try:
        return v.exact(root, fields)
    except Malformed:
        return False


def _inline_state_init(s: Slice) -> Cell:
    """A StateInit written inline in the slice, as the cell its fields make."""
    bits_at, refs_at = s.at, s.ref_at
    if s.bit():
        s.uint(5)
    if s.bit():
        s.uint(2)
    s.maybe_ref()
    s.maybe_ref()
    s.maybe_ref()
    length = s.at - bits_at
    return Cell((s.cell.value >> (s.cell.length - s.at)) & ((1 << length) - 1), length, s.cell.refs[refs_at : s.ref_at])


@dataclass(frozen=True, slots=True)
class Relaxed:
    """A relaxed message: internal carries dest; the body is its own cell."""

    internal: bool
    dest: Address | None
    body: Cell


def load_message_relaxed(s: Slice) -> Relaxed:
    """MessageRelaxed: CommonMsgInfoRelaxed, Maybe (Either StateInit ^StateInit), Either X ^X. An int_msg_info is read
    in full; any other info is reported as not internal. The init, a ^StateInit or the cell its inline fields make,
    must be one is_state_init holds, and the extra currencies a HashmapE 32 (VarUInteger 32) validated as TON validates
    the action that sends the message: within 1,024 cell reads with its node and the message, a ^StateInit and a
    referenced body."""
    if s.bit():
        return Relaxed(False, None, Cell(0, 0))
    s.bit()
    s.bit()
    s.bit()
    load_maybe_address(s)
    dest = load_address(s)
    s.coins()
    extra = s.maybe_ref()
    s.coins()
    s.coins()
    s.uint(64)
    s.uint(32)
    init_ref = False
    if s.bit():
        init_ref = s.bit()
        if not is_state_init(s.ref() if init_ref else _inline_state_init(s)):
            raise Malformed
    body_ref = s.bit()
    body = s.ref() if body_ref else s.as_cell()
    reads = STATE_INIT_MAX_READS - 2 - init_ref - body_ref
    if extra is not None and not Validation(reads).hashmap(extra, 32, _extra_currency):
        raise Malformed
    return Relaxed(True, dest, body)


def store_internal_message(
    b: Builder, *, bounce: bool, dest: Address, coins: int, body: Cell, init: Cell | None = None
) -> None:
    """int_msg_info with IHR disabled, no source, no extra currencies, zero fees, lt and time; then the state init
    cell as given and the body, each as a reference."""
    b.bit(0).bit(1).bit(bounce).bit(0)
    store_address(b, None)
    store_address(b, dest)
    b.coins(coins).bit(0).coins(0).coins(0).uint(0, 64).uint(0, 32)
    if init is None:
        b.bit(0)
    else:
        b.bit(1).bit(1).ref(init)
    b.bit(1).ref(body)
