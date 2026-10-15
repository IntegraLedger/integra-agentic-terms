"""The TL-B the TON pairing reads and writes: raw addresses (MsgAddressInt addr_std, with anycast read), StateInit, and
a message as TON's action phase sends it, at a network's configuration."""

import re
from dataclasses import dataclass

from ._ton_cell import Builder, Cell, Malformed, Slice, Validation, merkle_depth

_RAW_ADDRESS = re.compile(r"-?[0-9]{1,10}:[0-9a-fA-F]{64}")
# The cells TON's TL-B validation reads at most (ton-blockchain/ton crypto/tl/tlblib.hpp, default_validate_max_cells):
# of a message's state init, and of the action that sends a message.
STATE_INIT_MAX_READS = 1024
# The Merkle proofs and updates a sent message may nest (ton-blockchain/ton crypto/block/transaction.h,
# Transaction::max_allowed_merkle_depth).
MAX_MERKLE_DEPTH = 2


@dataclass(frozen=True, slots=True)
class TonConfiguration:
    """The network configuration TON's message rules rest on, for one network.
    - global_version: ConfigParam 8, capabilities#c4 version:uint32. From 4, TON's action phase takes a send mode's
      +16 as bounce-on-fail (bounce_on_fail_enabled); from 10, it refuses an anycast address (disable_anycast),
      TON deploys no account whose fixed prefix length is above max_acc_fixed_prefix_length, and a message's extra
      currencies are held to max_msg_extra_currencies (extra_currency_v2); from 12, a message's extra_flags may set
      its two low bits only; from 15, no account is deployed from a state init that holds libraries
      (unpack_msg_state).
    - workchains: the workchains a message may name: the masterchain (-1), and ConfigParam 12's workchains that are
      basic and accept messages. Each takes 256-bit addresses only.
    - max_msg_extra_currencies: ConfigParam 43, how many extra currencies a sent message may hold.
    - max_acc_fixed_prefix_length: ConfigParam 43, the longest fixed prefix of an account TON deploys."""

    global_version: int
    workchains: frozenset[int]
    max_msg_extra_currencies: int
    max_acc_fixed_prefix_length: int


# Mainnet's configuration: the one @ton/sandbox 0.45.0 ships (defaultConfig, configuration seqno 92871331, ConfigParam
# 19 global id -239), read offline. ConfigParam 12 holds one workchain, 0.
MAINNET = TonConfiguration(
    global_version=15, workchains=frozenset({-1, 0}), max_msg_extra_currencies=0, max_acc_fixed_prefix_length=8
)
# Testnet's configuration. Testnet's own values are not read: these are mainnet's, from MAINNET's source, since no
# offline source pinned by seqno holds testnet's ConfigParams 8, 12 and 43.
TESTNET = TonConfiguration(
    global_version=15, workchains=frozenset({-1, 0}), max_msg_extra_currencies=0, max_acc_fixed_prefix_length=8
)


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


def deploys_from(root: Cell, config: TonConfiguration) -> bool:
    """True when TON deploys an account from a state init is_state_init holds, at the configuration
    (ton-blockchain/ton crypto/block/transaction.cpp, unpack_msg_state and prepare_compute_phase): from global version
    15 its library:(HashmapE 256 SimpleLib) is hme_empty ("libraries are not null"), and from global version 10 its
    fixed_prefix_length is absent or at most the configuration's max_acc_fixed_prefix_length ("too big fixed prefix
    length")."""
    s = root.slice()
    prefix = s.uint(5) if s.bit() else 0
    if s.bit():
        s.uint(2)
    s.maybe_ref()
    s.maybe_ref()
    libraries = s.bit()
    if config.global_version >= 15 and libraries:
        return False
    return not (config.global_version >= 10 and prefix > config.max_acc_fixed_prefix_length)


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


def msg_address(s: Slice, config: TonConfiguration) -> tuple[int, Address | None]:
    """A TL-B MsgAddress read from the slice (block.tlb: addr_none$00, addr_extern$01, addr_std$10 and addr_var$11, an
    anycast's depth:(#<= 30) { depth >= 1 }): its tag, and the address it names when it has no anycast, 256 bits and a
    workchain the configuration holds, else None. TON refuses an anycast address from global version 10. Another
    anycast depth, or a read past the slice's end, is Malformed."""
    tag = s.uint(2)
    if tag == 0:
        return tag, None
    if tag == 1:
        s.uint(s.uint(9))
        return tag, None
    anycast = s.bit()
    if anycast:
        depth = s.uint(5)
        if not 1 <= depth <= 30:
            raise Malformed
        s.uint(depth)
    length = 256 if tag == 2 else s.uint(9)
    workchain = s.sint(8) if tag == 2 else s.sint(32)
    if length != 256:
        s.uint(length)
        return tag, None
    address = Address(workchain, s.buf(32))
    return tag, None if anycast or workchain not in config.workchains else address


@dataclass(frozen=True, slots=True)
class Message:
    """A message TON's action phase sends: the address it sends to, and its body."""

    dest: Address
    body: Cell


def message_of(c: Cell, sender: Address | None, config: TonConfiguration) -> Message | None:
    """The message as TON's action phase sends it at the configuration (ton-blockchain/ton
    crypto/block/transaction.cpp: the action list's t_OutListNode.validate_ref, then try_action_send_msg), or None
    where TON refuses to send it. The cell is TL-B's MessageRelaxed Any with int_msg_info$0, read to its end:
    - src is addr_none or the sender's own address (check_replace_src_addr): sender when it is known, else an addr_std
      with no anycast on a workchain the configuration holds. The settlement message's sender is the account that
      relays it, which the bytes do not name: a source naming another account is read, and TON sends it when that
      account relays it;
    - dest is an address TON sends to (check_rewrite_dest_addr): an addr_std with no anycast, or an addr_var of 256
      bits with no anycast, which TON sends as that addr_std, on a workchain the configuration holds. The answer's dest
      is that addr_std;
    - the value's Grams is a VarUInteger 16 in its shortest form (Slice.var_uint), the extra currencies are a valid
      HashmapE 32 (VarUIntegerPos 32) of at most the configuration's max_msg_extra_currencies entries, and from global
      version 12 extra_flags is a VarUInteger 16 in its shortest form that sets no bit above its two low ones;
    - the init, when present, is a ^StateInit, or a StateInit inline, taken as the cell its fields make, either of
      them one is_state_init holds;
    - the body is the remainder, or a reference to an ordinary cell with nothing after it (TL-B validation reads the
      referenced cell, TLB::validate_ref_internal);
    - the action list's validation reads at most 1,024 cells: its node, the message, each extra-currency dictionary
      cell on each path, a ^StateInit and a referenced body;
    - at most MAX_MERKLE_DEPTH Merkle proofs and updates nest under the init and the body."""
    if c.exotic:
        return None
    try:
        s = c.slice()
        if s.bit():
            return None
        s.uint(3)
        tag, src = msg_address(s, config)
        if tag != 0 and (tag != 2 or src is None or (sender is not None and src != sender)):
            return None
        tag, dest = msg_address(s, config)
        if tag < 2 or dest is None:
            return None
        if s.var_uint(4) is None:
            return None
        extra = s.maybe_ref()
        flags = s.var_uint(4)
        if config.global_version >= 12 and (flags is None or flags > 3):
            return None
        s.coins()
        s.uint(64 + 32)
        init: Cell | None = None
        init_ref = False
        if s.bit():
            init_ref = s.bit()
            init = s.ref() if init_ref else _inline_state_init(s)
            if not is_state_init(init):
                return None
        body_ref = s.bit()
        body = s.ref() if body_ref else s.as_cell()
        if body_ref and (body.exotic or s.remaining_bits != 0 or s.remaining_refs != 0):
            return None
        if extra is not None:
            count = 0

            def currency(v: Slice) -> bool:
                nonlocal count
                amount = v.var_uint(5)
                count += 1
                return amount is not None and amount > 0

            reads = STATE_INIT_MAX_READS - 2 - init_ref - body_ref
            if not Validation(reads).hashmap(extra, 32, currency) or count > config.max_msg_extra_currencies:
                return None
        under = ([] if init is None else [init]) + ([body] if body_ref else list(body.refs))
        if merkle_depth(under) > MAX_MERKLE_DEPTH:
            return None
        return Message(dest, body)
    except Malformed:
        return None


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
