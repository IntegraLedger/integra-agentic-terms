"""The TL-B the TON pairing reads and writes: raw addresses (MsgAddressInt addr_std, with anycast read), the
relaxed message (CommonMsgInfoRelaxed, Maybe StateInit, the body), StateInit, and currency collections."""

import re
from dataclasses import dataclass

from ._ton_cell import Builder, Cell, Malformed, Slice, load_dict

_RAW_ADDRESS = re.compile(r"-?[0-9]{1,10}:[0-9a-fA-F]{64}")


@dataclass(frozen=True, slots=True)
class Address:
    workchain: int
    hash: bytes


def raw_address(text: object) -> Address | None:
    """workchain:64 hex digits as an address, or None."""
    if not isinstance(text, str) or _RAW_ADDRESS.fullmatch(text) is None:
        return None
    workchain, hex_hash = text.split(":")
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


def _extra_currency(s: Slice) -> object:
    return s.uint(8 * s.uint(5))


def _library(s: Slice) -> object:
    s.bit()
    return s.ref()


@dataclass(frozen=True, slots=True)
class StateInit:
    split_depth: int | None
    special: tuple[bool, bool] | None
    code: Cell | None
    data: Cell | None
    libraries: Cell | None


def load_state_init(s: Slice) -> StateInit:
    split_depth = s.uint(5) if s.bit() else None
    special = (s.bit(), s.bit()) if s.bit() else None
    code = s.maybe_ref()
    data = s.maybe_ref()
    libraries = load_dict(s, 256, _library)
    return StateInit(split_depth, special, code, data, libraries)


def store_state_init(b: Builder, init: StateInit) -> None:
    if init.split_depth is None:
        b.bit(0)
    else:
        b.bit(1).uint(init.split_depth, 5)
    if init.special is None:
        b.bit(0)
    else:
        b.bit(1).bit(init.special[0]).bit(init.special[1])
    b.maybe_ref(init.code).maybe_ref(init.data).maybe_ref(init.libraries)


@dataclass(frozen=True, slots=True)
class Relaxed:
    """A relaxed message: internal carries dest; the body is its own cell."""

    internal: bool
    dest: Address | None
    body: Cell


def load_message_relaxed(s: Slice) -> Relaxed:
    """MessageRelaxed: CommonMsgInfoRelaxed, Maybe (Either StateInit ^StateInit), Either X ^X. An int_msg_info is read
    in full; any other info is reported as not internal."""
    if s.bit():
        return Relaxed(False, None, Cell(0, 0))
    s.bit()
    s.bit()
    s.bit()
    load_maybe_address(s)
    dest = load_address(s)
    s.coins()
    load_dict(s, 32, _extra_currency)
    s.coins()
    s.coins()
    s.uint(64)
    s.uint(32)
    if s.bit():
        if not s.bit():
            load_state_init(s)
        else:
            load_state_init(s.ref().slice())
    body = s.ref() if s.bit() else s.as_cell()
    return Relaxed(True, dest, body)


def store_internal_message(
    b: Builder, *, bounce: bool, dest: Address, coins: int, body: Cell, init: StateInit | None = None
) -> None:
    """int_msg_info with IHR disabled, no source, no extra currencies, zero fees, lt and time; then the state init
    and the body, each as a reference."""
    b.bit(0).bit(1).bit(bounce).bit(0)
    store_address(b, None)
    store_address(b, dest)
    b.coins(coins).bit(0).coins(0).coins(0).uint(0, 64).uint(0, 32)
    if init is None:
        b.bit(0)
    else:
        inner = Builder()
        store_state_init(inner, init)
        b.bit(1).bit(1).ref(inner.end())
    b.bit(1).ref(body)
