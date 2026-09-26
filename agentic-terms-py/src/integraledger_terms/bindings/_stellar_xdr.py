"""The Stellar XDR subset the buyer half reads: a TransactionEnvelope (v1, or a fee bump of one) read in full, with
the one InvokeHostFunction operation's values kept (host function, ScVal, SCAddress, authorization entries and
invocations). Every read is checked as XDR requires: enum and union values the definitions name, bool and option
flags of 0 or 1, array and string bounds, zero padding, and no trailing bytes. The parse keeps the byte offsets of
the spans a signature changes, so the envelope is re-encoded by splicing.
"""

from dataclasses import dataclass, field
from typing import Any

# ScVal vectors and maps (a contract instance's storage counting as a map) nest at most MAX_DEPTH levels within one
# ScVal, the outermost container being level 1, and authorized invocations at most MAX_DEPTH levels within one
# authorization entry, the root invocation being level 1. One read holds at most MAX_ELEMENTS vector elements and map
# entries.
MAX_DEPTH = 64
MAX_ELEMENTS = 1536
UNBOUNDED = 0xFFFFFFFF


class Malformed(Exception):
    """The bytes are not XDR of the type read."""


class NotOneTransfer(Exception):
    """The operations are not one InvokeHostFunction whose host function is a contract call."""


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0
        self.elements = 0

    def elements_of(self, n: int) -> int:
        """n vector elements or map entries, counted against MAX_ELEMENTS."""
        self.elements += n
        if self.elements > MAX_ELEMENTS:
            raise Malformed
        return n

    @property
    def remaining(self) -> int:
        return len(self.data) - self.at

    def take(self, n: int) -> bytes:
        if n < 0 or n > self.remaining:
            raise Malformed
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def i32(self) -> int:
        return int.from_bytes(self.take(4), "big", signed=True)

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")

    def i64(self) -> int:
        return int.from_bytes(self.take(8), "big", signed=True)

    def pad(self, length: int) -> None:
        if self.take((4 - length % 4) % 4).strip(b"\0"):
            raise Malformed

    def opaque(self, length: int) -> bytes:
        out = self.take(length)
        self.pad(length)
        return out

    def var_opaque(self, maximum: int = UNBOUNDED) -> bytes:
        length = self.u32()
        if length > maximum or length > self.remaining:
            raise Malformed
        return self.opaque(length)

    def flag(self) -> bool:
        value = self.u32()
        if value not in (0, 1):
            raise Malformed
        return value == 1

    def count(self, maximum: int = UNBOUNDED) -> int:
        """An array's length: within its bound and no more than the bytes left."""
        length = self.u32()
        if length > maximum or length > self.remaining:
            raise Malformed
        return length

    def enum(self, members: range | frozenset[int]) -> int:
        value = self.i32()
        if value not in members:
            raise Malformed
        return value


# ── addresses and keys ───────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Address:
    """An SCAddress: kind 0 account, 1 contract, 2 muxed account (key and id), 3 or 4 others; with its bytes."""

    kind: int
    key: bytes
    id: int | None
    raw: bytes


def public_key(r: Reader) -> bytes:
    r.enum(range(0, 1))
    return r.opaque(32)


def muxed_account(r: Reader) -> None:
    kind = r.enum(frozenset({0, 256}))
    if kind == 256:
        r.u64()
    r.opaque(32)


def sc_address(r: Reader) -> Address:
    start = r.at
    kind = r.enum(range(0, 5))
    muxed_id = None
    if kind == 0:
        key = public_key(r)
    elif kind in (1, 4):
        key = r.opaque(32)
    elif kind == 2:
        muxed_id = r.u64()
        key = r.opaque(32)
    else:
        r.enum(range(0, 1))
        key = r.opaque(32)
    return Address(kind, key, muxed_id, r.data[start : r.at])


def _asset(r: Reader, pool_share: bool) -> None:
    kind = r.enum(range(0, 4 if pool_share else 3))
    if kind == 1:
        r.opaque(4)
        public_key(r)
    elif kind == 2:
        r.opaque(12)
        public_key(r)
    elif kind == 3:
        r.opaque(32)


# ── ScVal ────────────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Val:
    """An ScVal's type, its address when it is one, its i128 when it is one, and its span."""

    kind: int
    address: Address | None
    i128: int | None
    start: int
    end: int


def _executable(r: Reader) -> None:
    kind = r.enum(range(0, 3))
    if kind == 0:
        r.opaque(32)
    elif kind == 2:
        sc_address(r)
        r.var_opaque()


def _map_entries(r: Reader, depth: int) -> None:
    for _ in range(r.elements_of(r.count())):
        sc_val(r, depth + 1)
        sc_val(r, depth + 1)


def sc_val(r: Reader, depth: int = 0) -> Val:
    """One ScVal inside depth vectors and maps."""
    start = r.at
    kind = r.enum(range(0, 23))
    if kind in (16, 17, 19) and depth + 1 > MAX_DEPTH:
        raise Malformed
    address = None
    i128 = None
    if kind == 0:
        r.flag()
    elif kind == 2:
        error = r.enum(range(0, 10))
        if error == 0:
            r.u32()
        else:
            r.enum(range(0, 10))
    elif kind in (3, 4):
        r.u32()
    elif kind in (5, 6, 7, 8):
        r.u64()
    elif kind == 9:
        r.take(16)
    elif kind == 10:
        hi, lo = r.i64(), r.u64()
        i128 = (hi << 64) | lo
    elif kind in (11, 12):
        r.take(32)
    elif kind in (13, 14, 22):
        r.var_opaque()
    elif kind == 15:
        r.var_opaque(32)
    elif kind == 16:
        if r.flag():
            for _ in range(r.elements_of(r.count())):
                sc_val(r, depth + 1)
    elif kind == 17:
        if r.flag():
            _map_entries(r, depth)
    elif kind == 18:
        address = sc_address(r)
    elif kind == 19:
        _executable(r)
        if r.flag():
            _map_entries(r, depth)
    elif kind == 21:
        r.i64()
    return Val(kind, address, i128, start, r.at)


def sc_vals(r: Reader) -> list[Val]:
    return [sc_val(r) for _ in range(r.count())]


# ── host functions and authorization ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Call:
    """An InvokeContractArgs: the contract, the function, the arguments, and its own XDR bytes."""

    contract: Address
    function: bytes
    args: list[Val]
    raw: bytes


def invoke_contract_args(r: Reader) -> Call:
    start = r.at
    contract = sc_address(r)
    function = r.var_opaque(32)
    args = sc_vals(r)
    return Call(contract, function, args, r.data[start : r.at])


def _contract_id_preimage(r: Reader) -> None:
    if r.enum(range(0, 2)) == 0:
        sc_address(r)
        r.opaque(32)
    else:
        _asset(r, False)


def _create_contract(r: Reader, v2: bool) -> None:
    _contract_id_preimage(r)
    _executable(r)
    if v2:
        sc_vals(r)


@dataclass(frozen=True, slots=True)
class Invocation:
    """A SorobanAuthorizedInvocation: its contract call (None for a contract creation) and how many sub-invocations it
    holds."""

    call: Call | None
    subs: int


def invocation(r: Reader, depth: int = 0) -> Invocation:
    """One authorized invocation inside depth others."""
    if depth + 1 > MAX_DEPTH:
        raise Malformed
    kind = r.enum(range(0, 3))
    call = None
    if kind == 0:
        call = invoke_contract_args(r)
    else:
        _create_contract(r, kind == 2)
    subs = r.count()
    for _ in range(subs):
        invocation(r, depth + 1)
    return Invocation(call, subs)


@dataclass(frozen=True, slots=True)
class Credentials:
    """An authorization entry's address credentials: V1 or V2, the address, the nonce, the offset of the expiration
    ledger, and the span of the signature."""

    v2: bool
    address: Address
    nonce: int
    expiration: int
    expiration_at: int
    signature_start: int
    signature_end: int


@dataclass(frozen=True, slots=True)
class Entry:
    credentials: Credentials | None
    invocation: bytes
    root: Invocation


def _address_credentials(r: Reader, v2: bool) -> Credentials:
    address = sc_address(r)
    nonce = r.i64()
    expiration_at = r.at
    expiration = r.u32()
    signature = sc_val(r)
    return Credentials(v2, address, nonce, expiration, expiration_at, signature.start, signature.end)


def _delegate(r: Reader, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise Malformed
    sc_address(r)
    sc_val(r)
    for _ in range(r.count()):
        _delegate(r, depth + 1)


def auth_entry(r: Reader) -> Entry:
    kind = r.enum(range(0, 4))
    credentials = None
    if kind in (1, 2):
        credentials = _address_credentials(r, kind == 2)
    elif kind == 3:
        _address_credentials(r, False)
        for _ in range(r.count()):
            _delegate(r, 0)
    start = r.at
    root = invocation(r)
    return Entry(credentials, r.data[start : r.at], root)


# ── the transaction ──────────────────────────────────────────────────────────────────────────────────────────────


@dataclass
class Invoke:
    call: Call
    entries: list[Entry] = field(default_factory=list)


def _preconditions(r: Reader) -> None:
    kind = r.enum(range(0, 3))
    if kind == 1:
        r.u64()
        r.u64()
    elif kind == 2:
        if r.flag():
            r.u64()
            r.u64()
        if r.flag():
            r.u32()
            r.u32()
        if r.flag():
            r.i64()
        r.u64()
        r.u32()
        for _ in range(r.count(2)):
            signer = r.enum(range(0, 4))
            r.opaque(32)
            if signer == 3:
                r.var_opaque(64)


def _memo(r: Reader) -> None:
    kind = r.enum(range(0, 5))
    if kind == 1:
        r.var_opaque(28)
    elif kind == 2:
        r.u64()
    elif kind in (3, 4):
        r.opaque(32)


def _ledger_key(r: Reader) -> None:
    kind = r.enum(range(0, 10))
    if kind == 0:
        public_key(r)
    elif kind == 1:
        public_key(r)
        _asset(r, True)
    elif kind == 2:
        public_key(r)
        r.i64()
    elif kind == 3:
        public_key(r)
        r.var_opaque(64)
    elif kind == 4:
        r.enum(range(0, 1))
        r.opaque(32)
    elif kind in (5, 7, 9):
        r.opaque(32)
    elif kind == 6:
        sc_address(r)
        sc_val(r)
        r.enum(range(0, 2))
    elif kind == 8:
        r.enum(range(0, 21))


def _transaction_ext(r: Reader) -> None:
    if r.enum(range(0, 2)) == 1:
        if r.enum(range(0, 2)) == 1:
            for _ in range(r.count()):
                r.u32()
        for _ in range(2):
            for _ in range(r.count()):
                _ledger_key(r)
        r.u32()
        r.u32()
        r.u32()
        r.i64()


def _price(r: Reader) -> None:
    r.i32()
    r.i32()


def _claim_predicate(r: Reader, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise Malformed
    kind = r.enum(range(0, 6))
    if kind in (1, 2):
        for _ in range(r.count(2)):
            _claim_predicate(r, depth + 1)
    elif kind == 3:
        if r.flag():
            _claim_predicate(r, depth + 1)
    elif kind in (4, 5):
        r.i64()


def _signer_key(r: Reader) -> None:
    kind = r.enum(range(0, 4))
    r.opaque(32)
    if kind == 3:
        r.var_opaque(64)


def _operation(r: Reader, kind: int) -> None:
    """The body of an operation other than InvokeHostFunction."""
    if kind == 0:
        public_key(r)
        r.i64()
    elif kind in (1, 19):
        if kind == 1:
            muxed_account(r)
            _asset(r, False)
        else:
            _asset(r, False)
            muxed_account(r)
        r.i64()
    elif kind in (2, 13):
        _asset(r, False)
        r.i64()
        muxed_account(r)
        _asset(r, False)
        r.i64()
        for _ in range(r.count(5)):
            _asset(r, False)
    elif kind in (3, 4, 12):
        _asset(r, False)
        _asset(r, False)
        r.i64()
        _price(r)
        if kind != 4:
            r.i64()
    elif kind == 5:
        if r.flag():
            public_key(r)
        for _ in range(6):
            if r.flag():
                r.u32()
        if r.flag():
            r.var_opaque(32)
        if r.flag():
            _signer_key(r)
            r.u32()
    elif kind == 6:
        line = r.enum(range(0, 4))
        if line in (1, 2):
            r.opaque(4 if line == 1 else 12)
            public_key(r)
        elif line == 3:
            r.enum(range(0, 1))
            _asset(r, False)
            _asset(r, False)
            r.i32()
        r.i64()
    elif kind == 7:
        public_key(r)
        code = r.enum(range(1, 3))
        r.opaque(4 if code == 1 else 12)
        r.u32()
    elif kind == 8:
        muxed_account(r)
    elif kind == 10:
        r.var_opaque(64)
        if r.flag():
            r.var_opaque(64)
    elif kind == 11:
        r.i64()
    elif kind == 14:
        _asset(r, False)
        r.i64()
        for _ in range(r.count(10)):
            r.enum(range(0, 1))
            public_key(r)
            _claim_predicate(r, 0)
    elif kind in (15, 20):
        r.enum(range(0, 1))
        r.opaque(32)
    elif kind == 16:
        public_key(r)
    elif kind == 18:
        if r.enum(range(0, 2)) == 0:
            _ledger_key(r)
        else:
            public_key(r)
            _signer_key(r)
    elif kind == 21:
        public_key(r)
        _asset(r, False)
        r.u32()
        r.u32()
    elif kind == 22:
        r.opaque(32)
        r.i64()
        r.i64()
        _price(r)
        _price(r)
    elif kind == 23:
        r.opaque(32)
        r.i64()
        r.i64()
        r.i64()
    elif kind in (25, 26):
        r.enum(range(0, 1))
        if kind == 25:
            r.u32()


def _invoke(r: Reader) -> Invoke | None:
    """An InvokeHostFunction operation: its contract call and entries, or None for another host function."""
    kind = r.enum(range(0, 4))
    call = None
    if kind == 0:
        call = invoke_contract_args(r)
    elif kind == 2:
        r.var_opaque()
    else:
        _create_contract(r, kind == 3)
    entries = [auth_entry(r) for _ in range(r.count())]
    return None if call is None else Invoke(call, entries)


@dataclass(frozen=True, slots=True)
class Envelope:
    """A v1 transaction's one invoke, where its source account's bytes sit, and whether it came in a fee bump."""

    fee_bump: bool
    source_start: int
    source_end: int
    invoke: Invoke


def _signatures(r: Reader) -> None:
    for _ in range(r.count(20)):
        r.opaque(4)
        r.var_opaque(64)


def _v1(r: Reader) -> tuple[int, int, list[Invoke | None]]:
    source_start = r.at
    muxed_account(r)
    source_end = r.at
    r.u32()
    r.i64()
    _preconditions(r)
    _memo(r)
    invokes: list[Invoke | None] = []
    for _ in range(r.count(100)):
        if r.flag():
            muxed_account(r)
        kind = r.enum(range(0, 27))
        if kind == 24:
            invokes.append(_invoke(r))
        else:
            _operation(r, kind)
            invokes.append(None)
    _transaction_ext(r)
    _signatures(r)
    return source_start, source_end, invokes


def envelope(data: bytes) -> Envelope:
    """The envelope's one invoke. Raises Malformed for bytes that are not an envelope of a v1 transaction or a fee
    bump of one, and NotOneTransfer when its operations are not one contract call."""
    r = Reader(data)
    kind = r.enum(frozenset({0, 2, 5}))
    if kind == 0:
        raise Malformed
    if kind == 2:
        start, end, invokes = _v1(r)
    else:
        muxed_account(r)
        r.i64()
        r.enum(frozenset({2}))
        start, end, invokes = _v1(r)
        r.enum(range(0, 1))
        _signatures(r)
    if r.remaining:
        raise Malformed
    if len(invokes) != 1 or invokes[0] is None:
        raise NotOneTransfer
    return Envelope(kind == 5, start, end, invokes[0])
