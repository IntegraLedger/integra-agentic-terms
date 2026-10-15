"""The Stellar XDR subset the buyer half reads: a TransactionEnvelope (v1, or a fee bump of one) read in full, with
the one InvokeHostFunction operation's values kept (host function, ScVal, SCAddress, authorization entries and
invocations). Every read is checked as XDR requires: enum and union values the definitions name, bool and option
flags of 0 or 1, array and string bounds, zero padding, and no trailing bytes. The parse keeps the byte offsets of
the spans a signature changes, so the envelope is re-encoded by splicing. Nested values (ScVals, authorized
invocations, delegates and claim predicates) are read with a stack of their own, so the read takes any nesting the
bytes hold; it records how deep each ScVal and each authorization entry nests, and the caller bounds what it reads.
"""

from dataclasses import dataclass, field
from typing import Any

# The deepest nesting of ScVal vectors and maps (a contract instance's storage counting as a map) within one ScVal, the
# outermost container being level 1, and of authorized invocations within one authorization entry, the root invocation
# being level 1, in what the read takes: the operation's host function and the payer's authorization entry. Another
# entry, the footprint and the other operations are read whole with no bound on their nesting.
MAX_DEPTH = 64
UNBOUNDED = 0xFFFFFFFF


class Malformed(Exception):
    """The bytes are not XDR of the type read."""


class NotOneTransfer(Exception):
    """The operations are not one InvokeHostFunction."""


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

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


def muxed_account(r: Reader) -> bytes:
    """A MuxedAccount's Ed25519 key, its id left out."""
    kind = r.enum(frozenset({0, 256}))
    if kind == 256:
        r.u64()
    return r.opaque(32)


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
    """An ScVal's type, its address when it is one, its i128 when it is one, its span, and the deepest nesting of
    vectors and maps within it (a contract instance's storage counting as a map), itself level 1 when it is one; 0 for
    any other ScVal."""

    kind: int
    address: Address | None
    i128: int | None
    start: int
    end: int
    nesting: int


def _executable(r: Reader) -> None:
    kind = r.enum(range(0, 3))
    if kind == 0:
        r.opaque(32)
    elif kind == 2:
        sc_address(r)
        r.var_opaque()


def _sc_head(r: Reader) -> tuple[int, Address | None, int | None, int | None]:
    """One ScVal's type and what follows it: for a vector, a map or a contract instance, how many ScVals it holds,
    which follow it in order (a map entry being its key and its value); for any other type, its body, read, with its
    address or its i128 when it is one, and None for what it holds."""
    kind = r.enum(range(0, 23))
    address = None
    i128 = None
    if kind == 16:
        return kind, None, None, r.count() if r.flag() else 0
    if kind == 17:
        return kind, None, None, 2 * r.count() if r.flag() else 0
    if kind == 19:
        _executable(r)
        return kind, None, None, 2 * r.count() if r.flag() else 0
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
    elif kind == 18:
        address = sc_address(r)
    elif kind == 21:
        r.i64()
    return kind, address, i128, None


def sc_val(r: Reader) -> Val:
    """One ScVal, read whole with a stack of the containers open around the value read next."""
    start = r.at
    kind, address, i128, held = _sc_head(r)
    nesting = 0 if held is None else 1
    remaining = [held] if held else []
    while remaining:
        if remaining[-1] == 0:
            remaining.pop()
            continue
        remaining[-1] -= 1
        inner = _sc_head(r)[3]
        if inner is not None:
            nesting = max(nesting, len(remaining) + 1)
            if inner:
                remaining.append(inner)
    return Val(kind, address, i128, start, r.at, nesting)


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


def _nesting_of(values: list[Val]) -> int:
    return max((v.nesting for v in values), default=0)


def _create_contract(r: Reader, v2: bool) -> int:
    """A contract creation, and the deepest ScVal nesting among its constructor arguments (V2 only)."""
    _contract_id_preimage(r)
    _executable(r)
    return _nesting_of(sc_vals(r)) if v2 else 0


@dataclass(frozen=True, slots=True)
class Invocation:
    """A SorobanAuthorizedInvocation: its contract call (None for a contract creation), how many sub-invocations it
    holds, and the deepest nesting within it, of authorized invocations (itself level 1) or of the ScVal vectors and
    maps of any of their arguments."""

    call: Call | None
    subs: int
    nesting: int


def _invocation_head(r: Reader) -> tuple[Call | None, int, int]:
    """One authorized invocation's function, how many sub-invocations follow it, and the deepest ScVal nesting among
    its arguments."""
    kind = r.enum(range(0, 3))
    if kind == 0:
        call = invoke_contract_args(r)
        return call, r.count(), _nesting_of(call.args)
    nesting = _create_contract(r, kind == 2)
    return None, r.count(), nesting


def invocation(r: Reader) -> Invocation:
    """One authorized invocation with its sub-invocations, read whole with a stack of the invocations open around the
    one read next."""
    call, subs, nesting = _invocation_head(r)
    nesting = max(nesting, 1)
    remaining = [subs] if subs else []
    while remaining:
        if remaining[-1] == 0:
            remaining.pop()
            continue
        remaining[-1] -= 1
        _, inner, args = _invocation_head(r)
        nesting = max(nesting, args, len(remaining) + 1)
        if inner:
            remaining.append(inner)
    return Invocation(call, subs, nesting)


@dataclass(frozen=True, slots=True)
class Credentials:
    """An authorization entry's address credentials: V1 or V2, the address, the nonce, the offset of the expiration
    ledger, the span of the signature, and the signature's ScVal nesting."""

    v2: bool
    address: Address
    nonce: int
    expiration: int
    expiration_at: int
    signature_start: int
    signature_end: int
    nesting: int


@dataclass(frozen=True, slots=True)
class Entry:
    """An authorization entry: its credentials' kind (0 the source account, 1 address, 2 address V2, 3 address with
    delegates), its address credentials of kind 1 or 2, its root invocation's bytes, the root invocation, and the
    deepest nesting within the address credentials' signature and the invocations."""

    kind: int
    credentials: Credentials | None
    invocation: bytes
    root: Invocation
    nesting: int


def _address_credentials(r: Reader, v2: bool) -> Credentials:
    address = sc_address(r)
    nonce = r.i64()
    expiration_at = r.at
    expiration = r.u32()
    signature = sc_val(r)
    return Credentials(v2, address, nonce, expiration, expiration_at, signature.start, signature.end, signature.nesting)


def _delegates(r: Reader) -> None:
    """A list of delegate signatures, read whole: each delegate's address, its signature and its own delegates, which
    follow it before its next sibling."""
    pending = r.count()
    while pending:
        pending -= 1
        sc_address(r)
        sc_val(r)
        pending += r.count()


def auth_entry(r: Reader) -> Entry:
    kind = r.enum(range(0, 4))
    credentials = None
    if kind in (1, 2):
        credentials = _address_credentials(r, kind == 2)
    elif kind == 3:
        _address_credentials(r, False)
        _delegates(r)
    start = r.at
    root = invocation(r)
    signed = 0 if credentials is None else credentials.nesting
    return Entry(kind, credentials, r.data[start : r.at], root, max(signed, root.nesting))


# ── the transaction ──────────────────────────────────────────────────────────────────────────────────────────────


@dataclass
class Invoke:
    """An InvokeHostFunction operation: its contract call (None for another host function), the deepest ScVal nesting
    among its host function's arguments, and its authorization entries."""

    call: Call | None
    nesting: int
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


def _claim_predicate(r: Reader) -> None:
    """A claim predicate, read whole: an and or an or holds its predicates, a not one optional predicate, each of which
    follows it."""
    pending = 1
    while pending:
        pending -= 1
        kind = r.enum(range(0, 6))
        if kind in (1, 2):
            pending += r.count(2)
        elif kind == 3 and r.flag():
            pending += 1
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
            _claim_predicate(r)
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


def _invoke(r: Reader) -> Invoke:
    """An InvokeHostFunction operation."""
    kind = r.enum(range(0, 4))
    call = None
    nesting = 0
    if kind == 0:
        call = invoke_contract_args(r)
        nesting = _nesting_of(call.args)
    elif kind == 2:
        r.var_opaque()
    else:
        nesting = _create_contract(r, kind == 3)
    entries = [auth_entry(r) for _ in range(r.count())]
    return Invoke(call, nesting, entries)


@dataclass(frozen=True, slots=True)
class Envelope:
    """A v1 transaction's one invoke, where its source account's bytes sit, and whether it came in a fee bump; the
    Ed25519 keys of the v1 transaction's source account and of the operation's, None when the operation names none."""

    fee_bump: bool
    source_start: int
    source_end: int
    invoke: Invoke
    source: bytes
    operation_source: bytes | None


def _signatures(r: Reader) -> None:
    for _ in range(r.count(20)):
        r.opaque(4)
        r.var_opaque(64)


@dataclass(frozen=True, slots=True)
class _V1:
    source_start: int
    source_end: int
    source: bytes
    operations: list[tuple[bytes | None, Invoke | None]]


def _v1(r: Reader) -> _V1:
    source_start = r.at
    source = muxed_account(r)
    source_end = r.at
    r.u32()
    r.i64()
    _preconditions(r)
    _memo(r)
    operations: list[tuple[bytes | None, Invoke | None]] = []
    for _ in range(r.count(100)):
        operation_source = muxed_account(r) if r.flag() else None
        kind = r.enum(range(0, 27))
        if kind == 24:
            operations.append((operation_source, _invoke(r)))
        else:
            _operation(r, kind)
            operations.append((operation_source, None))
    _transaction_ext(r)
    _signatures(r)
    return _V1(source_start, source_end, source, operations)


def envelope(data: bytes) -> Envelope:
    """The envelope's one invoke. Raises Malformed for bytes that are not an envelope of a v1 transaction or a fee
    bump of one, and NotOneTransfer when its operations are not one InvokeHostFunction."""
    r = Reader(data)
    kind = r.enum(frozenset({0, 2, 5}))
    if kind == 0:
        raise Malformed
    if kind == 2:
        v1 = _v1(r)
    else:
        muxed_account(r)
        r.i64()
        r.enum(frozenset({2}))
        v1 = _v1(r)
        r.enum(range(0, 1))
        _signatures(r)
    if r.remaining:
        raise Malformed
    if len(v1.operations) != 1:
        raise NotOneTransfer
    operation_source, invoke = v1.operations[0]
    if invoke is None:
        raise NotOneTransfer
    return Envelope(kind == 5, v1.source_start, v1.source_end, invoke, v1.source, operation_source)
