"""The Hedera wire subset, read and written by hand: protobuf varints and length-delimited fields over the five
messages a CryptoTransfer payment uses (Transaction, SignedTransaction, TransactionBody, SignatureMap and the transfer
lists), and the transaction-id text forms."""

import base64
import re
from dataclasses import dataclass

from .._types import Refusal

MAX_TX = 8192
MAX_LIST = 16
MAX_DEPTH = 8
MAX_MEMO = 100
VALID_DURATION = 120
INT64_LIMIT = 1 << 63
UINT64_LIMIT = 1 << 64

_MAX_FIELD_NUMBER = 536_870_911
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


@dataclass(frozen=True, slots=True)
class TxId:
    account: str
    seconds: int
    nanos: int


def tx_id_text(tx_id: TxId) -> str:
    """0.0.1235@1700000000.000000000"""
    return f"{tx_id.account}@{tx_id.seconds}.{tx_id.nanos:09d}"


def tx_id_mirror(tx_id: TxId) -> str:
    """0.0.1235-1700000000-000000000, the Mirror Node's form."""
    return f"{tx_id.account}-{tx_id.seconds}-{tx_id.nanos:09d}"


@dataclass(frozen=True, slots=True)
class HederaBody:
    tx_id: TxId
    valid_duration: int
    memo: str
    body_bytes: bytes


@dataclass(frozen=True, slots=True)
class _Field:
    n: int
    wt: int
    varint: int
    data: bytes


# ── read ──────────────────────────────────────────────────────────────────────────────────────────────────────────


def _varint_at(buf: bytes, at: int) -> tuple[int, int] | None:
    """The varint at `at` and the index after it: at most 10 bytes and below 2^64."""
    value = 0
    for k in range(10):
        if at + k >= len(buf):
            return None
        b = buf[at + k]
        value |= (b & 0x7F) << (7 * k)
        if b & 0x80 == 0:
            return (value, at + k + 1) if value < UINT64_LIMIT else None
    return None


def _fields_of(buf: bytes) -> list[_Field] | None:
    """Every field of one message, in wire order; None when the bytes are not a well-formed message."""
    out: list[_Field] = []
    i = 0
    while i < len(buf):
        key = _varint_at(buf, i)
        if key is None:
            return None
        i = key[1]
        n, wt = key[0] >> 3, key[0] & 7
        if n < 1 or n > _MAX_FIELD_NUMBER:
            return None
        if wt == 0:
            v = _varint_at(buf, i)
            if v is None:
                return None
            out.append(_Field(n, wt, v[0], b""))
            i = v[1]
        elif wt in (1, 5):
            size = 8 if wt == 1 else 4
            if i + size > len(buf):
                return None
            out.append(_Field(n, wt, 0, buf[i : i + size]))
            i += size
        elif wt == 2:
            length = _varint_at(buf, i)
            if length is None or length[0] > len(buf) - length[1]:
                return None
            end = length[1] + length[0]
            out.append(_Field(n, wt, 0, buf[length[1] : end]))
            i = end
        else:
            return None
    return out


class _Repeated:
    """A field that must appear once appeared again, or with another wire type."""


_REPEATED = _Repeated()


def _single(fields: list[_Field], n: int, wt: int) -> _Field | None | _Repeated:
    """The one field numbered n, of wire type wt: None when absent, _REPEATED when repeated or mistyped."""
    found: _Field | None = None
    for f in fields:
        if f.n != n:
            continue
        if f.wt != wt or found is not None:
            return _REPEATED
        found = f
    return found


def _int64_of(v: int) -> int:
    return v - UINT64_LIMIT if v >= INT64_LIMIT else v


def decode_hedera_tx(wire: object) -> list[HederaBody] | Refusal:
    """A wire Transaction, or a TransactionList of them (a top-level field 1): each body's transaction id, valid
    duration, memo and exact bytes. Every body of a list must share id and memo."""
    if not isinstance(wire, (bytes, bytearray)):
        return Refusal("hedera/tx-malformed")
    if len(wire) > MAX_TX:
        return Refusal("hedera/tx-too-large")
    wire = bytes(wire)
    top = _fields_of(wire)
    if top is None or len(top) == 0:
        return Refusal("hedera/tx-malformed")
    if not any(f.n == 1 for f in top):
        body = _transaction_of(top, 1)
        return body if isinstance(body, Refusal) else [body]
    if any(f.n != 1 or f.wt != 2 for f in top):
        return Refusal("hedera/tx-malformed")
    if len(top) > MAX_LIST:
        return Refusal("hedera/tx-malformed")
    bodies: list[HederaBody] = []
    for entry in top:
        fields = _fields_of(entry.data)
        if fields is None:
            return Refusal("hedera/tx-malformed")
        body = _transaction_of(fields, 2)
        if isinstance(body, Refusal):
            return body
        bodies.append(body)
    first = bodies[0]
    same = all(tx_id_text(b.tx_id) == tx_id_text(first.tx_id) and b.memo == first.memo for b in bodies)
    return bodies if same else Refusal("hedera/list-inconsistent")


def _transaction_of(tx: list[_Field], depth: int) -> HederaBody | Refusal:
    """Transaction -> SignedTransaction -> TransactionBody. Transaction fields 1 to 4 are deprecated."""
    if depth > MAX_DEPTH:
        return Refusal("hedera/tx-malformed")
    if any(1 <= f.n <= 4 for f in tx):
        return Refusal("hedera/deprecated-fields")
    signed = _single(tx, 5, 2)
    if not isinstance(signed, _Field):
        return Refusal("hedera/tx-malformed")
    signed_fields = _fields_of(signed.data)
    if signed_fields is None:
        return Refusal("hedera/tx-malformed")
    body_field = _single(signed_fields, 1, 2)
    if not isinstance(body_field, _Field):
        return Refusal("hedera/tx-malformed")
    body = _body_of(body_field.data, depth + 2)
    return Refusal("hedera/tx-malformed") if body is None else body


def _body_of(body_bytes: bytes, depth: int) -> HederaBody | None:
    """TransactionBody: transactionID (1), transactionValidDuration (4), memo (6)."""
    if depth + 3 > MAX_DEPTH:
        return None
    fields = _fields_of(body_bytes)
    if fields is None:
        return None
    id_field = _single(fields, 1, 2)
    duration_field = _single(fields, 4, 2)
    memo_field = _single(fields, 6, 2)
    if not isinstance(id_field, _Field) or duration_field is _REPEATED or memo_field is _REPEATED:
        return None

    id_fields = _fields_of(id_field.data)
    if id_fields is None:
        return None
    start_field = _single(id_fields, 1, 2)
    account_field = _single(id_fields, 2, 2)
    if not isinstance(start_field, _Field) or not isinstance(account_field, _Field):
        return None
    start = _fields_of(start_field.data)
    account = _account_of(account_field.data)
    if start is None or account is None:
        return None
    seconds = _single(start, 1, 0)
    nanos = _single(start, 2, 0)
    if seconds is _REPEATED or nanos is _REPEATED:
        return None
    s = _int64_of(seconds.varint) if isinstance(seconds, _Field) else 0
    ns = _int64_of(nanos.varint) if isinstance(nanos, _Field) else 0
    if s < 0 or ns < 0 or ns > 999_999_999:
        return None

    valid_duration = 0
    if isinstance(duration_field, _Field):
        d = _fields_of(duration_field.data)
        if d is None:
            return None
        ds = _single(d, 1, 0)
        if ds is _REPEATED:
            return None
        v = _int64_of(ds.varint) if isinstance(ds, _Field) else 0
        if v < 0 or v > 1_000_000:
            return None
        valid_duration = v

    memo = ""
    if isinstance(memo_field, _Field):
        if len(memo_field.data) > MAX_MEMO:
            return None
        try:
            memo = memo_field.data.decode("utf-8")
        except UnicodeDecodeError:
            return None
    return HederaBody(TxId(account, s, ns), valid_duration, memo, body_bytes)


def _account_of(data: bytes) -> str | None:
    """AccountID {shardNum 1, realmNum 2, accountNum 3} as shard.realm.num; an alias account (4) is not read."""
    f = _fields_of(data)
    if f is None or any(x.n == 4 for x in f):
        return None
    parts: list[int] = []
    for n in (1, 2, 3):
        x = _single(f, n, 0)
        if x is _REPEATED:
            return None
        v = _int64_of(x.varint) if isinstance(x, _Field) else 0
        if v < 0:
            return None
        parts.append(v)
    return ".".join(str(p) for p in parts)


# ── write ─────────────────────────────────────────────────────────────────────────────────────────────────────────


def _varint(v: int) -> bytes:
    x = v + UINT64_LIMIT if v < 0 else v
    out = bytearray()
    while True:
        b = x & 0x7F
        x >>= 7
        out.append(b | 0x80 if x else b)
        if not x:
            return bytes(out)


def v_field(n: int, v: int) -> bytes:
    """A varint field; a zero value is not written."""
    return b"" if v == 0 else _varint(n << 3) + _varint(v)


def len_field(n: int, data: bytes) -> bytes:
    """A length-delimited field, written even when empty."""
    return _varint((n << 3) | 2) + _varint(len(data)) + data


def len_field_non_empty(n: int, data: bytes) -> bytes:
    """A length-delimited field; an empty value is not written."""
    return len_field(n, data) if data else b""


def _zigzag(v: int) -> int:
    return v << 1 if v >= 0 else (-v << 1) - 1


def entity(entity_id: str) -> bytes:
    """A shard.realm.num entity id as {shardNum 1, realmNum 2, num 3}."""
    shard, realm, num = (int(p) for p in entity_id.split("."))
    return v_field(1, shard) + v_field(2, realm) + v_field(3, num)


def account_amount(account: str, amount: int) -> bytes:
    """AccountAmount {accountID 1, amount 2 as sint64}."""
    return len_field(1, entity(account)) + v_field(2, _zigzag(amount))


def tx_id_field(seconds: int, nanos: int, account: str) -> bytes:
    """TransactionID {transactionValidStart 1 {seconds 1, nanos 2}, accountID 2}."""
    return len_field(1, v_field(1, seconds) + v_field(2, nanos)) + len_field(2, entity(account))


def write_body(tx_id: bytes, node: str, max_fee: int, memo: str, transfer: bytes) -> bytes:
    """TransactionBody: transactionID 1, nodeAccountID 2, transactionFee 3, transactionValidDuration 4 (120 s), memo 6,
    cryptoTransfer 14; in field-number order, with zero and empty values not written."""
    return (
        len_field(1, tx_id)
        + len_field(2, entity(node))
        + v_field(3, max_fee)
        + len_field(4, v_field(1, VALID_DURATION))
        + len_field_non_empty(6, memo.encode("utf-8"))
        + len_field(14, transfer)
    )


def complete_with(body_bytes: bytes, s: object) -> str | Refusal:
    """Transaction {5: SignedTransaction {1: bodyBytes, 2: SignatureMap {1: SignaturePair}}}, base64. The pair holds
    the full public key (1) and the Ed25519 (3) or ECDSA secp256k1 (6) signature."""
    if not isinstance(s, dict):
        return Refusal("hedera/tx-malformed")
    public_key, signature, kind = s.get("publicKey"), s.get("signature"), s.get("type")
    if not isinstance(public_key, bytes) or not isinstance(signature, bytes):
        return Refusal("hedera/tx-malformed")
    key_length = 32 if kind == "ed25519" else 33 if kind == "ecdsa-secp256k1" else -1
    if len(public_key) != key_length or len(signature) != 64:
        return Refusal("hedera/tx-malformed")
    pair = len_field(1, public_key) + len_field(3 if kind == "ed25519" else 6, signature)
    signed = len_field(1, body_bytes) + len_field(2, len_field(1, pair))
    return base64.b64encode(len_field(5, signed)).decode("ascii")


def from_base64(text: object) -> bytes | None:
    """Standard padded base64 whose length is a multiple of 4, or None."""
    if not isinstance(text, str) or len(text) % 4 != 0 or _BASE64.fullmatch(text) is None:
        return None
    return base64.b64decode(text)
