"""Sui's TransactionData as the x402/exact/sui binding reads it, from transactions written here byte by byte in BCS's
layout (@mysten/sui 2.35.0's schema). Expected values come from that layout, from the WHATWG Encoding standard's UTF-8
decoder and encoder as @mysten/bcs 2.1.2 runs them for a String (TextDecoder with fatal and ignoreBOM set,
TextEncoder), and from the vector file's fixed values; digests are hashlib's Blake2b-256."""

import base64
import hashlib
import sys
from collections.abc import Callable

import pytest

from integraledger_terms import X402_EXACT_SUI, Refusal
from integraledger_terms.bindings._bcs import STRING, BcsError
from integraledger_terms.bindings._codec import b58_encode
from integraledger_terms.bindings._sui_tx import parse_transaction_data
from integraledger_terms.bindings.x402_exact_sui import decode_sui_tx, sui_carrier

from support import load

SUI = load("x402-exact-sui.json")
H = bytes.fromhex(SUI["fixed"]["H"][2:])
SENDER = bytes([0x11]) * 32
TWO = bytes(31) + b"\x02"


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def u64(n: int) -> bytes:
    return n.to_bytes(8, "little")


def bcs_bytes(b: bytes) -> bytes:
    return uleb(len(b)) + b


def pure(b: bytes) -> bytes:
    """CallArg::Pure."""
    return b"\x00" + bcs_bytes(b)


def move_call(module: bytes = b"m", function: bytes = b"f", types: tuple[bytes, ...] = ()) -> bytes:
    """Command::MoveCall on package 0x2, with no arguments."""
    return b"\x00" + TWO + bcs_bytes(module) + bcs_bytes(function) + uleb(len(types)) + b"".join(types) + uleb(0)


def transaction(inputs: list[bytes], commands: list[bytes], kind: int = 0, expiration: bytes = b"\x00") -> bytes:
    """TransactionData::V1 of the kind (0 is ProgrammableTransaction), with gas paid by the sender from no objects at
    price 1000 and budget 5000000, and the expiration (None by default)."""
    body = uleb(len(inputs)) + b"".join(inputs) + uleb(len(commands)) + b"".join(commands)
    gas = uleb(0) + SENDER + u64(1000) + u64(5_000_000)
    return b"\x00" + uleb(kind) + body + SENDER + gas + expiration


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def digest(data: bytes) -> str:
    return b58_encode(hashlib.blake2b(b"TransactionData::" + data, digest_size=32).digest())


def payment(transaction: str) -> dict[str, object]:
    return {"x402Version": 2, "accepted": SUI["fixed"]["O"], "payload": {"signature": "AAAA", "transaction": transaction}}


# ── A String: strict UTF-8, a leading U+FEFF kept.


@pytest.mark.parametrize(
    ("utf8", "text"),
    [
        ("", ""),
        ("636f696e", "coin"),
        ("efbbbf636f696e", "﻿coin"),
        ("efbbbfefbbbf", "﻿﻿"),
        ("c3a9", "é"),
        ("f09f9880", "\U0001f600"),
        ("efbfbd", "�"),
    ],
)
def test_a_string_reads_its_utf8_with_a_leading_bom_kept(utf8: str, text: str) -> None:
    data = bytes.fromhex(utf8)
    assert STRING.parse(bcs_bytes(data)) == text


@pytest.mark.parametrize(
    "utf8",
    [
        "ff",  # never a UTF-8 byte
        "80",  # a continuation byte first
        "c080",  # an overlong NUL
        "e08080",  # an overlong three-byte form
        "eda080",  # a surrogate's three bytes
        "f4908080",  # past U+10FFFF
        "f09f98",  # a four-byte sequence cut short
        "efbb",  # a BOM cut short
        "efbbbfff",  # a BOM, then a byte that is not UTF-8
    ],
)
def test_a_string_of_bytes_that_are_not_utf8_raises(utf8: str) -> None:
    with pytest.raises(BcsError):
        STRING.parse(bcs_bytes(bytes.fromhex(utf8)))


@pytest.mark.parametrize(
    ("text", "utf8"),
    [
        ("\U0001f600", "f09f9880"),
        ("\ud83d\ude00", "f09f9880"),  # the same pair held as two code points: the one character they form
        ("a\ud83d\ude00b", "61f09f988062"),
        ("\ud83d", "efbfbd"),  # a lone high surrogate is U+FFFD
        ("\ude00", "efbfbd"),  # a lone low surrogate is U+FFFD
        ("\ude00\ud83d", "efbfbdefbfbd"),  # low then high is no pair
        ("\ufeffcoin", "efbbbf636f696e"),
    ],
)
def test_a_string_writes_the_utf8_textencoder_writes(text: str, utf8: str) -> None:
    data = bytes.fromhex(utf8)
    assert STRING.serialize(text) == bcs_bytes(data)


def test_a_call_whose_module_name_is_led_by_a_bom_decodes_and_carries_h() -> None:
    """The name reads as its exact bytes, so the transaction serialises back to itself."""
    data = transaction([pure(H)], [move_call(module=b"\xef\xbb\xbfcoin", function=b"value")])
    tx = decode_sui_tx(b64(data))
    assert not isinstance(tx, Refusal), tx
    assert (tx.digest, sui_carrier(tx)) == (digest(data), SUI["fixed"]["H"])
    assert X402_EXACT_SUI.bound(payment(b64(data))) == SUI["fixed"]["H"]


def test_a_call_whose_name_is_not_utf8_is_malformed() -> None:
    for name in (b"\xff", b"\xc0\x80", b"\xed\xa0\x80", b"co\xefin"):
        data = transaction([pure(H)], [move_call(module=name)])
        assert decode_sui_tx(b64(data)) == Refusal("sui/tx-malformed"), name


# ── An Epoch expiration: Sui's EpochId is a u64.

V2 = base64.b64decode(SUI["V2"]["tx"]["transactionBase64"])


def test_v2_ends_with_its_epoch_expiration() -> None:
    """Recipe R's expiration is its last field: TransactionExpiration::Epoch (1) and the epoch as eight bytes,
    little-endian."""
    assert V2[-9] == 1 and int.from_bytes(V2[-8:], "little") == int(SUI["V2"]["expectReference"]["untilEpoch"])


@pytest.mark.parametrize("epoch", [2**53 - 1, 2**53, 2**53 + 1, 2**63 + 1, 2**64 - 1])
def test_an_epoch_at_any_u64_reads_exactly(epoch: int) -> None:
    data = V2[:-8] + u64(epoch)
    tx = decode_sui_tx(b64(data))
    assert not isinstance(tx, Refusal), tx
    assert (tx.until_epoch, tx.digest, sui_carrier(tx)) == (epoch, digest(data), SUI["fixed"]["H"])


def test_an_epoch_with_a_byte_after_it_is_malformed() -> None:
    assert decode_sui_tx(b64(V2[:-8] + u64(2**53 + 1) + b"\x00")) == Refusal("sui/tx-malformed")


# ── A type nested to Sui's type depth limit: the protocol config's max_type_argument_depth is 16, and Sui's
# transaction checks refuse a type with a node at that depth, the outermost node at depth 1, in a call's type arguments
# and a vector's element type; a funds withdrawal's Balance<T> holds at most 16 nodes, so its T holds at most 15.


def vectors(levels: int) -> bytes:
    """TypeTag vector<...<u8>> with levels nodes: vector is 6 before its element type, u8 is 1."""
    return b"\x06" * (levels - 1) + b"\x01"


def struct(*params: bytes) -> bytes:
    """TypeTag struct 0x2::m::S with the type parameters."""
    return b"\x07" + TWO + bcs_bytes(b"m") + bcs_bytes(b"S") + uleb(len(params)) + b"".join(params)


SHAPES: dict[str, Callable[[bytes], bytes]] = {
    "a call's type argument": lambda t: transaction([pure(H)], [move_call(types=(t,))]),
    "a vector's element type": lambda t: transaction([pure(H)], [b"\x05\x01" + t + uleb(0)]),
    "a funds withdrawal's type": lambda t: transaction([pure(H), b"\x02\x00" + u64(1) + b"\x00" + t + b"\x00"], []),
}


@pytest.mark.parametrize("shape", SHAPES)
def test_a_type_of_15_levels_decodes_and_16_or_more_is_malformed(shape: str) -> None:
    ok = decode_sui_tx(b64(SHAPES[shape](vectors(15))))
    assert not isinstance(ok, Refusal), ok
    assert sui_carrier(ok) == SUI["fixed"]["H"]
    for levels in (16, 17, 1000, 20_000):
        data = SHAPES[shape](vectors(levels))
        assert decode_sui_tx(b64(data)) == Refusal("sui/tx-malformed"), levels
        assert X402_EXACT_SUI.bound(payment(b64(data))) == Refusal("sui/tx-malformed"), levels


def test_a_structs_type_parameters_sit_one_level_below_it_each_counted_on_its_own() -> None:
    call = SHAPES["a call's type argument"]
    for t in (struct(b"\x01", vectors(14)), struct(struct(vectors(13))), struct(vectors(14), b"\x01", b"\x01")):
        assert not isinstance(decode_sui_tx(b64(call(t))), Refusal)
    for t in (struct(b"\x01", vectors(15)), struct(vectors(15), b"\x01"), struct(struct(vectors(14)))):
        assert decode_sui_tx(b64(call(t))) == Refusal("sui/tx-malformed")


def test_a_type_past_the_limit_is_refused_by_its_read_at_any_recursion_limit() -> None:
    """The read counts a type's nesting and stops at the limit, so a type nested as deep as 128 KiB allows is refused
    without recursing past it, whatever the interpreter's recursion limit."""
    data = SHAPES["a call's type argument"](vectors(130_000))
    for limit in (1_000, 100_000):
        before = sys.getrecursionlimit()
        sys.setrecursionlimit(limit)
        try:
            with pytest.raises(BcsError) as raised:
                parse_transaction_data(data)
        finally:
            sys.setrecursionlimit(before)
        assert not isinstance(raised.value.__cause__, RecursionError), limit


def test_one_type_past_the_limit_among_others_within_it_is_malformed() -> None:
    data = transaction([pure(H)], [move_call(types=(vectors(15),)), move_call(types=(vectors(1), vectors(16)))])
    assert decode_sui_tx(b64(data)) == Refusal("sui/tx-malformed")


# ── Another kind: Sui's TransactionKind lists ProgrammableTransaction first (0), and ProgrammableSystemTransaction
# tenth from zero, with a programmable transaction's body.


@pytest.mark.parametrize("levels", [15, 16, 1000, 20_000])
def test_another_kind_is_not_programmable_at_every_depth_of_its_types(levels: int) -> None:
    for kind in (1, 10):
        data = transaction([pure(H)], [move_call(types=(vectors(levels),))], kind=kind)
        assert decode_sui_tx(b64(data)) == Refusal("sui/not-programmable"), kind


def test_another_kind_is_read_from_its_tag_before_its_body() -> None:
    for data in (b"\x00\x01", b"\x00\x0a\xff", b"\x00\x0b", b"\x00\x80\x00", b"\x00\x7f" + bytes(40)):
        assert decode_sui_tx(b64(data)) == Refusal("sui/not-programmable"), data.hex()
    for data in (b"", b"\x00", b"\x00\x00", b"\x01\x00", b"\x01\x01"):
        assert decode_sui_tx(b64(data)) == Refusal("sui/tx-malformed"), data.hex()
