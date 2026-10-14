"""The Solana rail helpers each answer as @integraledger/lcp 0.4.0's do: the wire text's length in UTF-16 code units,
the signed wire's length guard, the Ed25519 point rule, @solana/kit 8.4.0's v0 compile limits and TextEncoder's memo
length; and each x402 build of a hash carried in its option refuses an h that is not a hash first."""

import base64
from typing import Any

import pytest
from support import load

from integraledger_terms import (
    X402_BATCH_SETTLEMENT_SOLANA,
    X402_EXACT_SOLANA,
    X402_EXACT_STELLAR,
    X402_EXACT_XRPL,
    X402_UPTO_SOLANA,
    Refusal,
)
from integraledger_terms.bindings import _svm
from integraledger_terms.bindings._codec import b58_encode

PAYER = load("x402-exact-solana.json")["fixed"]["payer"]
# The wire bound lcp's wireOf holds a text to before it decodes: ceil(1232 / 3) * 4 + 4 characters.
WIRE_TEXT_BOUND = 1648


def test_the_wire_text_is_measured_in_utf_16_code_units() -> None:
    """lcp's wireOf compares String.prototype.length with the bound, so an astral character counts two: 825 of them
    are 1650 units, past the bound, and svm/tx-too-large; 824 are 1648 units, within it, and svm/tx-malformed."""
    assert _svm.wire_of("\U0001f600" * (WIRE_TEXT_BOUND // 2 + 1)) == Refusal("svm/tx-too-large")
    assert _svm.wire_of("\U0001f600" * (WIRE_TEXT_BOUND // 2)) == Refusal("svm/tx-malformed")
    assert _svm.wire_of(chr(0xE9) * WIRE_TEXT_BOUND) == Refusal("svm/tx-malformed")
    assert _svm.wire_of(chr(0xE9) * (WIRE_TEXT_BOUND + 1)) == Refusal("svm/tx-too-large")


@pytest.mark.parametrize("message", [b"", b"\x80", b"\x01"], ids=["empty", "80", "01"])
def test_a_message_under_two_bytes_is_tx_malformed(message: bytes) -> None:
    """lcp's signedWire answers svm/tx-malformed for a message under 2 bytes, with a valid signer and signature; a
    signer that is not a key is svm/input-malformed first."""
    assert _svm.signed_wire(message, PAYER, bytes(64)) == Refusal("svm/tx-malformed")
    assert _svm.signed_wire(message, "x", bytes(64)) == Refusal("svm/input-malformed")


@pytest.mark.parametrize(
    "encoding",
    [
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ],
    ids=["y 1, sign set", "y p - 1, sign set", "y p + 1, sign set"],
)
def test_x_zero_with_the_sign_bit_set_is_a_point(encoding: str) -> None:
    """@noble/curves 2.4.0's ed25519.Point.fromBytes(b, true), the point rule lcp's PDA search uses, decompresses each
    of these, whose x is 0 with the sign bit set."""
    assert _svm.is_point(bytes.fromhex(encoding))


def _key(i: int) -> str:
    return b58_encode(bytes([7]) + i.to_bytes(4, "big") + bytes(27))


FEE_PAYER, PROGRAM, BLOCKHASH = _key(1_000_000), _key(1_000_001), _key(1_000_002)


def _compile(instructions: list[_svm.Instruction]) -> object:
    return _svm.compile_v0(FEE_PAYER, BLOCKHASH, instructions)


def _accounts(n: int, role: int) -> tuple[tuple[str, int], ...]:
    return tuple((_key(i), role) for i in range(n))


@pytest.mark.parametrize(
    ("within", "past"),
    [
        # 64 static accounts: the fee payer, the program and 62 more.
        ([_svm.Instruction(PROGRAM, _accounts(62, _svm.READONLY), b"")], [_svm.Instruction(PROGRAM, _accounts(63, _svm.READONLY), b"")]),
        # 12 signers: the fee payer and 11 more.
        ([_svm.Instruction(PROGRAM, _accounts(11, _svm.READONLY_SIGNER), b"")], [_svm.Instruction(PROGRAM, _accounts(12, _svm.READONLY_SIGNER), b"")]),
        # 64 instructions.
        ([_svm.Instruction(PROGRAM, (), b"")] * 64, [_svm.Instruction(PROGRAM, (), b"")] * 65),
        # 255 accounts named by one instruction.
        ([_svm.Instruction(PROGRAM, ((_key(1), _svm.READONLY),) * 255, b"")], [_svm.Instruction(PROGRAM, ((_key(1), _svm.READONLY),) * 256, b"")]),
        # 65 535 bytes of data, the most a compact-u16 length holds.
        ([_svm.Instruction(PROGRAM, (), bytes(65535))], [_svm.Instruction(PROGRAM, (), bytes(65536))]),
    ],
    ids=["accounts", "signers", "instructions", "accounts in an instruction", "data"],
)
def test_compile_holds_kits_v0_limits(within: list[_svm.Instruction], past: list[_svm.Instruction]) -> None:
    """@solana/kit 8.4.0, lcp's dev pin, compiles a v0 message of at most 64 accounts, 12 signers and 64 instructions,
    each naming at most 255 accounts, and encodes each length as a compact-u16; past any of these lcp's compileV0
    answers svm/input-malformed."""
    assert isinstance(_compile(within), bytes)
    assert _compile(past) == Refusal("svm/input-malformed")


@pytest.mark.parametrize(
    ("memo", "length"),
    [
        (chr(0x1F600), 4),
        (chr(0xD83D) + chr(0xDE00), 4),
        (chr(0xD83D), 3),
        (chr(0xDE00) + chr(0xD83D), 6),
        (chr(0xD83D) + "a" + chr(0xDE00), 7),
        (chr(0xE9), 2),
    ],
    ids=["a pair as one code point", "a pair as two", "a lone high", "a reversed pair", "a pair split by a", "e acute"],
)
def test_the_memo_length_is_textencoders(memo: str, length: int) -> None:
    """lcp measures a memo with new TextEncoder().encode(memo).length: a surrogate pair is one four-byte character,
    however Python holds it, and each lone surrogate is U+FFFD's three bytes (WHATWG Encoding, UTF-8 encode)."""
    assert _svm.memo_length(memo) == length


# The member of each vector file whose accepted is the pairing's option.
OPTION_OF = {
    "x402-exact-solana.json": "V2",
    "x402-upto-solana.json": "EU4",
    "x402-exact-xrpl.json": "V2",
    "x402-exact-stellar.json": "V3",
    "x402-batch-settlement.json": "ES4",
}


def _option(name: str) -> dict[str, Any]:
    accepted: dict[str, Any] = load(name)[OPTION_OF[name]]["accepted"]
    return accepted


BUILDS: list[tuple[Any, str]] = [
    (X402_EXACT_SOLANA, "x402-exact-solana.json"),
    (X402_UPTO_SOLANA, "x402-upto-solana.json"),
    (X402_EXACT_XRPL, "x402-exact-xrpl.json"),
    (X402_EXACT_STELLAR, "x402-exact-stellar.json"),
    (X402_BATCH_SETTLEMENT_SOLANA, "x402-batch-settlement.json"),
]


@pytest.mark.parametrize(("binding", "name"), BUILDS, ids=[b.id for b, _ in BUILDS])
@pytest.mark.parametrize("h", ["abc", "0X" + "ab" * 32, None, 5, "ab" * 32], ids=["abc", "0X", "null", "a number", "no 0x"])
def test_a_build_refuses_an_h_that_is_not_a_hash_first(binding: Any, name: str, h: Any) -> None:
    """lcp 0.4.0's exact Solana, upto Solana, exact XRPL, exact Stellar and batch Solana builds answer
    x402/payload-malformed when normalHash(h) is null, right after the option's own checks and before the carrier."""
    accepted = _option(name)
    required = {"x402Version": 2, "resource": {"url": "https://example.com/x"}, "accepts": [accepted]}
    assert binding.build({"required": required, "accepted": accepted}, h) == Refusal("x402/payload-malformed")


def test_the_wire_reader_reads_a_canonical_wire() -> None:
    """A control on the length measure: a canonical wire of 1232 bytes, 1644 characters, decodes."""
    assert _svm.wire_of(base64.b64encode(bytes(1232)).decode()) == bytes(1232)
