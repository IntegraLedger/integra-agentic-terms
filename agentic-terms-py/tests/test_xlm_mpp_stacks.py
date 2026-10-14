"""mpp/charge/usdc/stacks: the TypeScript gate's B2 and B6 rows (pairings-b7.test.ts), and the buyer half's M4 rows.
Expected values are the vector file's (M4); the wallet stub answers with M4's signed transaction, as the TypeScript
gate's test does."""

import base64
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_USDC_STACKS, AtrHash, Refusal
from integraledger_terms.bindings import _stacks

from breadth import H, LINK, Pairing, build_and_sign, plant
from mpp_docs import issued, placed_doc
from support import load

V = load("mpp-charge-usdc-stacks.json")
F: dict[str, Any] = V["fixed"]
M4: dict[str, Any] = V["M4"]
WIRE = bytes.fromhex(M4["wireHex"][2:])


def request_json() -> str:
    return json.dumps(F["request"], separators=(",", ":"))


def answer(request: Any) -> Any:
    assert request["kind"] == "stacks-contract-call", request["kind"]
    return M4["wireHex"]


STACKS = Pairing(
    binding=MPP_CHARGE_USDC_STACKS,
    doc=placed_doc(issued("usdc", "charge", request_json(), F["realm"], F["expires"]), H, LINK),
    account=f"{F['network']}:{F['sender']}",
    answer=answer,
)

def test_mpp_charge_usdc_stacks_b6_wallet_is_handed_m4_transfer_and_signed_transaction_is_bound() -> None:
    def inspect(request: Any) -> None:
        assert request == {
            "kind": "stacks-contract-call",
            "contract": F["contract"],
            "functionName": "transfer",
            "args": {"amount": F["amount"], "sender": F["sender"], "recipient": F["recipient"], "memo": H},
            "postCondition": "SentEq",
            "postConditionMode": "deny",
            "anchorMode": "onChainOnly",
        }

    signed, _ = build_and_sign(STACKS, inspect)
    assert signed["source"] == STACKS.account
    assert base64.b64decode(signed["payload"]["transaction"]) == WIRE


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def credential(wire: bytes, form: str | None = "stacks_transaction_v1") -> dict[str, Any]:
    payload: dict[str, Any] = {"type": "transaction", "transaction": base64.b64encode(wire).decode("ascii")}
    if form is not None:
        payload["transactionFormat"] = form
    return {"challenge": STACKS.doc[0], "source": STACKS.account, "payload": payload}


def test_mpp_charge_usdc_stacks_m4_bound_memo_none_and_other_format() -> None:
    assert len(WIRE) == M4["expectLength"]
    assert M4["wireHex"].startswith(M4["expectPrefix"]) and M4["wireHex"].endswith(M4["expectSuffix"][2:])
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE)) == M4["expectBound"]
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE, None)) == M4["expectBound"]
    # The same transfer with the memo argument none: the 38 bytes of (some H) become the one byte of none.
    memo_none = WIRE[: -len(bytes.fromhex(M4["expectSuffix"][2:]))] + b"\x09"
    assert len(memo_none) == M4["memoNoneLength"]
    assert MPP_CHARGE_USDC_STACKS.bound(credential(memo_none)) == Refusal(M4["expectMemoNone"]["code"])
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE, M4["otherFormat"])) == Refusal(M4["expectOtherFormat"]["code"])


def test_mpp_charge_usdc_stacks_malformed_and_type() -> None:
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE[:40])) == Refusal("mpp/stacks-tx-malformed")
    assert MPP_CHARGE_USDC_STACKS.bound(credential(b"")) == Refusal("mpp/stacks-tx-malformed")
    hashed = {**credential(WIRE), "payload": {"type": "hash", "hash": "0x" + "00" * 32}}
    assert MPP_CHARGE_USDC_STACKS.bound(hashed) == Refusal("mpp/credential-type")


def test_mpp_charge_usdc_stacks_truncated_or_extended_transaction_is_malformed() -> None:
    # SIP-005: a transaction is exactly its encoding, so bytes read short, or bytes after the encoding, are not one.
    for wire in (WIRE[:-1], WIRE + b"\x00"):
        assert MPP_CHARGE_USDC_STACKS.bound(credential(wire)) == Refusal("mpp/stacks-tx-malformed")


# ── Clarity values and a Stacks node's depth bound ───────────────────────────────────────────────────────────────
# A Stacks node reads a transaction's Clarity values to 16 levels, the outermost counting 1 (stacks-core's
# UNSANITIZED_DEPTH_CHECK). The transactions below are M4's with one value replaced, left with M4's signature, which
# bound does not verify. Each expected answer is what stacks-core 4.0.5's deserializer reads in the same bytes.

PREFIX, FT_CONDITION, CALL = WIRE[:111], WIRE[115:186], WIRE[186:]
ARGUMENTS_AT = 41  # the call's type, contract address, contract name, function name and argument count
UINT = b"\x01" + (0xA1A2A3A4A5A6A7A8).to_bytes(16, "big")
CONTAINERS = {
    "some": b"\x0a",
    "ok": b"\x07",
    "err": b"\x08",
    "list": b"\x0b\x00\x00\x00\x01",
    "tuple": b"\x0c\x00\x00\x00\x01\x01a",
}
MALFORMED = Refusal("mpp/stacks-tx-malformed")
NOT_H = Refusal("mpp/stacks-memo-not-h")


def levels(n: int, container: bytes, inner: bytes = UINT) -> bytes:
    """inner as the one value of n - 1 nested containers, so that it sits at level n."""
    return container * (n - 1) + inner


def transaction(conditions: list[bytes], payload: bytes) -> bytes:
    return PREFIX + len(conditions).to_bytes(4, "big") + b"".join(conditions) + payload


def first_argument(value: bytes) -> bytes:
    """M4's transfer with value as its first argument in place of the uint amount."""
    assert CALL[ARGUMENTS_AT : ARGUMENTS_AT + 17] == b"\x01" + int(F["amount"]).to_bytes(16, "big")
    return transaction([FT_CONDITION], CALL[:ARGUMENTS_AT] + value + CALL[ARGUMENTS_AT + 17 :])


def nft_asset_value(value: bytes) -> bytes:
    """M4's transfer under one non-fungible post-condition (the sender does not send the token's nft) on value."""
    condition = b"\x02\x02" + FT_CONDITION[2:44] + b"\x05usdcx\x03nft" + value + b"\x11"
    return transaction([condition], CALL)


def bind(wire: bytes) -> AtrHash | Refusal:
    return MPP_CHARGE_USDC_STACKS.bound(credential(wire))


def test_mpp_charge_usdc_stacks_clarity_value_past_16_levels_is_malformed() -> None:
    assert bind(first_argument(UINT)) == bind(nft_asset_value(UINT)) == M4["expectBound"]
    for name, container in CONTAINERS.items():
        for build in (first_argument, nft_asset_value):
            assert (name, bind(build(levels(16, container)))) == (name, M4["expectBound"])
            assert (name, bind(build(levels(17, container)))) == (name, MALFORMED)
    mixed = b"".join(CONTAINERS.values()) * 3
    assert bind(first_argument(mixed + UINT)) == M4["expectBound"]
    assert bind(first_argument(mixed + CONTAINERS["some"] + UINT)) == MALFORMED
    assert bind(first_argument(levels(1000, CONTAINERS["some"]))) == MALFORMED


def test_mpp_charge_usdc_stacks_depth_reads_every_element_and_member() -> None:
    lists, empty = CONTAINERS["list"], b"\x0b\x00\x00\x00\x00"
    assert bind(first_argument(levels(16, lists, empty))) == M4["expectBound"]
    assert bind(first_argument(levels(17, lists, empty))) == MALFORMED
    three = b"\x0b\x00\x00\x00\x03" + UINT * 3
    assert bind(first_argument(levels(15, lists, three))) == M4["expectBound"]
    assert bind(first_argument(levels(16, lists, three))) == MALFORMED

    def pair(a: bytes) -> bytes:
        """A tuple of two members: a, then a uint."""
        return b"\x0c\x00\x00\x00\x02\x01a" + a + b"\x01b" + UINT

    assert bind(first_argument(pair(levels(15, CONTAINERS["some"])))) == M4["expectBound"]
    assert bind(first_argument(pair(levels(16, CONTAINERS["some"])))) == MALFORMED


# ── Clarity values as a Stacks node types them ─────────────────────────────────────────────────────────────────
# stacks-core 4.0.5 reads each Clarity value a transaction carries with Value::consensus_deserialize and types it as it
# reads (clarity-types/src/types/mod.rs, signatures.rs and serialization.rs). Each table's expected answers are that
# deserializer's reading of the same bytes, run on them: H when the transaction decodes, serializes back to the same
# bytes and calls transfer with (some H) fourth, else mpp/stacks-memo-not-h; bytes it does not read are
# mpp/stacks-tx-malformed. Each transaction is M4's with one part replaced.

H_M4: AtrHash = M4["expectBound"]


def word(n: int, size: int) -> bytes:
    return n.to_bytes(size, "big")


def name(text: str) -> bytes:
    """A length byte and the name's bytes."""
    return bytes([len(text)]) + text.encode("latin-1")


def int_value(n: int) -> bytes:
    return b"\x00" + word(n, 16)


def uint_value(n: int) -> bytes:
    return b"\x01" + word(n, 16)


def buffer_value(length: int) -> bytes:
    return b"\x02" + word(length, 4) + b"A" * length


def some(value: bytes) -> bytes:
    return b"\x0a" + value


def list_value(items: list[bytes]) -> bytes:
    return b"\x0b" + word(len(items), 4) + b"".join(items)


def tuple_value(members: list[tuple[str, bytes]]) -> bytes:
    return b"\x0c" + word(len(members), 4) + b"".join(name(k) + v for k, v in members)


def ascii_value(content: bytes) -> bytes:
    return b"\x0d" + word(len(content), 4) + content


def utf8_value(content: bytes) -> bytes:
    return b"\x0e" + word(len(content), 4) + content


def assert_reads(cases: Sequence[tuple[str, bytes, AtrHash | Refusal]]) -> None:
    """Each case's bound beside its label equals the expected answer beside it."""
    assert [(label, bind(wire)) for label, wire, _ in cases] == [(label, want) for label, _, want in cases]


def test_mpp_charge_usdc_stacks_tuple_members_are_named_once_in_byte_order() -> None:
    # A tuple has members (mod.rs:1855-1870), named by Clarity names of at most 128 characters, and the serialization
    # writes them in name order as bytes (serialization.rs:1185-1193): a node writes {a, B} back as {B, a}.
    assert_reads(
        [
            ("{B, a}", first_argument(tuple_value([("B", int_value(1)), ("a", int_value(2))])), H_M4),
            ("{a-b, a_b}", first_argument(tuple_value([("a-b", int_value(1)), ("a_b", int_value(2))])), H_M4),
            ("{a, aa}", first_argument(tuple_value([("a", int_value(1)), ("aa", int_value(2))])), H_M4),
            ("{<, <=, =, >, >=}", first_argument(tuple_value([(k, UINT) for k in ("<", "<=", "=", ">", ">=")])), H_M4),
            ("a name of 128 characters", first_argument(tuple_value([("a" * 128, int_value(1))])), H_M4),
            ("the empty tuple", first_argument(tuple_value([])), MALFORMED),
            ("(some <the empty tuple>)", first_argument(some(tuple_value([]))), MALFORMED),
            ("{a, B}", first_argument(tuple_value([("a", int_value(2)), ("B", int_value(1))])), MALFORMED),
            ("{a_b, a-b}", first_argument(tuple_value([("a_b", int_value(2)), ("a-b", int_value(1))])), MALFORMED),
            ("{a, a}", first_argument(tuple_value([("a", int_value(1)), ("a", int_value(2))])), MALFORMED),
            ("a name of 129 characters", first_argument(tuple_value([("a" * 129, int_value(1))])), MALFORMED),
            ("the name 1a", first_argument(tuple_value([("1a", int_value(1))])), MALFORMED),
        ]
    )


def test_mpp_charge_usdc_stacks_list_items_have_a_least_common_type() -> None:
    # A list's type is its items' least common type (mod.rs:1149-1155; signatures.rs:1130-1281): none joins a (some
    # ...), an ok joins an err, a tuple keeps the first's members when each is in the next, an empty list joins any
    # list, buffers join at the longer length; any other two types only when equal.
    one = tuple_value([("a", int_value(1))])
    two = tuple_value([("a", int_value(2)), ("b", int_value(3))])
    assert_reads(
        [
            ("(none (some 1))", first_argument(list_value([b"\x09", some(int_value(1))])), H_M4),
            ("((ok 1) (err u1))", first_argument(list_value([b"\x07" + int_value(1), b"\x08" + uint_value(1)])), H_M4),
            ("({a 1} {a 2, b 3})", first_argument(list_value([one, two])), H_M4),
            ("((list) (list 1))", first_argument(list_value([list_value([]), list_value([int_value(1)])])), H_M4),
            ("(0x41 0x4141)", first_argument(list_value([buffer_value(1), buffer_value(2)])), H_M4),
            ("(1 u1)", first_argument(list_value([int_value(1), uint_value(1)])), MALFORMED),
            ("(1 none)", first_argument(list_value([int_value(1), b"\x09"])), MALFORMED),
            ("((some 1) (some u1))", first_argument(list_value([some(int_value(1)), some(uint_value(1))])), MALFORMED),
            ("({a 1, b 3} {a 2})", first_argument(list_value([two, one])), MALFORMED),
            (
                "((list 1) (list u1))",
                first_argument(list_value([list_value([int_value(1)]), list_value([uint_value(1)])])),
                MALFORMED,
            ),
            ('(0x41 "A")', first_argument(list_value([buffer_value(1), ascii_value(b"A")])), MALFORMED),
        ]
    )


def test_mpp_charge_usdc_stacks_string_ascii_holds_text_bytes_only() -> None:
    # A string-ascii holds alphanumeric, punctuation and whitespace bytes (space, tab, newline, form feed, carriage
    # return) and no others (mod.rs:1202-1214).
    held = [0x09, 0x0A, 0x0C, 0x0D, 0x20, 0x21, 0x7E]
    refused = [0x00, 0x0B, 0x1F, 0x7F, 0x80, 0xFF]
    assert_reads(
        [(f"byte {b:#04x}", first_argument(ascii_value(bytes([0x61, b, 0x62]))), H_M4) for b in held]
        + [(f"byte {b:#04x}", first_argument(ascii_value(bytes([0x61, b, 0x62]))), MALFORMED) for b in refused]
    )


def test_mpp_charge_usdc_stacks_string_utf8_is_well_formed_utf8_with_any_first_character() -> None:
    # A string-utf8 is well-formed UTF-8 (mod.rs:1261-1279), its bytes kept as they are: a byte-order mark is a
    # character like any other.
    assert_reads(
        [
            ("a byte-order mark", first_argument(utf8_value(bytes.fromhex("efbbbf61"))), H_M4),
            ("é", first_argument(utf8_value("é".encode())), H_M4),
            ("U+10FFFF", first_argument(utf8_value(bytes.fromhex("f48fbfbf"))), H_M4),
            ("a lone continuation byte", first_argument(utf8_value(b"\x80")), MALFORMED),
            ("an overlong /", first_argument(utf8_value(bytes.fromhex("c0af"))), MALFORMED),
            ("the surrogate U+D800", first_argument(utf8_value(bytes.fromhex("eda080"))), MALFORMED),
            ("past U+10FFFF", first_argument(utf8_value(bytes.fromhex("f4908080"))), MALFORMED),
            ("a truncated character", first_argument(utf8_value(bytes.fromhex("e282"))), MALFORMED),
        ]
    )


def test_mpp_charge_usdc_stacks_value_type_is_at_most_1_mib() -> None:
    # A value's type is at most 1,048,576 bytes (mod.rs:48): a list's is its length times its item type's size plus a
    # few bytes (signatures.rs:1553-1600), a buffer's its length plus 4, a string-utf8's 4 a character plus 4, a
    # tuple's its members' and their names' plus 2 a member and its type's own, and (some ...), (ok ...) and (err ...)
    # add 1 to the value's (mod.rs:1002-1063).
    def buffers(longest: int) -> bytes:
        return list_value([buffer_value(longest)] + [buffer_value(0)] * 199)

    def texts(characters: int) -> bytes:
        return list_value([utf8_value("é".encode() * characters)] + [utf8_value(b"")] * 199)

    def tuples(longest: int, key: str = "kk") -> bytes:
        """269 one-member tuples {key <buffer>}, the first's buffer longest bytes."""
        return list_value([tuple_value([(key, buffer_value(longest))])] + [tuple_value([(key, buffer_value(0))])] * 268)

    assert_reads(
        [
            ("200 buffers, the longest 5,238 bytes: 1,048,410", first_argument(buffers(5238)), H_M4),
            ("200 buffers, the longest 5,239 bytes: 1,048,610", first_argument(buffers(5239)), MALFORMED),
            ("200 string-utf8, the longest 1,309 characters: 1,048,010", first_argument(texts(1309)), H_M4),
            ("200 string-utf8, the longest 1,310 characters: 1,048,810", first_argument(texts(1310)), MALFORMED),
            ("269 tuples: 1,048,576", first_argument(tuples(3881)), H_M4),
            ("(some ...) of 1,048,576", first_argument(some(tuples(3881))), MALFORMED),
            ("(ok ...) of 1,048,576", first_argument(b"\x07" + tuples(3881)), MALFORMED),
            ("(some ...) of 1,048,575", first_argument(some(tuples(3883, "k"))), H_M4),
            ("{a <1,048,575>}", first_argument(tuple_value([("a", tuples(3883, "k"))])), MALFORMED),
        ]
    )


def test_mpp_charge_usdc_stacks_reader_bounds_value_lengths() -> None:
    # A buffer or string-ascii holds at most 1,048,576 bytes and a string-utf8 at most 262,144 characters (mod.rs:48,
    # :54). Each such transaction is past bound's 16 KiB, so the reader is asked directly; stacks-core 4.0.5's
    # deserializer reads the first of each pair and refuses the second.
    for prefix, most, unit in ((b"\x02", 2**20, b"A"), (b"\x0d", 2**20, b"A"), (b"\x0e", 2**18, b"a")):
        for n in (most, most + 1):
            wire = first_argument(prefix + word(n, 4) + unit * n)
            if n == most:
                assert _stacks.contract_call(wire) is not None
            else:
                with pytest.raises(_stacks.Malformed):
                    _stacks.contract_call(wire)


def test_mpp_charge_usdc_stacks_principal_value_has_version_below_32_and_a_contract_name() -> None:
    # A principal in a value has a version below 32 (mod.rs:106-111), and a contract principal's name is a letter, then
    # letters, digits, - and _, or __transient, of at most 128 characters (representations.rs:36-60).
    sender = FT_CONDITION[2:23]

    def contract(contract_name: str) -> bytes:
        return first_argument(b"\x06" + sender + name(contract_name))

    assert_reads(
        [
            ("a name of 41 characters", contract("a" * 41), H_M4),
            ("a name of 128 characters", contract("a" * 128), H_M4),
            ("__transient", contract("__transient"), H_M4),
            ("version 31", first_argument(b"\x05\x1f" + sender[1:]), H_M4),
            ("a name of 129 characters", contract("a" * 129), MALFORMED),
            ("a name starting with a digit", contract("1abc"), MALFORMED),
            ("a name holding a dot", contract("a.b"), MALFORMED),
            ("version 32", first_argument(b"\x05\x20" + sender[1:]), MALFORMED),
        ]
    )


def test_mpp_charge_usdc_stacks_function_and_asset_names_are_clarity_names() -> None:
    # A contract call's function and a post-condition's asset are named by Clarity names of at most 128 characters
    # (representations.rs:51-56, :96-116; stacks-codec/src/transaction.rs:2114-2135, :2177-2186).
    address, contract_name = CALL[1:22], CALL[22:28]
    assert contract_name == name("usdcx")

    def call(function: str) -> bytes:
        arguments = CALL[ARGUMENTS_AT - 4 :]
        return transaction([FT_CONDITION], b"\x02" + address + contract_name + name(function) + arguments)

    def asset(asset_name: str) -> bytes:
        return transaction([FT_CONDITION[:44] + contract_name + name(asset_name) + FT_CONDITION[-9:]], CALL)

    assert FT_CONDITION[44:50] == contract_name and FT_CONDITION[50:62] == name("usdcx-token")
    assert_reads(
        [
            ("the function transfer", call("transfer"), H_M4),
            ("the function transfer-memo", call("transfer-memo"), NOT_H),
            ("the function !", call("!"), MALFORMED),
            ("the function 1a", call("1a"), MALFORMED),
            ("an empty function name", call(""), MALFORMED),
            ("the asset usdcx-token", asset("usdcx-token"), H_M4),
            ("the asset <=", asset("<="), H_M4),
            ("an asset name of 128 characters", asset("a" * 128), H_M4),
            ("the asset 1a", asset("1a"), MALFORMED),
            ("an asset name of 129 characters", asset("a" * 129), MALFORMED),
        ]
    )


def test_mpp_charge_usdc_stacks_smart_contract_clarity_version_is_1_to_7() -> None:
    # A versioned smart contract names a Clarity version from 1 to 7 (stacks-codec/src/transaction.rs:2825-2842).
    code = b"(define-data-var a int 1)"

    def versioned(version: int) -> bytes:
        return transaction([FT_CONDITION], b"\x06" + bytes([version]) + name("hello") + word(len(code), 4) + code)

    assert_reads(
        [(f"Clarity version {v}", versioned(v), NOT_H) for v in range(1, 8)]
        + [(f"Clarity version {v}", versioned(v), MALFORMED) for v in (0, 8, 255)]
    )


def test_mpp_charge_usdc_stacks_canonical_rows() -> None:
    rows = json.loads((Path(__file__).parent / "stacks_canonical.json").read_text())["rows"]
    assert len(rows) == 48
    for row in rows:
        out = MPP_CHARGE_USDC_STACKS.bound(credential(bytes.fromhex(row["wire"])))
        assert (out if isinstance(out, str) else out.code) == row["expect"], row["case"]


def test_mpp_charge_usdc_stacks_multisig_key_fields() -> None:
    # SIP-005: a multisig key field holds a compressed secp256k1 point, marked compressed (0x00) or uncompressed (0x01).
    # A key off the curve, a 65-byte body, or an uncompressed key under P2WSH is not a transaction that decodes and
    # re-serializes to the same bytes.
    rows = json.loads((Path(__file__).parent / "stacks_key_fields.json").read_text())["rows"]
    assert len(rows) == 11
    for row in rows:
        out = MPP_CHARGE_USDC_STACKS.bound(credential(bytes.fromhex(row["wire"])))
        assert (out if isinstance(out, str) else out.code) == row["expect"], row["case"]


def test_mpp_charge_usdc_stacks_agreed_refusals() -> None:
    # Each agreedRefusals row is M4's signed transaction with its payload replaced, presented as the credential's
    # transaction; bound refuses it with the row's code, the outcome @stacks/transactions 7.6.0 gives. The rows are
    # selected by their input, and the file holds at least one.
    rows = [r for r in V.get("agreedRefusals", {}).get("rows", []) if isinstance(r.get("wireHex"), str)]
    assert rows, "mpp-charge-usdc-stacks.json holds no agreedRefusals row with a wireHex"
    for row in rows:
        out = MPP_CHARGE_USDC_STACKS.bound(credential(bytes.fromhex(row["wireHex"][2:])))
        assert (row["case"], out) == (row["case"], Refusal(row["expect"]))
