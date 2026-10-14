"""x402/exact/algorand: the TypeScript gate's B2, B6, B10 and B16 rows, and the buyer half's vector rows. Expected
values are the vector file's; the payer signs with the Ed25519 seed the file names, 01×32."""

import base64
import copy
import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_ALGORAND, Refusal
from integraledger_terms.bindings import _algorand
from integraledger_terms.bindings.x402_exact_algorand import AvmUnsigned, check

import ed25519
from breadth import H, Pairing, build_and_sign, plant, x402_doc
from support import hexb, load, msgpack_strings
from xlm_support import EVM_ACCOUNT, b10, b16

A = load("x402-exact-algorand.json")
F: dict[str, Any] = A["fixed"]
SEED = bytes([1]) * 32


def answer(request: Any) -> Any:
    assert request["kind"] == "algorand-txn", request["kind"]
    return "0x" + ed25519.sign(SEED, hexb(request["bytes"])).hex()


ALGORAND = Pairing(
    binding=X402_EXACT_ALGORAND,
    doc=x402_doc(F["O"], F["resource"]),
    account=f"{F['O']['network']}:{F['payer']}",
    answer=answer,
    inputs={"params": F["params"]},
)


def txid(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def built(option: dict[str, Any]) -> AvmUnsigned:
    doc = x402_doc(option, F["resource"])
    params = {**F["params"], **{k: int(F["params"][k]) for k in ("firstValid", "minFee", "feePerByte")}}
    unsigned = X402_EXACT_ALGORAND.build({"required": doc, "accepted": option, "payer": F["payer"], "params": params}, H)
    assert isinstance(unsigned, AvmUnsigned), unsigned
    return unsigned


def encode_address(public_key: bytes) -> str:
    """Base32 of the 32-byte key and the last 4 bytes of its SHA-512/256, without padding: Algorand's address form."""
    checksum = hashlib.new("sha512_256", public_key).digest()[-4:]
    return base64.b32encode(public_key + checksum).decode("ascii").rstrip("=")


def test_x402_exact_algorand_payer_key_is_the_vector_payer() -> None:
    assert encode_address(ed25519.public_key(SEED)) == F["payer"]

def test_x402_exact_algorand_b6_bytes_to_sign_and_payment_group_are_v2() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "algorand-txn"
        assert hexb(request["bytes"]).hex() == A["V2"]["expectBytesToSign"]
        assert answer(request) == "0x" + F["signature"]

    signed, _ = build_and_sign(ALGORAND, inspect)
    assert signed["payload"] == {
        "paymentIndex": A["V2"]["expectPaymentIndex"],
        "paymentGroup": A["V2"]["expectPaymentGroup"],
    }


def test_x402_exact_algorand_b10_http_link() -> None:
    b10(ALGORAND)


def test_x402_exact_algorand_b16_other_accounts() -> None:
    b16(ALGORAND, [EVM_ACCOUNT, f"algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k:{F['payer']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def test_x402_exact_algorand_v1_standalone_axfer() -> None:
    unsigned = built(F["OStandalone"])
    (txn,) = unsigned._group
    assert txn.fee == 1000 and txn.group is None
    assert txid(txn.raw_id()) == A["V1"]["expectTxid"]
    assert len(txn.encoded()) == A["V1"]["expectEncodedLength"]


def test_x402_exact_algorand_v2_group_id_and_txids() -> None:
    unsigned = built(F["O"])
    pay, transfer = unsigned._group
    assert pay.fee == 2000 and transfer.fee == 0
    assert pay.group is not None and base64.b64encode(pay.group).decode() == A["V2"]["expectGroupId"]
    assert txid(transfer.raw_id()) == A["V2"]["expectPaymentTxid"]
    assert txid(pay.raw_id()) == A["V2"]["expectFeePayerTxid"]
    completed = unsigned.complete(bytes.fromhex(F["signature"]))
    assert isinstance(completed, dict)
    assert completed["payload"]["paymentGroup"] == A["V2"]["expectPaymentGroup"]


def presented(payload: dict[str, Any], option: Any = None) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": option or F["O"], "payload": payload}


def test_x402_exact_algorand_v3_bound_and_refusals() -> None:
    payload = {"paymentIndex": A["V2"]["expectPaymentIndex"], "paymentGroup": A["V2"]["expectPaymentGroup"]}
    assert X402_EXACT_ALGORAND.bound(presented(payload)) == A["V3"]["expectBound"]
    for row in A["V3"]["refusals"]:
        payload = {"paymentIndex": row["paymentIndex"], "paymentGroup": row["paymentGroup"]}
        expect = row.get("expect", "avm/group-too-large")
        assert X402_EXACT_ALGORAND.bound(presented(payload)) == Refusal(expect), row["case"]


SIGNED_MEMBERS = ("msig", "lsig", "pqsig")
TXN_MEMBERS = ("hb", "sp", "spmsg")


def carries_another_signature_or_a_proof(row: dict[str, Any]) -> bool:
    """Whether the row's payment entry, read as msgpack, carries msig, lsig or pqsig, or a transaction with hb, sp or
    spmsg. An entry that is not a msgpack value _algorand reads carries neither."""
    group, index = row["paymentGroup"], row["paymentIndex"]
    if not 0 <= index < len(group):
        return False
    try:
        signed = _algorand.unpack(base64.b64decode(group[index]))
    except _algorand.Malformed:
        return False
    txn = signed.get("txn")
    return any(k in signed for k in SIGNED_MEMBERS) or (isinstance(txn, dict) and any(k in txn for k in TXN_MEMBERS))


def test_x402_exact_algorand_v3_signed_transactions_algosdk_does_not_decode() -> None:
    """The V3.refusals rows whose payment entry carries another signature or a proof member of a kind algosdk 3.8.0's
    decodeSignedTransaction refuses: bound gives each row's refusal."""
    rows = [row for row in A["V3"]["refusals"] if carries_another_signature_or_a_proof(row)]
    assert rows
    for row in rows:
        payload = {"paymentIndex": row["paymentIndex"], "paymentGroup": row["paymentGroup"]}
        assert X402_EXACT_ALGORAND.bound(presented(payload)) == Refusal(row["expect"]), row["case"]


V2_GROUP, V2_INDEX = A["V2"]["expectPaymentGroup"], A["V2"]["expectPaymentIndex"]
V2_ENTRY: dict[str, Any] = _algorand.unpack(base64.b64decode(V2_GROUP[V2_INDEX]))
PROGRAM = bytes([0x01, 0x20, 0x01, 0x01])
Z32, Z64 = bytes(32), bytes(64)
# V2's payment entry with one member set, and whether algosdk 3.8.0's decodeSignedTransaction decodes it (True, and
# lcp's exactAvm.bound gives H) or refuses it (False, avm/txn-malformed). msig, lsig and pqsig replace sig.
SIGNED_SHAPES: list[tuple[str, Any, bool]] = [
    ("msig", {}, True),
    ("msig", {"v": 1, "thr": 1, "subsig": [{"pk": Z32, "s": Z64}]}, True),
    ("msig", {"v": 2**53}, False),
    ("msig", {"thr": 2**53}, False),
    ("msig", {"subsig": [{"pk": bytes(31)}]}, False),
    ("msig", {"subsig": [{"pk": Z32, "s": bytes(63)}]}, False),
    ("lsig", {"l": PROGRAM, "arg": [b"a"], "msig": {}, "lmsig": {}}, True),
    ("lsig", {"l": bytes([0x7F])}, True),
    ("lsig", {}, False),
    ("lsig", {"l": b"ab\ncd"}, False),
    ("lsig", {"l": PROGRAM, "arg": [5]}, False),
    ("lsig", {"l": PROGRAM, "lmsig": {"v": 2**53}}, False),
    ("lsig", {"l": PROGRAM, "pqsig": {}}, False),
    ("pqsig", {"sch": b"ab", "slt": 255}, True),
    ("pqsig", {}, False),
    ("pqsig", {"sch": b"abc"}, False),
    ("pqsig", {"sch": b"ab", "slt": 256}, False),
    ("txn.hb", {}, True),
    ("txn.hb", {"a": Z32, "prf": {"p2s": Z64}, "sd": b"x", "kd": 7, "c": True}, True),
    ("txn.hb", {"prf": {"s": bytes(63)}}, False),
    ("txn.hb", {"c": 1}, False),
    ("txn.sp", {"S": {"pth": [b"x"]}, "pr": [5], "r": {1: {"p": {"p": {"cmt": Z64}}}}}, True),
    ("txn.sp", {"r": {1: {"s": {"s": {"vkey": {"k": bytes(0x701)}}}}}}, True),
    ("txn.sp", {"r": {"x": {}}}, False),
    ("txn.sp", {"r": {1: {"s": {"s": {"vkey": {"k": b"\0"}}}}}}, False),
    ("txn.sp", {"S": {"hsh": {"t": "x"}}}, False),
    ("txn.sp", {"pr": ["x"]}, False),
    ("txn.spmsg", {"b": b"x", "f": 3}, True),
    ("txn.spmsg", {"l": b"x"}, False),
]


def entry_with(member: str, value: Any) -> dict[str, Any]:
    entry = copy.deepcopy(V2_ENTRY)
    if member.startswith("txn."):
        entry["txn"][member[4:]] = value
    else:
        del entry["sig"]
        entry[member] = value
    return entry


def bound_of_entry(data: bytes) -> Any:
    group = list(V2_GROUP)
    group[V2_INDEX] = base64.b64encode(data).decode("ascii")
    return X402_EXACT_ALGORAND.bound(presented({"paymentIndex": V2_INDEX, "paymentGroup": group}))


@pytest.mark.parametrize(("member", "value", "decodes"), SIGNED_SHAPES)
def test_x402_exact_algorand_signed_transaction_shapes_as_algosdk_decodes_them(
    member: str, value: Any, decodes: bool
) -> None:
    got = bound_of_entry(_algorand.pack(entry_with(member, value)))
    assert got == (A["V3"]["expectBound"] if decodes else Refusal("avm/txn-malformed"))


FLOAT_1, FLOAT_1_5 = "cb3ff0000000000000", "cb3ff8000000000000"  # msgpack float 64 of 1.0 and of 1.5


@pytest.mark.parametrize(
    ("keys", "decodes"),
    [
        (["01", FLOAT_1], False),  # the integer 1 and the float 1.0: two keys algosdk reads as one u64
        ([FLOAT_1], True),
        (["01", "01"], True),  # the integer 1 twice: one key
        ([FLOAT_1_5], False),  # no u64
    ],
)
def test_x402_exact_algorand_state_proof_reveal_keys_as_algosdk_decodes_them(keys: list[str], decodes: bool) -> None:
    """A state proof whose reveals map r, written by hand, maps each key to an empty map."""
    placeholder = bytes([0xAB]) * 7
    data = _algorand.pack(entry_with("txn.sp", placeholder))
    raw = bytes([0x81, 0xA1, ord("r"), 0x80 | len(keys)]) + b"".join(bytes.fromhex(k) + b"\x80" for k in keys)
    got = bound_of_entry(data.replace(_algorand.pack(placeholder), raw))
    assert got == (A["V3"]["expectBound"] if decodes else Refusal("avm/txn-malformed"))


SEVENS = bytes([7]) * 32
# V2's transaction with its type and members set, and what lcp's exactAvm.bound answers through algosdk 3.8.0's
# Transaction constructor: H, avm/txn-malformed where the constructor throws, or avm/not-axfer.
TRANSACTION_SHAPES: list[tuple[dict[str, Any], str]] = [
    ({"aclose": Z32}, "avm/txn-malformed"),
    ({"asnd": Z32}, "avm/txn-malformed"),
    ({"rekey": Z32}, "avm/txn-malformed"),
    ({"aclose": SEVENS, "asnd": SEVENS, "rekey": SEVENS, "close": Z32}, "H"),
    ({"type": "pay"}, "avm/not-axfer"),
    ({"type": "pay", "close": Z32}, "avm/txn-malformed"),
    ({"type": "afrz", "rekey": Z32}, "avm/txn-malformed"),
    ({"type": "hb"}, "avm/txn-malformed"),
    ({"type": "hb", "hb": {}}, "avm/not-axfer"),
    ({"type": "keyreg", "nonpart": True}, "avm/not-axfer"),
    ({"type": "keyreg", "nonpart": True, "votekey": SEVENS}, "avm/txn-malformed"),
    ({"type": "keyreg", "votefst": 0}, "avm/txn-malformed"),
    ({"type": "keyreg", "votekey": SEVENS, "selkey": SEVENS, "votefst": 1, "votelst": 2, "votekd": 3}, "avm/not-axfer"),
    ({"type": "acfg", "apar": {"m": Z32}}, "avm/txn-malformed"),
    ({"type": "acfg", "apar": {"dc": 2**53}}, "avm/txn-malformed"),
    ({"type": "acfg", "apar": {"am": Z32, "dc": 2**53 - 1}}, "avm/not-axfer"),
    ({"type": "appl", "apan": 5}, "avm/not-axfer"),
    ({"type": "appl", "apan": 6}, "avm/txn-malformed"),
    ({"type": "appl", "apls": {"nui": 2**53}}, "avm/txn-malformed"),
    ({"type": "appl", "apep": 2**53}, "avm/txn-malformed"),
    ({"type": "appl", "apbx": [{"i": 1}]}, "avm/txn-malformed"),
    ({"type": "appl", "apbx": [{"i": 1}], "apfa": [7]}, "avm/not-axfer"),
    ({"type": "appl", "al": [{"h": {"s": 1}}]}, "avm/txn-malformed"),
    ({"type": "appl", "al": [{"s": 5}, {"h": {"s": 1}}]}, "avm/not-axfer"),
    ({"type": "appl", "al": [{"l": {"p": 2}}]}, "avm/txn-malformed"),
    ({"type": "appl", "al": [{"p": 7}, {"b": {"i": 1, "n": b"x"}}]}, "avm/not-axfer"),
    ({"type": "stpf", "sptype": 2**53}, "avm/txn-malformed"),
]


@pytest.mark.parametrize(("members", "expect"), TRANSACTION_SHAPES)
def test_x402_exact_algorand_transactions_as_algosdk_constructs_them(members: dict[str, Any], expect: str) -> None:
    entry = copy.deepcopy(V2_ENTRY)
    entry["txn"].update(members)
    got = bound_of_entry(_algorand.pack(entry))
    assert got == (A["V3"]["expectBound"] if expect == "H" else Refusal(expect))


@pytest.mark.parametrize(("length", "decodes"), [(3, False), (4, True), (5, False), (8, True), (12, True)])
def test_x402_exact_algorand_timestamp_extensions_as_algosdk_decodes_them(length: int, decodes: bool) -> None:
    """V2's entry with one more member, msgpack's timestamp extension (type -1) of length bytes, which algosdk's decoder
    reads only at 4, 8 or 12 bytes."""
    data = _algorand.pack(V2_ENTRY)
    extension = bytes([0xC7, length, 0xFF]) + bytes(length)
    got = bound_of_entry(bytes([data[0] + 1]) + data[1:] + bytes([0xA2]) + b"zz" + extension)
    assert got == (A["V3"]["expectBound"] if decodes else Refusal("avm/txn-malformed"))


def msgpack_str(data: bytes) -> bytes:
    """data as one msgpack string: a fixstr up to 31 bytes, else a str 8."""
    return (bytes([0xA0 | len(data)]) if len(data) < 32 else bytes([0xD9, len(data)])) + data


def once(data: bytes, old: bytes, new: bytes) -> bytes:
    assert data.count(old) == 1, old.hex()
    return data.replace(old, new)


# V2's payment entry as the file writes it, {sig, txn}, whose last member is txn, a fixmap of 11 members whose last is
# xaid; and "gen": "testnet-v1.0" in it.
V2_BYTES = base64.b64decode(V2_GROUP[V2_INDEX])
TXN_HEAD, GEN = bytes.fromhex("a374786e8b"), bytes.fromhex("a367656eac746573746e65742d76312e30")
# Five places for a msgpack string in V2's payment entry, edited by hand (the msgpack specification's formats): the key
# and the value of a member appended to the entry's map, the key of a member appended to the transaction's map, an
# element of an array appended to it, and gen's value.
ENTRY_PLACES: dict[str, Callable[[bytes], bytes]] = {
    "the entry's key": lambda s: b"\x83" + V2_BYTES[1:] + s + b"\x05",
    "the entry's value": lambda s: b"\x83" + V2_BYTES[1:] + b"\xa2zz" + s,
    "the transaction's key": lambda s: once(V2_BYTES, TXN_HEAD, b"\xa3txn\x8c") + s + b"\x05",
    "an array in the transaction": lambda s: once(V2_BYTES, TXN_HEAD, b"\xa3txn\x8c") + b"\xa2zz\x91" + s,
    "gen": lambda s: once(V2_BYTES, GEN, b"\xa3gen" + s),
}
MARK = b"\xef\xbb\xbf"
# Strings RFC 3629 section 4's syntax refuses, each after an x (an overlong t, the surrogate U+D800, U+110000 above
# U+10FFFF, a two-byte lead the string's end cuts short, a continuation byte with no lead), C1 and 200 x (a str 8 of
# 201 bytes), and the byte-order mark EF BB BF and 198 x (201 bytes), which algosdk 3.8.0's decoder, algorand-msgpack
# 1.1.0, reads without the mark (src/utils/utf8.ts:160-177).
NOT_AS_SPELLED = ["78c1b4", "78eda080", "78f4908080", "78c3", "7880", "c1" + "78" * 200, "efbbbf" + "78" * 198]
# Strings of the boundary code points the syntax takes, each after an x; the mark and 197 x (200 bytes), which that
# decoder reads with its mark; and x, the mark and 197 x (201 bytes), which the mark does not begin.
AS_SPELLED = ["78c280", "78dfbf", "78e0a080", "78ed9fbf", "78ee8080", "78efbbbf", "78f0908080", "78f48fbfbf",
              "efbbbf" + "78" * 197, "78efbbbf" + "78" * 197]  # fmt: skip


@pytest.mark.parametrize("place", ENTRY_PLACES)
def test_x402_exact_algorand_a_string_algosdk_reads_as_other_text_is_malformed_wherever_it_sits(place: str) -> None:
    """bound refuses a payment entry holding a msgpack string that is not well-formed UTF-8, or that is longer than 200
    bytes and begins with the byte-order mark, and reads H from one whose strings are text as spelled. Expected values
    are lcp's: exactAvm.bound's answers for these strings, in these places."""
    at = ENTRY_PLACES[place]
    for text in NOT_AS_SPELLED:
        assert bound_of_entry(at(msgpack_str(bytes.fromhex(text)))) == Refusal("avm/txn-malformed"), text[:16]
    for text in AS_SPELLED:
        assert bound_of_entry(at(msgpack_str(bytes.fromhex(text)))) == A["V3"]["expectBound"], text[:16]


@pytest.mark.parametrize(
    ("header", "text", "read"),
    [
        pytest.param("d9c8", MARK + b"x" * 197, "\ufeff" + "x" * 197, id="the mark and 197 x, str 8"),
        pytest.param("da00c8", MARK + b"x" * 197, "\ufeff" + "x" * 197, id="the mark and 197 x, str 16"),
        pytest.param("d9c9", MARK + b"x" * 198, None, id="the mark and 198 x, str 8"),
        pytest.param("da00c9", MARK + b"x" * 198, None, id="the mark and 198 x, str 16"),
        pytest.param("db000000c9", MARK + b"x" * 198, None, id="the mark and 198 x, str 32"),
        pytest.param("da012c", MARK + b"x" * 297, None, id="the mark and 297 x, str 16"),
        pytest.param("d9c9", b"x" + MARK + b"x" * 197, "x\ufeff" + "x" * 197, id="x, the mark and 197 x, str 8"),
        pytest.param("d9c9", b"x" * 201, "x" * 201, id="201 x, str 8"),
    ],
)
def test_x402_exact_algorand_a_string_is_judged_by_its_length_in_bytes(
    header: str, text: bytes, read: str | None
) -> None:
    """A string's length in bytes decides, whatever its format: one longer than 200 bytes that begins with the
    byte-order mark is Malformed, and every other well-formed string is read with its mark. Expected values are lcp's
    msgpackWithinCaps, which algosdk 3.8.0's decoder reads only after it admits the bytes."""
    data = bytes.fromhex(header) + text
    if read is None:
        with pytest.raises(_algorand.Malformed):
            _algorand.unpack(data)
    else:
        assert _algorand.unpack(data) == read


def holds_a_string_algosdk_reads_as_other_text(row: dict[str, Any]) -> bool:
    """Whether the row's payment entry holds a msgpack string that Python's strict UTF-8 codec refuses (RFC 3629), or
    one longer than 200 bytes that begins with the byte-order mark EF BB BF, read with support.msgpack_strings."""
    group, index = row["paymentGroup"], row["paymentIndex"]
    if not 0 <= index < len(group):
        return False

    def other_text(text: bytes) -> bool:
        try:
            text.decode("utf-8")
        except UnicodeDecodeError:
            return True
        return len(text) > 200 and text.startswith(MARK)

    return any(other_text(s) for s in msgpack_strings(base64.b64decode(group[index])) or [])


def test_x402_exact_algorand_v3_entries_holding_a_string_algosdk_reads_as_other_text() -> None:
    """The V3.refusals rows whose payment entry holds a msgpack string that is not well-formed UTF-8, or that is longer
    than 200 bytes and begins with the byte-order mark: bound gives each row's refusal."""
    rows = [row for row in A["V3"]["refusals"] if holds_a_string_algosdk_reads_as_other_text(row)]
    assert rows, "x402-exact-algorand.json holds no V3.refusals row whose payment entry holds such a string"
    for row in rows:
        payload = {"paymentIndex": row["paymentIndex"], "paymentGroup": row["paymentGroup"]}
        assert X402_EXACT_ALGORAND.bound(presented(payload)) == Refusal(row["expect"]), row["case"]


def test_x402_exact_algorand_v3_presented_options_are_bound_without_their_amount_or_timeout() -> None:
    """V2's payment under each V3.presentedOptions option, whose amount or timeout no build could use: bound reads the
    signed transaction and gives the row's expectBound, while read serves no such option and build refuses it, as lcp's
    own test of these rows expects. Under each options row, bound gives that row's refusal."""
    payload = {"paymentIndex": A["V2"]["expectPaymentIndex"], "paymentGroup": A["V2"]["expectPaymentGroup"]}
    params = {**F["params"], **{k: int(F["params"][k]) for k in ("firstValid", "minFee", "feePerByte")}}
    rows = A["V3"]["presentedOptions"]
    assert rows
    for row in rows:
        accepted = row["accepted"]
        assert X402_EXACT_ALGORAND.bound(presented(payload, accepted)) == row["expectBound"], row["case"]
        doc = x402_doc(accepted, F["resource"])
        assert X402_EXACT_ALGORAND.read(doc) == Refusal("x402/no-payable-option"), row["case"]
        choice = {"required": doc, "accepted": accepted, "payer": F["payer"], "params": params}
        assert X402_EXACT_ALGORAND.build(choice, H) == Refusal("avm/option-malformed"), row["case"]
    assert A["options"]
    for row in A["options"]:
        assert X402_EXACT_ALGORAND.bound(presented(payload, row["option"])) == Refusal(row["expect"]), row["case"]


def test_x402_exact_algorand_option_filter_rows() -> None:
    for row in A["options"]:
        assert check(row["option"]) == Refusal(row["expect"]), row["case"]
    assert check(copy.deepcopy(F["O"])) is True
