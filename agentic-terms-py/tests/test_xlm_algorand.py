"""x402/exact/algorand: the TypeScript gate's B2, B6, B10 and B16 rows, and the buyer half's vector rows. Expected
values are the vector file's; the payer signs with the Ed25519 seed the file names, 01×32."""

import base64
import copy
import hashlib
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_ALGORAND, Refusal
from integraledger_terms.bindings import _algorand
from integraledger_terms.bindings.x402_exact_algorand import AvmUnsigned, check

import ed25519
from breadth import H, Pairing, build_and_sign, plant, x402_doc
from support import hexb, load
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
    spmsg."""
    group, index = row["paymentGroup"], row["paymentIndex"]
    if not 0 <= index < len(group):
        return False
    signed = _algorand.unpack(base64.b64decode(group[index]))
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
