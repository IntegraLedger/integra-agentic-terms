"""x402/exact/algorand: the TypeScript gate's B2, B6, B10 and B16 rows, and the buyer half's vector rows. Expected
values are the vector file's; the payer signs with the Ed25519 seed the file names, 01×32."""

import base64
import copy
from typing import Any

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


def test_x402_exact_algorand_payer_key_is_the_vector_payer() -> None:
    assert _algorand.encode_address(ed25519.public_key(SEED)) == F["payer"]

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


def test_x402_exact_algorand_option_filter_rows() -> None:
    for row in A["options"]:
        assert check(row["option"]) == Refusal(row["expect"]), row["case"]
    assert check(copy.deepcopy(F["O"])) is True
