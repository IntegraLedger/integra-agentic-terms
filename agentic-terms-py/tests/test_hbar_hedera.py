"""B2, B6, B10 and B16 for x402/exact/hedera and x402/exact/hedera/transfer-executor, and the payment identifier row.
Expected bytes, signatures and payments are the vector files'."""

from dataclasses import replace
from typing import Any

import pytest

from integraledger_terms import (
    X402_EXACT_HEDERA,
    X402_EXACT_HEDERA_TRANSFER_EXECUTOR,
    Advertised,
    Refusal,
    _gate,
)

import ed25519
from breadth import LINK, Pairing, build_and_sign, plant, x402_doc
from hbar_support import EVM_ACCOUNT, REF, b10, b16, with_identifier
from support import hexb, load

# ── x402/exact/hedera ─────────────────────────────────────────────────────────────────────────────────────────────

E = load("x402-exact-hedera.json")
F: dict[str, Any] = E["fixed"]
# The vector file names the payer key: Ed25519 seed 03×32.
SEED = bytes([3]) * 32


def hedera_answer(request: Any) -> Any:
    if request["kind"] != "hedera-body":
        raise AssertionError(request["kind"])
    body = hexb(request["bodyBytes"])
    return {
        "publicKey": "0x" + ed25519.public_key(SEED).hex(),
        "signature": "0x" + ed25519.sign(SEED, body).hex(),
        "type": "ed25519",
    }


HEDERA = Pairing(
    binding=X402_EXACT_HEDERA,
    doc=x402_doc(F["O"], F["resource"]),
    account=f"{F['O']['network']}:{F['payer']}",
    answer=hedera_answer,
    inputs={"node": F["node"], "validStart": F["validStart"], "maxFee": F["maxFee"]},
)


def test_x402_exact_hedera_the_payer_key_is_the_vector_public_key() -> None:
    assert ed25519.public_key(SEED).hex() == F["publicKey"]

def test_x402_exact_hedera_b6_body_is_v2_and_signature_completes_v2_transaction() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "hedera-body"
        assert hexb(request["bodyBytes"]).hex() == E["V2"]["expectBodyBytes"]
        assert len(hexb(request["bodyBytes"])) == E["V2"]["expectBodyLength"]
        assert hedera_answer(request)["signature"] == "0x" + F["signature"]

    signed, _ = build_and_sign(HEDERA, inspect)
    assert signed["x402Version"] == 2
    assert signed["resource"] == F["resource"]
    assert signed["accepted"] == F["O"]
    assert signed["payload"] == {"transaction": E["V2"]["expectTransactionBase64"]}


def test_x402_exact_hedera_payment_identifier() -> None:
    signed, _ = build_and_sign(replace(HEDERA, doc=with_identifier(HEDERA.doc)), lambda request: None)
    assert REF.fullmatch(signed["extensions"]["payment-identifier"]["info"]["id"])


def test_x402_exact_hedera_b10_http_link() -> None:
    b10(HEDERA)


def test_x402_exact_hedera_b16_other_accounts() -> None:
    b16(HEDERA, [EVM_ACCOUNT, f"hedera:mainnet:{F['payer']}"])


# ── x402/exact/hedera/transfer-executor ───────────────────────────────────────────────────────────────────────────

X = load("x402-exact-hedera-transfer-executor.json")
XF: dict[str, Any] = X["fixed"]


def executor_answer(request: Any) -> Any:
    if request["kind"] != "hedera-executor":
        raise AssertionError(request["kind"])
    return XF["payload"]


EXECUTOR = Pairing(
    binding=X402_EXACT_HEDERA_TRANSFER_EXECUTOR,
    doc=x402_doc(XF["O"], XF["resource"], link=LINK),
    account=f"{XF['O']['network']}:{XF['payload']['payer']}",
    answer=executor_answer,
)


@pytest.fixture
def executor_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: XF["now"])

@pytest.mark.usefixtures("executor_clock")
def test_x402_exact_hedera_transfer_executor_b6_request_and_echoed_extension() -> None:
    def inspect(request: Any) -> None:
        assert request == X["build"]["expectRequest"]

    signed, _ = build_and_sign(EXECUTOR, inspect)
    assert signed["x402Version"] == 2
    assert signed["accepted"] == XF["O"]
    assert signed["payload"] == XF["payload"]


def test_x402_exact_hedera_transfer_executor_b10_http_link() -> None:
    b10(EXECUTOR)


def test_x402_exact_hedera_transfer_executor_b16_other_accounts() -> None:
    b16(EXECUTOR, [EVM_ACCOUNT, f"hedera:mainnet:{XF['payload']['payer']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def presented(transaction: str) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": F["O"], "payload": {"transaction": transaction}}


def hedera_choice(option: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    offered = option if option is not None else F["O"]
    value: dict[str, Any] = {
        "required": {"x402Version": 2, "resource": F["resource"], "accepts": [offered]},
        "accepted": offered,
        "payer": F["payer"],
        "node": F["node"],
        "validStart": {"seconds": int(F["validStart"]["seconds"]), "nanos": F["validStart"]["nanos"]},
        "maxFee": int(F["maxFee"]),
    }
    value.update(changes)
    return value


def test_x402_exact_hedera_v2_build_complete_bound() -> None:
    unsigned = X402_EXACT_HEDERA.build(hedera_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert unsigned.request["bodyBytes"].hex() == E["V2"]["expectBodyBytes"]
    wire = unsigned.complete(
        {"publicKey": bytes.fromhex(F["publicKey"]), "signature": bytes.fromhex(F["signature"]), "type": "ed25519"}
    )
    assert wire == E["V2"]["expectTransactionBase64"]
    assert X402_EXACT_HEDERA.bound(presented(wire)) == E["V2"]["expectBound"]


def test_x402_exact_hedera_v1_memo() -> None:
    unsigned = X402_EXACT_HEDERA.build(hedera_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert E["V1"]["expectMemo"].encode() in unsigned.request["bodyBytes"]
    assert len(E["V1"]["expectMemo"].encode()) == F["Lbytes"]


def test_x402_exact_hedera_v3_list_form() -> None:
    assert X402_EXACT_HEDERA.bound(presented(E["V3"]["listBase64"])) == E["V3"]["expectBound"]
    assert X402_EXACT_HEDERA.bound(presented(E["V3"]["inconsistentListBase64"])) == Refusal(E["V3"]["expectInconsistent"])


def test_x402_exact_hedera_v4x_attribution_memo_is_not_lcp() -> None:
    assert X402_EXACT_HEDERA.bound(presented(E["V4x"]["transactionBase64"])) == Refusal(E["V4x"]["expectRefusal"])


def test_x402_exact_hedera_plant_no_memo() -> None:
    no_memo = E["plants"]["noMemo"]
    assert X402_EXACT_HEDERA.bound(presented(no_memo["transactionBase64"])) == Refusal(no_memo["expectRefusal"])


def test_x402_exact_hedera_refusals() -> None:
    for row in E["refusals"]:
        if "transactionBase64" in row:
            assert X402_EXACT_HEDERA.bound(presented(row["transactionBase64"])) == Refusal(row["expect"]), row["case"]
        else:
            assert X402_EXACT_HEDERA.build(hedera_choice(row["option"]), F["H"]) == Refusal(row["expect"]), row["case"]


def test_x402_exact_hedera_token_build() -> None:
    token = E["tokenBuild"]
    option = {**F["O"], "asset": token["asset"]}
    for decimals, expect in ((6, token["expectBodyBytesDecimals6"]), (0, token["expectBodyBytesDecimals0"])):
        unsigned = X402_EXACT_HEDERA.build(hedera_choice(option, decimals=decimals), F["H"])
        assert not isinstance(unsigned, Refusal)
        assert unsigned.request["bodyBytes"].hex() == expect


def test_x402_exact_hedera_transfer_executor_pairing_of() -> None:
    for row in X["pairingOf"]:
        option = row["option"]
        exact = X402_EXACT_HEDERA.build(hedera_choice(option), F["H"])
        executor = X402_EXACT_HEDERA_TRANSFER_EXECUTOR.build(
            {"required": {"x402Version": 2, "accepts": [option]}, "accepted": option, "now": XF["now"]}, F["H"]
        )
        if row["expect"] == "x402/exact/hedera":
            assert not isinstance(exact, Refusal)
            assert executor == Refusal("x402/option-not-this-pairing")
        elif row["expect"] == "x402/exact/hedera/transfer-executor":
            assert not isinstance(executor, Refusal)
            assert exact == Refusal("x402/option-not-this-pairing")
        else:
            assert Refusal(row["expect"]) in (exact, executor), row


def executor_unsigned() -> Any:
    unsigned = X402_EXACT_HEDERA_TRANSFER_EXECUTOR.build(
        {"required": EXECUTOR.doc, "accepted": XF["O"], "now": XF["now"]}, F["H"]
    )
    assert not isinstance(unsigned, Refusal)
    return unsigned


def test_x402_exact_hedera_transfer_executor_complete_and_bound() -> None:
    unsigned = executor_unsigned()
    assert unsigned.request == X["build"]["expectRequest"]
    for row in X["complete"]:
        answer = {**XF["payload"], **{k: v for k, v in row.items() if k in ("payer", "executor", "authorization")}}
        assert unsigned.complete(answer) == Refusal(row["expect"]), row
    signed = unsigned.complete(XF["payload"])
    assert X402_EXACT_HEDERA_TRANSFER_EXECUTOR.bound(signed) == X["bound"]["expectWithExtension"]
    bare = {k: v for k, v in signed.items() if k != "extensions"}
    assert X402_EXACT_HEDERA_TRANSFER_EXECUTOR.bound(bare) == Refusal(X["bound"]["expectWithoutExtension"])


def test_x402_exact_hedera_reads_h_and_the_link() -> None:
    for binding, doc in ((X402_EXACT_HEDERA, HEDERA.doc), (X402_EXACT_HEDERA_TRANSFER_EXECUTOR, EXECUTOR.doc)):
        read = binding.read(doc)
        assert isinstance(read, Advertised)
        assert read.h == F["H"] and read.link == F["link"]
