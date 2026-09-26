"""B2, B6, B10, B16, the payment identifier and the inputs rows for x402/exact/tron/lcp-trc20-memo, and the buyer
half's vector rows. Expected values are x402-exact-tron-lcp-trc20-memo.json's."""

import hashlib
from typing import Any

import pytest
from eth_account import Account

from integraledger_terms import X402_EXACT_TRON_LCP_TRC20_MEMO as BINDING
from integraledger_terms import Refusal, _gate
from integraledger_terms.bindings._codec import b58_encode

from breadth import Pairing, build_and_sign, plant, x402_doc
from hbar_support import EVM_ACCOUNT, b10, b16, identifier_row, inputs_row
from support import hexb, load

T = load("x402-exact-tron-lcp-trc20-memo.json")
F: dict[str, Any] = T["fixed"]
NOW = int(F["now"]) // 1000


def tron_sign(txid: bytes) -> str:
    """The vector's published Anvil key's secp256k1 signature over the id as r ‖ s ‖ v, v the recovery bit."""
    signed = Account.unsafe_sign_hash(txid, F["payerKey"])
    r, s, v = int(signed.r), int(signed.s), int(signed.v)
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + f"{v - 27:02x}"


def tron_answer(request: Any) -> Any:
    if request["kind"] != "tron-txid":
        raise AssertionError(request["kind"])
    return tron_sign(hexb(request["txid"]))


TRON = Pairing(
    binding=BINDING,
    doc=x402_doc(F["O"], F["resource"]),
    account=f"{F['O']['network']}:{F['payer']}",
    answer=tron_answer,
    inputs={"refBlock": {"number": F["refBlock"]["number"], "id": F["refBlock"]["id"]}, "feeLimit": F["feeLimit"]},
)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def base58check(payload: bytes) -> str:
    return b58_encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])

def test_x402_exact_tron_lcp_trc20_memo_b6_request_signature_and_transaction() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "tron-txid"
        assert request["txid"] == T["V2"]["expectTxid"]
        sig = tron_sign(hexb(request["txid"]))
        assert sig[2:] == T["V2"]["expectSignature"]
        recovered = Account._recover_hash(hexb(request["txid"]), signature=bytes.fromhex(sig[2:-2]) + bytes([int(sig[-2:], 16) + 27]))
        assert "41" + recovered[2:].lower() == F["payerBytes"]
        assert base58check(bytes.fromhex(F["payerBytes"])) == T["V2"]["expectRecoversTo"]

    signed, _ = build_and_sign(TRON, inspect)
    assert signed["payload"]["transaction"] == T["V2"]["expectTransactionHex"]


def test_x402_exact_tron_lcp_trc20_memo_b6_payment_identifier() -> None:
    identifier_row(TRON)


def test_x402_exact_tron_lcp_trc20_memo_b10_http_link() -> None:
    b10(TRON)


def test_x402_exact_tron_lcp_trc20_memo_b16_other_accounts() -> None:
    b16(TRON, [EVM_ACCOUNT, f"tron:3448148188:{F['payer']}"])


def test_x402_exact_tron_lcp_trc20_memo_inputs() -> None:
    inputs_row(TRON, {"refBlock": {"number": "86542765", "id": "0x00"}, "feeLimit": "100000000"}, "x402/input-missing")


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def tron_choice(option: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    offered = option if option is not None else F["O"]
    value: dict[str, Any] = {
        "required": {"x402Version": 2, "resource": F["resource"], "accepts": [offered]},
        "accepted": offered,
        "payer": F["payer"],
        "refBlock": {"number": int(F["refBlock"]["number"]), "id": F["refBlock"]["id"]},
        "now": int(F["now"]),
        "feeLimit": int(F["feeLimit"]),
    }
    value.update(changes)
    return value


def presented(transaction: Any) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": F["O"], "payload": {"transaction": transaction}}


def test_x402_exact_tron_lcp_trc20_memo_v1_mainnet_transaction() -> None:
    from integraledger_terms.bindings._tron_proto import decode_raw, encode_transaction

    raw_bytes = bytes.fromhex(T["V1"]["rawHex"])
    assert "0x" + hashlib.sha256(raw_bytes).hexdigest() == T["V1"]["expectTxid"]
    raw = decode_raw(raw_bytes)
    assert not isinstance(raw, Refusal)
    expect = T["V1"]["expectDecoded"]
    assert raw.ref_block_bytes.hex() == expect["refBlockBytes"] and raw.ref_block_hash.hex() == expect["refBlockHash"]
    assert str(raw.expiration) == expect["expiration"] and raw.data.hex() == expect["data"]
    assert raw.owner.hex() == expect["owner"] and raw.contract_address.hex() == expect["contractAddress"]
    assert raw.call_data.hex() == expect["callData"] and str(raw.timestamp) == expect["timestamp"]
    assert str(raw.fee_limit) == expect["feeLimit"]
    assert raw.data.decode() == T["V1"]["expectDataUtf8"]
    signed = encode_transaction(raw_bytes, [bytes.fromhex(T["V1"]["signatureForPayload"])]).hex()
    assert BINDING.bound(presented(signed)) == Refusal(T["V1"]["expectBound"]["code"])


def test_x402_exact_tron_lcp_trc20_memo_v2_build_and_complete() -> None:
    unsigned = BINDING.build(tron_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert "0x" + unsigned.request["txid"].hex() == T["V2"]["expectTxid"]
    assert hashlib.sha256(bytes.fromhex(T["V2"]["expectRawHex"])).digest() == unsigned.request["txid"]
    assert T["V2"]["expectRawHex"][4:8] == T["V2"]["expectRefBlockBytes"]
    signed = unsigned.complete(bytes.fromhex(T["V2"]["expectSignature"]))
    assert signed == T["V2"]["expectPayload"]


def test_x402_exact_tron_lcp_trc20_memo_v3_bound_and_refusals() -> None:
    assert BINDING.bound(T["V2"]["expectPayload"]) == T["V3"]["expectBound"]
    for row in T["V3"]["refusals"]:
        assert BINDING.bound(presented(row["transaction"])) == Refusal(row["expect"]), row["case"]


def test_x402_exact_tron_lcp_trc20_memo_agreed_refusals() -> None:
    seen = 0
    for row in T["agreedRefusals"]["rows"]:
        expect = Refusal(row["expect"])
        if "option" in row:
            assert BINDING.build(tron_choice(row["option"]), F["H"]) == expect, row["case"]
        elif "transaction" in row:
            assert BINDING.bound(presented(row["transaction"])) == expect, row["case"]
        elif "payer" in row:
            assert BINDING.build(tron_choice(payer=row["payer"]), F["H"]) == expect
        elif "feeLimit" in row:
            for fee in row["feeLimit"]:
                assert BINDING.build(tron_choice(feeLimit=int(fee)), F["H"]) == expect
        elif "refBlockId" in row:
            block = {"number": int(F["refBlock"]["number"]), "id": row["refBlockId"]}
            assert BINDING.build(tron_choice(refBlock=block), F["H"]) == expect
            assert BINDING.build(tron_choice(now=0), F["H"]) == expect
        elif "signatureV" in row:
            unsigned = BINDING.build(tron_choice(), F["H"])
            assert not isinstance(unsigned, Refusal)
            sig = bytes.fromhex(T["V2"]["expectSignature"])
            assert unsigned.complete(sig[:64] + bytes([row["signatureV"]])) == expect
            assert unsigned.complete(sig[:64]) == expect
        elif row["case"].startswith("bound with payload.transaction"):
            assert BINDING.bound(presented(7)) == expect
        else:
            continue
        seen += 1
    assert seen > 10
