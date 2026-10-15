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
from integraledger_terms.bindings._hedera_proto import TxId, tx_id_text

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


def test_x402_exact_hedera_an_account_whose_address_is_not_an_entity_id() -> None:
    """An account whose address is not shard.realm.num as @integraledger/lcp's Hedera pairings read it (each part 0, or
    up to 19 digits with no leading zero) has no payable option on either pairing; nothing is fetched."""
    for pairing in (HEDERA, EXECUTOR):
        b16(pairing, ["hedera:testnet:0.0.05555", "hedera:testnet:00.0.5555", "hedera:testnet:0.0." + "9" * 20])


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


def test_x402_exact_hedera_v2_presented_options() -> None:
    """V2's signed transaction under each presented option of V2.presentedOptions: bound holds the presented option to
    the filter read applies, so a row whose option read does not offer gives its expect refusal, and a row whose option
    read offers gives its expectBound."""
    rows = E["V2"]["presentedOptions"]
    assert any("expect" in row for row in rows), "the vector file holds no refused V2.presentedOptions row"
    assert any("expectBound" in row for row in rows), "the vector file holds no bound V2.presentedOptions row"
    for row in rows:
        p = {**presented(E["V2"]["expectTransactionBase64"]), "accepted": row["accepted"]}
        want = Refusal(row["expect"]) if "expect" in row else row["expectBound"]
        assert X402_EXACT_HEDERA.bound(p) == want, row["case"]


def test_x402_exact_hedera_v1_memo() -> None:
    unsigned = X402_EXACT_HEDERA.build(hedera_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert E["V1"]["expectMemo"].encode() in unsigned.request["bodyBytes"]
    assert len(E["V1"]["expectMemo"].encode()) == F["Lbytes"]


def test_x402_exact_hedera_v3_list_form() -> None:
    assert X402_EXACT_HEDERA.bound(presented(E["V3"]["listBase64"])) == E["V3"]["expectBound"]
    assert X402_EXACT_HEDERA.bound(presented(E["V3"]["inconsistentListBase64"])) == Refusal(E["V3"]["expectInconsistent"])


def test_hedera_transaction_id_text_takes_only_a_transaction_id() -> None:
    """The list form compares each body's transaction id as text, account@seconds.nanos with nine digits of nanos. The
    writer raises TypeError for an id outside its type, as @integraledger/lcp's txIdText does: an account that is not
    shard.realm.num, seconds that are not a non-negative int, or nanos that are not an int from 0 to 999,999,999."""

    def tx_id(*fields: Any) -> Any:
        return TxId(*fields)

    assert tx_id_text(TxId("0.0.1235", 1700000000, 0)) == "0.0.1235@1700000000.000000000"
    assert tx_id_text(TxId("1.2.3", 0, 999_999_999)) == "1.2.3@0.999999999"
    outside: tuple[Any, ...] = (
        tx_id("x", 1700000000, 0),
        tx_id("0.0.01", 1700000000, 0),
        tx_id("0.1235", 1700000000, 0),
        tx_id(5, 1700000000, 0),
        tx_id("0.0.1235", -1, 0),
        tx_id("0.0.1235", True, 0),
        tx_id("0.0.1235", 1.5, 0),
        tx_id("0.0.1235", "1700000000", 0),
        tx_id("0.0.1235", 1700000000, -1),
        tx_id("0.0.1235", 1700000000, 1_000_000_000),
        tx_id("0.0.1235", 1700000000, True),
        tx_id("0.0.1235", 1700000000, 1.5),
        "0.0.1235@1700000000.000000000",
    )
    for value in outside:
        with pytest.raises(TypeError):
            tx_id_text(value)


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


def test_x402_exact_hedera_an_amount_of_zero_or_2_63_is_not_served() -> None:
    """x402 v2's PaymentRequirements gives amount as the atomic amount in a string, and the protocol package's filter
    holds it to the canonical decimal of a positive integer below 2^63, the int64 the transfer carries: read does not
    offer an option whose amount is 0 or 2^63, and build refuses it hedera/option-malformed."""
    for amount in ("0", str(2**63)):
        option = {**F["O"], "amount": amount}
        assert X402_EXACT_HEDERA.read(x402_doc(option, F["resource"])) == Refusal("x402/no-payable-option"), amount
        assert X402_EXACT_HEDERA.build(hedera_choice(option), F["H"]) == Refusal("hedera/option-malformed"), amount


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


def test_x402_exact_hedera_a_null_transfer_method_is_malformed() -> None:
    """A null assetTransferMethod is a value, neither absent, cryptoTransfer nor transferExecutor, so both pairings
    refuse the option: read finds no payable option, and build and bound answer hedera/option-malformed. These are
    @integraledger/lcp's answers (hedera.ts methodOf, exactOption and checkExecutor) for the vector files' options
    with the member set to null."""
    exact = {**F["O"], "extra": {**F["O"]["extra"], "assetTransferMethod": None}}
    executor = {**XF["O"], "extra": {**XF["O"]["extra"], "assetTransferMethod": None}}
    for option in (exact, executor):
        doc = x402_doc(option, F["resource"])
        assert X402_EXACT_HEDERA.read(doc) == Refusal("x402/no-payable-option")
        assert X402_EXACT_HEDERA_TRANSFER_EXECUTOR.read(doc) == Refusal("x402/no-payable-option")
        assert X402_EXACT_HEDERA.build(hedera_choice(option), F["H"]) == Refusal("hedera/option-malformed")
        executor_build = X402_EXACT_HEDERA_TRANSFER_EXECUTOR.build(
            {"required": doc, "accepted": option, "now": XF["now"]}, F["H"]
        )
        assert executor_build == Refusal("hedera/option-malformed")
    paid = {**presented(E["V2"]["expectTransactionBase64"]), "accepted": exact}
    assert X402_EXACT_HEDERA.bound(paid) == Refusal("hedera/option-malformed")
    echoed = {**executor_unsigned().complete(XF["payload"]), "accepted": executor}
    assert X402_EXACT_HEDERA_TRANSFER_EXECUTOR.bound(echoed) == Refusal("hedera/option-malformed")


def test_x402_exact_hedera_null_transfer_method_refusal_rows() -> None:
    """The refusals rows whose option names assetTransferMethod null: each pairing's read finds no payable option in a
    document offering it (the row's expectRead), and each pairing's build refuses it with the row's code. The rows are
    selected by their input, and the file holds at least one."""
    rows = [
        row
        for row in E["refusals"]
        if isinstance(row.get("option"), dict)
        and isinstance(row["option"].get("extra"), dict)
        and "assetTransferMethod" in row["option"]["extra"]
        and row["option"]["extra"]["assetTransferMethod"] is None
    ]
    assert rows, "x402-exact-hedera.json holds no refusals row whose option names assetTransferMethod null"
    for row in rows:
        option = row["option"]
        doc = x402_doc(option, F["resource"])
        for binding in (X402_EXACT_HEDERA, X402_EXACT_HEDERA_TRANSFER_EXECUTOR):
            assert binding.read(doc) == Refusal(row["expectRead"]), row["case"]
        assert X402_EXACT_HEDERA.build(hedera_choice(option), F["H"]) == Refusal(row["expect"]), row["case"]
        choice = {"required": doc, "accepted": option, "now": XF["now"]}
        assert X402_EXACT_HEDERA_TRANSFER_EXECUTOR.build(choice, F["H"]) == Refusal(row["expect"]), row["case"]


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


def test_x402_exact_hedera_transfer_executor_an_amount_of_zero_is_not_served() -> None:
    """The executor's filter holds amount to the canonical decimal of a positive integer, as x402/exact/hedera's does:
    read does not offer an executor option whose amount is 0, and build refuses it hedera/option-malformed."""
    zero = {**XF["O"], "amount": "0"}
    doc = x402_doc(zero, XF["resource"], link=LINK)
    assert X402_EXACT_HEDERA_TRANSFER_EXECUTOR.read(doc) == Refusal("x402/no-payable-option")
    built = X402_EXACT_HEDERA_TRANSFER_EXECUTOR.build({"required": doc, "accepted": zero, "now": XF["now"]}, F["H"])
    assert built == Refusal("hedera/option-malformed")


def test_x402_exact_hedera_transfer_executor_valid_before_is_a_safe_integer() -> None:
    """validBefore, now plus the option's maxTimeoutSeconds, is a safe integer: a sum of 2^53 - 1, ECMAScript's
    Number.MAX_SAFE_INTEGER, is served, and a sum past it is hedera/option-malformed, before the hash is read, as
    @integraledger/lcp's transfer-executor build answers."""
    longest = {**XF["O"], "maxTimeoutSeconds": 2**53 - 1}

    def build(option: dict[str, Any], now: int, h: str = F["H"]) -> Any:
        doc = x402_doc(option, XF["resource"], link=LINK)
        return X402_EXACT_HEDERA_TRANSFER_EXECUTOR.build({"required": doc, "accepted": option, "now": now}, h)

    timeout = XF["O"]["maxTimeoutSeconds"]
    for option, now in ((XF["O"], 2**53 - 1 - timeout), (longest, 0)):
        served = build(option, now)
        assert not isinstance(served, Refusal) and served.request["validBefore"] == 2**53 - 1
    for option, now in ((XF["O"], 2**53 - timeout), (longest, 1), (longest, XF["now"])):
        assert build(option, now) == Refusal("hedera/option-malformed")
        assert build(option, now, "x") == Refusal("hedera/option-malformed")
    assert build(XF["O"], XF["now"], "x") == Refusal("x402/payload-malformed")


def test_x402_exact_hedera_reads_h_and_the_link() -> None:
    for binding, doc in ((X402_EXACT_HEDERA, HEDERA.doc), (X402_EXACT_HEDERA_TRANSFER_EXECUTOR, EXECUTOR.doc)):
        read = binding.read(doc)
        assert isinstance(read, Advertised)
        assert read.h == F["H"] and read.link == F["link"]
