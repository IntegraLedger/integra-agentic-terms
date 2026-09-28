"""The Solana family's rows: the gate's rows for each pairing (B2, B6, B10, B16 and the pairing's own), and the buyer-side
vectors for build and bound. Expected messages, wires and codes are the vector files'; the Ed25519 keys come from the
seeds those files publish as test values."""

import asyncio
import base64
import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from breadth import ABC, H, LINK, Pairing, Recording, build_and_sign, code, link_calls, plant, run, x402_doc
from ed25519 import public_key, sign
from integraledger_terms import (
    MPP_SESSION_SOLANA,
    MPP_CHARGE_SOLANA,
    MPP_CHARGE_USDC_SOLANA,
    X402_BATCH_SETTLEMENT_SOLANA,
    X402_EXACT_SOLANA,
    X402_UPTO_SOLANA,
    BatchUnsigned,
    ChannelRef,
    Confirmed,
    Declined,
    Refusal,
    Transacted,
    Within,
    _gate,
    confirm,
    finish,
    open_channel,
    transact,
    within,
)
from integraledger_terms.bindings import _svm
from integraledger_terms.bindings._codec import b58_encode
from integraledger_terms.pieces.x402_batch_settlement_solana import PIECE as X402_BATCH_SETTLEMENT_SOLANA_PIECE
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings._mpp_checks import decode_object, decode_string_map
from integraledger_terms.bindings.mpp_session_solana import session_salt
from mpp_docs import b64u, issued, place_carrier, placed_doc
from support import hexb, load, serving

EVM_ACCOUNT = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
MAINNET = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
L = "lcp:sha256:" + H


def signing(seed_hex: str) -> Callable[[Any], str]:
    """A test signer's answer: the seed's Ed25519 signature over a solana-message request, as 0x hex."""
    seed = bytes.fromhex(seed_hex)

    def answer(request: Any) -> str:
        assert request["kind"] == "solana-message"
        return "0x" + sign(seed, hexb(request["message"])).hex()

    return answer


def decompile(message: bytes) -> dict[str, Any]:
    """A v0 message's fee payer, blockhash and instructions: program, accounts with their signer and writable flags,
    and data, as addresses."""
    required = message[1]
    tx = _svm.decode_svm_tx(bytes([required]) + bytes(64 * required) + message)
    assert not isinstance(tx, Refusal), tx
    signers, readonly_signed, readonly_unsigned = message[1], message[2], message[3]
    n = len(tx.keys)

    def flags(i: int) -> dict[str, bool]:
        writable = i < signers - readonly_signed if i < signers else i < n - readonly_unsigned
        return {"signer": i < signers, "writable": writable}

    return {
        "feePayer": b58_encode(tx.keys[0]),
        "blockhash": b58_encode(tx.blockhash),
        "instructions": [
            {
                "program": b58_encode(tx.keys[ix.program]),
                "accounts": [{"address": b58_encode(tx.keys[a]), **flags(a)} for a in ix.accounts],
                "data": ix.data.hex(),
            }
            for ix in tx.instructions
        ],
    }


def http_doc(doc: Mapping[str, Any]) -> dict[str, Any]:
    """The document with its legal context's link as http://."""
    out = copy.deepcopy(dict(doc))
    info = out["extensions"]["legalContext"]["info"]
    info["legalContextUrl"] = info["legalContextUrl"].replace("https://", "http://")
    return out


def with_memo(option: Mapping[str, Any]) -> dict[str, Any]:
    """The option as advertise places H: extra.memo = L."""
    return {**option, "extra": {**option["extra"], "memo": L}}


def refusals(p: Pairing, others: list[str]) -> None:
    """B10: an http link is offer-unreadable, x402/link-not-https, before any fetch. B16: an account of another
    namespace, and one on another network, have no payable option, and nothing is fetched."""
    out, calls = link_calls(p, p.account, http_doc(p.doc))
    assert code(out) == "offer-unreadable" and isinstance(out, Declined) and out.detail == "x402/link-not-https"
    assert calls == 0
    for account in others:
        out, calls = link_calls(p, account)
        assert code(out) == "no-payable-option", (account, out)
        assert calls == 0


# ── x402/exact/solana ───────────────────────────────────────────────────────────────────────────────────────────

S = load("x402-exact-solana.json")
SF = S["fixed"]


def exact_pairing() -> Pairing:
    return Pairing(
        binding=X402_EXACT_SOLANA,
        doc=x402_doc(with_memo(SF["option"]), SF["resource"]),
        account=f"{SF['option']['network']}:{SF['payer']}",
        answer=signing(SF["payerSeed"]),
        inputs={"decimals": SF["decimals"], "tokenProgram": SF["tokenProgram"], "recentBlockhash": SF["blockhash"]},
    )


def test_x402_exact_solana_the_payers_key_is_the_vectors_payer() -> None:
    assert b58_encode(public_key(bytes.fromhex(SF["payerSeed"]))) == SF["payer"]
    assert b58_encode(public_key(bytes.fromhex(SF["feePayerSeed"]))) == SF["feePayer"]

def test_x402_exact_solana_b6_the_message_decompiles_to_v1_and_the_signature_completes_a_payment_bound_to_h() -> None:
    p = exact_pairing()
    seen: list[bytes] = []

    def inspect(request: Any) -> None:
        assert request["kind"] == "solana-message"
        message = hexb(request["message"])
        seen.append(message)
        assert len(message) == S["V1"]["messageLength"]
        assert message[0] == S["V1"]["messageFirstByte"]
        m = decompile(message)
        assert m["feePayer"] == S["V1"]["feePayer"]
        assert m["blockhash"] == S["V1"]["blockhash"]
        # Built with no computeUnitLimit or computeUnitPrice input: the Compute Budget prefix is the vector's default.
        assert m["instructions"] == S["defaultComputeBudget"]["instructions"] + S["V1"]["instructions"][2:]

    signed, _ = build_and_sign(p, inspect)
    wire = base64.b64decode(signed["payload"]["transaction"])
    tx = _svm.decode_svm_tx(wire)
    assert not isinstance(tx, Refusal)
    assert tx.message == seen[0]
    slot = [b58_encode(k) for k in tx.keys].index(SF["payer"])
    assert tx.signatures[slot] == sign(bytes.fromhex(SF["payerSeed"]), seen[0])
    assert tx.signatures[0] == bytes(64)
    assert signed["accepted"] == with_memo(SF["option"])
    assert signed["resource"] == SF["resource"]


def test_x402_exact_solana_the_offers_recent_blockhash_is_the_builds() -> None:
    p = exact_pairing()
    option = with_memo({**SF["option"], "extra": {**SF["option"]["extra"], "recentBlockhash": SF["blockhash"]}})
    doc = x402_doc(option, SF["resource"])
    inputs = {"decimals": SF["decimals"], "tokenProgram": SF["tokenProgram"]}
    out = run(lambda c: confirm(doc, X402_EXACT_SOLANA, p.account, c, inputs), serving(ABC))
    assert isinstance(out, Confirmed) and out.request is not None and out.request["kind"] == "solana-message"
    assert decompile(hexb(out.request["message"]))["blockhash"] == S["V1"]["blockhash"]


def test_x402_exact_solana_a_missing_input_is_declined_before_any_fetch() -> None:
    p = exact_pairing()
    link = serving(ABC)
    inputs = {"decimals": SF["decimals"], "recentBlockhash": SF["blockhash"]}
    out = run(lambda c: confirm(p.doc, X402_EXACT_SOLANA, p.account, c, inputs), link)
    assert code(out) == "no-payable-option" and isinstance(out, Declined) and out.detail == "x402/input-missing"
    assert link.calls == 0


def test_x402_exact_solana_b10_b16_refusals() -> None:
    refusals(exact_pairing(), [EVM_ACCOUNT, f"{MAINNET}:{SF['payer']}"])


def test_x402_exact_solana_a_signature_that_is_not_64_bytes_of_hex_is_signed_not_bound() -> None:
    p = exact_pairing()
    out = run(lambda c: confirm(p.doc, X402_EXACT_SOLANA, p.account, c, p.inputs), serving(ABC))
    assert isinstance(out, Confirmed)
    assert code(finish(ABC, out.chosen, "0x1234", X402_EXACT_SOLANA)) == "signed-not-bound"


def test_x402_exact_solana_v2_the_payers_signature_over_the_vectors_message_makes_the_vectors_wire() -> None:
    wire = base64.b64decode(S["V2"]["wireBase64"])
    assert len(wire) == S["V2"]["wireLength"]
    tx = _svm.decode_svm_tx(wire)
    assert not isinstance(tx, Refusal)
    assert hashlib.sha256(tx.message).hexdigest() == S["V1"]["messageSha256"]
    signature = sign(bytes.fromhex(SF["payerSeed"]), tx.message)
    assert signature.hex().startswith(S["V1"]["payerSignaturePrefix"])
    assert signature.hex().endswith(S["V1"]["payerSignatureSuffix"])
    assert _svm.signed_wire(tx.message, SF["payer"], signature) == wire


def test_x402_exact_solana_v2_bound_of_the_partially_signed_wire_is_h() -> None:
    presented = {"x402Version": 2, "accepted": S["V2"]["accepted"], "payload": {"transaction": S["V2"]["wireBase64"]}}
    assert X402_EXACT_SOLANA.bound(presented) == S["V2"]["expectBound"]


@pytest.mark.parametrize("row", S["V3"][:3], ids=lambda r: r["case"])
def test_x402_exact_solana_v3_bound_refusals(row: dict[str, Any]) -> None:
    presented = {"x402Version": 2, "accepted": row["accepted"], "payload": {"transaction": row["wireBase64"]}}
    assert X402_EXACT_SOLANA.bound(presented) == Refusal(row["expect"])


def agreed(case_start: str) -> str:
    for r in S["agreedRefusals"]["rows"]:
        if r["case"].startswith(case_start):
            found: str = r["expect"]
            return found
    raise KeyError(case_start)


def test_x402_exact_solana_agreed_refusals_on_the_buyer_half() -> None:
    accepted = S["V2"]["accepted"]
    wire = base64.b64decode(S["V2"]["wireBase64"])

    def bound(transaction: object, option: object = accepted) -> object:
        return X402_EXACT_SOLANA.bound({"x402Version": 2, "accepted": option, "payload": {"transaction": transaction}})

    malformed = agreed("a payload whose transaction")
    assert bound("not base64!") == Refusal(malformed)
    assert bound(base64.b64encode(wire[:-1]).decode()) == Refusal(malformed)
    assert bound(base64.b64encode(bytes([1]) + wire[1:]).decode()) == Refusal(malformed)
    assert bound(base64.b64encode(wire + bytes(1232)).decode()) == Refusal(agreed("a wire over 1232 bytes"))
    other = {**accepted, "scheme": "upto"}
    assert bound(S["V2"]["wireBase64"], other) == Refusal(agreed("a payment whose option fails"))
    two_memos = _svm.decode_svm_tx(base64.b64decode(S["V3"][1]["wireBase64"]))
    assert not isinstance(two_memos, Refusal)
    assert _svm.svm_carrier(two_memos) == Refusal(agreed("svmCarrier"))


def test_x402_exact_solana_agreed_refusals_on_build() -> None:
    doc = x402_doc(with_memo(SF["option"]), SF["resource"])
    accepted = doc["accepts"][0]
    base = {
        "required": doc,
        "accepted": accepted,
        "payer": SF["payer"],
        "decimals": SF["decimals"],
        "tokenProgram": SF["tokenProgram"],
        "recentBlockhash": SF["blockhash"],
    }
    assert not isinstance(X402_EXACT_SOLANA.build(base, H), Refusal)
    input_malformed = agreed("build or buildSvmMessage")
    for key, value in (
        ("payer", "not-a-key"),
        ("tokenProgram", SF["mint"]),
        ("decimals", 256),
        ("recentBlockhash", "0x00"),
        ("computeUnitLimit", 2**32),
        ("computeUnitPrice", 2**64),
    ):
        assert X402_EXACT_SOLANA.build({**base, key: value}, H) == Refusal(input_malformed), key
    unsigned = X402_EXACT_SOLANA.build(base, H)
    assert not isinstance(unsigned, Refusal)
    assert unsigned.complete(bytes(63)) == Refusal(input_malformed)
    bad = {**accepted, "amount": str(2**64)}
    bad_doc = {**doc, "accepts": [bad]}
    assert X402_EXACT_SOLANA.build({**base, "required": bad_doc, "accepted": bad}, H) == Refusal(
        agreed("advertise or build with an amount")
    )
    assert X402_EXACT_SOLANA.build({**base}, "0x" + "00" * 32) == Refusal("svm/carrier-mismatch")


# ── x402/upto/solana ────────────────────────────────────────────────────────────────────────────────────────────

U = load("x402-upto-solana.json")
UF = U["fixed"]
UPTO_INPUTS = {
    "nonce": UF["nonce"],
    "openSlot": UF["openSlot"],
    "tokenProgram": UF["tokenProgram"],
    "recentBlockhash": UF["blockhash"],
}


@pytest.fixture
def upto_now(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: UF["now"])


def upto_pairing(inputs: Mapping[str, Any] = UPTO_INPUTS) -> Pairing:
    return Pairing(
        binding=X402_UPTO_SOLANA,
        doc=x402_doc(with_memo(UF["option"]), UF["resource"]),
        account=f"{UF['option']['network']}:{UF['payer']}",
        answer=signing(UF["payerSeed"]),
        inputs=dict(inputs),
    )

def test_x402_upto_solana_b6_the_open_message_decompiles_to_eu3_and_the_payment_opens_eu1s_channel(
    upto_now: None,
) -> None:
    expected = [
        {
            "program": ix["program"],
            "accounts": [{"address": a, "signer": sg, "writable": w} for a, sg, w in ix["accounts"]],
            "data": ix["data"],
        }
        for ix in U["EU3"]["instructions"]
    ]
    seen: list[bytes] = []

    def inspect(request: Any) -> None:
        assert request["kind"] == "solana-message"
        message = hexb(request["message"])
        seen.append(message)
        assert len(message) == U["EU3"]["messageLength"]
        m = decompile(message)
        assert m["feePayer"] == U["EU3"]["feePayer"]
        assert m["blockhash"] == U["EU3"]["blockhash"]
        assert m["instructions"] == expected
        assert m["instructions"][2]["data"] == U["EU2"]["openInstructionData"]

    signed, _ = build_and_sign(upto_pairing(), inspect)
    payload = signed["payload"]
    option = UF["option"]
    assert {k: payload[k] for k in payload if k != "openTransaction"} == {
        "from": UF["payer"],
        "maxAmount": option["amount"],
        "expiresAt": UF["now"] + option["maxTimeoutSeconds"],
        "validAfter": UF["now"],
        "nonce": UF["nonce"],
        "openSlot": int(UF["openSlot"]),
        "channelId": U["EU1"]["channelPda"],
        "deposit": option["amount"],
        "authorizedSigner": UF["receiverAuthorizer"],
    }
    tx = _svm.decode_svm_tx(base64.b64decode(payload["openTransaction"]))
    assert not isinstance(tx, Refusal)
    assert tx.message == seen[0]
    slot = [b58_encode(k) for k in tx.keys].index(UF["payer"])
    assert tx.signatures[slot] == sign(bytes.fromhex(UF["payerSeed"]), seen[0])


def test_x402_upto_solana_without_a_nonce_input_the_choice_carries_a_fresh_random_u64_nonce(upto_now: None) -> None:
    rest = {k: v for k, v in UPTO_INPUTS.items() if k != "nonce"}
    p = upto_pairing(rest)
    nonces = []
    for _ in range(2):
        out = run(lambda c: confirm(p.doc, X402_UPTO_SOLANA, p.account, c, rest), serving(ABC))
        assert isinstance(out, Confirmed), out
        n = out.chosen.choice["nonce"]
        assert isinstance(n, str) and n.isdigit() and 1 <= len(n) <= 20 and int(n) < 2**64
        nonces.append(n)
    assert nonces[0] != nonces[1]


def test_x402_upto_solana_b10_b16_refusals(upto_now: None) -> None:
    refusals(upto_pairing(), [EVM_ACCOUNT, f"{MAINNET}:{UF['payer']}"])


def test_x402_upto_solana_eu1_eu2_the_channel_and_its_open_data() -> None:
    pda = _svm.find_pda(
        [
            b"channel",
            *(
                _svm.key_bytes(k) or b""
                for k in (UF["payer"], UF["feePayer"], UF["mint"], UF["receiverAuthorizer"])
            ),
            _svm.u64le(int(UF["nonce"])),
            _svm.u64le(int(UF["openSlot"])),
        ],
        _svm.PAYMENT_CHANNELS,
    )
    assert pda == _svm.Pda(U["EU1"]["channelPda"], U["EU1"]["bump"])
    data = _svm.open_instruction_data(
        int(UF["nonce"]), int(UF["option"]["amount"]), UF["option"]["extra"]["withdrawDelay"], int(UF["openSlot"]),
        UF["payTo"],
    )
    assert data is not None and data.hex() == U["EU2"]["openInstructionData"] and len(data) == U["EU2"]["length"]


def test_x402_upto_solana_eu3_the_payers_signature_over_the_vectors_message_makes_the_vectors_wire() -> None:
    wire = base64.b64decode(U["EU3"]["wireBase64"])
    assert len(wire) == U["EU3"]["wireLength"]
    tx = _svm.decode_svm_tx(wire)
    assert not isinstance(tx, Refusal)
    assert hashlib.sha256(tx.message).hexdigest() == U["EU3"]["messageSha256"]
    signature = sign(bytes.fromhex(UF["payerSeed"]), tx.message)
    assert signature.hex().startswith(U["EU3"]["payerSignaturePrefix"])
    assert signature.hex().endswith(U["EU3"]["payerSignatureSuffix"])
    assert _svm.signed_wire(tx.message, UF["payer"], signature) == wire


def upto_presented(accepted: Mapping[str, Any], wire: str) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "accepted": accepted,
        "payload": {"channelId": U["EU4"]["channelId"], "openTransaction": wire},
    }


def test_x402_upto_solana_eu4_bound_of_the_opening_is_h() -> None:
    assert X402_UPTO_SOLANA.bound(upto_presented(U["EU4"]["accepted"], U["EU3"]["wireBase64"])) == U["EU4"]["expectBound"]


def test_x402_upto_solana_eu4_read_of_an_option_without_a_flow_succeeds() -> None:
    doc = x402_doc(with_memo(U["EU4"]["noFlowOption"]), UF["resource"])
    read = X402_UPTO_SOLANA.read(doc)
    assert not isinstance(read, Refusal) and read.h == H


@pytest.mark.parametrize("row", U["plant"], ids=lambda r: r["case"])
def test_x402_upto_solana_plant_an_opening_whose_carrier_is_not_this_atrs_h(row: dict[str, Any]) -> None:
    tx = _svm.decode_svm_tx(base64.b64decode(row["wireBase64"]))
    assert not isinstance(tx, Refusal)
    if "messageSha256" in row:
        assert hashlib.sha256(tx.message).hexdigest() == row["messageSha256"]
    assert X402_UPTO_SOLANA.bound(upto_presented(row["accepted"], row["wireBase64"])) == Refusal(row["expect"])


# ── x402/batch-settlement/solana ────────────────────────────────────────────────────────────────────────────────

BV = load("x402-batch-settlement.json")
BS = BV["fixed"]["svm"]
BATCH_ACCOUNT = f"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:{BS['payer']}"
BATCH_INPUTS = {
    "payerAuthorizer": BS["payer"],
    "deposit": BS["deposit"],
    "openSlot": BS["openSlot"],
    "tokenProgram": BS["tokenProgram"],
    "recentBlockhash": BS["blockhash"],
    "salt": BS["salt"],
}
BATCH_BINDING: Any = X402_BATCH_SETTLEMENT_SOLANA


def batch_answer(request: Any) -> list[str]:
    """The payer, who is also the payer authorizer, signs the transaction message and the voucher, each in base58."""
    assert request["kind"] == "batch"
    out = []
    for r in request["requests"]:
        assert r["kind"] in ("solana-message", "ed25519-raw")
        out.append(b58_encode(sign(bytes.fromhex(BS["payerSeed"]), hexb(r["message"]))))
    return out


def batch_pairing(option: Mapping[str, Any] | None = None, inputs: Mapping[str, Any] = BATCH_INPUTS) -> Pairing:
    return Pairing(
        binding=X402_BATCH_SETTLEMENT_SOLANA,
        doc=x402_doc(with_memo(option or BS["option"]), BV["fixed"]["resource"]),
        account=BATCH_ACCOUNT,
        answer=batch_answer,
        inputs=dict(inputs),
    )

def test_x402_batch_settlement_solana_b6_es2s_opening_and_es3s_voucher_the_signed_wire_is_bound_to_h() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "batch"
        tx, voucher = request["requests"]
        assert tx["kind"] == "solana-message" and voucher["kind"] == "ed25519-raw"
        assert len(hexb(tx["message"])) == BV["ES2"]["messageLength"]
        assert BV["ES2"]["openInstructionData"] in hexb(tx["message"]).hex()
        assert BV["fixed"]["L"].encode().hex() in hexb(tx["message"]).hex()
        assert hexb(voucher["message"]).hex() == BV["ES3"]["message"]
        assert voucher["signer"] == BS["payer"]
        vs = sign(bytes.fromhex(BS["payerSeed"]), hexb(voucher["message"])).hex()
        assert vs.startswith(BV["ES3"]["signaturePrefix"]) and vs.endswith(BV["ES3"]["signatureSuffix"])

    signed, _ = build_and_sign(batch_pairing(), inspect)
    payload = signed["payload"]
    assert len(base64.b64decode(payload["deposit"]["transaction"])) == BV["ES2"]["wireLength"]
    assert payload["voucher"]["channelId"] == BV["ES1"]["channelPda"]
    assert BATCH_BINDING.channel_kind(signed) == "open"
    assert BATCH_BINDING.channel_ref(signed) == ChannelRef(**BV["ES4"]["expectRef"])


def test_x402_batch_settlement_solana_b10_b16_refusals() -> None:
    refusals(batch_pairing(), [EVM_ACCOUNT, f"{MAINNET}:{BS['payer']}"])


def test_x402_batch_settlement_solana_the_recent_blockhash_is_the_offers_when_present() -> None:
    option = {**BS["option"], "extra": {**BS["option"]["extra"], "recentBlockhash": BS["blockhash"]}}
    rest = {k: v for k, v in BATCH_INPUTS.items() if k != "recentBlockhash"}
    p = batch_pairing(option, rest)
    out = run(lambda c: confirm(p.doc, X402_BATCH_SETTLEMENT_SOLANA, p.account, c, rest), serving(ABC))
    assert isinstance(out, Confirmed), out
    assert out.chosen.choice["recentBlockhash"] == BS["blockhash"]


def test_x402_batch_settlement_solana_es1_the_pdas_and_the_curve_test() -> None:
    assert _svm.channel_pda(BS["payer"], BS["feePayer"], BS["mint"], BS["payer"], 42, 341000000) == BV["ES1"]["channelPda"]
    assert _svm.channel_pda(BS["payer"], BS["feePayer"], BS["mint"], BS["payer"], 43, 341000000) == BV["ES1"]["salt43"]
    authority = _svm.find_pda([b"event_authority"], _svm.PAYMENT_CHANNELS)
    assert authority == _svm.Pda(BV["ES1"]["eventAuthority"], BV["ES1"]["eventAuthorityBump"])
    assert not isinstance(authority, Refusal) and authority.address != BV["ES1"]["wrongCurveTest"]


def test_x402_batch_settlement_solana_es2_es3_the_opening_wire_and_the_voucher_message() -> None:
    wire = base64.b64decode(BV["ES2"]["wireBase64"])
    assert len(wire) == BV["ES2"]["wireLength"]
    tx = _svm.decode_svm_tx(wire)
    assert not isinstance(tx, Refusal)
    assert hashlib.sha256(tx.message).hexdigest() == BV["ES2"]["messageSha256"]
    assert hashlib.sha256(wire).hexdigest().startswith(BV["ES2"]["wireSha256Prefix"])
    signature = sign(bytes.fromhex(BS["payerSeed"]), tx.message)
    assert _svm.signed_wire(tx.message, BS["payer"], signature) == wire
    data = _svm.open_instruction_data(
        int(BS["salt"]), int(BS["deposit"]), BS["withdrawDelay"], int(BS["openSlot"]), BS["payTo"]
    )
    assert data is not None and data.hex() == BV["ES2"]["openInstructionData"]
    voucher = _svm.channel_voucher_message(BV["ES1"]["channelPda"], int(BS["option"]["amount"]), 0)
    assert voucher is not None and voucher.hex() == BV["ES3"]["message"]


def batch_presented(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {"x402Version": 2, "accepted": BV["ES4"]["accepted"], "payload": dict(payload)}


ES4_VOUCHER = {"channelId": BV["ES1"]["channelPda"], "maxClaimableAmount": "1000", "expiresAt": 0, "signature": "x"}


def batch_deposit(wire: str) -> dict[str, Any]:
    return batch_presented(
        {
            "type": "deposit",
            "channelConfig": BV["ES4"]["config"],
            "voucher": ES4_VOUCHER,
            "deposit": {"amount": BS["deposit"], "transaction": wire},
        }
    )


def test_x402_batch_settlement_solana_es4_bound_the_members_and_the_plants() -> None:
    es4 = BV["ES4"]
    opening = batch_deposit(BV["ES2"]["wireBase64"])
    assert BATCH_BINDING.bound(opening) == es4["expectBound"]
    assert BATCH_BINDING.channel_kind(opening) == es4["expectKind"]
    assert BATCH_BINDING.channel_ref(opening) == ChannelRef(**es4["expectRef"])
    top_up = batch_deposit(es4["topUpWireBase64"])
    assert BATCH_BINDING.channel_kind(top_up) == es4["expectTopUpKind"]
    assert BATCH_BINDING.bound(top_up) == Refusal("x402/not-an-opening")
    close = batch_presented({"type": "refund", "channelConfig": es4["config"], "transaction": es4["closeWireBase64"]})
    assert BATCH_BINDING.channel_kind(close) == es4["expectCloseKind"]
    assert BATCH_BINDING.channel_ref(close) == ChannelRef(**es4["expectRef"])
    assert BATCH_BINDING.bound_within(opening) == Refusal(es4["expectBoundWithin"])
    assert BATCH_BINDING.bound(batch_deposit(es4["plantNonce"]["wireBase64"])) == Refusal(es4["plantNonce"]["expect"])
    salt43 = batch_presented({"type": "voucher", "channelConfig": {**es4["config"], "salt": "43"}, "voucher": ES4_VOUCHER})
    assert BATCH_BINDING.channel_ref(salt43) == Refusal(es4["plantSalt43"]["expect"])


def batch_agreed(case_start: str) -> str:
    for r in BV["agreedRefusals"]["rows"]:
        if r["case"].startswith(case_start):
            found: str = r["expect"]
            return found
    raise KeyError(case_start)


def test_x402_batch_settlement_solana_agreed_refusals_on_the_buyer_half() -> None:
    malformed = batch_agreed("bound, reference or ref")
    for member in ("payer", "payerAuthorizer", "receiver", "token", "withdrawDelay", "salt", "openSlot"):
        config = {k: v for k, v in BV["ES4"]["config"].items() if k != member}
        presented = batch_deposit(BV["ES2"]["wireBase64"])
        presented["payload"]["channelConfig"] = config
        assert BATCH_BINDING.bound(presented) == Refusal(malformed), member
        assert BATCH_BINDING.channel_ref(presented) == Refusal(malformed), member

    p = batch_pairing()
    out = run(lambda c: confirm(p.doc, X402_BATCH_SETTLEMENT_SOLANA, p.account, c, p.inputs), serving(ABC))
    assert isinstance(out, Confirmed) and out.request is not None
    good = batch_answer(out.request)
    assert code(finish(ABC, out.chosen, good[:1], X402_BATCH_SETTLEMENT_SOLANA)) == "signed-not-bound"
    doc, accepted = p.doc, p.doc["accepts"][0]
    choice = {
        "required": doc,
        "accepted": accepted,
        "payer": BS["payer"],
        "payerAuthorizer": BS["payer"],
        "deposit": int(BS["deposit"]),
        "salt": int(BS["salt"]),
        "openSlot": int(BS["openSlot"]),
        "tokenProgram": BS["tokenProgram"],
        "recentBlockhash": BS["blockhash"],
    }
    unsigned = BATCH_BINDING.build(choice, H)
    assert not isinstance(unsigned, Refusal)
    signature_count = batch_agreed("complete with a signature count")
    assert X402_BATCH_SETTLEMENT_SOLANA_PIECE.complete(unsigned, good[:1], out.chosen) == Refusal(signature_count)
    input_malformed = batch_agreed("SVM complete with a signature")
    assert unsigned.complete([good[0], b58_encode(bytes(63))]) == Refusal(input_malformed)
    assert unsigned.complete(["0x" + "11" * 64, good[1]]) == Refusal(input_malformed)
    for key, value in (("deposit", 0), ("deposit", 2**64), ("openSlot", 2**64), ("salt", -1), ("tokenProgram", "x")):
        assert BATCH_BINDING.build({**choice, key: value}, H) == Refusal(input_malformed), key


def test_x402_batch_settlement_solana_open_channel_holds_es1s_channel_and_within_signs_es3s_voucher() -> None:
    p = batch_pairing()
    opener = Recording(BATCH_ACCOUNT, batch_answer)
    opened = run(lambda c: transact(p.doc, X402_BATCH_SETTLEMENT_SOLANA, opener, c, inputs=p.inputs), serving(ABC))
    assert isinstance(opened, Transacted) and opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, X402_BATCH_SETTLEMENT_SOLANA)
    assert not isinstance(hold, Declined), hold
    expected = {"network": BV["ES4"]["expectRef"]["network"], "channel": BV["ES1"]["channelPda"], "h": H, "charged": "0",
                "signedMax": "1000"}  # fmt: skip
    assert {k: hold[k] for k in expected} == expected
    signer = Recording(BATCH_ACCOUNT, batch_answer)
    out = asyncio.run(within(p.doc, json.loads(json.dumps(hold)), X402_BATCH_SETTLEMENT_SOLANA, signer))
    assert isinstance(out, Within), out
    request = signer.requests[0]
    assert request["kind"] == "batch" and request["requests"][0]["kind"] == "ed25519-raw"
    message = hexb(request["requests"][0]["message"])
    assert message.hex() == BV["ES3"]["message"]
    sig = sign(bytes.fromhex(BS["payerSeed"]), message).hex()
    assert sig.startswith(BV["ES3"]["signaturePrefix"]) and sig.endswith(BV["ES3"]["signatureSuffix"])
    assert BATCH_BINDING.channel_kind(out.signed) == "within"
    assert BATCH_BINDING.channel_ref(out.signed) == ChannelRef(**BV["ES4"]["expectRef"])
    other = {**hold, "channel": BV["ES1"]["salt43"]}
    refused = Recording(BATCH_ACCOUNT, batch_answer)
    assert code(asyncio.run(within(p.doc, other, X402_BATCH_SETTLEMENT_SOLANA, refused))) == "signed-not-bound"
    assert refused.requests == []


class RefundWithin:
    """The batch binding with a build_within that stands in for the protocol package's: it records what the gate hands
    it and completes with the held channel's configuration, without the transaction the package's completion carries."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.handed: list[dict[str, Any]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def build_within(self, w: dict[str, Any], h: str) -> BatchUnsigned:
        self.handed.append(w)
        return BatchUnsigned(
            requests=[{"kind": "solana-message", "message": bytes([1, 2, 3])}],
            complete=lambda signatures: {
                "x402Version": 2,
                "accepted": w["accepted"],
                "payload": {"type": "refund", "channelConfig": w["channelConfig"]},
            },
        )


def test_x402_batch_settlement_solana_a_full_refund_hands_build_within_refund_and_returns_the_close() -> None:
    """The Solana batch-settlement refund: within(doc, hold, binding, signer, {}) calls the protocol package's
    build_within with refund {}, which builds request_close itself and returns one solana-message request, and the gate
    checks that the completion's kind is close and that it names the held channel."""
    p = batch_pairing()
    opened = run(lambda c: transact(p.doc, X402_BATCH_SETTLEMENT_SOLANA, Recording(BATCH_ACCOUNT, batch_answer), c,
                                    inputs=p.inputs), serving(ABC))  # fmt: skip
    assert isinstance(opened, Transacted) and opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, X402_BATCH_SETTLEMENT_SOLANA)
    assert not isinstance(hold, Declined), hold
    binding = RefundWithin(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, lambda r: ["0x00"])
    out = asyncio.run(within(p.doc, hold, binding, signer, {}))
    assert isinstance(out, Within), out
    assert [w["refund"] for w in binding.handed] == [{}]
    assert binding.handed[0]["channelConfig"] == hold["opening"]["payload"]["channelConfig"]
    assert signer.requests == [{"kind": "batch", "requests": [{"kind": "solana-message", "message": "0x010203"}]}]
    assert BATCH_BINDING.channel_kind(out.signed) == "close"
    assert BATCH_BINDING.channel_ref(out.signed) == ChannelRef(**BV["ES4"]["expectRef"])


# ── mpp/charge/solana ───────────────────────────────────────────────────────────────────────────────────────────

MS = load("mpp-charge-solana.json")
MU = load("mpp-charge-usdc-solana.json")
DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
MPP_INPUTS = {"computeUnitLimit": MS["build"]["computeUnitLimit"], "computeUnitPrice": MS["build"]["computeUnitPrice"]}


def memo_carrier(occupied: str) -> Callable[[Any], Any]:
    """The Solana charge's placement of H: externalId set to L, refused when it already holds another value."""

    def carrier(value: Any) -> Any:
        return L if value is None or value == L else Refusal(occupied)

    return carrier


def mpp_doc(challenge: Mapping[str, Any], occupied: str = "svm/carrier-occupied") -> list[dict[str, Any]]:
    placed = place_carrier([challenge], H, LINK, challenge, memo_carrier(occupied))
    assert not isinstance(placed, Refusal), placed
    return placed


def http_mpp_doc(doc: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The document with each challenge's legal-context link as http://."""
    out = []
    for c in doc:
        m = decode_string_map(c["opaque"])
        assert m is not None
        m = {**m, "legalContextUrl": m["legalContextUrl"].replace("https://", "http://")}
        out.append({**c, "opaque": b64u(json.dumps(m, separators=(",", ":")))})
    return out


def mpp_refusals(p: Pairing, others: list[str]) -> None:
    """B10: an http link is offer-unreadable, mpp/link-not-https, before any fetch. B16: an account of another
    namespace, and one on another network, have no payable option, and nothing is fetched."""
    out, calls = link_calls(p, p.account, http_mpp_doc(p.doc))
    assert isinstance(out, Declined) and (out.code, out.detail) == ("offer-unreadable", "mpp/link-not-https")
    assert calls == 0
    for account in others:
        out, calls = link_calls(p, account)
        assert code(out) == "no-payable-option", (account, out)
        assert calls == 0


def charge_pairing() -> Pairing:
    return Pairing(
        binding=MPP_CHARGE_SOLANA,
        doc=mpp_doc(MS["challenge"]),
        account=f"{DEVNET}:{MS['fixed']['payer']}",
        answer=signing(SF["payerSeed"]),
        inputs=MPP_INPUTS,
    )


def test_mpp_charge_solana_the_placed_challenge_is_the_vectors() -> None:
    assert charge_pairing().doc == [MS["place"]["expect"]]
    occupied = {**MS["challenge"], "request": b64u(json.dumps(MS["occupied"]["request"], separators=(",", ":")))}
    assert place_carrier([occupied], H, LINK, occupied, memo_carrier("svm/carrier-occupied")) == Refusal(
        MS["occupied"]["expect"]
    )

def test_mpp_charge_solana_b6_the_message_is_v1s_and_the_signature_completes_a_bound_credential() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "solana-message"
        m = decompile(hexb(request["message"]))
        assert m["feePayer"] == S["V1"]["feePayer"]
        assert m["instructions"] == S["V1"]["instructions"]

    signed, _ = build_and_sign(charge_pairing(), inspect)
    assert signed["payload"]["type"] == "transaction"


def test_mpp_charge_solana_build_without_compute_budget_inputs_writes_the_default_prefix() -> None:
    placed = MS["place"]["expect"]
    out = MPP_CHARGE_SOLANA.build({"challenge": placed, "payer": MS["fixed"]["payer"]}, H)
    assert not isinstance(out, Refusal), out
    m = decompile(out.request["message"])
    assert m["instructions"][:2] == MS["defaultComputeBudget"]["instructions"]


def test_mpp_charge_solana_a_request_without_the_mints_decimals_needs_the_buyers() -> None:
    request = decode_object(MS["challenge"]["request"])
    assert request is not None
    del request["methodDetails"]["decimals"]
    challenge = {**MS["challenge"], "request": b64u(json.dumps(request, separators=(",", ":")))}
    p = charge_pairing()
    doc = mpp_doc(challenge)
    out, calls = link_calls(p, p.account, doc)
    assert isinstance(out, Declined) and (out.code, out.detail) == ("no-payable-option", "mpp/input-missing")
    assert calls == 0


def test_mpp_charge_solana_b10_b16_refusals() -> None:
    mpp_refusals(charge_pairing(), [EVM_ACCOUNT, f"{MAINNET}:{MS['fixed']['payer']}"])


def credential(challenge: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, Any]:
    return {"challenge": dict(challenge), "payload": dict(payload)}


def with_external_id(challenge: Mapping[str, Any], external_id: str) -> dict[str, Any]:
    request = decode_object(challenge["request"])
    assert request is not None
    return {**challenge, "request": b64u(json.dumps({**request, "externalId": external_id}, separators=(",", ":")))}


def test_mpp_charge_solana_v2_bound_the_refusals_the_split_and_the_plant() -> None:
    placed = MS["place"]["expect"]
    tx = {"type": "transaction", "transaction": MS["V2"]["wireBase64"]}
    assert MPP_CHARGE_SOLANA.bound(credential(placed, tx)) == MS["V2"]["expectBound"]
    for row in MS["refusals"]:
        if "payload" in row:
            payload = row["payload"]
        else:
            payload = {"type": "transaction", "transaction": row["wireBase64"]}
        challenge = with_external_id(placed, row["externalId"]) if "externalId" in row else placed
        assert MPP_CHARGE_SOLANA.bound(credential(challenge, payload)) == Refusal(row["expect"]), row["case"]
    plant_tx = {"type": "transaction", "transaction": MS["plant"]["wireBase64"]}
    assert MPP_CHARGE_SOLANA.bound(credential(placed, plant_tx)) == Refusal(MS["plant"]["expect"])
    other = {"type": "hash", "transaction": MS["V2"]["wireBase64"]}
    assert MPP_CHARGE_SOLANA.bound(credential(placed, other)) == Refusal(
        next(r["expect"] for r in MS["agreedRefusals"]["rows"] if r["case"].startswith("a payload type other"))
    )


def test_mpp_charge_solana_e64_a_split_memo_beside_the_lcp_memo_is_not_read() -> None:
    fixed = MS["fixed"]
    details = fixed["request"]["methodDetails"]
    source = _svm.ata(fixed["payer"], details["tokenProgram"], fixed["request"]["currency"])
    destination = _svm.ata(fixed["request"]["recipient"], details["tokenProgram"], fixed["request"]["currency"])
    assert isinstance(source, str) and isinstance(destination, str)
    transfer = _svm.Instruction(
        details["tokenProgram"],
        (
            (source, _svm.WRITABLE),
            (fixed["request"]["currency"], _svm.READONLY),
            (destination, _svm.WRITABLE),
            (fixed["payer"], _svm.READONLY_SIGNER),
        ),
        b"\x0c" + _svm.u64le(int(fixed["request"]["amount"])) + bytes([details["decimals"]]),
    )
    message = _svm.compile_v0(
        fixed["feePayer"],
        details["recentBlockhash"],
        [
            transfer,
            _svm.Instruction(_svm.MEMO_V3, (), L.encode()),
            _svm.Instruction(_svm.MEMO_V3, (), MS["split"]["splitMemo"].encode()),
        ],
    )
    assert isinstance(message, bytes)
    wire = _svm.signed_wire(message, fixed["payer"], sign(bytes.fromhex(SF["payerSeed"]), message))
    assert isinstance(wire, bytes)
    tx = {"type": "transaction", "transaction": base64.b64encode(wire).decode()}
    assert MPP_CHARGE_SOLANA.bound(credential(MS["place"]["expect"], tx)) == MS["split"]["expectBound"]


# ── mpp/charge/usdc/solana ──────────────────────────────────────────────────────────────────────────────────────

USDC_ISSUED = issued(
    "usdc", "charge", json.dumps(MU["fixed"]["request"], separators=(",", ":")), MU["fixed"]["realm"], MU["fixed"]["expires"]
)


def usdc_pairing() -> Pairing:
    return Pairing(
        binding=MPP_CHARGE_USDC_SOLANA,
        doc=mpp_doc(USDC_ISSUED, "mpp/carrier-occupied"),
        account=f"{MU['V2']['expectReference']['network']}:{MS['fixed']['payer']}",
        answer=signing(SF["payerSeed"]),
        inputs=MPP_INPUTS,
    )

def test_mpp_charge_usdc_solana_b6_the_payers_signature_completes_a_credential_bound_to_h() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "solana-message"
        m = decompile(hexb(request["message"]))
        assert m["feePayer"] == S["V1"]["feePayer"]
        assert m["instructions"] == S["V1"]["instructions"]

    signed, _ = build_and_sign(usdc_pairing(), inspect)
    assert signed["payload"]["type"] == "transaction"


def test_mpp_charge_usdc_solana_v2_bound_and_the_credential_types() -> None:
    placed = usdc_pairing().doc[0]
    tx = {"type": "transaction", "transaction": MU["V2"]["wireBase64"]}
    assert MPP_CHARGE_USDC_SOLANA.bound(credential(placed, tx)) == MU["V2"]["expectBound"]
    for row in MU["refusals"]["credentials"]["rows"]:
        expect = Refusal(row["expect"]["code"])
        assert MPP_CHARGE_USDC_SOLANA.bound(credential(placed, row["payload"])) == expect, row["case"]


def test_mpp_charge_usdc_solana_the_profile_refusals_on_the_buyers_read() -> None:
    for row in MU["refusals"]["rows"]:
        if "externalId" in row:
            continue
        request = copy.deepcopy(MU["fixed"]["request"])
        md = request["methodDetails"]
        if "type" in row:
            md["type"] = row["type"]
        md.update(row.get("extra", {}))
        if row.get("dropNetwork"):
            del md["solana"]["network"]
        c = issued("usdc", "charge", json.dumps(request, separators=(",", ":")), MU["fixed"]["realm"], MU["fixed"]["expires"])
        assert pairings_of(c) == Refusal(row["expect"]["code"]), row["case"]


# ── mpp/session/solana ──────────────────────────────────────────────────────────────────────────────────────────

SV = load("mpp-session-hedera-solana-xrpl.json")
SESSION_DETAILS = (decode_object(SV["SS1"]["solana"]["challenge"]["request"]) or {})["methodDetails"]
SESSION_PLANT = SV["plants"]["solana"]
SV2_OPEN = {"action": "open", "channelId": SV["SV2"]["channel"], "transaction": SV["SV2"]["wireBase64"]}
PAYER_SEED = bytes.fromhex(SF["payerSeed"])


def session_answer(request: Any) -> Any:
    """The channel client's open (SV2's wire, composed from the request's values and signed by the payer), and the
    payer's base58 signature over a session proof."""
    if request["kind"] == "solana-session-open":
        return dict(SV2_OPEN)
    assert request["kind"] == "ed25519-raw", request["kind"]
    return b58_encode(sign(PAYER_SEED, hexb(request["message"])))


def session_pairing(doc: list[dict[str, Any]] | None = None) -> Pairing:
    return Pairing(
        binding=MPP_SESSION_SOLANA,
        doc=doc if doc is not None else mpp_session_doc(SV["SS1"]["solana"]["challenge"]),
        account=f"{DEVNET}:{SV['SV3']['payer']}",
        answer=session_answer,
    )


def mpp_session_doc(challenge: Mapping[str, Any]) -> list[dict[str, Any]]:
    return placed_doc(challenge, H, LINK)


def test_mpp_session_solana_the_placed_challenge_and_sv2s_signed_wire() -> None:
    p = session_pairing()
    assert p.doc == [SV["SS1"]["solana"]["placed"]]
    wire = base64.b64decode(SV["SV2"]["wireBase64"])
    assert len(wire) == SV["SV2"]["wireLength"]
    message = wire[1 + 64 * wire[0] :]
    assert "0x" + hashlib.sha256(message).hexdigest() == SV["SV2"]["expectMessageSha256"]
    assert SV["SV2"]["expectOpenData"] in message.hex()
    assert b58_encode(public_key(PAYER_SEED)) == SV["SV3"]["payer"]
    slots = [wire[1 + 64 * i : 65 + 64 * i] for i in range(wire[0])]
    assert sign(PAYER_SEED, message) in slots

def test_mpp_session_solana_b6_the_salt_is_sv1s_and_the_composed_open_is_sv2s() -> None:
    def inspect(request: Any) -> None:
        assert request == {
            "kind": "solana-session-open",
            "salt": int(SV["SV1"]["expectSalt"]),
            "channelProgram": SESSION_DETAILS["channelProgram"],
            "network": DEVNET,
            "recentBlockhash": SESSION_DETAILS["recentBlockhash"],
            "recentSlot": int(SESSION_DETAILS["recentSlot"]),
        }

    signed, _ = build_and_sign(session_pairing(), inspect)
    assert signed["payload"] == SV2_OPEN


def test_mpp_session_solana_the_plants_open_salted_with_h2_is_not_bound() -> None:
    p = session_pairing()
    confirmed = run(lambda c: confirm(p.doc, MPP_SESSION_SOLANA, p.account, c), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    plant_open = {"action": "open", "channelId": SESSION_PLANT["channel"], "transaction": SESSION_PLANT["wireBase64"]}
    out = finish(ABC, confirmed.chosen, plant_open, MPP_SESSION_SOLANA)
    assert out == Declined("signed-not-bound", SV["plants"]["solana"]["expect"])


def operator_doc() -> list[dict[str, Any]]:
    issued_request = decode_object(SV["SS1"]["solana"]["challenge"]["request"])
    assert issued_request is not None
    request = {**issued_request, "methodDetails": {**issued_request["methodDetails"], **SV["SV5"]["methodDetails"]}}
    challenge = {**SV["SS1"]["solana"]["challenge"], "request": b64u(json.dumps(request, separators=(",", ":")))}
    return mpp_session_doc(challenge)


def test_mpp_session_solana_sv5_the_payer_signs_sv3s_session_proof_after_the_open() -> None:
    proof_text = SV["SV3"]["expectProofText"].encode()
    digest_hex = hashlib.sha256(proof_text).hexdigest()
    assert digest_hex.startswith(SV["SV3"]["expectProofSha256Prefix"])
    assert digest_hex.endswith(SV["SV3"]["expectProofSha256Suffix"])
    proof_signature = sign(PAYER_SEED, proof_text)
    assert proof_signature.hex().startswith(SV["SV3"]["expectProofSignaturePrefix"])
    assert proof_signature.hex().endswith(SV["SV3"]["expectProofSignatureSuffix"])

    doc: Any = operator_doc()
    signer = Recording(f"{DEVNET}:{SV['SV3']['payer']}", session_answer)
    out = run(lambda c: transact(doc, MPP_SESSION_SOLANA, signer, c), serving(ABC))
    assert isinstance(out, Transacted) and out.signed is not None, out
    assert [r["kind"] for r in signer.requests] == SV["SV5"]["expectRequestKinds"]
    assert hexb(signer.requests[1]["message"]).decode("utf-8") == SV["SV3"]["expectProofText"]
    assert signer.requests[1]["signer"] == SV["SV3"]["payer"]
    payload = out.signed["payload"]
    assert list(payload["authentication"]) == SV["SV5"]["expectAuthenticationKeys"]
    assert payload["authentication"] == {**SV["SV5"]["expectAuthentication"], "signature": b58_encode(proof_signature)}
    assert {k: payload[k] for k in SV2_OPEN} == SV2_OPEN
    assert MPP_SESSION_SOLANA.bound(out.signed) == H
    use = {**out.signed, "payload": {**payload, "action": "use"}}
    assert MPP_SESSION_SOLANA.bound_within(use) == H


def test_mpp_session_solana_without_operator_mode_the_open_alone_completes_the_credential() -> None:
    p = session_pairing()
    signer = Recording(p.account, session_answer)
    out = run(lambda c: transact(p.doc, MPP_SESSION_SOLANA, signer, c), serving(ABC))
    assert isinstance(out, Transacted) and out.signed is not None, out
    assert [r["kind"] for r in signer.requests] == SV["SV5"]["expectRequestKinds"][:1]
    assert "authentication" not in out.signed["payload"]


def test_mpp_session_solana_b10_b16_refusals() -> None:
    mpp_refusals(session_pairing(), [EVM_ACCOUNT, f"{MAINNET}:{SV['SV3']['payer']}"])


def test_mpp_session_solana_sv1_to_sv3_and_the_channel_members() -> None:
    assert "0x" + session_salt(H).to_bytes(8, "big").hex() == SV["SV1"]["expectSaltHex"]
    assert session_salt(H) == int(SV["SV1"]["expectSalt"])
    placed = SV["SS1"]["solana"]["placed"]
    opening = credential(placed, SV2_OPEN)
    assert MPP_SESSION_SOLANA.bound(opening) == SV["SV2"]["expectBound"]
    assert MPP_SESSION_SOLANA.channel_kind(opening) == "open"
    assert MPP_SESSION_SOLANA.channel_ref(opening) == ChannelRef(DEVNET, SV["SV2"]["channel"])
    voucher = _svm.channel_voucher_message(SV["SV2"]["channel"], 100, 0)
    assert voucher is not None and voucher.hex() == SV["SV3"]["expectVoucher"]
    within_voucher = credential(placed, {"action": "voucher", "channelId": SV["SV2"]["channel"]})
    assert MPP_SESSION_SOLANA.channel_kind(within_voucher) == "within"
    assert MPP_SESSION_SOLANA.bound_within(within_voucher) == Refusal("mpp/not-bound-within")
    wrong = {"type": "proof", "challengeId": SV["plants"]["solana"]["useWrongChallengeId"]}
    use = credential(placed, {"action": "use", "channelId": SV["SV2"]["channel"], "authentication": wrong})
    assert MPP_SESSION_SOLANA.bound_within(use) == Refusal(SV["plants"]["solana"]["expectUse"])
    plant_open = {"action": "open", "channelId": SESSION_PLANT["channel"], "transaction": SESSION_PLANT["wireBase64"]}
    assert MPP_SESSION_SOLANA.bound(credential(placed, plant_open)) == Refusal(SV["plants"]["solana"]["expect"])


def test_x402_batch_settlement_solana_es6_a_full_refunds_request_close_built_by_build_within() -> None:
    # ES6: a full refund's request_close is built by build_within: the Compute Budget prefix (200 000 units, 1
    # microlamport), request_close (05) with the payer (read-only signer) and the channel (writable), then one Memo v3
    # with extra.memo when the option carries one; the payload is {type: refund, channelConfig, transaction}.
    s6 = BV["ES6"]
    with_memo: dict[str, Any] = BV["ES4"]["accepted"]
    without_memo = {**with_memo, "extra": {k: v for k, v in with_memo["extra"].items() if k != "memo"}}
    svm = BV["fixed"]["svm"]

    def build(accepted: Mapping[str, Any], **extra: Any) -> Any:
        w = {
            "required": {"x402Version": 2, "resource": BV["fixed"]["resource"], "accepts": [accepted]},
            "accepted": accepted,
            "channelConfig": BV["ES4"]["config"],
            "maxClaimableAmount": 1000,
            "refund": {},
            "recentBlockhash": svm["blockhash"],
            **extra,
        }
        binding: Any = X402_BATCH_SETTLEMENT_SOLANA
        return binding.build_within({k: v for k, v in w.items() if v is not None}, H)

    u = build(with_memo)
    assert not isinstance(u, Refusal), u
    assert len(u.requests) == 1 and u.requests[0]["kind"] == "solana-message"
    message = u.requests[0]["message"]
    wire = base64.b64decode(BV["ES4"]["closeWireBase64"])
    assert decompile(message) == decompile(wire[1 + 64 * wire[0] :])
    sig = sign(bytes.fromhex(svm["payerSeed"]), message)
    p = u.complete([b58_encode(sig)])
    assert not isinstance(p, Refusal), p
    assert sorted(p["payload"]) == ["channelConfig", "transaction", "type"]
    assert p["payload"]["type"] == "refund" and p["payload"]["channelConfig"] == BV["ES4"]["config"]
    signed = base64.b64decode(p["payload"]["transaction"])
    assert signed[0] == 2 and signed[1:65] == bytes(64) and signed[65:129] == sig and signed[129:] == message
    assert BATCH_BINDING.channel_kind(p) == s6["withMemo"]["expectKind"]
    assert BATCH_BINDING.channel_ref(p) == ChannelRef(**BV["ES4"]["expectRef"])

    v = build(without_memo)
    assert not isinstance(v, Refusal), v
    d = decompile(v.requests[0]["message"])
    assert (d["feePayer"], d["blockhash"]) == (svm["feePayer"], svm["blockhash"])
    assert d["instructions"] == s6["withoutMemo"]["instructions"]

    assert build(with_memo, refund={"amount": 5}) == Refusal(s6["refundWithAmount"]["expect"])
    assert build(with_memo, recentBlockhash=None) == Refusal(s6["noBlockhash"]["expect"])
