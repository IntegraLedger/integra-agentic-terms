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
    ChannelHold,
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
    record_charge,
    transact,
    within,
)
from integraledger_terms.bindings import _svm
from integraledger_terms.bindings._codec import b58_encode
from integraledger_terms.pieces.x402_batch_settlement_solana import PIECE as X402_BATCH_SETTLEMENT_SOLANA_PIECE
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings._mpp_checks import decode_object, decode_string_map
from integraledger_terms.bindings.x402_batch_settlement_solana import pairs as batch_pairs
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


@pytest.mark.parametrize("offered", ["x", "", "0" * 44, "1" * 31, "2" * 43, "z" * 44, 7])
def test_x402_exact_solana_an_offered_recent_blockhash_that_is_not_a_base58_key_is_not_taken(offered: Any) -> None:
    """x402's exact SVM scheme: a client whose offered blockhash is absent or malformed fetches its own. So the buyer's
    recentBlockhash is the build's, and without one the option is declined x402/input-missing before any fetch."""
    p = exact_pairing()
    option = with_memo({**SF["option"], "extra": {**SF["option"]["extra"], "recentBlockhash": offered}})
    doc = x402_doc(option, SF["resource"])
    given = {"decimals": SF["decimals"], "tokenProgram": SF["tokenProgram"]}
    out = run(lambda c: confirm(doc, X402_EXACT_SOLANA, p.account, c, {**given, "recentBlockhash": SF["blockhash"]}), serving(ABC))
    assert isinstance(out, Confirmed) and out.request is not None and out.request["kind"] == "solana-message"
    assert decompile(hexb(out.request["message"]))["blockhash"] == S["V1"]["blockhash"]
    link = serving(ABC)
    without = run(lambda c: confirm(doc, X402_EXACT_SOLANA, p.account, c, given), link)
    assert code(without) == "no-payable-option" and isinstance(without, Declined) and without.detail == "x402/input-missing"
    assert link.calls == 0


def test_x402_exact_solana_a_missing_input_is_declined_before_any_fetch() -> None:
    p = exact_pairing()
    link = serving(ABC)
    inputs = {"decimals": SF["decimals"], "recentBlockhash": SF["blockhash"]}
    out = run(lambda c: confirm(p.doc, X402_EXACT_SOLANA, p.account, c, inputs), link)
    assert code(out) == "no-payable-option" and isinstance(out, Declined) and out.detail == "x402/input-missing"
    assert link.calls == 0


def exact_choice() -> dict[str, Any]:
    """V1's choice: build's choice of the fixed option with the fixed payer, decimals, token program and blockhash."""
    doc = x402_doc(with_memo(SF["option"]), SF["resource"])
    return {
        "required": doc,
        "accepted": doc["accepts"][0],
        "payer": SF["payer"],
        "decimals": SF["decimals"],
        "tokenProgram": SF["tokenProgram"],
        "recentBlockhash": SF["blockhash"],
    }


def test_x402_exact_solana_agreed_refusals_with_a_choice_or_an_h() -> None:
    """The file holds agreedRefusals rows with a choice and rows with an h. build gives each row's refusal: a row's
    choice with H, and V1's choice with a row's h."""
    rows = [r for r in S["agreedRefusals"]["rows"] if "choice" in r or "h" in r]
    assert any("choice" in r for r in rows), "no agreedRefusals row carries a choice"
    assert any("h" in r for r in rows), "no agreedRefusals row carries an h"
    assert not isinstance(X402_EXACT_SOLANA.build(exact_choice(), H), Refusal)
    for row in rows:
        got = X402_EXACT_SOLANA.build(row["choice"], H) if "choice" in row else X402_EXACT_SOLANA.build(exact_choice(), row["h"])
        assert got == Refusal(row["expect"]), row["case"]


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


V3_WIRES = [r for r in S["V3"] if "wireBase64" in r]


def test_x402_exact_solana_v3_holds_wire_rows() -> None:
    assert V3_WIRES


@pytest.mark.parametrize("row", V3_WIRES, ids=lambda r: r["case"])
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


def upto_choice() -> dict[str, Any]:
    """EU3's choice: build's choice of the fixed option with the fixed payer, nonce, open slot, now, token program and
    blockhash."""
    doc = x402_doc(with_memo(UF["option"]), UF["resource"])
    return {
        "required": doc,
        "accepted": doc["accepts"][0],
        "payer": UF["payer"],
        "nonce": int(UF["nonce"]),
        "openSlot": int(UF["openSlot"]),
        "now": UF["now"],
        "tokenProgram": UF["tokenProgram"],
        "recentBlockhash": UF["blockhash"],
    }


def test_x402_upto_solana_agreed_refusals_with_a_choice_or_an_h() -> None:
    """The file holds agreedRefusals rows with a choice and rows with an h. build gives each row's refusal: a row's
    choice with H, and EU3's choice with a row's h."""
    rows = [r for r in U["agreedRefusals"]["rows"] if "choice" in r or "h" in r]
    assert any("choice" in r for r in rows), "no agreedRefusals row carries a choice"
    assert any("h" in r for r in rows), "no agreedRefusals row carries an h"
    assert not isinstance(X402_UPTO_SOLANA.build(upto_choice(), H), Refusal)
    for row in rows:
        got = X402_UPTO_SOLANA.build(row["choice"], H) if "choice" in row else X402_UPTO_SOLANA.build(upto_choice(), row["h"])
        assert got == Refusal(row["expect"]), row["case"]


def test_x402_upto_solana_agreed_refusals_an_open_slot_past_the_safe_integers() -> None:
    """The file holds agreedRefusals rows with an openSlot. build of EU3's choice with the row's openSlot, above
    2^53 - 1, gives the row's refusal, as @integraledger/lcp 0.4.0's build does after the channel address."""
    rows = [r for r in U["agreedRefusals"]["rows"] if "openSlot" in r]
    assert rows, "no agreedRefusals row carries an openSlot"
    for row in rows:
        assert int(row["openSlot"]) > 2**53 - 1, row["case"]
        got = X402_UPTO_SOLANA.build({**upto_choice(), "openSlot": int(row["openSlot"])}, H)
        assert got == Refusal(row["expect"]), row["case"]


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
        wire = base64.b64decode(BV["ES2"]["wireBase64"])
        assert decompile(hexb(tx["message"])) == decompile(wire[1 + 64 * wire[0] :])
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


def test_x402_batch_settlement_solana_es2_the_opening_build_is_its_build_message_byte_for_byte() -> None:
    """build's open transaction message for ES2's choice is, byte for byte, the message whose SHA-256 is ES2's
    buildMessageSha256: ES2's instructions compiled with the account order of @solana/kit 8.4.0, the compiler of the
    x402 steward SDK's open transaction (x402-foundation/x402 751590a2,
    typescript/packages/mechanisms/svm/src/payment-channels/open.ts L501-516). ES2's own wire holds the same
    instructions with each class of account keys in byte order."""
    doc = x402_doc(with_memo(BS["option"]), BV["fixed"]["resource"])
    unsigned = BATCH_BINDING.build(batch_choice(doc), H)
    assert not isinstance(unsigned, Refusal), unsigned
    message = unsigned.requests[0]["message"]
    assert isinstance(message, bytes) and len(message) == BV["ES2"]["messageLength"]
    assert hashlib.sha256(message).hexdigest() == BV["ES2"]["buildMessageSha256"]


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


def test_x402_batch_settlement_solana_es2_the_opening_ends_with_the_seller_memo_then_the_binding_memo() -> None:
    """build's open transaction message has ES2's length and, decompiled, ES2's fee payer, blockhash and instructions
    with their accounts and flags. Its last two instructions are v3 Memos, extra.memo and then x402's binding memo,
    x402:batch-settlement:svm:rcvauth:v1: followed by extra.receiverAuthorizer (x402's scheme_batch_settlement_svm,
    section 3), in ES2's order. The payment's channelConfig, with its receiverAuthorizer, is ES4's config, member for
    member."""
    doc = x402_doc(with_memo(BS["option"]), BV["fixed"]["resource"])
    unsigned = BATCH_BINDING.build(batch_choice(doc), H)
    assert not isinstance(unsigned, Refusal), unsigned
    message = unsigned.requests[0]["message"]
    assert isinstance(message, bytes) and len(message) == BV["ES2"]["messageLength"]
    wire = base64.b64decode(BV["ES2"]["wireBase64"])
    assert decompile(message) == decompile(wire[1 + 64 * wire[0] :])
    memos = [bytes.fromhex(ix["data"]).decode() for ix in decompile(message)["instructions"] if ix["program"] == _svm.MEMO_V3]
    assert memos == [L, "x402:batch-settlement:svm:rcvauth:v1:" + BS["receiverAuthorizer"]]
    payment = unsigned.complete([b58_encode(bytes([1]) * 64), b58_encode(bytes([2]) * 64)])
    assert not isinstance(payment, Refusal), payment
    assert list(payment["payload"]["channelConfig"].items()) == list(BV["ES4"]["config"].items())


def test_the_solana_builds_answer_a_choice_that_is_not_an_object_with_not_v2() -> None:
    """x402/exact/solana's and x402/upto/solana's build, and the batch build and build_within, answer x402/not-v2
    before they read the choice, as @integraledger/lcp's builds do."""
    exact: Any = X402_EXACT_SOLANA
    upto: Any = X402_UPTO_SOLANA
    batch: Any = X402_BATCH_SETTLEMENT_SOLANA
    values: list[Any] = [None, "x", [], 42]
    for value in values:
        for call in (exact.build, upto.build, batch.build, batch.build_within):
            assert call(value, H) == Refusal("x402/not-v2"), (call, value)


def test_x402_batch_settlement_solana_the_option_names_a_receiver_authorizer_and_client_vouchers() -> None:
    """The filter takes an option whose extra.receiverAuthorizer is a base58 key and whose extra.voucherSigner is
    absent or client, as @integraledger/lcp's pairingOf names x402/batch-settlement/solana."""
    option = BS["option"]
    extra = option["extra"]
    assert batch_pairs(option) and batch_pairs({**option, "extra": {**extra, "voucherSigner": "client"}})
    without = {k: v for k, v in extra.items() if k != "receiverAuthorizer"}
    others: list[Any] = [without, {**extra, "receiverAuthorizer": "not-a-key"}, {**extra, "receiverAuthorizer": None}]
    others += [{**extra, "voucherSigner": v} for v in ("server", None, "")]
    for other in others:
        assert not batch_pairs({**option, "extra": other}), other


def batch_choice(doc: Mapping[str, Any]) -> dict[str, Any]:
    """build's choice of doc's first option: the svm payer as payer and payer authorizer, and the fixed deposit, salt,
    open slot, token program and blockhash."""
    return {
        "required": doc,
        "accepted": doc["accepts"][0],
        "payer": BS["payer"],
        "payerAuthorizer": BS["payer"],
        "deposit": int(BS["deposit"]),
        "salt": int(BS["salt"]),
        "openSlot": int(BS["openSlot"]),
        "tokenProgram": BS["tokenProgram"],
        "recentBlockhash": BS["blockhash"],
    }


def test_x402_batch_settlement_solana_es9_the_timeout_is_compared_only_as_a_number() -> None:
    """The file holds ES9's rows: fixed.svm.option with the row's maxTimeoutSeconds, or without the member. read offers
    the option when the row names the pairing, since the pairing's filter is the one pairingOf names it by, and build of
    the advertised option gives the row's expectAdvertise refusal, or builds when it is null: build refuses the options
    advertise refuses."""
    rows = BV.get("ES9", {}).get("rows", [])
    assert rows, "the vector file holds no ES9 rows"
    bare = {k: v for k, v in BS["option"].items() if k != "maxTimeoutSeconds"}
    for row in rows:
        option = {**bare, "maxTimeoutSeconds": row["maxTimeoutSeconds"]} if "maxTimeoutSeconds" in row else bare
        label = repr(row.get("maxTimeoutSeconds", "absent"))
        assert option["extra"]["withdrawDelay"] == 3600, label
        doc = x402_doc(with_memo(option), BV["fixed"]["resource"])
        offered = not isinstance(BATCH_BINDING.read(doc), Refusal)
        assert (X402_BATCH_SETTLEMENT_SOLANA.id if offered else None) == row["expectPairing"], label
        built = BATCH_BINDING.build(batch_choice(doc), H)
        assert (built.code if isinstance(built, Refusal) else None) == row["expectAdvertise"], label


def test_x402_batch_settlement_solana_agreed_refusals_with_an_h() -> None:
    """The file holds agreedRefusals rows that carry an h. The Solana build of the advertised option's choice builds
    with H, and gives each row's refusal with the row's h."""
    rows = [r for r in BV["agreedRefusals"]["rows"] if "h" in r]
    assert rows, "no agreedRefusals row carries an h"
    choice = batch_choice(x402_doc(with_memo(BS["option"]), BV["fixed"]["resource"]))
    assert not isinstance(BATCH_BINDING.build(choice, H), Refusal)
    for row in rows:
        assert (row["pairing"], row["call"]) == (X402_BATCH_SETTLEMENT_SOLANA.id, "build"), row["case"]
        assert BATCH_BINDING.build(copy.deepcopy(choice), row["h"]) == Refusal(row["expect"]), row["case"]


def test_x402_batch_settlement_solana_agreed_refusals_a_channel_config_the_program_refuses() -> None:
    """The file holds x402/batch-settlement/solana agreedRefusals rows that carry configMembers. Each member set
    replaces those members of ES4's config in ES2's opening as ES4 presents it, and in build_within of the advertised
    option with maxClaimableAmount 1000, and each name in the row's calls refuses it with the row's code. The
    payment-channels program's open refuses a grace_period of 0 and takes it as a u32, and refuses an authorized signer
    off the Ed25519 curve (solana-foundation/payment-channels 0c07d5751c8972abf6a219570a3f39a72f46f879, the revision
    x402 751590a2 pins, program/payment_channels/src/instructions/open.rs L85, L116, L267-269 and L271-273); each row's
    payerAuthorizer is ES10's y = 2 bytes, no point by ES10, or ES1's channel PDA. The delays 1 and 2^32 - 1 are
    read, and each opening's channel is ES1's: the delay is no seed of the channel PDA. The Python binding has no
    reference: a row's reference is run by the TypeScript package's tests."""
    rows = [r for r in BV["agreedRefusals"]["rows"] if "configMembers" in r and r.get("pairing") == BATCH_BINDING.id]
    assert rows, "no x402/batch-settlement/solana agreedRefusals row carries configMembers"
    y2 = next(r for r in BV["ES10"]["rows"] if r["case"] == "y = 2")
    assert y2["point"] is False
    off_curve = {b58_encode(bytes.fromhex(y2["bytesHex"])), BV["ES1"]["channelPda"]}
    accepted = BV["ES4"]["accepted"]
    required = {"x402Version": 2, "resource": BV["fixed"]["resource"], "accepts": [accepted]}

    def runs(members: Mapping[str, Any]) -> dict[str, Callable[[], Any]]:
        config = {**BV["ES4"]["config"], **members}
        opening = batch_presented(
            {"type": "deposit", "channelConfig": config, "voucher": ES4_VOUCHER,
             "deposit": {"amount": BS["deposit"], "transaction": BV["ES2"]["wireBase64"]}}
        )  # fmt: skip
        w = {"required": required, "accepted": accepted, "channelConfig": config, "maxClaimableAmount": 1000}
        return {
            "bound": lambda: BATCH_BINDING.bound(opening),
            "channel.ref": lambda: BATCH_BINDING.channel_ref(opening),
            "buildWithin": lambda: BATCH_BINDING.build_within(w, H),
        }

    for row in rows:
        for members in row["configMembers"]:
            assert "payerAuthorizer" not in members or members["payerAuthorizer"] in off_curve, members
            calls = runs(members)
            assert set(row["calls"]) <= set(calls) | {"reference"}, row["case"]
            for name in row["calls"]:
                if name != "reference":
                    assert calls[name]() == Refusal(row["expect"]), (name, members)
    for delay in (1, 2**32 - 1):
        calls = runs({"withdrawDelay": delay})
        assert calls["bound"]() == BV["ES4"]["expectBound"], delay
        assert calls["channel.ref"]() == ChannelRef(**BV["ES4"]["expectRef"]), delay
        assert not isinstance(calls["buildWithin"](), Refusal), delay


def test_x402_batch_settlement_solana_es10_the_ed25519_point_rule() -> None:
    """The file holds ES10's rows: is_point, the rule a program-derived address candidate meets, gives each row's
    point value for its 32 bytes."""
    rows = BV.get("ES10", {}).get("rows", [])
    assert rows, "the vector file holds no ES10 rows"
    for row in rows:
        assert _svm.is_point(bytes.fromhex(row["bytesHex"])) == row["point"], row["case"]


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
    choice = batch_choice(p.doc)
    unsigned = BATCH_BINDING.build(choice, H)
    assert not isinstance(unsigned, Refusal)
    signature_count = batch_agreed("complete with a signature count")
    assert X402_BATCH_SETTLEMENT_SOLANA_PIECE.complete(unsigned, good[:1], out.chosen) == Refusal(signature_count)
    input_malformed = batch_agreed("SVM complete with a signature")
    assert unsigned.complete([good[0], b58_encode(bytes(63))]) == Refusal(input_malformed)
    assert unsigned.complete(["0x" + "11" * 64, good[1]]) == Refusal(input_malformed)
    for key, value in (("deposit", 0), ("deposit", 2**64), ("openSlot", 2**64), ("salt", -1), ("tokenProgram", "x")):
        assert BATCH_BINDING.build({**choice, key: value}, H) == Refusal(input_malformed), key
    # ES1's channel PDA, a key off the Ed25519 curve, as the payer authorizer: the program's open refuses it as the
    # authorized signer (solana-foundation/payment-channels 0c07d5751c8972abf6a219570a3f39a72f46f879,
    # program/payment_channels/src/instructions/open.rs L271-273).
    assert BATCH_BINDING.build({**choice, "payerAuthorizer": BV["ES1"]["channelPda"]}, H) == Refusal(input_malformed)


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


def test_x402_batch_settlement_solana_within_another_fee_payer_signs_nothing() -> None:
    """A payment for a channel the buyer never opened is refused, and nothing is signed. On Solana the channel address
    is derived from the option's feePayer as well as the held channel configuration, so a within challenge naming
    another fee payer asks for a voucher or a refund in another channel. The refund here is the one taken again after
    the receiver's binding is unavailable, which carries the request_close."""
    p = batch_pairing()
    opener = Recording(BATCH_ACCOUNT, batch_answer)
    opened = run(lambda c: transact(p.doc, X402_BATCH_SETTLEMENT_SOLANA, opener, c, inputs=p.inputs), serving(ABC))
    assert isinstance(opened, Transacted) and opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, X402_BATCH_SETTLEMENT_SOLANA)
    assert not isinstance(hold, Declined), hold
    other = copy.deepcopy(p.doc)
    other["accepts"][0]["extra"]["feePayer"] = BV["ES1"]["channelPda"]
    signer = Recording(BATCH_ACCOUNT, batch_answer)
    voucher = asyncio.run(within(other, json.loads(json.dumps(hold)), X402_BATCH_SETTLEMENT_SOLANA, signer))
    retry = {**other, "error": RETRY}
    refund = asyncio.run(
        within(retry, hold, X402_BATCH_SETTLEMENT_SOLANA, signer, {}, {"recentBlockhash": BS["blockhash"]})
    )
    assert code(voucher) == "no-payable-option" and code(refund) == "no-payable-option"
    assert signer.requests == []


# The code a seller answers a Solana refund with when the receiver's binding is unavailable, as a settle failure's
# PAYMENT-RESPONSE errorReason or a payment request's error (x402's scheme_batch_settlement_svm.md): the refund is then
# taken again with the payer-signed request_close.
RETRY = "invalid_batch_settlement_svm_receiver_binding_unavailable"
# The request_close message inside ES4's close wire: its signature count, the signatures, then the message.
_CLOSE_WIRE = base64.b64decode(BV["ES4"]["closeWireBase64"])
CLOSE_MESSAGE = _CLOSE_WIRE[1 + 64 * _CLOSE_WIRE[0] :]
# A recent blockhash other than the opening's: any 32 bytes, in base58.
OTHER_BLOCKHASH = b58_encode(bytes(range(1, 33)))


class Handed:
    """The package's batch binding, recording each w the gate hands its build_within before the binding builds it."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.handed: list[dict[str, Any]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def build_within(self, w: dict[str, Any], h: str) -> Any:
        self.handed.append(w)
        return self._inner.build_within(w, h)


def answer_each(request: Any) -> list[str]:
    """The payer's answer, who is also the payer authorizer: its Ed25519 signature, in base58, over each request of
    the batch."""
    return [b58_encode(sign(bytes.fromhex(BS["payerSeed"]), hexb(r["message"]))) for r in request["requests"]]


def compute_budget(limit: int, price: int) -> list[str]:
    """The data of the two Compute Budget instructions: SetComputeUnitLimit (02, u32 LE) and SetComputeUnitPrice (03,
    u64 LE), as Solana's Compute Budget program reads them."""
    return ["02" + limit.to_bytes(4, "little").hex(), "03" + price.to_bytes(8, "little").hex()]


def charged_1000() -> tuple[Any, ChannelHold]:
    """The batch pairing's document, and a channel opened through the gate over abc, held, with 1000 charged."""
    doc, hold = batch_hold()
    charged = record_charge(hold, "1000")
    assert not isinstance(charged, Declined), charged
    return doc, charged


def refund_form(out: Any, signer: Recording) -> tuple[list[str], list[str]]:
    """The kinds of the one batch handed to the signer, and the sorted members of the signed refund's payload."""
    assert isinstance(out, Within), out
    assert len(signer.requests) == 1 and signer.requests[0]["kind"] == "batch", signer.requests
    return [q["kind"] for q in signer.requests[0]["requests"]], sorted(out.signed["payload"])


def test_x402_batch_settlement_solana_a_full_refund_hands_build_within_the_request_close_values_only_when_taken_again() -> None:
    """The Solana batch-settlement refund (x402's scheme_batch_settlement_svm.md, the vectors' ES6), through the gate
    and the package's binding: within(doc, hold, binding, signer, {}) hands build_within refund {} and none of the
    buyer's request_close values, so the refund is the voucher alone, ES6.cooperative's form; under a payment request
    whose error is invalid_batch_settlement_svm_receiver_binding_unavailable it hands all three, and the refund also
    carries the payer-signed request_close, ES6.withMemo's form, built with them. At a recorded charge of 1000 the
    voucher's message is ES3's, and the request_close holds ES4's close instructions with the given Compute Budget
    values. The gate checks that each completion's kind is close and that it names the held channel."""
    doc, hold = charged_1000()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    given = {"recentBlockhash": BS["blockhash"], "computeUnitLimit": 300000, "computeUnitPrice": "2"}
    forms = (
        (doc, ["ed25519-raw"], BV["ES6"]["cooperative"]),
        ({**doc, "error": RETRY}, ["solana-message", "ed25519-raw"], BV["ES6"]["withMemo"]),
    )
    seed = bytes.fromhex(BS["payerSeed"])
    for d, kinds, form in forms:
        signer = Recording(BATCH_ACCOUNT, answer_each)
        out = asyncio.run(within(d, hold, binding, signer, {}, given))
        assert refund_form(out, signer) == (kinds, sorted(form["payloadMembers"]))
        assert isinstance(out, Within)
        requests = signer.requests[0]["requests"]
        voucher_message = hexb(requests[-1]["message"])
        assert voucher_message.hex() == BV["ES3"]["message"] and requests[-1]["signer"] == BS["payer"]
        voucher = out.signed["payload"]["voucher"]
        assert voucher == {"channelId": BV["ES1"]["channelPda"], "maxClaimableAmount": "1000", "expiresAt": 0,
                           "signature": b58_encode(sign(seed, voucher_message))}  # fmt: skip
        assert BATCH_BINDING.channel_kind(out.signed) == form["expectKind"]
        assert BATCH_BINDING.channel_ref(out.signed) == ChannelRef(**BV["ES4"]["expectRef"])
    message = hexb(requests[0]["message"])
    close = decompile(CLOSE_MESSAGE)
    assert decompile(message) == {**close, "instructions": [
        *({"program": _svm.COMPUTE_BUDGET, "accounts": [], "data": x} for x in compute_budget(300000, 2)),
        *close["instructions"][2:],
    ]}  # fmt: skip
    assert isinstance(out, Within)
    wire = base64.b64decode(out.signed["payload"]["transaction"])
    assert wire[:65] == bytes([2]) + bytes(64) and wire[65:129] == sign(seed, message) and wire[129:] == message
    values = ("recentBlockhash", "computeUnitLimit", "computeUnitPrice")
    assert [(w["refund"], [w.get(k) for k in values]) for w in binding.handed] == [
        ({}, [None, None, None]),
        ({}, [BS["blockhash"], 300000, 2]),
    ]
    assert binding.handed[0]["channelConfig"] == hold["opening"]["payload"]["channelConfig"]


def settle_failure(error_reason: str | None) -> dict[str, Any]:
    """A decoded PAYMENT-RESPONSE in the HTTP transport's settle-failure form, with errorReason where one is given."""
    failure: dict[str, Any] = {"success": False, "transaction": "", "network": BS["option"]["network"], "payer": BS["payer"]}
    if error_reason is not None:
        failure["errorReason"] = error_reason
    return failure


@pytest.mark.parametrize(
    ("taken_again", "error", "error_reason"),
    [
        (True, None, RETRY),
        (True, RETRY, None),
        (False, None, "insufficient_funds"),
        (False, None, None),
        (False, RETRY, "insufficient_funds"),
    ],
    ids=[
        "the code only in the errorReason",
        "the code in the error, with no errorReason",
        "another errorReason, and no error",
        "neither",
        "another errorReason, read before the error's code",
    ],
)
def test_x402_batch_settlement_solana_the_refund_is_taken_again_on_the_paymentresponse_errorreason_read_first(
    taken_again: bool, error: str | None, error_reason: str | None
) -> None:
    """x402's reference client takes the refund again when the settle failure's PAYMENT-RESPONSE carries errorReason
    invalid_batch_settlement_svm_receiver_binding_unavailable, read first, or else when the 402 payment request's error
    does (x402's TypeScript client, client/refund.ts; its Go client, refund.go, reads the error only when no
    PAYMENT-RESPONSE is given, so a PAYMENT-RESPONSE without errorReason follows refund.ts). refund's paymentResponse
    carries the decoded PAYMENT-RESPONSE. Taken again, the refund is ES6.withMemo's form, its request_close built with
    the given recentBlockhash; else it is the voucher alone."""
    doc, hold = charged_1000()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, answer_each)
    d = doc if error is None else {**doc, "error": error}
    out = asyncio.run(within(d, hold, binding, signer, {"paymentResponse": settle_failure(error_reason)},
                             {"recentBlockhash": OTHER_BLOCKHASH}))  # fmt: skip
    form = BV["ES6"]["withMemo"] if taken_again else BV["ES6"]["cooperative"]
    kinds = ["solana-message", "ed25519-raw"] if taken_again else ["ed25519-raw"]
    assert refund_form(out, signer) == (kinds, sorted(form["payloadMembers"]))
    assert binding.handed[0].get("recentBlockhash") == (OTHER_BLOCKHASH if taken_again else None)
    if taken_again:
        assert decompile(hexb(signer.requests[0]["requests"][0]["message"]))["blockhash"] == OTHER_BLOCKHASH


def test_x402_batch_settlement_solana_a_refund_never_reads_the_offers_recent_blockhash() -> None:
    """An option may offer extra.recentBlockhash for the opening; the refund reads only the blockhash the caller gives
    for the refund taken again (@integraledger/lcp's svmBuildWithin reads w.recentBlockhash alone). Under such an
    option the first refund is the voucher alone, ES6.cooperative's form, and the refund taken again carries the
    request_close built with the given blockhash."""
    doc, hold = charged_1000()
    offered = copy.deepcopy(doc)
    offered["accepts"][0]["extra"]["recentBlockhash"] = OTHER_BLOCKHASH
    signer = Recording(BATCH_ACCOUNT, answer_each)
    out = asyncio.run(within(offered, hold, X402_BATCH_SETTLEMENT_SOLANA, signer, {}, {}))
    assert refund_form(out, signer) == (["ed25519-raw"], sorted(BV["ES6"]["cooperative"]["payloadMembers"]))
    signer = Recording(BATCH_ACCOUNT, answer_each)
    retry = {**offered, "error": RETRY}
    out = asyncio.run(within(retry, hold, X402_BATCH_SETTLEMENT_SOLANA, signer, {}, {"recentBlockhash": BS["blockhash"]}))
    assert refund_form(out, signer) == (["solana-message", "ed25519-raw"], sorted(BV["ES6"]["withMemo"]["payloadMembers"]))
    assert decompile(hexb(signer.requests[0]["requests"][0]["message"]))["blockhash"] == BS["blockhash"]


def test_x402_batch_settlement_solana_the_code_in_the_errorreason_with_no_blockhash_is_input_missing() -> None:
    doc, hold = charged_1000()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, answer_each)
    out = asyncio.run(within(doc, hold, binding, signer, {"paymentResponse": settle_failure(RETRY)}, {}))
    assert out == Declined("no-payable-option", "x402/input-missing")
    assert (binding.handed, signer.requests) == ([], [])


@pytest.mark.parametrize("response", ["eyJzdWNjZXNzIjpmYWxzZX0=", None, []], ids=["a string", "None", "a list"])
def test_x402_batch_settlement_solana_a_paymentresponse_that_is_not_a_mapping_is_input_malformed(response: Any) -> None:
    doc, hold = charged_1000()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, answer_each)
    out = asyncio.run(within(doc, hold, binding, signer, {"paymentResponse": response}, {"recentBlockhash": BS["blockhash"]}))
    assert out == Declined("no-payable-option", "x402/input-malformed")
    assert (binding.handed, signer.requests) == ([], [])


@pytest.mark.parametrize(
    "reason", [5, True, [RETRY], {"code": RETRY}], ids=["a number", "a bool", "a list", "a mapping"]
)
def test_x402_batch_settlement_solana_an_errorreason_that_is_not_a_string_is_input_malformed(reason: Any) -> None:
    """A SettlementResponse's errorReason is a string where it is given (x402's core specification v2, §5.3.2). One in
    another form is declined as every other refund value in another form is, though the payment request's error
    carries the code."""
    doc, hold = charged_1000()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, answer_each)
    response = {**settle_failure(None), "errorReason": reason}
    out = asyncio.run(within({**doc, "error": RETRY}, hold, binding, signer, {"paymentResponse": response},
                             {"recentBlockhash": BS["blockhash"]}))  # fmt: skip
    assert out == Declined("no-payable-option", "x402/input-malformed")
    assert (binding.handed, signer.requests) == ([], [])


def test_x402_batch_settlement_solana_the_refund_taken_again_with_no_blockhash_is_input_missing() -> None:
    doc, hold = batch_hold()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, batch_answer)
    out = asyncio.run(within({**doc, "error": RETRY}, hold, binding, signer, {}, {"computeUnitLimit": 200000}))
    assert out == Declined("no-payable-option", "x402/input-missing")
    assert (binding.handed, signer.requests) == ([], [])


@pytest.mark.parametrize(
    "given",
    [
        {"computeUnitLimit": -1},
        {"computeUnitLimit": 4294967296},
        {"computeUnitLimit": 1.5},
        {"computeUnitLimit": "200000"},
        {"computeUnitLimit": True},
        {"computeUnitPrice": "1.5"},
        {"computeUnitPrice": 1},
        {"computeUnitPrice": "18446744073709551616"},
        {"recentBlockhash": 7},
        {"recentBlockhash": "0" * 44},
    ],
    ids=[
        "computeUnitLimit -1",
        "computeUnitLimit 4294967296, past a u32",
        "computeUnitLimit 1.5",
        "computeUnitLimit a string",
        "computeUnitLimit a bool",
        "computeUnitPrice 1.5, not a decimal integer string",
        "computeUnitPrice a number",
        "computeUnitPrice 2^64, past a u64",
        "recentBlockhash 7, not a string",
        "recentBlockhash outside the base58 alphabet",
    ],
)
def test_x402_batch_settlement_solana_a_refund_value_in_another_form_is_input_malformed(given: dict[str, Any]) -> None:
    """buyer.json's BW3: a refund value given in a form the request_close does not take is declined no-payable-option
    with x402/input-malformed, before the build and the signer call, never dropped. The forms are the rail's: a base58
    blockhash, a u32 computeUnitLimit and a u64 computeUnitPrice written in decimal."""
    doc, hold = batch_hold()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, batch_answer)
    for d in (doc, {**doc, "error": RETRY}):
        out = asyncio.run(within(d, hold, binding, signer, {}, given))
        assert out == Declined("no-payable-option", "x402/input-malformed"), d
    assert (binding.handed, signer.requests) == ([], [])


def test_x402_batch_settlement_solana_bw3s_control_signs_the_refund_once() -> None:
    """BW3's control: each value in its rail form, the limit as a float with an integral value, which JSON reads as
    that integer. The package's binding builds the request_close with them, and the refund is signed once."""
    doc, hold = batch_hold()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, answer_each)
    given = {"computeUnitLimit": 200000.0, "computeUnitPrice": "1", "recentBlockhash": OTHER_BLOCKHASH}
    assert isinstance(asyncio.run(within({**doc, "error": RETRY}, hold, binding, signer, {}, given)), Within)
    assert len(signer.requests) == 1
    assert binding.handed[0]["computeUnitLimit"] == 200000 and isinstance(binding.handed[0]["computeUnitLimit"], int)
    built = decompile(hexb(signer.requests[0]["requests"][0]["message"]))
    assert built["blockhash"] == OTHER_BLOCKHASH
    assert [ix["data"] for ix in built["instructions"][:2]] == compute_budget(200000, 1)


def batch_hold() -> tuple[Any, ChannelHold]:
    """The batch pairing's document, and a channel opened through the gate over abc and held."""
    p = batch_pairing()
    opened = run(lambda c: transact(p.doc, X402_BATCH_SETTLEMENT_SOLANA, Recording(BATCH_ACCOUNT, batch_answer), c,
                                    inputs=p.inputs), serving(ABC))  # fmt: skip
    assert isinstance(opened, Transacted) and opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, X402_BATCH_SETTLEMENT_SOLANA)
    assert not isinstance(hold, Declined), hold
    return p.doc, hold


@pytest.mark.parametrize("inputs", ["x", 5, []], ids=["a string", "a number", "a list"])
def test_x402_batch_settlement_solana_within_declines_inputs_that_are_not_a_mapping(inputs: Any) -> None:
    """buyer.json's BW4: within declines inputs given and not a mapping with no-payable-option and
    x402/input-malformed, for a refund and for a voucher, before the build and the signer call."""
    doc, hold = batch_hold()
    binding = Handed(X402_BATCH_SETTLEMENT_SOLANA)
    signer = Recording(BATCH_ACCOUNT, batch_answer)
    refunds: tuple[dict[str, Any] | None, ...] = ({}, None)
    for refund in refunds:
        out = asyncio.run(within(doc, hold, binding, signer, refund, inputs))
        assert out == Declined("no-payable-option", "x402/input-malformed"), refund
    assert (binding.handed, signer.requests) == ([], [])


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


def test_x402_batch_settlement_solana_es6_a_full_refund_carries_the_voucher_and_on_the_retry_request_close() -> None:
    # ES6: build_within with refund {} carries the voucher for maxClaimableAmount, signed by the payer authorizer, with
    # expiresAt 0 and no amount. With recentBlockhash it also carries the payer-signed request_close, signed first: the
    # Compute Budget prefix (200 000 units, 1 microlamport), request_close (05) with the payer (read-only signer) and the
    # channel (writable), then one Memo v3 with extra.memo when the option carries one.
    s6 = BV["ES6"]
    with_memo: dict[str, Any] = BV["ES4"]["accepted"]
    without_memo = {**with_memo, "extra": {k: v for k, v in with_memo["extra"].items() if k != "memo"}}
    svm = BV["fixed"]["svm"]
    seed = bytes.fromhex(svm["payerSeed"])

    def build(accepted: Mapping[str, Any], **extra: Any) -> Any:
        w = {
            "required": {"x402Version": 2, "resource": BV["fixed"]["resource"], "accepts": [accepted]},
            "accepted": accepted,
            "channelConfig": BV["ES4"]["config"],
            "maxClaimableAmount": 1000,
            "refund": {},
            **extra,
        }
        binding: Any = X402_BATCH_SETTLEMENT_SOLANA
        return binding.build_within(w, H)

    def voucher(signature: bytes) -> dict[str, Any]:
        return {"channelId": BV["ES1"]["channelPda"], "maxClaimableAmount": "1000", "expiresAt": 0,
                "signature": b58_encode(signature)}  # fmt: skip

    u = build(with_memo)
    assert not isinstance(u, Refusal), u
    assert [(r["kind"], r.get("signer")) for r in u.requests] == [("ed25519-raw", svm["payer"])]
    assert u.requests[0]["message"].hex() == BV["ES3"]["message"]
    voucher_sig = sign(seed, u.requests[0]["message"])
    p = u.complete([b58_encode(voucher_sig)])
    assert not isinstance(p, Refusal), p
    assert sorted(p["payload"]) == s6["cooperative"]["payloadMembers"]
    assert p["payload"]["type"] == "refund" and p["payload"]["channelConfig"] == BV["ES4"]["config"]
    assert p["payload"]["voucher"] == voucher(voucher_sig)
    assert BATCH_BINDING.channel_kind(p) == s6["cooperative"]["expectKind"]

    u = build(with_memo, recentBlockhash=svm["blockhash"])
    assert not isinstance(u, Refusal), u
    assert [r["kind"] for r in u.requests] == ["solana-message", "ed25519-raw"]
    message = u.requests[0]["message"]
    wire = base64.b64decode(BV["ES4"]["closeWireBase64"])
    assert decompile(message) == decompile(wire[1 + 64 * wire[0] :])
    assert u.requests[1]["message"].hex() == BV["ES3"]["message"] and u.requests[1]["signer"] == svm["payer"]
    tx_sig, voucher_sig = sign(seed, message), sign(seed, u.requests[1]["message"])
    p = u.complete([b58_encode(tx_sig), b58_encode(voucher_sig)])
    assert not isinstance(p, Refusal), p
    assert sorted(p["payload"]) == s6["withMemo"]["payloadMembers"]
    assert p["payload"]["type"] == "refund" and p["payload"]["channelConfig"] == BV["ES4"]["config"]
    assert p["payload"]["voucher"] == voucher(voucher_sig)
    signed = base64.b64decode(p["payload"]["transaction"])
    assert signed[0] == 2 and signed[1:65] == bytes(64) and signed[65:129] == tx_sig and signed[129:] == message
    assert BATCH_BINDING.channel_kind(p) == s6["withMemo"]["expectKind"]
    assert BATCH_BINDING.channel_ref(p) == ChannelRef(**BV["ES4"]["expectRef"])

    v = build(without_memo, recentBlockhash=svm["blockhash"])
    assert not isinstance(v, Refusal), v
    d = decompile(v.requests[0]["message"])
    assert (d["feePayer"], d["blockhash"]) == (svm["feePayer"], svm["blockhash"])
    assert d["instructions"] == s6["withoutMemo"]["instructions"]

    assert build(with_memo, refund={"amount": 5}) == Refusal(s6["refundWithAmount"]["expect"])
    lone = {**with_memo, "extra": {**with_memo["extra"], "memo": s6["loneSurrogateMemo"]["memo"]}}
    assert build(lone, recentBlockhash=svm["blockhash"]) == Refusal(s6["loneSurrogateMemo"]["expect"])


def test_x402_batch_settlement_solana_a_refunds_voucher_is_the_payer_authorizers_and_its_request_close_the_payers() -> None:
    """With a payer authorizer other than the payer, as x402's scheme lets a channel name: the refund's voucher is a
    request for the payer authorizer over the channel the config names, and the request_close is signed by the payer,
    in the payer's signer slot (@integraledger/lcp's svmBuildWithin: the voucher request's signer is the config's
    payerAuthorizer, the wire the payer's)."""
    svm = BV["fixed"]["svm"]
    config = {**BV["ES4"]["config"], "payerAuthorizer": svm["receiverAuthorizer"]}
    accepted = BV["ES4"]["accepted"]
    channel = _svm.channel_pda(config["payer"], svm["feePayer"], config["token"], config["payerAuthorizer"], 42, config["openSlot"])
    assert isinstance(channel, str) and channel != BV["ES1"]["channelPda"]
    w = {"required": {"x402Version": 2, "accepts": [accepted]}, "accepted": accepted, "channelConfig": config,
         "maxClaimableAmount": 1000, "refund": {}, "recentBlockhash": svm["blockhash"]}  # fmt: skip
    binding: Any = X402_BATCH_SETTLEMENT_SOLANA
    u = binding.build_within(w, H)
    assert not isinstance(u, Refusal), u
    assert [(r["kind"], r.get("signer")) for r in u.requests] == [("solana-message", None), ("ed25519-raw", config["payerAuthorizer"])]
    assert u.requests[1]["message"] == _svm.channel_voucher_message(channel, 1000, 0)
    tx_sig, voucher_sig = bytes([7]) * 64, bytes([9]) * 64
    p = u.complete([b58_encode(tx_sig), b58_encode(voucher_sig)])
    assert not isinstance(p, Refusal), p
    tx = _svm.decode_svm_tx(base64.b64decode(p["payload"]["transaction"]))
    assert not isinstance(tx, Refusal), tx
    signers = [b58_encode(k) for k in tx.keys[: tx.required_signatures]]
    assert tx.signatures[signers.index(config["payer"])] == tx_sig
    assert p["payload"]["voucher"]["channelId"] == channel and p["payload"]["voucher"]["signature"] == b58_encode(voucher_sig)


def test_x402_batch_settlement_solana_es8_the_opening_carries_one_binding_memo_and_one_other() -> None:
    """ES8: bound reads each row's wire as deposit.transaction under ES4's option and config, and gives H for exactly
    one binding memo beside one memo carrying L, in either order, and svm/memo-count for any other count."""
    rows = BV["ES8"]["rows"]
    assert rows, "the vector file holds no ES8 rows"
    for row in rows:
        got = BATCH_BINDING.bound(batch_deposit(row["wireBase64"]))
        assert (got.code if isinstance(got, Refusal) else got) == row["expect"], row["case"]


def batch_wire(instruction: Any, memos: list[str]) -> str:
    """A signed wire of the channel message for instruction with memos, under the fixed svm values; the signature is
    zeros, which bound does not verify."""
    message = _svm.channel_message(
        _svm.ChannelBuildInput(
            fee_payer=BS["feePayer"],
            payer=BS["payer"],
            mint=BS["mint"],
            token_program=BS["tokenProgram"],
            recent_blockhash=BS["blockhash"],
            memo=None,
            compute_unit_limit=200_000,
            compute_unit_price=1,
            instruction=instruction,
        ),
        memos,
    )
    assert isinstance(message, bytes), message
    wire = _svm.signed_wire(message, BS["payer"], bytes(64))
    assert isinstance(wire, bytes), wire
    return _svm.to_base64(wire)


def test_x402_batch_settlement_solana_bound_reads_the_channel_instruction_first_and_not_the_binding_memos_key() -> None:
    """bound reads as @integraledger/lcp 0.4.0's opening read does (svmOpening, then openingCarrier): the channel
    instruction before the memos, so a top-up with no memo, or with an opening's two, is x402/not-an-opening; and the
    binding memo by its prefix alone, so an opening whose binding memo names another key gives H."""
    binding = "x402:batch-settlement:svm:rcvauth:v1:" + BS["receiverAuthorizer"]
    top_up = _svm.ChannelTopUp(channel=BV["ES1"]["channelPda"], amount=5)
    for memos in ([], [L, binding]):
        assert BATCH_BINDING.bound(batch_deposit(batch_wire(top_up, memos))) == Refusal("x402/not-an-opening"), memos
    opening = _svm.ChannelOpen(
        channel=BV["ES1"]["channelPda"],
        signer=BS["payer"],
        salt=int(BS["salt"]),
        deposit=int(BS["deposit"]),
        grace_period=BS["withdrawDelay"],
        open_slot=int(BS["openSlot"]),
        recipient=BS["payTo"],
    )
    assert BATCH_BINDING.bound(batch_deposit(batch_wire(opening, [L, binding]))) == H
    other_key = "x402:batch-settlement:svm:rcvauth:v1:" + BS["payTo"]
    assert BATCH_BINDING.bound(batch_deposit(batch_wire(opening, [other_key, L]))) == H


def test_x402_batch_settlement_solana_bound_compares_the_seller_memo_with_extra_memo() -> None:
    """ES2's opening read under an option whose extra.memo is another LCP string, or under one with no extra.memo, is
    svm/carrier-mismatch: lcp 0.4.0's opening read compares the seller memo with extra.memo (svmOpening)."""
    extra = BV["ES4"]["accepted"]["extra"]
    opening = batch_deposit(BV["ES2"]["wireBase64"])
    others = [{**extra, "memo": "lcp:sha256:0x" + "11" * 32}, {k: v for k, v in extra.items() if k != "memo"}]
    for other in others:
        presented = {**opening, "accepted": {**BV["ES4"]["accepted"], "extra": other}}
        assert BATCH_BINDING.bound(presented) == Refusal("svm/carrier-mismatch"), other
