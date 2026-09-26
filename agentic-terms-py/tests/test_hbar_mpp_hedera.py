"""B2, B6, B10 and B16 for mpp/charge/hedera and mpp/session/hedera, and the buyer halves' vector rows. Expected
values are mpp-charge-hedera.json's and mpp-session-hedera-solana-xrpl.json's."""

import copy
import json
from typing import Any

from integraledger_terms import MPP_CHARGE_HEDERA as BINDING
from integraledger_terms import MPP_SESSION_HEDERA as SESSION
from integraledger_terms import Declined, Refusal, Transacted, confirm, transact
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode, js_json
from integraledger_terms.bindings._mpp import attribution_memo, check_attribution

import ed25519
from breadth import ABC, H, LINK, Pairing, Recording, build_and_sign, link_calls, plant, run
from hbar_support import EVM_ACCOUNT, b16
from mpp_docs import issued, placed_doc
from support import ACCOUNT, digest, hexb, load, serving, sign_typed

C = load("mpp-charge-hedera.json")
F: dict[str, Any] = C["fixed"]
# The payer key is Ed25519 seed 03×32; its public key is the vector's.
SEED = bytes([3]) * 32
ISSUED = issued("hedera", "charge", js_json(F["request"]), realm=F["realm"], expires=F["expires"])
DOC = placed_doc(ISSUED, H, LINK)


def charge_answer(request: Any) -> Any:
    if request["kind"] != "hedera-body":
        raise AssertionError(request["kind"])
    assert hexb(request["bodyBytes"]).hex() == C["build"]["expectBodyBytes"]
    return {"publicKey": "0x" + F["publicKey"], "signature": "0x" + F["signature"], "type": "ed25519"}


CHARGE = Pairing(
    binding=BINDING,
    doc=DOC,
    account=f"hedera:testnet:{F['payer']}",
    answer=charge_answer,
    inputs={"node": F["node"], "validStart": F["validStart"], "maxFee": F["maxFee"]},
)


def http_doc(doc: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The document with each challenge's legal-context link as http://."""
    out = copy.deepcopy(doc)
    for c in out:
        raw = b64u_decode(c["opaque"])
        assert raw is not None
        opaque = json.loads(raw)
        opaque["legalContextUrl"] = opaque["legalContextUrl"].replace("https://", "http://")
        c["opaque"] = b64u_encode(js_json(opaque).encode())
    return out


def test_mpp_charge_hedera_the_placed_challenge_id_is_the_vectors() -> None:
    assert DOC[0]["id"] == F["challengeId"]

def test_mpp_charge_hedera_b6_body_signature_and_credential() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "hedera-body"
        assert hexb(request["bodyBytes"]).hex() == C["build"]["expectBodyBytes"]
        assert ed25519.public_key(SEED).hex() == F["publicKey"]
        assert ed25519.sign(SEED, hexb(request["bodyBytes"])).hex() == F["signature"]

    signed, _ = build_and_sign(CHARGE, inspect)
    assert signed["payload"] == {"type": "transaction", "transaction": C["build"]["expectTransactionBase64"]}
    assert signed["challenge"] == DOC[0]


# The push form (draft-hedera-charge-00: "Two payload types are defined: "hash" (default) and "transaction" (pull
# mode)"): the wallet signs and broadcasts the compared body and answers its transaction id.
def push_answer(request: Any) -> Any:
    if request["kind"] != "hedera-body":
        raise AssertionError(request["kind"])
    return {"transactionId": C["push"]["transactionId"]}


PUSH = Pairing(
    binding=BINDING,
    doc=DOC,
    account=f"hedera:testnet:{F['payer']}",
    answer=push_answer,
    inputs={"node": F["node"], "validStart": F["validStart"], "maxFee": F["maxFee"], "credentialType": "hash"},
)


def test_mpp_charge_hedera_push_b2_plant() -> None:
    plant(PUSH)


def test_mpp_charge_hedera_push_b6_the_hash_form_whose_landed_memo_gives_h() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "hedera-body"
        assert hexb(request["bodyBytes"]).hex() == C["build"]["expectBodyBytes"]
        assert request["broadcast"] is True

    signed, _ = build_and_sign(PUSH, inspect)
    assert signed["payload"] == {"type": "hash", "transactionId": C["push"]["transactionId"]}
    assert "landed" not in signed
    whole = run(lambda c: transact(DOC, BINDING, Recording(PUSH.account, push_answer), c, inputs=PUSH.inputs), serving(ABC))
    assert isinstance(whole, Transacted), whole
    assert whole.landed == C["fetchPresented"]["expectLanded"]
    assert BINDING.bound(signed) == Refusal(C["push"]["expectWithout"])
    assert BINDING.bound({**signed, "landed": whole.landed}) == H


def test_mpp_charge_hedera_push_an_answer_naming_another_payer_or_valid_start_keeps_the_moved_payment() -> None:
    for tx_id in ("0.0.5556@1700000000.000000000", "0.0.5555@1700000001.000000000", "0.0.5555@1700000000.000000001"):
        def answer(_request: Any, t: str = tx_id) -> Any:
            return {"transactionId": t}

        signer = Recording(PUSH.account, answer)
        out = run(lambda c: transact(DOC, BINDING, signer, c, inputs=PUSH.inputs), serving(ABC))
        assert isinstance(out, Declined) and out.code == "signed-not-bound", out
        assert out.moved is not None and out.moved.signed == {"transactionId": tx_id} and out.moved.h == H
        assert len(signer.requests) == 1


def test_mpp_charge_hedera_a_credential_type_other_than_transaction_or_hash_is_no_payable_option() -> None:
    link = serving(ABC)
    out = run(lambda c: confirm(DOC, BINDING, CHARGE.account, c, {**(CHARGE.inputs or {}), "credentialType": "push"}), link)
    assert out == Declined("no-payable-option", "mpp/input-malformed")
    assert link.calls == 0


def test_mpp_charge_hedera_b10_http_link() -> None:
    out, calls = link_calls(CHARGE, CHARGE.account, http_doc(DOC))
    assert out == Declined("offer-unreadable", "mpp/link-not-https"), out
    assert calls == 0


def test_mpp_charge_hedera_b16_other_accounts() -> None:
    b16(CHARGE, [EVM_ACCOUNT, f"hedera:mainnet:{F['payer']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def credential(payload: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"challenge": DOC[0], "payload": payload, **extra}


def test_mpp_charge_hedera_v4_attribution_memo() -> None:
    v4 = C["V4"]
    assert attribution_memo(v4["realm"], v4["id"]) == v4["expectMemo"]
    assert attribution_memo(v4["realm"], v4["id"], v4["clientId"]) == v4["expectMemoWithClient"]
    assert check_attribution(v4["expectMemo"], v4["realm"], v4["otherId"]) == Refusal(v4["expectOther"])


def test_mpp_charge_hedera_build_complete_and_bound() -> None:
    choice = {
        "challenge": DOC[0],
        "payer": F["payer"],
        "node": F["node"],
        "validStart": {"seconds": int(F["validStart"]["seconds"]), "nanos": F["validStart"]["nanos"]},
        "maxFee": int(F["maxFee"]),
    }
    unsigned = BINDING.build(choice, H)
    assert not isinstance(unsigned, Refusal)
    body = unsigned.request["bodyBytes"]
    assert body.hex() == C["build"]["expectBodyBytes"]
    assert C["build"]["expectMemo"].encode() in body
    wire = unsigned.complete({"publicKey": bytes.fromhex(F["publicKey"]), "signature": bytes.fromhex(F["signature"]), "type": "ed25519"})
    assert wire == C["build"]["expectTransactionBase64"]
    assert BINDING.bound(credential({"type": "transaction", "transaction": wire})) == C["bound"]["expectBound"]
    other = credential({"type": "transaction", "transaction": C["bound"]["otherTransactionBase64"]})
    assert BINDING.bound(other) == Refusal(C["bound"]["expectOther"])


def test_mpp_charge_hedera_push_needs_the_landed_memo() -> None:
    push = C["push"]
    pushed = credential({"type": "hash", "transactionId": push["transactionId"]})
    assert BINDING.bound(pushed) == Refusal(push["expectWithout"])
    landed = {**pushed, "landed": {"network": "hedera:testnet", "memo": push["expectReference"]["expectMemo"]}}
    assert BINDING.bound(landed) == H


def test_mpp_charge_hedera_a_memo_that_is_not_an_attribution_memo() -> None:
    """The memo must be 0x and 64 hex digits; x402's LCP-string memo is not."""
    wire = load("x402-exact-hedera.json")["V2"]["expectTransactionBase64"]
    assert BINDING.bound(credential({"type": "transaction", "transaction": wire})) == Refusal("mpp/attribution-malformed")


# ── mpp/session/hedera ────────────────────────────────────────────────────────────────────────────────────────────

S = load("mpp-session-hedera-solana-xrpl.json")
SF: dict[str, Any] = S["fixed"]
SESSION_DOC = placed_doc(S["SS1"]["hedera"]["challenge"], H, LINK)


def session_answer(request: Any) -> Any:
    if request["kind"] != "hedera-session-open":
        raise AssertionError(request["kind"])
    return {
        "openTx": S["HS3"]["txHash"],
        "signature": sign_typed(request["voucher"]),
        # The landed receipt of the opening: HS3's escrow log. The block number is a fixture value bound does not read.
        "landed": {"transaction": S["HS3"]["txHash"], "blockNumber": "1", "logs": [S["HS3"]["log"]]},
    }


OPEN = Pairing(
    binding=SESSION,
    doc=SESSION_DOC,
    account=f"hedera:testnet:{SF['payer']}",
    answer=session_answer,
    inputs={"deposit": S["HS2"]["deposit"]},
)


def test_mpp_session_hedera_the_placed_challenge_is_the_vectors_and_the_payer_is_anvil_0() -> None:
    assert SESSION_DOC == [S["SS1"]["hedera"]["placed"]]
    assert ACCOUNT.split(":")[-1] == SF["payer"]

def test_mpp_session_hedera_b6_calls_voucher_and_landed_log() -> None:
    hs2 = S["HS2"]

    def inspect(request: Any) -> None:
        assert request["kind"] == "hedera-session-open"
        assert request["chainId"] == 296
        approve, open_ = request["calls"]
        assert approve["to"] == SF["token"]
        assert (len(approve["data"]) - 2) // 2 == hs2["expectApproveLength"]
        assert approve["data"].startswith(hs2["expectApprovePrefix"]) and approve["data"].endswith(hs2["expectApproveSuffix"])
        assert hs2["expectApproveContains"] in approve["data"]
        assert open_["to"] == SF["escrow"].lower()
        assert (len(open_["data"]) - 2) // 2 == hs2["expectOpenLength"]
        assert open_["data"].startswith(hs2["expectOpenSelector"])
        start, end = hs2["expectOpenSaltBytes"]
        assert "0x" + open_["data"][2 + 2 * start : 2 + 2 * end] == H
        assert digest(request["voucher"]) == hs2["expectVoucherDigest"]

    signed, _ = build_and_sign(OPEN, inspect)
    assert "landed" not in signed
    payload = signed["payload"]
    assert payload["action"] == "open"
    assert payload["channelId"] == S["HS1"]["expectChannelId"]
    assert payload["txHash"] == S["HS3"]["txHash"]
    assert payload["cumulativeAmount"] == "0"


def test_mpp_session_hedera_b10_http_link() -> None:
    out, calls = link_calls(OPEN, OPEN.account, http_doc(SESSION_DOC))
    assert out == Declined("offer-unreadable", "mpp/link-not-https"), out
    assert calls == 0


def test_mpp_session_hedera_b16_other_accounts() -> None:
    b16(OPEN, [EVM_ACCOUNT, f"hedera:mainnet:{SF['payer']}"])


def opened(logs: list[Any], channel: str | None = None) -> dict[str, Any]:
    payload = {
        "action": "open",
        "channelId": channel or S["HS1"]["expectChannelId"],
        "txHash": S["HS3"]["txHash"],
        "cumulativeAmount": "0",
        "signature": "0x" + "11" * 65,
    }
    return {"challenge": SESSION_DOC[0], "payload": payload, "landed": {"transaction": S["HS3"]["txHash"], "blockNumber": 1, "logs": logs}}


def test_mpp_session_hedera_hs3_bound_and_plants() -> None:
    assert SESSION.bound(opened([S["HS3"]["log"]])) == S["HS3"]["expectBound"]
    bare = {k: v for k, v in opened([S["HS3"]["log"]]).items() if k != "landed"}
    assert SESSION.bound(bare) == Refusal("hedera/read-first")
    plant_ = S["plants"]["hedera"]
    real = S["HS4"]["openReceipt"]["logs"]
    real_channel = real[1]["topics"][1]
    assert SESSION.bound(opened(real, real_channel)) == Refusal(plant_["expect"])
    moved = [{**log, "address": plant_["otherEmitter"]} for log in real]
    assert SESSION.bound(opened(moved, real_channel)) == Refusal(plant_["expectOtherEmitter"])
    bad = opened([S["HS3"]["log"]])
    bad["payload"] = {**bad["payload"], "action": S["HS5"]["badAction"]}
    assert SESSION.bound(bad) == Refusal(S["HS5"]["expectBad"])


def test_mpp_session_hedera_a_log_whose_payer_or_payee_topic_is_not_hex_is_not_the_opening() -> None:
    for at in (2, 3):
        log = S["HS3"]["log"]
        topics = list(log["topics"])
        topics[at] = "not-hex"
        assert SESSION.bound(opened([{**log, "topics": topics}])) == Refusal("hedera/channel-log-not-found")


def test_mpp_charge_hedera_build_hands_a_push_over_itself() -> None:
    # mpp-charge-hedera.json build.push: credentialType hash gives the vector's body with broadcast true; transaction,
    # or none, gives it with no broadcast member; any other value is the row's refusal.
    from integraledger_terms.bindings.mpp_charge_hedera import build_charge

    p = C["build"]["push"]
    base = {
        "payer": F["payer"],
        "node": F["node"],
        "validStart": {"seconds": int(F["validStart"]["seconds"]), "nanos": F["validStart"]["nanos"]},
        "maxFee": int(F["maxFee"]),
    }
    challenge = {"id": F["challengeId"], "realm": F["realm"]}

    def at(extra: dict[str, Any]) -> Any:
        u = build_charge(challenge, F["request"], {**base, **extra})
        if isinstance(u, Refusal):
            return u.code
        return {**u.request, "bodyBytes": bytes(u.request["bodyBytes"]).hex()}

    assert at({"credentialType": p["credentialType"]}) == p["expectRequest"]
    assert at({"credentialType": "transaction"}) == p["expectPullRequest"]
    assert at({}) == p["expectPullRequest"]
    assert at({"credentialType": p["otherCredentialType"]}) == p["expectOther"]
