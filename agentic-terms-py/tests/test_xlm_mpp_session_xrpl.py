"""mpp/session/xrpl: the TypeScript gate's placement, B2, B6, B10 and B16 rows, and the buyer half's XS and plant rows.
Expected values are the vector file's; the payer is the XRPL vectors' Ed25519 key from entropy 01×16, whose private key
is SHA-512Half of the entropy."""

import hashlib
from typing import Any

from integraledger_terms import MPP_SESSION_XRPL, Refusal
from integraledger_terms.bindings import _xrpl

import ed25519
from breadth import H, LINK, Pairing, build_and_sign, plant
from mpp_docs import placed_doc
from support import hexb, load
from xlm_support import EVM_ACCOUNT, b16, mpp_b10

V = load("mpp-session-hedera-solana-xrpl.json")
S: dict[str, Any] = V["XS2"]
SEED = hashlib.sha512(bytes([1]) * 16).digest()[:32]
PUBLIC_KEY = "ED" + ed25519.public_key(SEED).hex().upper()
MEMO = f"lcp:sha256:{H}".encode("utf-8").hex().upper()


def answer(request: Any) -> Any:
    assert request["kind"] == "xrpl-session-open", request["kind"]
    return {"signedBlob": "0x" + S["blob"], "claimSignature": "0x" + ed25519.sign(SEED, hexb(request["claim"]["bytes"])).hex()}


SESSION = Pairing(
    binding=MPP_SESSION_XRPL,
    doc=placed_doc(V["SS1"]["xrpl"]["challenge"], H, LINK),
    account=f"xrpl:1:{S['account']}",
    answer=answer,
    inputs={
        "deposit": S["deposit"],
        "xrpl": {
            "publicKey": "0x" + PUBLIC_KEY,
            "settleDelay": S["settleDelay"],
            "fee": S["fee"],
            "sequence": S["sequence"],
            "lastLedgerSequence": S["lastLedgerSequence"],
        },
    },
)


def test_mpp_session_xrpl_placed_challenge_is_the_vectors_and_xs2_carries_the_payer_key() -> None:
    assert SESSION.doc == [V["SS1"]["xrpl"]["placed"]]
    assert "7121" + PUBLIC_KEY in S["blob"]

def test_mpp_session_xrpl_b6_channel_create_with_one_lcp_memo_and_first_claim() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "xrpl-session-open"
        assert request["txJson"] == {
            "TransactionType": "PaymentChannelCreate",
            "Flags": 0,
            "Account": S["account"],
            "Amount": S["deposit"],
            "Destination": "rpjfAeE3DeeHPFnN2PgGFW5YxnZFAjrEyN",
            "SettleDelay": S["settleDelay"],
            "PublicKey": PUBLIC_KEY,
            "Memos": [{"Memo": {"MemoData": MEMO}}],
            "Fee": S["fee"],
            "Sequence": S["sequence"],
            "LastLedgerSequence": S["lastLedgerSequence"],
        }
        assert MEMO in S["blob"]
        assert request["claim"]["channelId"] == S["expectChannel"]
        assert request["claim"]["drops"] == int(V["XS3"]["drops"])
        assert hexb(request["claim"]["bytes"]).hex().upper() == V["XS3"]["expect"]

    signed, _ = build_and_sign(SESSION, inspect)
    assert signed["source"] == f"did:pkh:xrpl:1:{S['account']}"
    assert signed["payload"]["action"] == "open"
    assert signed["payload"]["transaction"] == S["blob"]
    assert signed["payload"]["amount"] == V["XS3"]["drops"]
    claim = bytes.fromhex(V["XS3"]["expect"])
    assert signed["payload"]["signature"] == ed25519.sign(SEED, claim).hex()
    assert signed["payload"]["signature"].startswith("c042fda5")
    assert signed["payload"]["signature"].endswith("a03901")


def test_mpp_session_xrpl_b10_http_link() -> None:
    mpp_b10(SESSION)


def test_mpp_session_xrpl_b16_other_accounts() -> None:
    b16(SESSION, [EVM_ACCOUNT, f"xrpl:0:{S['account']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def opening(blob: str, action: str = "open") -> dict[str, Any]:
    payload = {"action": action, "transaction": blob, "amount": V["XS3"]["drops"], "signature": "00"}
    return {"challenge": SESSION.doc[0], "source": f"did:pkh:xrpl:1:{S['account']}", "payload": payload}


def test_mpp_session_xrpl_xs1_channel_id_xs2_bound_and_hash() -> None:
    x1 = V["XS1"]
    assert _xrpl.channel_id(x1["account"], x1["destination"], x1["sequence"]) == x1["expect"]
    assert len(bytes.fromhex(S["blob"])) == S["expectLength"]
    blob = _xrpl.decode_blob(S["blob"])
    assert isinstance(blob, _xrpl.Blob) and blob.hash == S["expectHash"]
    assert MPP_SESSION_XRPL.bound(opening(S["blob"])) == S["expectBound"]
    assert _xrpl.claim_bytes(S["expectChannel"], int(V["XS3"]["drops"])) == bytes.fromhex(V["XS3"]["expect"])


def test_mpp_session_xrpl_plants_and_refusals() -> None:
    plants = V["plants"]["xrpl"]
    memo_h2 = f"lcp:sha256:{V['fixed']['H2']}".encode("utf-8").hex().upper()
    assert MPP_SESSION_XRPL.bound(opening(S["blob"].replace(MEMO, memo_h2))) == Refusal(plants["expectH2"])
    memos = "F9EA7D4D" + MEMO + "E1F1"
    assert memos in S["blob"]
    assert MPP_SESSION_XRPL.bound(opening(S["blob"].replace(memos, ""))) == Refusal(plants["expectNoMemo"])
    agreed = {r["case"]: r["expect"] for r in V["agreedRefusals"]["rows"]}
    nine = "F9EA7D4D" + MEMO + ("E1EA7D0100" * 8) + "E1F1"
    assert MPP_SESSION_XRPL.bound(opening(S["blob"].replace(memos, nine))) == Refusal(agreed["an xrpl opening with more than 8 memos"])
    assert MPP_SESSION_XRPL.bound(opening(S["blob"], "voucher")) == Refusal(agreed["bound of a credential whose action is not open"])
    assert _xrpl.channel_id("rBad", S["account"], 1) == Refusal(
        agreed["xrplChannelId with a malformed address or sequence, or xrplClaim with a malformed id or drops"]
    )
    terms = {"publicKey": PUBLIC_KEY, "settleDelay": 3600, "fee": "12", "sequence": 7, "lastLedgerSequence": 1000}
    choice = {"challenge": SESSION.doc[0], "from": S["account"], "now": 0, "deposit": 0, "xrpl": terms}
    assert MPP_SESSION_XRPL.build(choice, H) == Refusal(agreed["build with a malformed from, deposit or XRPL channel terms"])
