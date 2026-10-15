"""mpp/session/xrpl: the TypeScript gate's placement, B2, B6, B10 and B16 rows, and the buyer half's XS and plant rows.
Expected values are the vector file's; the payer is the XRPL vectors' Ed25519 key from entropy 01×16, whose private key
is SHA-512Half of the entropy."""

import asyncio
import base64
import hashlib
import json
from typing import Any

from integraledger_terms import MPP_SESSION_XRPL, Declined, Refusal, Transacted, Within, open_channel, transact, within
from integraledger_terms.bindings import _xrpl
from integraledger_terms.bindings._channel import ChannelRef
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings.mpp_session_xrpl import MppSessionXrpl

import ed25519
from breadth import ABC, H, LINK, Pairing, Recording, build_and_sign, plant, run
from mpp_docs import placed_doc
from support import hexb, load, serving
from xlm_support import EVM_ACCOUNT, b16, mpp_b10

V = load("mpp-session-hedera-solana-xrpl.json")
S: dict[str, Any] = V["XS2"]
SEED = hashlib.sha512(bytes([1]) * 16).digest()[:32]
PUBLIC_KEY = "ED" + ed25519.public_key(SEED).hex().upper()
MEMO = f"lcp:sha256:{H}".encode("utf-8").hex().upper()


def answer(request: Any) -> Any:
    """The wallet's answer, as the XRP Ledger writes a signed blob and a claim's signature: hex digits without 0x."""
    assert request["kind"] == "xrpl-session-open", request["kind"]
    return {"signedBlob": S["blob"], "claimSignature": ed25519.sign(SEED, hexb(request["claim"]["bytes"])).hex()}


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


_NOT_ADDRESS = "rf1BiGeXwwQoi8Z2ueFYTEXSwuJYfV2Jpm"  # XS1's account with its last character changed: its checksum fails


def test_channel_id_claim_bytes_and_build_refuse_malformed_input_with_the_agreed_code() -> None:
    # The cases are @integraledger/lcp's own test of xrplChannelId, xrplClaim and build; a Python int stands for its
    # bigint, and a bool for a value that is not one.
    agreed = {r["case"]: r["expect"] for r in V["agreedRefusals"]["rows"]}
    helpers = Refusal(agreed["xrplChannelId with a malformed address or sequence, or xrplClaim with a malformed id or drops"])
    x1 = V["XS1"]
    assert x1["account"][:-1] == _NOT_ADDRESS[:-1] and x1["account"] != _NOT_ADDRESS
    ids: list[tuple[Any, Any, Any]] = [
        (_NOT_ADDRESS, x1["destination"], x1["sequence"]),
        (x1["account"], _NOT_ADDRESS, x1["sequence"]),
        (7, x1["destination"], x1["sequence"]),
        (x1["account"], x1["destination"], -1),
        (x1["account"], x1["destination"], 2**32),
        (x1["account"], x1["destination"], 1.5),
        (x1["account"], x1["destination"], True),
    ]
    for account, destination, sequence in ids:
        assert (account, destination, sequence, _xrpl.channel_id(account, destination, sequence)) == (account, destination, sequence, helpers)
    claims: list[tuple[Any, Any]] = [
        ("zz", 100),
        (S["expectChannel"][2:], 100),
        (S["expectChannel"], True),
        (S["expectChannel"], -1),
        (S["expectChannel"], 1 << 64),
    ]
    for channel, drops in claims:
        assert (channel, drops, _xrpl.claim_bytes(channel, drops)) == (channel, drops, helpers)
    terms = {"publicKey": "ED" + "11" * 32, "settleDelay": 3600, "fee": "12", "sequence": 7, "lastLedgerSequence": 1000}
    choice = {"challenge": SESSION.doc[0], "from": S["account"], "now": 0, "deposit": int(S["deposit"]), "xrpl": terms}
    assert MPP_SESSION_XRPL.build({**choice, "from": _NOT_ADDRESS}, H) == Refusal(agreed["build with a malformed from, deposit or XRPL channel terms"])
    # The request's recipient holds the classic address's shape, and only its checksum fails: the challenge check reads
    # the AccountID the channel id derives from, so the pairing's filter refuses it mpp/request-malformed, the code
    # mpp-session-hedera-solana-xrpl.json's boundChallenge row gives, and build takes no such challenge.
    asked = V["SS1"]["xrpl"]["challenge"]
    text = asked["request"]
    request = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    recipient = json.dumps({**request, "recipient": _NOT_ADDRESS}, separators=(",", ":"), sort_keys=True)
    assert pairings_of(issued_from(asked, recipient)) == Refusal("mpp/request-malformed")
    placed = {**SESSION.doc[0], "request": issued_from(asked, recipient)["request"]}
    assert MPP_SESSION_XRPL.build({**choice, "challenge": placed}, H) == Refusal("mpp/request-malformed")


def issued_from(challenge: dict[str, Any], request_json: str) -> dict[str, Any]:
    """challenge with its request replaced by request_json as base64url without padding."""
    return {**challenge, "request": base64.urlsafe_b64encode(request_json.encode("utf-8")).decode("ascii").rstrip("=")}


# A PaymentChannelCreate names its Destination (xrpl.org, "PaymentChannelCreate"), and a Sequence of 0 leaves the
# sequence to TicketSequence (xrpl.org, "Transaction Common Fields"). An opening that lacks either derives no channel
# id: channel_ref and build_within refuse it xrpl/not-channel-create, as @integraledger/lcp's channel.ref and
# buildWithin do. The two blobs are XS2's with its Destination field (type 8, field 3: 0x83, then 20 bytes) removed,
# and with its Sequence (UInt32 field 4: 0x24) set to 0; ripple-binary-codec 2.11.0 encodes the same bytes.
_DESTINATION_FIELD = "831412EF6422DC22833EF13442F83E89FB113C01A65A"
_SEQUENCE_FIELD = "24" + f"{S['sequence']:08X}"


def test_an_opening_without_its_destination_or_sequence_names_no_channel() -> None:
    assert S["blob"].count(_DESTINATION_FIELD) == 1 and S["blob"].count(_SEQUENCE_FIELD) == 1
    no_destination = S["blob"].replace(_DESTINATION_FIELD, "")
    no_sequence = S["blob"].replace(_SEQUENCE_FIELD, "2400000000")
    without, zero = _xrpl.decode_blob(no_destination), _xrpl.decode_blob(no_sequence)
    assert isinstance(without, _xrpl.Blob) and isinstance(zero, _xrpl.Blob)
    assert "Destination" not in without.tx and zero.tx["Sequence"] == 0 and "TicketSequence" not in zero.tx
    session = MPP_SESSION_XRPL
    assert isinstance(session, MppSessionXrpl)
    within = {**V["SS1"]["xrpl"]["challenge"], "id": "seller-own-id"}
    for blob in (no_destination, no_sequence):
        assert session.channel_ref(opening(blob)) == Refusal("xrpl/not-channel-create")
        w = {"challenge": within, "opening": opening(blob), "cumulativeAmount": 100, "action": "voucher"}
        assert session.build_within(w, H) == Refusal("xrpl/not-channel-create")
    assert session.channel_ref(opening(S["blob"])) == ChannelRef("xrpl:1", S["expectChannel"])


# ── the answer forms: an opening's {signedBlob, claimSignature} and a later xrpl-claim's signature take one form, hex
# digits without 0x, the form the protocol package's complete reads.


def test_an_opening_answered_in_0x_hex_is_declined_signed_not_bound() -> None:
    def claim_signature(request: Any) -> str:
        return "0x" + ed25519.sign(SEED, hexb(request["claim"]["bytes"])).hex()

    for prefixed in (
        lambda r: {"signedBlob": "0x" + S["blob"], "claimSignature": claim_signature(r)},
        lambda r: {**answer(r), "signedBlob": "0x" + S["blob"]},
        lambda r: {"signedBlob": S["blob"], "claimSignature": claim_signature(r)},
    ):
        out = run(lambda c: transact(SESSION.doc, MPP_SESSION_XRPL, Recording(SESSION.account, prefixed), c, inputs=SESSION.inputs), serving(ABC))
        assert isinstance(out, Declined) and out.code == "signed-not-bound", out


def test_a_claim_within_the_held_channel_is_answered_as_hex_digits_without_0x() -> None:
    opened = run(lambda c: transact(SESSION.doc, MPP_SESSION_XRPL, Recording(SESSION.account, answer), c, inputs=SESSION.inputs), serving(ABC))
    assert isinstance(opened, Transacted) and opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, MPP_SESSION_XRPL)
    assert not isinstance(hold, Declined), hold
    assert hold["channel"] == S["expectChannel"]
    own = [{**V["SS1"]["xrpl"]["challenge"], "id": "seller-own-id"}]

    def claim(prefix: str) -> Any:
        return lambda r: [prefix + ed25519.sign(SEED, hexb(q["bytes"])).hex() for q in r["requests"]]

    signer = Recording(SESSION.account, claim(""))
    paid = asyncio.run(within(own, hold, MPP_SESSION_XRPL, signer))
    assert isinstance(paid, Within), paid
    handed = signer.requests[0]["requests"]
    assert [q["kind"] for q in handed] == ["xrpl-claim"] and hexb(handed[0]["bytes"]).hex().upper() == V["XS3"]["expect"]
    payload = paid.signed["payload"]
    assert (payload["action"], payload["channelId"], payload["amount"]) == ("voucher", S["expectChannel"], V["XS3"]["drops"])
    assert payload["signature"] == ed25519.sign(SEED, bytes.fromhex(V["XS3"]["expect"])).hex()
    prefixed = asyncio.run(within(own, hold, MPP_SESSION_XRPL, Recording(SESSION.account, claim("0x"))))
    assert prefixed == Declined("signed-not-bound", "mpp/credential-malformed")
