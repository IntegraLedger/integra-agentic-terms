"""The in-channel payment of MPP's sessions: build_within of each session binding, so the Python gate's within
serves MPP sessions as the TypeScript gate's does; and the within challenge the seller issues itself on a live
channel, with its own id and the channel named in methodDetails.channelId: the gate signs only for a channel it opened
for an ATR it compared, and only when the within challenge's legal context is absent or names that H. The voucher
digests and bytes are the vector files' (ES5, TS4, HS2, SV3 on SV2's opening, XS3 on XS2's); the within challenges are
the issued request with methodDetails.channelId added, a fresh id, and no opaque unless a legal context is given. The
TypeScript gate's tests are channels.test.ts's."""

import asyncio
import base64
import json
from typing import Any

import pytest

from integraledger_terms import (
    MPP_SESSION_EVM,
    MPP_SESSION_HEDERA,
    MPP_SESSION_SOLANA,
    MPP_SESSION_TEMPO,
    MPP_SESSION_XRPL,
    Declined,
    Transacted,
    Within,
    _gate,
    open_channel,
    transact,
    within,
)
from integraledger_terms._types import Refusal
from integraledger_terms.bindings._channel import BatchUnsigned
from integraledger_terms.bindings.mpp_session import MppSessionEvm

from breadth import ABC, H, LINK, Recording, offered, run
from mpp_docs import issued, placed_doc
from support import digest, load, serving, sign_typed

EVM = load("mpp-session-evm.json")
TEMPO = load("mpp-session-tempo.json")
HS = load("mpp-session-hedera-solana-xrpl.json")
MC = load("mpp-challenge.json")["fixed"]
TF = TEMPO["fixed"]
H_OTHER = "0x" + "11" * 32


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: TF["now"])


def b6(v: dict[str, Any]) -> dict[str, Any]:
    presented = next(r for r in v["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]
    assert isinstance(presented, dict), presented
    return presented


def build(binding: Any, opening: dict[str, Any], amount: int) -> BatchUnsigned:
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": amount, "action": "voucher"}
    unsigned = binding.build_within(w, H)
    assert isinstance(unsigned, BatchUnsigned), unsigned
    return unsigned


# ── build_within against the vectors' voucher digests.


def test_evm_build_within_at_zero_is_es5s_voucher() -> None:
    unsigned = build(MPP_SESSION_EVM, b6(EVM), 0)
    assert [r["kind"] for r in unsigned.requests] == ["eip712"]
    assert digest(unsigned.requests[0]["typedData"]) == EVM["ES5"]["expectVoucherDigest"]


def tempo_opened() -> Transacted:
    doc = placed_doc(issued("tempo", "session", TF["requestV2"]), H, LINK)
    from test_mpp_session import TempoAnswer

    out = run(lambda c: transact(doc, MPP_SESSION_TEMPO, Recording(f"eip155:42431:{TF['payer']}", TempoAnswer()), c, inputs={"deposit": TF["deposit"]}), serving(ABC))
    assert isinstance(out, Transacted) and out.signed is not None, out
    return out


def test_tempo_v2_build_within_at_0_and_250_are_ts4s_vouchers() -> None:
    opening = tempo_opened().signed
    assert opening is not None
    zero = build(MPP_SESSION_TEMPO, opening, 0)
    assert digest(zero.requests[0]["typedData"]) == TEMPO["TS4"]["expectVoucher0"]
    at250 = digest(build(MPP_SESSION_TEMPO, opening, 250).requests[0]["typedData"])
    e = TEMPO["TS4"]["expectVoucher250"]
    assert at250.startswith(e["prefix"]) and at250.endswith(e["suffix"])
    credential = zero.complete([sign_typed(zero.requests[0]["typedData"])])
    assert isinstance(credential, dict)
    assert credential["payload"]["descriptor"] == opening["payload"]["descriptor"]


def hedera_opened() -> Transacted:
    doc = placed_doc(HS["SS1"]["hedera"]["challenge"], H, LINK)
    signer = Recording(
        f"hedera:testnet:{HS['fixed']['payer']}",
        lambda r: {
            "openTx": HS["HS3"]["txHash"],
            "signature": sign_typed(r["voucher"]),
            "landed": {"transaction": HS["HS3"]["txHash"], "blockNumber": "1", "logs": [HS["HS3"]["log"]]},
        },
    )
    out = run(lambda c: transact(doc, offered(MPP_SESSION_HEDERA), signer, c, inputs={"deposit": HS["HS2"]["deposit"]}), serving(ABC))
    assert isinstance(out, Transacted), out
    return out


def test_hedera_build_within_at_zero_is_hs2s_voucher() -> None:
    opening = hedera_opened().signed
    assert opening is not None
    assert digest(build(MPP_SESSION_HEDERA, opening, 0).requests[0]["typedData"]) == HS["HS2"]["expectVoucherDigest"]


SOLANA_OPENING = {
    "challenge": HS["SS1"]["solana"]["placed"],
    "payload": {"action": "open", "channelId": HS["SV2"]["channel"], "transaction": HS["SV2"]["wireBase64"]},
}
XRPL_OPENING = {
    "challenge": HS["SS1"]["xrpl"]["placed"],
    "payload": {"action": "open", "transaction": HS["XS2"]["blob"], "amount": "100", "signature": "00"},
}


def test_solana_build_within_at_100_is_sv3s_voucher_for_the_opening_s_signer() -> None:
    unsigned = build(MPP_SESSION_SOLANA, SOLANA_OPENING, 100)
    assert unsigned.requests == [
        {"kind": "ed25519-raw", "message": bytes.fromhex(HS["SV3"]["expectVoucher"]), "signer": HS["SV3"]["payer"]}
    ]
    signature = "1" * 64
    credential = unsigned.complete([signature])
    channel = HS["SV2"]["channel"]
    assert credential == {
        "challenge": SOLANA_OPENING["challenge"],
        "payload": {
            "action": "voucher",
            "channelId": channel,
            "voucher": {
                "voucher": {"channelId": channel, "cumulativeAmount": "100"},
                "signer": HS["SV3"]["payer"],
                "signature": signature,
                "signatureType": "ed25519",
            },
        },
    }
    assert unsigned.complete(["0x" + "11" * 64]) == Refusal("mpp/credential-malformed")


def test_solana_build_within_refuses_an_operator_channel_s_voucher() -> None:
    placed = dict(HS["SS1"]["solana"]["placed"])
    text = placed["request"]
    request = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    request["methodDetails"].update(HS["SV5"]["methodDetails"])
    placed["request"] = base64.urlsafe_b64encode(json.dumps(request).encode("utf-8")).decode("ascii").rstrip("=")
    opening = {**SOLANA_OPENING, "challenge": placed}
    w = {"challenge": placed, "opening": opening, "cumulativeAmount": 100, "action": "voucher"}
    assert MPP_SESSION_SOLANA.build_within(w, H) == Refusal("mpp/within-action-not-built")


def test_xrpl_build_within_at_100_is_xs3s_claim_on_xs2s_channel() -> None:
    unsigned = build(MPP_SESSION_XRPL, XRPL_OPENING, int(HS["XS3"]["drops"]))
    channel = HS["XS2"]["expectChannel"]
    assert unsigned.requests == [
        {"kind": "xrpl-claim", "channelId": channel, "drops": int(HS["XS3"]["drops"]), "bytes": bytes.fromhex(HS["XS3"]["expect"])}
    ]
    assert unsigned.complete(["C0" * 64]) == {
        "challenge": XRPL_OPENING["challenge"],
        "payload": {"action": "voucher", "channelId": channel, "amount": HS["XS3"]["drops"], "signature": "C0" * 64},
    }
    assert unsigned.complete(["0x" + "C0" * 64]) == Refusal("mpp/credential-malformed")


def test_build_within_refuses_an_action_it_does_not_build_and_another_hash() -> None:
    evm = MPP_SESSION_EVM
    assert isinstance(evm, MppSessionEvm)
    opening = b6(EVM)
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 1, "action": "topUp"}
    assert evm.build_within(w, H) == Refusal("mpp/within-action-not-built")
    assert evm.build_within({**w, "action": "voucher"}, H_OTHER) == Refusal("mpp/id-not-ours")


# ── the seller's own within challenge on a held Tempo channel.


def own(channel_id: str | None = None, legal_context: str | None = None) -> dict[str, Any]:
    request = json.loads(TF["requestV2"])
    if channel_id is not None:
        request["methodDetails"]["channelId"] = channel_id
    c = {
        "realm": MC["realm"],
        "method": "tempo",
        "intent": "session",
        "request": base64.urlsafe_b64encode(json.dumps(request).encode("utf-8")).decode("ascii").rstrip("="),
        "expires": MC["expires"],
        "id": "sellerOwnChallengeId-0123456789abcdef",
    }
    if legal_context is not None:
        opaque = json.dumps({"legalContext": f"lcp:sha256:{legal_context}", "legalContextUrl": LINK}).encode("utf-8")
        c["opaque"] = base64.urlsafe_b64encode(opaque).decode("ascii").rstrip("=")
    return c


def tempo_hold() -> dict[str, Any]:
    opened = tempo_opened()
    assert opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, MPP_SESSION_TEMPO)
    assert not isinstance(hold, Declined), hold
    return hold


def wallet() -> Recording:
    return Recording(f"eip155:42431:{TF['payer']}", lambda r: [sign_typed(q["typedData"]) for q in r["requests"]])


CHANNEL = TEMPO["TS3"]["expectChannelId"]


@pytest.mark.parametrize(
    ("channel_id", "legal_context"),
    [(CHANNEL, None), (CHANNEL, H), (None, None)],
    ids=["the held channelId and no legal context", "the held channelId and a legal context naming the held H", "no channelId and no legal context"],
)
def test_the_sellers_own_challenge_is_paid_with_one_voucher_request(channel_id: str | None, legal_context: str | None) -> None:
    hold = tempo_hold()
    challenge = own(channel_id, legal_context)
    signer = wallet()
    out = asyncio.run(within([challenge], hold, MPP_SESSION_TEMPO, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]
    assert out.signed["challenge"] == challenge
    assert (out.signed["payload"]["action"], out.signed["payload"]["channelId"].lower()) == ("voucher", CHANNEL)


def test_the_sellers_own_challenge_naming_another_channel_declines_before_any_signer_call() -> None:
    hold = tempo_hold()
    signer = wallet()
    out = asyncio.run(within([own("0x" + "22" * 32)], hold, MPP_SESSION_TEMPO, signer))
    assert out == Declined("no-payable-option", "The challenge names a channel this hold did not open.")
    assert signer.requests == []


def test_the_sellers_own_challenge_naming_another_hash_declines_before_any_signer_call() -> None:
    hold = tempo_hold()
    signer = wallet()
    for c in (own(CHANNEL, H_OTHER), own(None, H_OTHER)):
        out = asyncio.run(within([c], hold, MPP_SESSION_TEMPO, signer))
        assert isinstance(out, Declined) and out.code == "hash-mismatch"
    assert signer.requests == []


# ── the held Hedera session pays the seller's own within challenge (its own id, no legal context).


def test_a_held_hedera_session_pays_the_sellers_own_challenge() -> None:
    opened = hedera_opened()
    assert opened.signed is not None, opened
    hold = open_channel(opened.atr_bytes, opened.signed, MPP_SESSION_HEDERA, opened.landed)
    assert not isinstance(hold, Declined), hold
    challenge = {k: v for k, v in HS["SS1"]["hedera"]["challenge"].items() if k != "opaque"}
    challenge["id"] = "sellerOwnChallengeId-0123456789abcdef"
    signer = Recording(hold["network"], lambda r: [sign_typed(q["typedData"]) for q in r["requests"]])
    out = asyncio.run(within([challenge], hold, MPP_SESSION_HEDERA, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]
    assert (out.signed["payload"]["action"], out.signed["payload"]["channelId"]) == ("voucher", HS["HS1"]["expectChannelId"])
