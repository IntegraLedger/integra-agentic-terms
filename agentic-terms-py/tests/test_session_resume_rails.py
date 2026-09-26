"""session_resume on the Hedera, Solana and XRPL sessions, and within on a held Hedera, Solana and XRPL session
paying the seller's own challenge naming the held channel with one voucher, and declining one naming another channel
before any signer call. Where each session draft names the channel in the challenge: Hedera's
methodDetails.channelId, "Channel ID if resuming" (draft-hedera-session-00), a bytes32 in hex, none on a new channel;
Solana's methodDetails.channelId, "Existing channel identifier to resume" (draft-solana-session-00), the base58
channel address; XRPL's request channelId, "64-hex channel ID, or "" on an open" (draft-xrpl-session-00), empty "when
the server names no channel", "two spellings of one channel are one channel". The openings, channels and challenges
are the vector file's SS1, HS1-HS3, SV2, SV3, XS1, XS2 and plants; the Solana signer is the seed of 32 bytes 0x01,
the SV2 opening's signer. The TypeScript gate's tests are session-resume-rails.test.ts."""

import asyncio
import base64
import json
from collections.abc import Callable
from typing import Any

from integraledger_terms import (
    MPP_SESSION_HEDERA,
    MPP_SESSION_SOLANA,
    MPP_SESSION_XRPL,
    Declined,
    Within,
    _gate,
    open_channel,
    transact,
    within,
)
from integraledger_terms.bindings._channel import ChannelRef
from integraledger_terms.bindings.mpp_session import session_resume
from integraledger_terms._types import Refusal

import pytest

import ed25519
from breadth import ABC, H, LINK, Recording, offered, run
from mpp_docs import placed_doc
from support import hexb, load, serving, sign_typed

HS = load("mpp-session-hedera-solana-xrpl.json")
OWN_ID = "sellerOwnChallengeId-0123456789abcdef"


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: load("mpp-session-tempo.json")["fixed"]["now"])


def edited(issued: dict[str, Any], edit: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    text = issued["request"]
    request = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))
    edit(request)
    out = {k: v for k, v in issued.items() if k != "opaque"}
    out["request"] = base64.urlsafe_b64encode(json.dumps(request).encode("utf-8")).decode("ascii").rstrip("=")
    out["id"] = OWN_ID
    return out


def hedera_named(channel: object) -> dict[str, Any]:
    def edit(r: dict[str, Any]) -> None:
        r["methodDetails"]["channelId"] = channel
        r.pop("suggestedDeposit", None)

    return edited(HS["SS1"]["hedera"]["challenge"], edit)


def solana_named(channel: object) -> dict[str, Any]:
    def edit(r: dict[str, Any]) -> None:
        r["methodDetails"]["channelId"] = channel
        r["methodDetails"].pop("recentBlockhash")
        r["methodDetails"].pop("recentSlot")

    return edited(HS["SS1"]["solana"]["challenge"], edit)


def xrpl_named(channel: object) -> dict[str, Any]:
    def edit(r: dict[str, Any]) -> None:
        r["channelId"] = channel

    return edited(HS["SS1"]["xrpl"]["challenge"], edit)


# ── the read.


def test_hedera_names_the_channel_as_its_ref_spells_it_in_either_case_of_hex() -> None:
    ref = ChannelRef(HS["HS3"]["expectRef"]["network"], HS["HS3"]["expectRef"]["channel"])
    assert session_resume(hedera_named(HS["HS1"]["expectChannelId"])) == ref
    assert session_resume(hedera_named("0x" + HS["HS1"]["expectChannelId"][2:].upper())) == ref
    assert session_resume(HS["SS1"]["hedera"]["challenge"]) is None
    assert session_resume(hedera_named("0x1234")) == Refusal("mpp/request-malformed")


def test_solana_names_the_channel_as_its_ref_spells_it() -> None:
    ref = ChannelRef(HS["SV2"]["expectReference"]["network"], HS["SV2"]["channel"])
    assert session_resume(solana_named(HS["SV2"]["channel"])) == ref
    assert session_resume(HS["SS1"]["solana"]["challenge"]) is None
    assert session_resume(solana_named("0OIl")) == Refusal("mpp/request-malformed")


def test_xrpl_names_the_channel_in_the_request_in_upper_case_and_empty_names_none() -> None:
    ref = ChannelRef("xrpl:1", HS["XS2"]["expectChannel"])
    assert session_resume(xrpl_named(HS["XS2"]["expectChannel"])) == ref
    assert session_resume(xrpl_named(HS["XS2"]["expectChannel"].lower())) == ref
    assert session_resume(HS["SS1"]["xrpl"]["challenge"]) is None
    assert session_resume(xrpl_named("")) is None
    assert session_resume(xrpl_named("0x" + HS["XS2"]["expectChannel"])) == Refusal("mpp/request-malformed")


# ── within on a held Hedera session.


def hedera_hold() -> dict[str, Any]:
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
    assert out.signed is not None, out
    hold = open_channel(out.atr_bytes, out.signed, MPP_SESSION_HEDERA, out.landed)
    assert not isinstance(hold, Declined), hold
    return hold


def wallet(hold: dict[str, Any]) -> Recording:
    return Recording(hold["network"], lambda r: [sign_typed(q["typedData"]) for q in r["requests"]])


def test_a_held_hedera_session_pays_the_sellers_own_challenge_naming_the_held_channel() -> None:
    hold = hedera_hold()
    challenge = hedera_named(HS["HS1"]["expectChannelId"])
    signer = wallet(hold)
    out = asyncio.run(within([challenge], hold, MPP_SESSION_HEDERA, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]
    assert out.signed["challenge"] == challenge
    assert (out.signed["payload"]["action"], out.signed["payload"]["channelId"]) == ("voucher", HS["HS1"]["expectChannelId"])


def test_a_held_hedera_session_declines_the_sellers_own_challenge_naming_another_channel_before_any_signer_call() -> None:
    hold = hedera_hold()
    signer = wallet(hold)
    out = asyncio.run(within([hedera_named("0x" + "22" * 32)], hold, MPP_SESSION_HEDERA, signer))
    assert out == Declined("no-payable-option", "The challenge names a channel this hold did not open.")
    assert signer.requests == []


# ── within on a held Solana session.

SOLANA_SEED = bytes([1]) * 32
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def solana_hold() -> dict[str, Any]:
    opening = {
        "challenge": HS["SS1"]["solana"]["placed"],
        "payload": {"action": "open", "channelId": HS["SV2"]["channel"], "transaction": HS["SV2"]["wireBase64"]},
    }
    hold = open_channel(ABC, opening, MPP_SESSION_SOLANA)
    assert not isinstance(hold, Declined), hold
    return hold


def solana_wallet() -> Recording:
    return Recording(
        f"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:{HS['SV3']['payer']}",
        lambda r: [base58(ed25519.sign(SOLANA_SEED, hexb(q["message"]))) for q in r["requests"]],
    )


def test_a_held_solana_session_pays_the_sellers_own_challenge_naming_the_held_channel() -> None:
    hold = solana_hold()
    challenge = solana_named(HS["SV2"]["channel"])
    signer = solana_wallet()
    out = asyncio.run(within([challenge], hold, MPP_SESSION_SOLANA, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]
    assert out.signed["challenge"] == challenge
    assert (out.signed["payload"]["action"], out.signed["payload"]["channelId"]) == ("voucher", HS["SV2"]["channel"])


def test_a_held_solana_session_declines_the_sellers_own_challenge_naming_another_channel_before_any_signer_call() -> None:
    hold = solana_hold()
    signer = solana_wallet()
    out = asyncio.run(within([solana_named(HS["plants"]["solana"]["channel"])], hold, MPP_SESSION_SOLANA, signer))
    assert out == Declined("no-payable-option", "The challenge names a channel this hold did not open.")
    assert signer.requests == []


# ── within on a held XRPL session.


def xrpl_hold() -> dict[str, Any]:
    opening = {
        "challenge": HS["SS1"]["xrpl"]["placed"],
        "payload": {"action": "open", "transaction": HS["XS2"]["blob"], "amount": "100", "signature": "00"},
    }
    hold = open_channel(ABC, opening, MPP_SESSION_XRPL)
    assert not isinstance(hold, Declined), hold
    return hold


def xrpl_wallet() -> Recording:
    return Recording(f"xrpl:1:{HS['XS2']['account']}", lambda r: ["C0" * 64 for _ in r["requests"]])


@pytest.mark.parametrize(
    "channel",
    [HS["XS2"]["expectChannel"], HS["XS2"]["expectChannel"].lower()],
    ids=["in upper case", "in lower case"],
)
def test_a_held_xrpl_session_pays_the_sellers_own_challenge_naming_the_held_channel(channel: str) -> None:
    hold = xrpl_hold()
    challenge = xrpl_named(channel)
    signer = xrpl_wallet()
    out = asyncio.run(within([challenge], hold, MPP_SESSION_XRPL, signer))
    assert isinstance(out, Within), out
    assert [r["kind"] for r in signer.requests] == ["batch"]
    assert out.signed["challenge"] == challenge
    assert (out.signed["payload"]["action"], out.signed["payload"]["channelId"]) == ("voucher", HS["XS2"]["expectChannel"])


def test_a_held_xrpl_session_declines_the_sellers_own_challenge_naming_another_channel_before_any_signer_call() -> None:
    hold = xrpl_hold()
    signer = xrpl_wallet()
    out = asyncio.run(within([xrpl_named(HS["XS1"]["expect"])], hold, MPP_SESSION_XRPL, signer))
    assert out == Declined("no-payable-option", "The challenge names a channel this hold did not open.")
    assert signer.requests == []
