"""session_resume on the XRPL session, and within on a held XRPL session paying the seller's own challenge naming the
held channel with one voucher, and declining one naming another channel before any signer call. Where the session
draft names the channel in the challenge: XRPL's request channelId, "64-hex channel ID, or "" on an open"
(draft-xrpl-session-00), empty "when the server names no channel", "two spellings of one channel are one channel". The
openings, channels and challenges are the vector file's SS1, XS1 and XS2. The TypeScript gate's tests are
session-resume-rails.test.ts."""

import asyncio
import base64
import json
from collections.abc import Callable
from typing import Any

from integraledger_terms import (
    MPP_SESSION_XRPL,
    Declined,
    Within,
    _gate,
    open_channel,
    within,
)
from integraledger_terms.bindings._channel import ChannelRef
from integraledger_terms.bindings.mpp_session import session_resume
from integraledger_terms._types import Refusal

import pytest

from breadth import ABC, Recording
from support import load

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


def xrpl_named(channel: object) -> dict[str, Any]:
    def edit(r: dict[str, Any]) -> None:
        r["channelId"] = channel

    return edited(HS["SS1"]["xrpl"]["challenge"], edit)


# ── the read.


def test_xrpl_names_the_channel_in_the_request_in_upper_case_and_empty_names_none() -> None:
    ref = ChannelRef("xrpl:1", HS["XS2"]["expectChannel"])
    assert session_resume(xrpl_named(HS["XS2"]["expectChannel"])) == ref
    assert session_resume(xrpl_named(HS["XS2"]["expectChannel"].lower())) == ref
    assert session_resume(HS["SS1"]["xrpl"]["challenge"]) is None
    assert session_resume(xrpl_named("")) is None
    assert session_resume(xrpl_named("0x" + HS["XS2"]["expectChannel"])) == Refusal("mpp/request-malformed")


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
