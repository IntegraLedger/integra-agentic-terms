"""The Python gate holds the Hedera session it opened: transact returns the opening's landed receipt beside the
payment in a JSON-safe form, integers as decimal strings as lcp's vectors write landed.blockNumber, and open_channel
takes it, so bound reads the escrow log that carries the channel's salt. The opening, the log and the channel id are
the vector file's HS1 to HS3; the signer is the published Anvil key #0, the vectors' payer.

The hold keeps the read made for a channel's opening as its own landed member, beside the opening as signed: the
landed given, else the read the opening holds in Held, as @integraledger/lcp holds it under the payment's own FETCHED
member: an attribute no JSON decode makes. within holds that read in Held with the opening, as bound and build_within
read it. A member of the opening's own, landed, tables or any other, is never read as the read: an opening carrying
one gives the answer the same opening without it gives. The Solana openings, tables and signer are the vector file's
SV6 row that names a signer, whose opening names its voucher signer (account 4) through an address lookup table, with
the tables a reader gives for it, and SV2. The TypeScript gate's test is the same."""

import asyncio
import json
from typing import Any

import pytest

from integraledger_terms import (
    MPP_SESSION_HEDERA,
    MPP_SESSION_SOLANA,
    Declined,
    Transacted,
    Within,
    _gate,
    open_channel,
    transact,
    within,
)
from integraledger_terms.bindings._mpp import Held

from breadth import ABC, H, LINK, Recording, offered, run
from mpp_docs import placed_doc
from support import load, serving, sign_typed
from test_session_resume_rails import hedera_named, solana_named, wallet
from test_sol_lookup_tables import TABLE_ROWS, at, presented_of

HS = load("mpp-session-hedera-solana-xrpl.json")
DOC = placed_doc(HS["SS1"]["hedera"]["challenge"], H, LINK)
ACCOUNT = f"hedera:testnet:{HS['fixed']['payer']}"
INPUTS = {"deposit": HS["HS2"]["deposit"]}
BLOCK = "47312717"


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: 1_790_000_000)


def opened() -> Transacted:
    signer = Recording(
        ACCOUNT,
        lambda r: {
            "openTx": HS["HS3"]["txHash"],
            "signature": sign_typed(r["voucher"]),
            "landed": {"transaction": HS["HS3"]["txHash"], "blockNumber": BLOCK, "logs": [HS["HS3"]["log"]]},
        },
    )
    out = run(lambda c: transact(DOC, offered(MPP_SESSION_HEDERA), signer, c, inputs=INPUTS), serving(ABC))
    assert isinstance(out, Transacted), out
    return out


def test_transact_returns_landed_as_json_its_block_number_a_decimal_string() -> None:
    out = opened()
    assert out.landed == {"transaction": HS["HS3"]["txHash"], "blockNumber": BLOCK, "logs": [HS["HS3"]["log"]]}
    assert json.loads(json.dumps(out.landed)) == out.landed


def test_open_channel_with_transacts_landed_holds_the_session() -> None:
    out = opened()
    assert out.signed is not None, out
    hold: Any = open_channel(out.atr_bytes, out.signed, MPP_SESSION_HEDERA, out.landed)
    assert not isinstance(hold, Declined), hold
    assert (hold["pairing"], hold["channel"], hold["h"]) == ("mpp/session/hedera", HS["HS1"]["expectChannelId"], H)
    assert json.loads(json.dumps(hold)) == hold


def test_without_the_landed_receipt_the_opening_cannot_be_held() -> None:
    out = opened()
    assert out.signed is not None, out
    hold = open_channel(out.atr_bytes, out.signed, MPP_SESSION_HEDERA)
    assert isinstance(hold, Declined)
    assert (hold.code, hold.detail) == (
        "signed-not-bound",
        "The pairing does not read the hash of the compared bytes from the opening.",
    )


# ── the read made for an opening is the hold's own landed member.

SESSION_NOW = load("mpp-session-tempo.json")["fixed"]["now"]
HEDERA_OPENING: dict[str, Any] = {
    "challenge": HS["SS1"]["hedera"]["placed"],
    "payload": {
        "action": "open",
        "channelId": HS["HS1"]["expectChannelId"],
        "txHash": HS["HS3"]["txHash"],
        "cumulativeAmount": "0",
        "signature": "0x00",
    },
}
HEDERA_LANDED = {"transaction": HS["HS3"]["txHash"], "blockNumber": BLOCK, "logs": [HS["HS3"]["log"]]}


def hedera_paid(hold: Any) -> Any:
    """The voucher within signs on the hold, at the session file's clock, or the decline."""
    if isinstance(hold, Declined):
        return hold
    out = asyncio.run(within([hedera_named(HS["HS1"]["expectChannelId"])], hold, MPP_SESSION_HEDERA, wallet(hold)))
    return out.signed if isinstance(out, Within) else out


def test_a_hedera_opening_holding_its_receipt_in_held_given_no_landed_is_held_with_it_and_paid_as_with_landed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: SESSION_NOW)
    voucher = hedera_paid(open_channel(ABC, HEDERA_OPENING, MPP_SESSION_HEDERA, HEDERA_LANDED))
    assert (voucher["payload"]["action"], voucher["payload"]["channelId"]) == ("voucher", HS["HS1"]["expectChannelId"])
    hold = open_channel(ABC, Held(HEDERA_OPENING, HEDERA_LANDED), MPP_SESSION_HEDERA)
    assert isinstance(hold, dict), hold
    assert hedera_paid(hold) == voucher
    assert hedera_paid(json.loads(json.dumps(hold))) == voucher
    assert (hold["opening"], hold["landed"]) == (HEDERA_OPENING, HEDERA_LANDED)


def test_a_landed_member_of_a_hedera_openings_own_is_never_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: SESSION_NOW)
    voucher = hedera_paid(open_channel(ABC, HEDERA_OPENING, MPP_SESSION_HEDERA, HEDERA_LANDED))
    carrying = {**HEDERA_OPENING, "landed": {**HEDERA_LANDED, "logs": []}}
    bare = open_channel(ABC, carrying, MPP_SESSION_HEDERA)
    assert isinstance(bare, Declined) and bare.code == "signed-not-bound", bare
    hold = open_channel(ABC, Held(carrying, HEDERA_LANDED), MPP_SESSION_HEDERA)
    assert isinstance(hold, dict), hold
    assert hedera_paid(hold) == voucher
    assert (hold["opening"], hold["landed"]) == (carrying, HEDERA_LANDED)


SIGNER_ROWS = [r for r in HS["SV6"]["rows"] if "signer" in r]
SV6_ROW = SIGNER_ROWS[0]
SV6_CHANNEL: str = at(SV6_ROW["opening"])["channel"]
# SS1's placed Solana challenge, which the row answers as C_S, with its client voucher signer.
SV6_OPENING = presented_of(SV6_ROW["opening"], "C_S")
TABLES = {"tables": SV6_ROW["expect"]["tables"]}
# The same tables naming another key at each read-only index: the channel of the other table row, which names its
# channel elsewhere.
ANOTHER: str = [r["channel"] for r in TABLE_ROWS if r["channel"] != SV6_CHANNEL][0]
FORGED = {"tables": [{**t, "readonly": [ANOTHER] * len(t["readonly"])} for t in SV6_ROW["expect"]["tables"]]}


def solana_signers(hold: Any, channel: str = SV6_CHANNEL) -> Any:
    """The keys within asks the signer to sign for, a voucher and a close, or the opening's decline code."""
    if isinstance(hold, Declined):
        return hold.code
    out: list[Any] = []
    refunds: tuple[dict[str, Any] | None, ...] = (None, {})
    for refund in refunds:
        signer = Recording(
            f"solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:{HS['SV3']['payer']}", lambda r: ["1" * 64 for _ in r["requests"]]
        )
        w = asyncio.run(within([solana_named(channel)], hold, MPP_SESSION_SOLANA, signer, refund))
        out.append(w.code if isinstance(w, Declined) else [q["signer"] for r in signer.requests for q in r["requests"]])
    return out


def test_the_sv6_row_names_one_signer_read_through_the_tables_a_reader_gives() -> None:
    assert len(SIGNER_ROWS) == 1, [r["case"] for r in SIGNER_ROWS]
    assert "C_S" in SV6_ROW["challenges"]
    assert ANOTHER != SV6_ROW["signer"]


def test_tables_given_as_landed_or_held_with_no_landed_are_the_holds_landed_and_within_signs_for_their_signer() -> None:
    given = open_channel(ABC, SV6_OPENING, MPP_SESSION_SOLANA, TABLES)
    fetched = open_channel(ABC, Held(SV6_OPENING, TABLES), MPP_SESSION_SOLANA)
    for hold in (given, fetched):
        assert isinstance(hold, dict), hold
        assert solana_signers(hold) == [[SV6_ROW["signer"]]] * 2
        assert solana_signers(json.loads(json.dumps(hold))) == [[SV6_ROW["signer"]]] * 2
        assert (hold["opening"], hold["landed"]) == (SV6_OPENING, TABLES)


def test_held_tables_alone_are_read_beside_other_tables_as_the_openings_own_landed_or_tables_member() -> None:
    for member, value in (("landed", FORGED), ("tables", FORGED["tables"])):
        carrying = {**SV6_OPENING, member: value}
        hold = open_channel(ABC, Held(carrying, TABLES), MPP_SESSION_SOLANA)
        assert isinstance(hold, dict), (member, hold)
        assert solana_signers(hold) == [[SV6_ROW["signer"]]] * 2, member
        assert (hold["opening"], hold["landed"]) == (carrying, TABLES)


def test_tables_as_the_openings_own_landed_or_tables_member_with_no_read_are_declined_at_the_opening() -> None:
    for carrying in ({**SV6_OPENING, "landed": TABLES}, {**SV6_OPENING, "tables": TABLES["tables"]}, SV6_OPENING):
        hold = open_channel(ABC, carrying, MPP_SESSION_SOLANA)
        assert isinstance(hold, Declined) and hold.code == "signed-not-bound", hold


def test_an_opening_without_lookups_carrying_a_landed_member_is_held_with_no_landed_and_paid_as_without_it() -> None:
    sv2 = {
        "challenge": HS["SS1"]["solana"]["placed"],
        "payload": {"action": "open", "channelId": HS["SV2"]["channel"], "transaction": HS["SV2"]["wireBase64"]},
    }
    carrying = {**sv2, "landed": FORGED}
    hold = open_channel(ABC, carrying, MPP_SESSION_SOLANA)
    assert isinstance(hold, dict), hold
    assert "landed" not in hold
    assert hold["opening"] == carrying
    plain = solana_signers(open_channel(ABC, sv2, MPP_SESSION_SOLANA), HS["SV2"]["channel"])
    assert solana_signers(hold, HS["SV2"]["channel"]) == plain
