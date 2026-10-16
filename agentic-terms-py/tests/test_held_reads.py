"""The read for a payment, a landed receipt or the landed wire, envelope or blob, is taken only from what is held in
Held, as @integraledger/lcp holds it under the payment's own FETCHED member: an attribute no JSON decode makes, never
from a member of the payment's own. For each rail the buyer half reads such a read on: the read held in Held gives H;
the payment as sent, the same read as a member of the payment's own under the rail's member and under the names
fetched, tables and landed, and a JSON round trip or a dict() of the held payment give the rail's read-first code; and
held with another read as a member of its own, the held read alone is read. Each
payment, read and code is its vector file's: the B6 rows and push sections of the mpp-charge-*.json files, their
refusals rows that carry such a member, and the session file's agreedRefusals row that carries a landed member, each
selected by its members."""

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from integraledger_terms import (
    MPP_CHARGE_HEDERA,
    MPP_CHARGE_SOLANA,
    MPP_CHARGE_STELLAR,
    MPP_CHARGE_TEMPO_PUSH,
    MPP_CHARGE_XRPL,
    MPP_SESSION_HEDERA,
    Checked,
    Declined,
    Refusal,
    check,
    open_channel,
)
from integraledger_terms.bindings._codec import js_json
from integraledger_terms.bindings._mpp import Held

from breadth import ABC, H, LINK
from mpp_docs import issued, placed_doc
from support import load

TP = load("mpp-charge-tempo-push.json")
HC = load("mpp-charge-hedera.json")
HS = load("mpp-session-hedera-solana-xrpl.json")
SC = load("mpp-charge-solana.json")
ST = load("mpp-charge-stellar.json")
XC = load("mpp-charge-xrpl.json")

Own = Callable[[dict[str, Any], Any], dict[str, Any]]


def landed(c: dict[str, Any], read: Any) -> dict[str, Any]:
    """The payment with the read as its own landed member."""
    return {**c, "landed": read}


def carrying(member: str) -> Own:
    """The payment with the read's member as a member of its own payload."""
    return lambda c, read: {**c, "payload": {**c["payload"], member: read[member]}}


def one(rows: list[dict[str, Any]], what: str) -> dict[str, Any]:
    assert len(rows) == 1, (what, [r.get("case") for r in rows])
    return rows[0]


def without(payload: dict[str, Any], member: str) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != member}


@dataclass(frozen=True)
class Rail:
    binding: Any
    # The payment as the buyer sends it, and the read that binds H, held in Held.
    sent: dict[str, Any]
    read: Any
    # Another read, which binds no H.
    other: Any
    own: Own
    read_first: str


def tempo_push() -> Rail:
    row = one([r for r in TP["buyer"]["rows"] if r["pairing"] == "mpp/charge/tempo/push" and "fetched" in r["input"]], "B6")
    read = row["input"]["fetched"]
    return Rail(MPP_CHARGE_TEMPO_PUSH, row["input"]["presented"], read, {**read, "logs": []}, landed, "tempo/read-first")


def hedera_charge() -> Rail:
    challenge = issued("hedera", "charge", js_json(HC["fixed"]["request"]), realm=HC["fixed"]["realm"], expires=HC["fixed"]["expires"])
    sent = {"challenge": placed_doc(challenge, H, LINK)[0], "payload": {"type": "hash", "transactionId": HC["push"]["transactionId"]}}
    read = HC["fetchPresented"]["expectLanded"]
    other = {"network": HC["fetchPresented"]["reader"], "memo": "not an attribution memo"}
    return Rail(MPP_CHARGE_HEDERA, sent, read, other, landed, HC["push"]["expectWithout"])


def hedera_session() -> Rail:
    row = one([r for r in HS["agreedRefusals"]["rows"] if "landed" in r], "agreedRefusals rows carrying landed")
    assert row["opening"] == "HS3"
    payload = {"action": "open", "channelId": HS["HS1"]["expectChannelId"], "txHash": HS["HS3"]["txHash"], "cumulativeAmount": "0", "signature": "0x00"}
    sent = {"challenge": HS["SS1"]["hedera"]["placed"], "payload": payload}
    read = row["landed"]
    return Rail(MPP_SESSION_HEDERA, sent, read, {**read, "logs": []}, landed, row["expect"])


def solana_charge() -> Rail:
    row = one(
        [r for r in SC["refusals"] if r.get("payload", {}).get("type") == "signature" and "transaction" in r["payload"]],
        "refusals carrying a signature credential's transaction",
    )
    read = {"transaction": row["payload"]["transaction"]}
    assert read["transaction"] == SC["push"]["landedWireBase64"]
    sent = {"challenge": SC["place"]["expect"], "payload": without(row["payload"], "transaction")}
    other = {"transaction": SC["plant"]["wireBase64"]}
    return Rail(MPP_CHARGE_SOLANA, sent, read, other, carrying("transaction"), row["expect"])


def stellar_charge() -> Rail:
    row = one(
        [r for r in ST["refusals"] if r.get("payload", {}).get("type") == "hash" and "transaction" in r["payload"]],
        "refusals carrying a hash credential's transaction",
    )
    read = {"transaction": row["payload"]["transaction"]}
    assert read["transaction"] == ST["V3"]["envelope"]
    sent = {"challenge": ST[row["challenge"]]["challenge"], "payload": without(row["payload"], "transaction")}
    other = {"transaction": ST["plant"]["envelope"]}
    return Rail(MPP_CHARGE_STELLAR, sent, read, other, carrying("transaction"), row["expect"])


def xrpl_charge() -> Rail:
    row = one(
        [r for r in XC["refusals"] if r.get("payload", {}).get("type") == "hash" and "blob" in r["payload"]],
        "refusals carrying a hash credential's blob",
    )
    read = {"blob": row["payload"]["blob"]}
    assert read["blob"] == XC["V3"]["blob"]
    sent = {"challenge": XC["place"]["expect"], "payload": without(row["payload"], "blob")}
    return Rail(MPP_CHARGE_XRPL, sent, read, {"blob": XC["plant"]["blob"]}, carrying("blob"), row["expect"])


RAILS = [tempo_push, hedera_charge, hedera_session, solana_charge, stellar_charge, xrpl_charge]


@pytest.mark.parametrize("rail_of", RAILS, ids=[f.__name__ for f in RAILS])
def test_a_read_is_taken_only_from_what_is_held_beside_the_payment(rail_of: Callable[[], Rail]) -> None:
    rail = rail_of()
    bound = rail.binding.bound
    read_first = Refusal(rail.read_first)
    held = Held(rail.sent, rail.read)
    assert bound(held) == H
    assert bound(rail.sent) == read_first
    assert bound(rail.own(rail.sent, rail.read)) == read_first
    for name in ("fetched", "tables", "landed"):
        assert bound({**rail.sent, name: rail.read}) == read_first, name
    other = bound(Held(rail.sent, rail.other))
    assert other != H, other
    assert bound(Held(rail.own(rail.sent, rail.other), rail.read)) == H
    assert bound(Held(rail.own(rail.sent, rail.read), rail.other)) == other
    for copied in (json.loads(json.dumps(held)), dict(held), {**held}):
        assert bound(copied) == read_first
    assert bound(copy.copy(held)) == H


def test_check_takes_the_landed_receipt_beside_the_payment() -> None:
    """check reads a payment with the landed receipt given beside it, never one written into the payment, and
    declines a landed receipt that is not a JSON object beside a payment that is one."""
    rail = tempo_push()
    binding = rail.binding
    assert check(ABC, rail.sent, binding, rail.read) == Checked(h=H)
    for out in (check(ABC, rail.sent, binding), check(ABC, landed(rail.sent, rail.read), binding)):
        assert isinstance(out, Declined) and out.code == "signed-not-bound", out
    for read, sent in (("landed", rail.sent), (rail.read, "payment")):
        out = check(ABC, sent, binding, read)
        assert out == Declined("signed-not-bound", "The landed receipt is not a JSON object beside the payment."), out


def test_a_held_hedera_session_keeps_the_landed_receipt_beside_its_opening() -> None:
    """open_channel holds the session opening with the landed receipt given beside it, and keeps the opening as
    signed and the receipt as the hold's own landed member; an opening that carries the receipt as a member of its
    own, given no receipt beside it, is not held."""
    rail = hedera_session()
    hold = open_channel(ABC, rail.sent, rail.binding, rail.read)
    assert isinstance(hold, dict), hold
    assert (hold["opening"], hold["landed"]) == (rail.sent, rail.read)
    out = open_channel(ABC, landed(rail.sent, rail.read), rail.binding)
    assert isinstance(out, Declined) and out.code == "signed-not-bound", out
