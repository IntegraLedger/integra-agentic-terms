"""The Python gate holds the Hedera session it opened: transact returns the opening's landed receipt beside the
payment in a JSON-safe form, integers as decimal strings as lcp's vectors write landed.blockNumber, and open_channel
takes it, so bound reads the escrow log that carries the channel's salt. The opening, the log and the channel id are
the vector file's HS1 to HS3; the signer is the published Anvil key #0, the vectors' payer. The TypeScript gate's test
is the same."""

import json
from typing import Any

import pytest

from integraledger_terms import MPP_SESSION_HEDERA, Declined, Transacted, _gate, open_channel, transact

from breadth import ABC, H, LINK, Recording, offered, run
from mpp_docs import placed_doc
from support import load, serving, sign_typed

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
    assert (hold.code, hold.detail) == ("signed-not-bound", "The opening does not carry the hash of these bytes.")
