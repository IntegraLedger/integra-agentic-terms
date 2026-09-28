"""mpp-session-hedera-solana-xrpl.json's SS1refusals: each row is SS1's challenge as issued for its method, with the
row's request written as compact JSON with sorted members in base64url without padding (RFC 4648 section 5), and
without expires where the row says so. pairings_of refuses each with the row's code. The XRPL rows are the session
amount: a u64 of drops in decimal, with no sign, point or leading zero."""

import base64
import json
from typing import Any

import pytest
from support import load

from integraledger_terms import Refusal
from integraledger_terms.bindings._mpp import pairings_of

V = load("mpp-session-hedera-solana-xrpl.json")


def b64u(value: Any) -> str:
    text = json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)
    return base64.urlsafe_b64encode(text.encode()).rstrip(b"=").decode()


@pytest.mark.parametrize("row", V["SS1refusals"], ids=[r["case"] for r in V["SS1refusals"]])
def test_ss1_refusals(row: dict[str, Any]) -> None:
    c = {**V["SS1"][row["method"]]["challenge"], "request": b64u(row["request"])}
    if row.get("noExpires"):
        del c["expires"]
    assert pairings_of(c) == Refusal(row["expect"])


def test_the_file_holds_the_xrpl_amount_rows() -> None:
    xrpl = [r["request"].get("amount") for r in V["SS1refusals"] if r["method"] == "xrpl"]
    assert None in xrpl and 100 in xrpl and "18446744073709551616" in xrpl
