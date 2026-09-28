"""card.json's C9 rows: TAP requests with two agent-payer-auth signatures. A verifier chooses which signature to process
by its own policy and configuration (RFC 9421 section 3.2, step 1.1), so bound takes the hash only when every
agent-payer-auth signature lists lcp-hash without parameters; otherwise it is card/tap-hash-not-covered."""

from typing import Any

import pytest
from support import load

from integraledger_terms import CARD_VISA_TAP, Refusal

ROWS = load("card.json")["C9"]["rows"]


def expected(row: dict[str, Any]) -> Any:
    e = row["expect"]
    return Refusal(e["code"]) if isinstance(e, dict) else e


@pytest.mark.parametrize("row", ROWS, ids=[r["case"] for r in ROWS])
def test_every_payer_signature_covers_the_hash(row: dict[str, Any]) -> None:
    presented = {k: row[k] for k in ("signatureInput", "signature", "lcpHash")}
    assert CARD_VISA_TAP.bound(presented) == expected(row)
