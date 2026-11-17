"""card.json's C9 rows: TAP requests with two agent-payer-auth signatures. A verifier chooses which signature to process
by its own policy and configuration (RFC 9421 section 3.2, step 1.1), so bound takes the hash only when every
agent-payer-auth signature carries it, and the same one."""

from typing import Any

import pytest
from support import load

from integraledger_terms import CARD_VISA_TAP, Refusal

ROWS = load("card.json")["C9"]["rows"]


def expected(row: dict[str, Any]) -> Any:
    """The row's hash, or its refusal code as a Refusal."""
    e: str = row["expect"]
    return Refusal(e) if e.startswith("card/") else e


@pytest.mark.parametrize("row", ROWS, ids=[r["case"] for r in ROWS])
def test_every_payer_signature_covers_the_hash(row: dict[str, Any]) -> None:
    presented = {k: row[k] for k in ("signatureInput", "signature")}
    assert CARD_VISA_TAP.bound(presented) == expected(row)
