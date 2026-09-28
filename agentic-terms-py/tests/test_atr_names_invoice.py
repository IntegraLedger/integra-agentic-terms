"""x402-exact-lnbtc-invoice-named.json's atrNamesInvoice rows: ATR bytes written by hand, and whether they name L6's
invoice (N) and plant2's (N2). The ATR names an invoice only when its first members are atrVersion, id and x402 and no
member name repeats (RFC 8259 section 4 leaves repeated names to each reader), and bytes that begin with a byte-order
mark are not one JSON object (RFC 8259 section 8.1). Each row's members are the member names in the order written, as
the row gives them."""

from typing import Any

import pytest
from support import load

from integraledger_terms.bindings._jose import member_names
from integraledger_terms.bindings.lightning import atr_names_invoice

V = load("x402-exact-lnbtc-invoice-named.json")
INVOICES = {"N": V["L6"]["invoice"], "N2": V["plant2"]["invoice"]}
ROWS = V["atrNamesInvoice"]["rows"]


@pytest.mark.parametrize("row", ROWS, ids=[r["case"] for r in ROWS])
def test_atr_names_invoice(row: dict[str, Any]) -> None:
    atr = bytes.fromhex(row["atrHex"])
    got = {name: atr_names_invoice(atr, INVOICES[name]) for name in row["expect"]}
    assert got == row["expect"]
    if row["members"] is not None:
        assert member_names(atr.decode("utf-8")) == row["members"]


def test_the_rows_hold_a_repeated_x402_and_a_byte_order_mark() -> None:
    assert any(r["members"] == ["atrVersion", "id", "x402", "x402"] for r in ROWS)
    assert any(r["members"] is None and r["atrHex"].startswith("efbbbf") for r in ROWS)
