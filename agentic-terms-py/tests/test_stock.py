"""The buyer halves of the stock pairings against @integraledger/lcp's vector rows for them. From x402-upto-xrpl.json,
whose options are the scheme's own examples (specs/schemes/upto/scheme_upto_xrpl.md at x402-foundation/x402 88b66dd4)
changed one member at a time: x402/upto/xrpl's option filter (filter.rows: read offers the row's option exactly where
the row names the pairing, and bound gives a payment presented under it the row's code, or x402/no-signed-place where
it names the pairing) and its bound (fixed.P, for the payment and for the agreement, and bound.rows). From
mpp-session-hedera-solana-xrpl.json: mpp/session/xrpl/stock's bound of XS6, a stock client's voucher as xrpl-mpp-sdk
0.1.0-beta.4 writes it, and of the same credential with action open. Every expected value is the file's."""

import copy
from typing import Any

import pytest

from integraledger_terms import MPP_SESSION_XRPL_STOCK, X402_UPTO_XRPL, Refusal

from support import load

UPTO = load("x402-upto-xrpl.json")
SESSION = load("mpp-session-hedera-solana-xrpl.json")
ID = "x402/upto/xrpl"
P: dict[str, Any] = UPTO["fixed"]["P"]
EXTENSIONS = UPTO["buyer"]["rows"][0]["input"]["doc"]["extensions"]


def changed(value: Any, row: dict[str, Any]) -> Any:
    """A copy of value with the member at the row's JSON Pointer (RFC 6901) set to the row's value, or removed."""
    out = copy.deepcopy(value)
    keys = row["path"].split("/")[1:]
    at = out
    for key in keys[:-1]:
        at = at[key]
    if row.get("remove") is True:
        del at[keys[-1]]
    else:
        at[keys[-1]] = row["value"]
    return out


@pytest.mark.parametrize("row", UPTO["filter"]["rows"], ids=[r["case"] for r in UPTO["filter"]["rows"]])
def test_x402_upto_xrpl_the_option_filter(row: dict[str, Any]) -> None:
    doc = {"x402Version": 2, "resource": UPTO["fixed"]["resource"], "accepts": [row["option"]], "extensions": EXTENSIONS}
    offered = not isinstance(X402_UPTO_XRPL.read(doc), Refusal)
    assert offered == (row["expect"] == ID)
    expected = "x402/no-signed-place" if row["expect"] == ID else row["expect"]
    assert X402_UPTO_XRPL.bound({**P, "accepted": row["option"]}) == Refusal(expected)


def test_x402_upto_xrpl_bound_finds_no_signed_place_for_the_payment_or_the_agreement() -> None:
    expected = Refusal(UPTO["bound"]["expect"])
    assert X402_UPTO_XRPL.bound(copy.deepcopy(P)) == expected
    assert X402_UPTO_XRPL.bound(copy.deepcopy(P), given={"act": "agreement", "h": UPTO["fixed"]["H"]}) == expected


@pytest.mark.parametrize("row", UPTO["bound"]["rows"], ids=[r["case"] for r in UPTO["bound"]["rows"]])
def test_x402_upto_xrpl_bound_rows(row: dict[str, Any]) -> None:
    assert X402_UPTO_XRPL.bound(changed(P, row)) == Refusal(row["expect"])


def test_mpp_session_xrpl_stock_bound_of_a_stock_voucher_and_of_an_open() -> None:
    xs6 = SESSION["XS6"]
    assert MPP_SESSION_XRPL_STOCK.bound(copy.deepcopy(xs6["presented"])) == Refusal(xs6["expectBound"])
    opening = changed(xs6["presented"], {"path": "/payload/action", "value": "open"})
    assert MPP_SESSION_XRPL_STOCK.bound(opening) == Refusal(xs6["expectOpen"])
