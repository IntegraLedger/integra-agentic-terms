"""The vector files' multisigned rows: an XRPL Payment or PaymentChannelCreate that carries Signers is admitted, and
bound gives H, since a payment is found by the payer's instrument, its Account with the signed Sequence or ticket, and
another quorum's copy, under another hash, is the same payment. Each row's hash is the ledger's hash of its blob, which
the decode gives."""

from typing import Any

import pytest
from support import load
from test_xlm_mpp_session_xrpl import opening
from test_xlm_mpp_xrpl import credential
from test_xlm_xrpl import presented

from integraledger_terms import MPP_CHARGE_XRPL, MPP_SESSION_XRPL, X402_EXACT_XRPL
from integraledger_terms.bindings import _xrpl

X = load("x402-exact-xrpl.json")
M = load("mpp-charge-xrpl.json")
S = load("mpp-session-hedera-solana-xrpl.json")
EXACT = X["multisigned"]["rows"]
CHARGE = M["multisigned"]["rows"]
SESSION = S["XS5"]


def decoded(row: dict[str, Any]) -> _xrpl.Blob:
    assert row["expect"] == "admitted"
    blob = _xrpl.decode_blob(row["blob"])
    assert isinstance(blob, _xrpl.Blob) and blob.hash == row["hash"]
    assert "Signers" in blob.tx
    return blob


@pytest.mark.parametrize("row", EXACT, ids=[r["case"] for r in EXACT])
def test_x402_exact_xrpl_admits_a_multisigned_payment(row: dict[str, Any]) -> None:
    decoded(row)
    assert X402_EXACT_XRPL.bound(presented(row["blob"])) == X["V2"]["expectBound"]


@pytest.mark.parametrize("row", CHARGE, ids=[r["case"] for r in CHARGE])
def test_mpp_charge_xrpl_admits_a_multisigned_payment(row: dict[str, Any]) -> None:
    decoded(row)
    assert MPP_CHARGE_XRPL.bound(credential({"type": "transaction", "blob": row["blob"]})) == M["fixed"]["H"]


def test_mpp_session_xrpl_admits_a_multisigned_opening() -> None:
    decoded(SESSION)
    assert MPP_SESSION_XRPL.bound(opening(SESSION["blob"])) == S["fixed"]["H"]
