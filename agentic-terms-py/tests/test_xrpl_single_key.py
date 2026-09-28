"""The vector files' multisigned rows: an XRPL Payment or PaymentChannelCreate that carries Signers is refused
xrpl/multisigned by bound. A multi-signed transaction's hash covers the Signers array, and signatures a transaction
does not need can be removed by anyone (xrpl.org, Multi-Signing), so the hash computed from the presented blob need not
be the one that lands; each row's hash is the ledger's hash of its blob, which the decode gives."""

from typing import Any

import pytest
from support import load
from test_xlm_mpp_session_xrpl import opening
from test_xlm_mpp_xrpl import credential
from test_xlm_xrpl import presented

from integraledger_terms import MPP_CHARGE_XRPL, MPP_SESSION_XRPL, X402_EXACT_XRPL, Refusal
from integraledger_terms.bindings import _xrpl

EXACT = load("x402-exact-xrpl.json")["multisigned"]["rows"]
CHARGE = load("mpp-charge-xrpl.json")["multisigned"]["rows"]
SESSION = load("mpp-session-hedera-solana-xrpl.json")["XS5"]


def decoded(row: dict[str, Any]) -> _xrpl.Blob:
    blob = _xrpl.decode_blob(row["blob"])
    assert isinstance(blob, _xrpl.Blob) and blob.hash == row["hash"]
    assert "Signers" in blob.tx
    return blob


@pytest.mark.parametrize("row", EXACT, ids=[r["case"] for r in EXACT])
def test_x402_exact_xrpl_refuses_a_multi_signed_payment(row: dict[str, Any]) -> None:
    decoded(row)
    assert X402_EXACT_XRPL.bound(presented(row["blob"])) == Refusal(row["expect"])


@pytest.mark.parametrize("row", CHARGE, ids=[r["case"] for r in CHARGE])
def test_mpp_charge_xrpl_refuses_a_multi_signed_payment(row: dict[str, Any]) -> None:
    decoded(row)
    assert MPP_CHARGE_XRPL.bound(credential({"type": "transaction", "blob": row["blob"]})) == Refusal(row["expect"])


def test_mpp_session_xrpl_refuses_a_multi_signed_opening() -> None:
    decoded(SESSION)
    assert MPP_SESSION_XRPL.bound(opening(SESSION["blob"])) == Refusal(SESSION["expect"])
