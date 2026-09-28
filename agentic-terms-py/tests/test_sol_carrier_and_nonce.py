"""x402-exact-solana.json's carrierSpelling and durableNonce groups through the Python x402/exact/solana bound, each in
a payment whose accepted is the group's (V2's for durableNonce). A memo that spells H other than as toLcpString(h),
lcp:sha256:0x and 64 lower-case hex digits, is svm/carrier-not-canonical. A message whose first instruction is
AdvanceNonceAccount and names its nonce account or the RecentBlockhashes sysvar through an address lookup table is
svm/nonce-account-not-static: the message alone cannot show the nonce it uses. A durable-nonce message whose accounts
are static keys carries V1's memo, so bound gives the file's H."""

import base64
import hashlib
from typing import Any

import pytest
from support import load

from integraledger_terms import X402_EXACT_SOLANA, Refusal
from integraledger_terms.bindings import _svm

S = load("x402-exact-solana.json")
H = S["fixed"]["H"]
NONCE = S["durableNonce"]
TABLE = NONCE["lookupTable"]["rows"]


def presented(accepted: dict[str, Any], wire: str) -> dict[str, Any]:
    return {"x402Version": 2, "accepted": accepted, "payload": {"transaction": wire}}


def test_a_memo_in_upper_case_hex_is_not_the_carrier() -> None:
    spelling = S["carrierSpelling"]
    assert spelling["memo"] == spelling["memo"][:13] + spelling["memo"][13:].upper()
    got = X402_EXACT_SOLANA.bound(presented(spelling["bound"]["accepted"], spelling["bound"]["wireBase64"]))
    assert got == Refusal(spelling["bound"]["expect"])


@pytest.mark.parametrize("row", TABLE, ids=[r["case"] for r in TABLE])
def test_a_nonce_account_or_sysvar_from_a_lookup_table_is_refused(row: dict[str, Any]) -> None:
    tx = _svm.decode_svm_tx(base64.b64decode(row["wireBase64"]))
    assert not isinstance(tx, Refusal)
    assert hashlib.sha256(tx.message).hexdigest() == row["messageSha256"]
    assert len(tx.keys) == row["staticKeys"]
    assert list(tx.instructions[0].accounts) == row["instruction0Accounts"]
    assert _svm.static_nonce(tx) == Refusal(row["expect"])
    assert X402_EXACT_SOLANA.bound(presented(S["V2"]["accepted"], row["wireBase64"])) == Refusal(row["expect"])


@pytest.mark.parametrize("row", NONCE["reference"], ids=[r["case"] for r in NONCE["reference"]])
def test_a_message_with_static_nonce_accounts_is_bound(row: dict[str, Any]) -> None:
    tx = _svm.decode_svm_tx(base64.b64decode(row["wireBase64"]))
    assert not isinstance(tx, Refusal)
    assert _svm.static_nonce(tx) is None
    assert X402_EXACT_SOLANA.bound(presented(S["V2"]["accepted"], row["wireBase64"])) == H
