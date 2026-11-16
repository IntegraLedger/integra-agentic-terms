"""The transactionV1 sections of @integraledger/lcp's x402-exact-solana.json, x402-upto-solana.json and
x402-batch-settlement.json: version-1 transactions (SIMD-0385) as the stock @x402/svm 2.31.0 client writes them. Each
is decoded, its message held to the file's length and SHA-256 and to the payer's Ed25519 signature, read as H by its
pairing's bound and by the gate's check, and each changed member refused with the file's code. Every expected value is
the file's."""

import base64
import copy
import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from breadth import ABC
from ed25519 import verify
from integraledger_terms import X402_BATCH_SETTLEMENT_SOLANA, X402_EXACT_SOLANA, X402_UPTO_SOLANA, Checked, Refusal, check
from integraledger_terms.bindings import _svm
from integraledger_terms.bindings._codec import b58_decode
from support import load

Wire = Callable[[dict[str, Any]], str]
Replace = Callable[[dict[str, Any], str], dict[str, Any]]


def _deposit(p: dict[str, Any], w: str) -> dict[str, Any]:
    return {**p, "deposit": {**p["deposit"], "transaction": w}}


CASES: list[tuple[str, Any, Wire, Replace]] = [
    (
        "x402-exact-solana.json",
        X402_EXACT_SOLANA,
        lambda p: str(p["transaction"]),
        lambda p, w: {**p, "transaction": w},
    ),
    (
        "x402-upto-solana.json",
        X402_UPTO_SOLANA,
        lambda p: str(p["openTransaction"]),
        lambda p, w: {**p, "openTransaction": w},
    ),
    (
        "x402-batch-settlement.json",
        X402_BATCH_SETTLEMENT_SOLANA,
        lambda p: str(p["deposit"]["transaction"]),
        _deposit,
    ),
]
IDS = [c[0] for c in CASES]


@pytest.mark.parametrize(("file", "binding", "wire_of", "with_wire"), CASES, ids=IDS)
def test_the_stock_wire_decodes_to_the_message_the_payer_signed(file: str, binding: Any, wire_of: Wire, with_wire: Replace) -> None:
    v = load(file)["transactionV1"]
    wire = base64.b64decode(wire_of(v["presented"]["payload"]))
    assert wire[0] == v["expectVersionByte"]
    tx = _svm.decode_svm_tx(wire)
    assert isinstance(tx, _svm.SvmTx), tx
    assert len(tx.message) == v["messageLength"]
    assert "0x" + hashlib.sha256(tx.message).hexdigest() == v["messageSha256"]
    assert tx.lookups == ()
    assert _svm.key_string(tx.keys[0]) == v["expectReference"]["feePayer"]
    assert tx.signatures[0] == bytes(64)
    assert verify(tx.keys[1], tx.message, tx.signatures[1])
    landed = _svm.decode_svm_tx(base64.b64decode(v["landedWireBase64"]))
    assert isinstance(landed, _svm.SvmTx), landed
    assert landed.message == tx.message
    fee_payer = b58_decode(v["expectReference"]["feePayer"])
    assert fee_payer is not None
    assert verify(fee_payer, tx.message, landed.signatures[0])


@pytest.mark.parametrize(("file", "binding", "wire_of", "with_wire"), CASES, ids=IDS)
def test_bound_and_check_give_h(file: str, binding: Any, wire_of: Wire, with_wire: Replace) -> None:
    v = load(file)["transactionV1"]
    assert binding.bound(copy.deepcopy(v["presented"])) == v["expectBound"]
    out = check(ABC, copy.deepcopy(v["presented"]), binding)
    assert isinstance(out, Checked) and out.h == v["expectBound"], out


@pytest.mark.parametrize(("file", "binding", "wire_of", "with_wire"), CASES, ids=IDS)
def test_each_changed_member_is_refused(file: str, binding: Any, wire_of: Wire, with_wire: Replace) -> None:
    v = load(file)["transactionV1"]
    rows = v["changed"]
    assert len(rows) == 3
    for row in rows:
        presented = {**copy.deepcopy(v["presented"]), "payload": with_wire(copy.deepcopy(v["presented"]["payload"]), row["wireBase64"])}
        assert binding.bound(presented) == Refusal(row["expect"]["code"]), row["case"]
