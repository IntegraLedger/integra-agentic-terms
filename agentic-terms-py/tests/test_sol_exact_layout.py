"""x402-exact-solana.json's zeroAmount and instructionLayout groups through the Python x402/exact/solana read, build and
bound. zeroAmount: an option at amount "0", the pairing's agreement floor, is offered; the build of the group's input
asks the payer to sign the stock client's version-0 message, and its completion with the payer's signature is the stock
wire. instructionLayout: each row's wire under its base's option, bound answering the row's expect. Every expected value
is the file's; the payer's key is the file's Ed25519 seed 01x32."""

import base64
import copy
from typing import Any

import pytest

from breadth import x402_doc
from ed25519 import sign
from integraledger_terms import X402_EXACT_SOLANA, Advertised, Refusal
from integraledger_terms.bindings import _svm
from support import load

S = load("x402-exact-solana.json")
Z: dict[str, Any] = S["zeroAmount"]
LAYOUT: list[dict[str, Any]] = S["instructionLayout"]["rows"]
PAYER_SEED = bytes([1]) * 32


def _doc(accepted: dict[str, Any], h: str) -> dict[str, Any]:
    return x402_doc(copy.deepcopy(accepted), S["fixed"]["resource"], h)


def test_an_option_at_amount_0_is_offered_and_bound() -> None:
    accepted = Z["presented"]["accepted"]
    assert accepted["amount"] == "0"
    read = X402_EXACT_SOLANA.read(_doc(accepted, Z["expectBound"]))
    assert isinstance(read, Advertised), read
    assert read.offer["options"] == [accepted]
    assert X402_EXACT_SOLANA.bound(copy.deepcopy(Z["presented"])) == Z["expectBound"]


def test_the_zero_build_asks_for_the_stock_message_and_completes_the_stock_wire() -> None:
    given = Z["build"]["input"]
    doc = _doc(Z["presented"]["accepted"], Z["expectBound"])
    choice = {**given, "computeUnitPrice": int(given["computeUnitPrice"]), "required": doc, "accepted": doc["accepts"][0]}
    unsigned = X402_EXACT_SOLANA.build(choice, Z["expectBound"])
    assert not isinstance(unsigned, Refusal), unsigned
    stock = base64.b64decode(Z["presented"]["payload"]["transaction"])
    tx = _svm.decode_svm_tx(stock)
    assert isinstance(tx, _svm.SvmTx), tx
    message = unsigned.request["message"]
    assert message[0] == 0x80
    assert message == tx.message
    paid = unsigned.complete(sign(PAYER_SEED, message))
    assert not isinstance(paid, Refusal), paid
    assert base64.b64decode(paid["payload"]["transaction"]) == stock


def _answer(expect: Any) -> Any:
    return expect if isinstance(expect, str) else Refusal(expect["code"])


@pytest.mark.parametrize("row", LAYOUT, ids=[f"{r['base']} {r['change']}" for r in LAYOUT])
def test_each_layout_row_is_bound_as_the_file_says(row: dict[str, Any]) -> None:
    base = S[row["base"]]["presented"]
    presented = {**copy.deepcopy(base), "payload": {"transaction": row["wireBase64"]}}
    assert X402_EXACT_SOLANA.bound(presented) == _answer(row["expect"]), row["case"]
