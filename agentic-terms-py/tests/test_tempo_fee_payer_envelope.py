"""The 0x78 envelope a stock signer sends where the fee is paid for the sender, read as the 0x76 envelope the sender
signed: the sender recovered from that form, which item 11 must name, the bytes the sender signed, the calls and the
expiring nonce hash. Every value is mpp-session-tempo.json's feePayerEnvelope, viem 2.57.4's and ox 0.14.54's output."""

from typing import Any

from integraledger_terms import Refusal
from integraledger_terms.bindings._tempo import (
    _envelope,
    _sender_signed,
    decode_tempo_tx,
    expiring_nonce_hash,
    tempo_sender,
)

from support import load

V: dict[str, Any] = load("mpp-session-tempo.json")["feePayerEnvelope"]


def wire(text: str) -> bytes:
    return bytes.fromhex(text[2:])


def test_the_sender_is_the_one_the_signature_recovers_over_the_0x76_form_which_item_11_names() -> None:
    assert tempo_sender(wire(V["wire"])) == V["sender"].lower()
    items = _envelope(wire(V["wire"]))
    assert not isinstance(items, Refusal), items
    assert "0x" + _sender_signed(items).hex() == V["signedBytes"]


def test_the_calls_and_the_expiring_nonce_hash_of_the_bytes_the_sender_signed() -> None:
    tx = decode_tempo_tx(wire(V["wire"]))
    assert not isinstance(tx, Refusal), tx
    assert [c.to for c in tx.calls] == [V["call"]["to"]]
    assert expiring_nonce_hash(wire(V["wire"]), V["sender"]) == V["expiringNonceHash"]


def test_a_0x78_envelope_whose_item_11_names_another_account_than_the_sender() -> None:
    assert tempo_sender(wire(V["otherSenderWire"])) == Refusal(V["otherSenderCode"])
