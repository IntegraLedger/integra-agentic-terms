"""The label-674 carrier read from hand-written auxiliary data. Map keys are compared as decoded values (RFC 8949
section 5.6: a map's keys are data items, and two keys with the same value repeat), so two encodings of one integer are
one key; a text key is compared without a leading byte-order mark; every floating-point key is one key. A repeated key,
or label 674 held twice, is cardano/ambiguous, and a map without one reads the carrier. Each transaction is
[body, witnesses, true, auxiliary data], its body {7: Blake2b-256 of the auxiliary data} (CIP-10's commitment)."""

import base64
import hashlib

from integraledger_terms import Refusal
from integraledger_terms.bindings.x402_exact_cardano import LCP_MARKER, decode_cardano_tx

H = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
MSG = bytes([0x63]) + b"msg"
LINES = bytes([0x82, 0x60 + len(LCP_MARKER)]) + LCP_MARKER.encode() + bytes([0x78, 0x40]) + H[2:].encode()
LABEL = bytes([0x19, 0x02, 0xA2])


def tx(aux: bytes) -> str:
    body = bytes([0xA1, 0x07, 0x58, 0x20]) + hashlib.blake2b(aux, digest_size=32).digest()
    return base64.b64encode(bytes([0x84]) + body + bytes([0xA0, 0xF5]) + aux).decode()


def message(*entries: bytes) -> bytes:
    """The metadata {674: {entries..., "msg": [marker, digits]}}, each entry a key and its value."""
    return bytes([0xA1]) + LABEL + bytes([0xA0 + len(entries) + 1]) + b"".join(entries) + MSG + LINES


def carried(aux: bytes) -> object:
    t = decode_cardano_tx(tx(aux))
    return t if isinstance(t, Refusal) else t.h


def test_the_carrier_alone_is_read() -> None:
    assert carried(message()) == H


def test_one_integer_key_in_two_encodings_repeats() -> None:
    one, one_again = bytes([0x01, 0x61]) + b"a", bytes([0x18, 0x01, 0x61]) + b"b"
    assert carried(message(one, one_again)) == Refusal("cardano/ambiguous")


def test_negative_keys_are_compared_by_value() -> None:
    minus_one, minus_one_again = bytes([0x20, 0x61]) + b"a", bytes([0x38, 0x00, 0x61]) + b"b"
    assert carried(message(minus_one, minus_one_again)) == Refusal("cardano/ambiguous")
    assert carried(message(bytes([0x20, 0x61]) + b"a", bytes([0x21, 0x61]) + b"b")) == H


def test_a_text_key_led_by_a_byte_order_mark_repeats_the_key_without_it() -> None:
    bom_msg = bytes([0x66]) + "﻿msg".encode()
    assert carried(message(bom_msg + bytes([0x61]) + b"x")) == Refusal("cardano/ambiguous")


def test_every_floating_point_key_is_one_key() -> None:
    one, two = bytes([0xF9, 0x3C, 0x00]), bytes([0xF9, 0x40, 0x00])
    assert carried(message(one + bytes([0x61]) + b"a", two + bytes([0x61]) + b"b")) == Refusal("cardano/ambiguous")


def test_label_674_twice_is_ambiguous() -> None:
    once = LABEL + bytes([0xA1]) + MSG + LINES
    assert carried(bytes([0xA2]) + once + once) == Refusal("cardano/ambiguous")


def test_a_marker_line_led_by_a_byte_order_mark_is_counted_and_carries_nothing() -> None:
    marker = "﻿" + LCP_MARKER
    lines = bytes([0x82, 0x60 + len(marker.encode())]) + marker.encode() + bytes([0x78, 0x40]) + H[2:].encode()
    assert carried(bytes([0xA1]) + LABEL + bytes([0xA1]) + MSG + lines) == Refusal("cardano/hash-not-carried")
