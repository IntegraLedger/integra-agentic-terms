"""The core vectors' hash half: the hashes of V1-V3's expected bytes, V4 (equality) and V6 (the one-byte plant)."""

from integraledger_terms import atr_hash, hash_equals

from support import core_vector


def test_v1_to_v3_hash_the_expected_bytes() -> None:
    for name in ("V1", "V2", "V3"):
        vector = core_vector(name)
        assert atr_hash(bytes.fromhex(vector["expectBytesHex"])) == vector["expectHash"], name


def test_v4_equality_compares_decoded_bytes() -> None:
    h = core_vector("V1")["expectHash"]
    assert hash_equals(h, h.upper().replace("0X", "0x"))
    assert not hash_equals("0X" + h[2:], h)
    assert not hash_equals(h[:-1], h)
    assert not hash_equals(h[:-1] + "g", h)


def test_v6_one_byte_plant_differs_from_v1() -> None:
    plant = core_vector("V6-plant")
    v1 = core_vector(plant["mustNotEqual"])
    computed = atr_hash(bytes.fromhex(plant["bytesHex"]))
    assert computed == plant["expectHash"]
    assert not hash_equals(computed, v1["expectHash"])
