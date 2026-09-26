"""The primitives the bindings share, against published values: Keccak-256, base58, strict base64url, and numbers
as ECMAScript writes them."""

from integraledger_terms._keccak import keccak256
from integraledger_terms.bindings._cbor import CborMap, CborSimple, decode_cbor
from integraledger_terms.bindings._codec import b58_decode, b58_encode, b64u_decode, canonical_json, es_number

import ed25519


def test_keccak256_of_the_empty_string_and_of_abc() -> None:
    # The Keccak team's published Keccak-256 digests (the Ethereum hash), which differ from SHA3-256's.
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def test_keccak256_across_the_rate_boundary() -> None:
    # 135, 136 and 137 bytes pad into one, two and two blocks; each digest differs.
    digests = {keccak256(b"a" * n) for n in (135, 136, 137)}
    assert len(digests) == 3


def test_base58_bitcoin_alphabet() -> None:
    # draft-msporny-base58-03 §5's test vectors.
    assert b58_encode(b"Hello World!") == "2NEpo7TZRRrLZSi2U"
    assert b58_encode(bytes.fromhex("0000287fb4cd")) == "11233QC4"
    assert b58_decode("11233QC4") == bytes.fromhex("0000287fb4cd")
    assert b58_decode("0OIl") is None


def test_base64url_is_strict() -> None:
    assert b64u_decode("YWJj") == b"abc"
    assert b64u_decode("YWI") == b"ab"
    assert b64u_decode("YWJ") is None
    assert b64u_decode("YWJj=") is None
    assert b64u_decode("Y") is None


def test_numbers_and_member_order_as_rfc_8785_writes_them() -> None:
    # RFC 8785 §3.2.2.3's examples, and §3.2.3's sorting by UTF-16 code units.
    assert es_number(1e21) == "1e+21"
    assert es_number(1e-7) == "1e-7"
    assert es_number(333333333.3333333) == "333333333.3333333"
    assert es_number(4.5) == "4.5"
    assert es_number(0.002) == "0.002"
    assert es_number(1.0) == "1"
    assert canonical_json({"\U0001f600": 1, "\u20ac": 2, "1": 3}) == '{"1":3,"\u20ac":2,"\U0001f600":1}'


def test_the_test_signers_ed25519_is_rfc_8032s() -> None:
    # RFC 8032 §7.1, TEST 1.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert ed25519.public_key(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert ed25519.sign(seed, b"").hex() == (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24"
        "655141438e7a100b"
    )


def test_a_null_spelling_is_present_as_json_null_not_absent() -> None:
    # lcp's fromLegalContext and agreementIn compare each spelling with undefined: a null one is present, and differs
    # from the other spelling's link.
    from integraledger_terms.bindings._lcp import AgreementFault, agreement_in, legal_context_info

    link = "https://atr.seller.example/a"
    h = "0x" + "ab" * 32
    assert legal_context_info({"type": "sha256", "value": h, "legalContextUrl": link}) == (h, link)
    assert legal_context_info({"type": "sha256", "value": h, "legalContextUrl": None, "legal_context_url": link}) is None
    assert agreement_in({"legalContextAgreementUrl": None, "legal_context_agreement_url": link}) == AgreementFault(
        "legal-context-malformed"
    )
    assert agreement_in({"legalContextAgreementUrl": None}) == AgreementFault("legal-context-malformed")
    assert agreement_in({"legalContextAgreementUrl": "http://pay.seller.example/a"}) == AgreementFault("link-not-https")
    assert agreement_in({}) is None


# The bounded CBOR reader against RFC 8949's data model: §3.3 (a simple value is not an integer, and simple(0..31) in
# the one-byte form is not well-formed), §3.1 (U+FEFF is a character of a text string) and §5.6 (a map with identical
# keys is malformed for the operations this reader serves).
def test_cbor_a_simple_value_is_not_an_integer() -> None:
    assert decode_cbor(bytes.fromhex("03")) == 3
    assert decode_cbor(bytes.fromhex("e3")) == CborSimple(3)
    assert decode_cbor(bytes.fromhex("e3")) != decode_cbor(bytes.fromhex("03"))
    assert decode_cbor(bytes.fromhex("f820")) != decode_cbor(bytes.fromhex("1820"))
    assert decode_cbor(bytes.fromhex("f4")) is False
    assert decode_cbor(bytes.fromhex("f5")) is True
    assert decode_cbor(bytes.fromhex("f81f")) is None


def test_cbor_text_keeps_a_leading_bom() -> None:
    assert decode_cbor(bytes.fromhex("63efbbbf")) == "﻿"
    assert decode_cbor(bytes.fromhex("64efbbbf61")) == "﻿a"


def test_cbor_a_map_with_a_repeated_key_is_malformed() -> None:
    assert decode_cbor(bytes.fromhex("a2616101616102")) is None
    assert decode_cbor(bytes.fromhex("a2e301e302")) is None
    assert decode_cbor(bytes.fromhex("a2034101034102")) is None
    assert decode_cbor(bytes.fromhex("a2010203f5")) == CborMap(((1, 2), (3, True)))
    assert decode_cbor(bytes.fromhex("a20301e302")) == CborMap(((3, 1), (CborSimple(3), 2)))
    assert decode_cbor(bytes.fromhex("a2f501f402")) == CborMap(((True, 1), (False, 2)))
    assert decode_cbor(bytes.fromhex("a201f5f501")) == CborMap(((1, True), (True, 1)))
