"""x402/exact/stellar: the TypeScript gate's B2, B6, payment identifier, B10 and B16 rows, and the buyer half's vector
rows. Expected values are the vector file's; the payer signs with the Ed25519 seed the file publishes."""

import base64
import copy
import hashlib
from dataclasses import replace
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_STELLAR, Declined, Refusal, transact
from integraledger_terms.bindings import _stellar
from integraledger_terms.bindings._stellar import StellarUnsigned

import ed25519
from breadth import ABC, H, Pairing, build_and_sign, link_calls, plant, run, x402_doc
from support import CountingSigner, hexb, load, serving
from xlm_support import EVM_ACCOUNT, REF, b10, b16, with_identifier

T = load("x402-exact-stellar.json")
F: dict[str, Any] = T["fixed"]
V2: dict[str, Any] = T["V2"]
V3: dict[str, Any] = T["V3"]
SEED = bytes.fromhex(F["payerSeed"])
# The option as advertise places H: payTo is the seller's muxed address whose id is H's first 8 bytes.
OPTION: dict[str, Any] = V3["accepted"]


def answer(request: Any) -> Any:
    assert request["kind"] == "stellar-auth", request["kind"]
    return "0x" + ed25519.sign(SEED, hashlib.sha256(hexb(request["preimage"])).digest()).hex()


STELLAR = Pairing(
    binding=X402_EXACT_STELLAR,
    doc=x402_doc(OPTION, F["resource"]),
    account=f"{F['option']['network']}:{F['payer']}",
    answer=answer,
    inputs={"simulatedXdr": V2["simulatedXdr"], "currentLedger": V2["currentLedger"]},
)


def test_x402_exact_stellar_keys_are_the_vector_keys() -> None:
    assert _stellar.account(ed25519.public_key(SEED)) == F["payer"]
    assert _stellar.account(ed25519.public_key(bytes.fromhex(F["sellerSeed"]))) == F["seller"]

def test_x402_exact_stellar_b6_preimage_is_v2_and_signature_completes_v2_envelope() -> None:
    assert STELLAR.doc["accepts"][0]["payTo"] == T["V1"]["M"]

    def inspect(request: Any) -> None:
        assert request["kind"] == "stellar-auth"
        assert len(hexb(request["preimage"])) == V2["expectPreimageLength"]
        assert hashlib.sha256(hexb(request["preimage"])).hexdigest() == V2["expectPreimageSha256"]
        signature = answer(request)
        assert signature.startswith("0x" + V2["expectSignaturePrefix"])
        assert signature.endswith(V2["expectSignatureSuffix"])

    signed, _ = build_and_sign(STELLAR, inspect)
    assert signed["x402Version"] == 2
    assert signed["resource"] == F["resource"]
    assert signed["accepted"] == STELLAR.doc["accepts"][0]
    assert signed["payload"] == {"transaction": V2["expectEnvelope"]}
    assert signed["extensions"] == STELLAR.doc["extensions"]


def test_x402_exact_stellar_payment_identifier() -> None:
    signed, _ = build_and_sign(replace(STELLAR, doc=with_identifier(STELLAR.doc)), lambda request: None)
    assert REF.fullmatch(signed["extensions"]["payment-identifier"]["info"]["id"])


def test_x402_exact_stellar_b10_http_link() -> None:
    b10(STELLAR)


def test_x402_exact_stellar_b16_other_accounts() -> None:
    b16(STELLAR, [EVM_ACCOUNT, f"stellar:pubnet:{F['payer']}"])


@pytest.mark.parametrize("network", [[], {}, [["x"]], 1, None, True])
def test_x402_exact_stellar_an_option_whose_network_is_not_a_string_has_no_payable_option(network: Any) -> None:
    """x402 v2's PaymentRequirements carries network as a string, a CAIP-2 network id (the protocol package types it
    `network: string`). An option whose network is any other JSON value is no payable option, the TypeScript gate's
    decline for the same document, and nothing is fetched or signed."""
    assert _stellar.is_stellar_network(network) is False
    doc = copy.deepcopy(STELLAR.doc)
    doc["accepts"][0]["network"] = network
    out, calls = link_calls(STELLAR, STELLAR.account, doc)
    assert out == Declined("offer-unreadable", "x402/no-payable-option")
    assert calls == 0
    signer = CountingSigner(account=STELLAR.account)
    moved = run(lambda c: transact(doc, X402_EXACT_STELLAR, signer, c), serving(ABC))
    assert moved == Declined("offer-unreadable", "x402/no-payable-option")
    assert signer.requests == []


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def test_x402_exact_stellar_v1_muxed_carrier() -> None:
    assert _stellar.muxed_id(H) == int(T["V1"]["muxedId"])
    assert _stellar.muxed_id(H).to_bytes(8, "big").hex() == T["V1"]["muxedIdHex"]
    m = _stellar.muxed_for(F["seller"], H)
    assert m == T["V1"]["M"] and len(m) == T["V1"]["Mlength"]
    unmuxed = _stellar.unmux(m)
    assert unmuxed is not None and unmuxed.base == F["seller"] and unmuxed.id == int(T["V1"]["muxedId"])


def presented(envelope: str, accepted: Any, extensions: Any) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "resource": F["resource"],
        "accepted": accepted,
        "payload": {"transaction": envelope},
        "extensions": extensions,
    }


def test_x402_exact_stellar_v3_bound_and_decoded_transfer() -> None:
    assert len(base64.b64decode(V3["envelope"])) == V3["envelopeLength"]
    assert X402_EXACT_STELLAR.bound(presented(V3["envelope"], V3["accepted"], V3["extensions"])) == V3["expectBound"]
    payment = _stellar.decode_stellar_tx(V3["envelope"], F["network"])
    assert isinstance(payment, _stellar.Payment)
    ref = V3["expectReference"]
    assert payment.auth.preimage_hash == ref["authDigest"]
    assert payment.asset == ref["asset"] and payment.to_base == ref["toBase"]
    assert str(payment.to_id) == ref["toId"] and payment.auth.expiration == ref["expiration"]


def test_x402_exact_stellar_v4_refusals() -> None:
    for row in T["V4"]:
        if "envelope" not in row:
            continue
        out = X402_EXACT_STELLAR.bound(presented(row["envelope"], row["accepted"], row["extensions"]))
        assert out == Refusal(row["expect"]), row["case"]


def test_x402_exact_stellar_v3v2_address_credentials_v2() -> None:
    row = T["V3v2"]
    doc = STELLAR.doc
    choice = {
        "required": doc,
        "accepted": doc["accepts"][0],
        "simulatedXdr": row["simulatedXdr"],
        "currentLedger": row["currentLedger"],
        "payer": F["payer"],
    }
    unsigned = X402_EXACT_STELLAR.build(choice, H)
    assert isinstance(unsigned, StellarUnsigned), unsigned
    preimage = unsigned.request["preimage"]
    assert isinstance(preimage, bytes)
    assert len(preimage) == row["expectPreimageLength"]
    assert hashlib.sha256(preimage).hexdigest() == row["expectPreimageSha256"]
    signature = ed25519.sign(SEED, hashlib.sha256(preimage).digest())
    assert signature.hex() == row["expectSignature"]
    assert unsigned.complete(signature) == row["envelope"]
    assert len(base64.b64decode(row["envelope"])) == row["envelopeLength"]
    assert X402_EXACT_STELLAR.bound(presented(row["envelope"], V3["accepted"], V3["extensions"])) == row["expectBound"]
    payment = _stellar.decode_stellar_tx(row["envelope"], F["network"])
    assert isinstance(payment, _stellar.Payment) and payment.auth.v2
    assert payment.auth.preimage_hash == row["expectReference"]["authDigest"]


def test_x402_exact_stellar_agreed_refusals() -> None:
    codes = [r["expect"] for r in T["agreedRefusals"]["rows"]]
    assert "stellar/tx-malformed" in codes and "stellar/tx-too-large" in codes
    accepted, extensions = V3["accepted"], V3["extensions"]
    assert X402_EXACT_STELLAR.bound(presented("AAAA", accepted, extensions)) == Refusal("stellar/tx-malformed")
    assert X402_EXACT_STELLAR.bound(presented("A" * 8193, accepted, extensions)) == Refusal("stellar/tx-too-large")
    assert X402_EXACT_STELLAR.bound(presented(V3["envelope"], accepted, None)) == Refusal("x402/no-legal-context")
    other = {**accepted, "extra": {"areFeesSponsored": False}}
    assert X402_EXACT_STELLAR.bound(presented(V3["envelope"], other, extensions)) == Refusal("x402/option-not-this-pairing")
    doc = STELLAR.doc
    choice = {
        "required": doc,
        "accepted": doc["accepts"][0],
        "simulatedXdr": V2["simulatedXdr"],
        "currentLedger": 988,
        "payer": F["payer"],
    }
    unsigned = X402_EXACT_STELLAR.build(choice, H)
    assert isinstance(unsigned, StellarUnsigned)
    assert unsigned.complete(b"\x01" * 63) == Refusal("stellar/tx-malformed")
    other_h = "0x" + "11" * 32
    assert X402_EXACT_STELLAR.build(choice, other_h) == Refusal("stellar/carrier-mismatch")
