"""mpp/charge/stellar: the TypeScript gate's placement, B2, B6, B10 and B16 rows, and the buyer half's vector rows.
Expected values are the vector files'; the payer signs with the Ed25519 seed x402-exact-stellar.json publishes."""

import hashlib
import json
from datetime import datetime
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_STELLAR, Refusal, _gate
from integraledger_terms.bindings import _stellar

import ed25519
from breadth import H, LINK, Pairing, build_and_sign, plant
from mpp_docs import issued, place_carrier
from support import hexb, load
from xlm_support import EVM_ACCOUNT, b16, mpp_b10

V = load("mpp-charge-stellar.json")
X = load("x402-exact-stellar.json")
F: dict[str, Any] = V["fixed"]
SEED = bytes.fromhex(X["fixed"]["payerSeed"])
# The entry's expiration is currentLedger + ceil((expires - now) / 5): 988 + 12 = 1000.
NOW = int(datetime.fromisoformat(F["expires"].replace("Z", "+00:00")).timestamp()) - 60


def muxed_carrier(h: str) -> Any:
    def carrier(value: Any) -> str | Refusal:
        if _stellar.unmux(value) is not None:
            return Refusal("stellar/carrier-occupied")
        try:
            return _stellar.muxed_for(value, h)
        except ValueError:
            return Refusal("stellar/option-malformed")

    return carrier


def doc_of(challenge: dict[str, Any], h: str = H) -> Any:
    return place_carrier([challenge], h, LINK, challenge, muxed_carrier(h))


def answer(request: Any) -> Any:
    assert request["kind"] == "stellar-auth", request["kind"]
    return "0x" + ed25519.sign(SEED, hashlib.sha256(hexb(request["preimage"])).digest()).hex()


STELLAR = Pairing(
    binding=MPP_CHARGE_STELLAR,
    doc=doc_of(V["challenge"]),
    account=f"stellar:testnet:{X['fixed']['payer']}",
    answer=answer,
    inputs={"simulatedXdr": X["V2"]["simulatedXdr"], "currentLedger": X["V2"]["currentLedger"]},
)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def test_mpp_charge_stellar_placed_challenge_is_the_vectors() -> None:
    assert STELLAR.doc == [V["place"]["expect"]]
    assert X["V2"]["expectExpiration"] == X["V2"]["currentLedger"] + 12

@pytest.mark.usefixtures("clock")
def test_mpp_charge_stellar_b6_preimage_is_v3_digest_and_signature_completes_v3_envelope() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "stellar-auth"
        assert "0x" + hashlib.sha256(hexb(request["preimage"])).hexdigest() == V["V3"]["expectReference"]["authDigest"]

    signed, _ = build_and_sign(STELLAR, inspect)
    assert signed["payload"] == {"type": "transaction", "transaction": V["V3"]["envelope"]}


def test_mpp_charge_stellar_b10_http_link() -> None:
    mpp_b10(STELLAR)


def test_mpp_charge_stellar_b16_other_accounts() -> None:
    b16(STELLAR, [EVM_ACCOUNT, f"stellar:pubnet:{X['fixed']['payer']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def credential(payload: dict[str, Any], challenge: Any = None) -> dict[str, Any]:
    return {"challenge": challenge or STELLAR.doc[0], "payload": payload}


def test_mpp_charge_stellar_v3_bound_plant_and_refusals() -> None:
    assert F["muxed"] == _stellar.muxed_for(F["request"]["recipient"], H)
    tx = {"type": "transaction", "transaction": V["V3"]["envelope"]}
    assert MPP_CHARGE_STELLAR.bound(credential(tx)) == V["V3"]["expectBound"]
    plant_tx = {"type": "transaction", "transaction": V["plant"]["envelope"]}
    assert MPP_CHARGE_STELLAR.bound(credential(plant_tx)) == Refusal(V["plant"]["expect"])
    rows = V["refusals"]
    assert MPP_CHARGE_STELLAR.bound(credential(rows[0]["payload"])) == Refusal(rows[0]["expect"])
    # The echoed challenge names H2 while its recipient is the muxed address of H's first 8 bytes.
    h2_doc = place_carrier([V["challenge"]], F["H2"], LINK, V["challenge"], lambda issued_value: F["muxed"])
    assert isinstance(h2_doc, list)
    assert MPP_CHARGE_STELLAR.bound(credential(tx, h2_doc[0])) == Refusal(rows[1]["expect"])
    assert MPP_CHARGE_STELLAR.bound(credential({"type": "other"})) == Refusal("mpp/credential-type")


def test_mpp_charge_stellar_occupied_and_option_malformed() -> None:
    occupied = issued("stellar", "charge", json.dumps(V["occupied"]["request"]), F["realm"], F["expires"])
    assert doc_of(occupied) == Refusal(V["occupied"]["expect"])
    not_g = {**F["request"], "recipient": F["request"]["currency"]}
    assert doc_of(issued("stellar", "charge", json.dumps(not_g), F["realm"], F["expires"])) == Refusal(
        "stellar/option-malformed"
    )
