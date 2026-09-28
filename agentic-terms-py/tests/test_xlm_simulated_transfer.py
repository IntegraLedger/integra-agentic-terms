"""The Stellar builds compare the buyer's simulated transfer with the option before anything reaches the signer. x402's
scheme_exact_stellar: "Argument 2 (amount): MUST equal requirements.amount exactly", on the SEP-41 token of
requirements.asset; MPP's Stellar charge: a transfer on the contract matching currency. The payer is the account whose
key signs, so the transfer's from must be the signer's account. The envelopes are stellar_transfers.json's, built with
@stellar/stellar-sdk 17.1.0; the TypeScript gate's test rebuilds each with the SDK and checks it against that file."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from integraledger_terms import (
    MPP_CHARGE_STELLAR,
    X402_EXACT_STELLAR,
    Binding,
    Confirmed,
    Declined,
    Refusal,
    _gate,
    confirm,
    transact,
)
from integraledger_terms.bindings import _stellar

import ed25519
from breadth import ABC, H, LINK, Recording, run, x402_doc
from mpp_docs import place_carrier
from support import load, serving

CASES: dict[str, Any] = json.loads((Path(__file__).parent / "stellar_transfers.json").read_text())
X = load("x402-exact-stellar.json")
M = load("mpp-charge-stellar.json")
PAYER: str = X["fixed"]["payer"]
ACCOUNT = f"stellar:testnet:{PAYER}"
V2: dict[str, Any] = X["V2"]
# The MPP entry's expiration is currentLedger + ceil((expires - now) / 5): 988 + 12 = V2's expiration 1000.
MPP_NOW = int(datetime.fromisoformat(M["fixed"]["expires"].replace("Z", "+00:00")).timestamp()) - 60


def mpp_doc() -> Any:
    def carrier(value: Any) -> str | Refusal:
        return _stellar.muxed_for(value, H)

    return place_carrier([M["challenge"]], H, LINK, M["challenge"], carrier)


PAIRINGS: list[tuple[Binding, Any, int | None]] = [
    (X402_EXACT_STELLAR, x402_doc(X["V3"]["accepted"], X["fixed"]["resource"]), None),
    (MPP_CHARGE_STELLAR, mpp_doc(), MPP_NOW),
]
IDS = [b.id for b, _, _ in PAIRINGS]


def never(request: Any) -> Any:
    raise AssertionError("the signer is never called")


def test_the_fixture_names_the_seeds_it_was_built_from() -> None:
    assert CASES["otherAsset"] == _stellar.contract(bytes([7]) * 32)
    assert CASES["otherPayer"] == _stellar.account(ed25519.public_key(bytes([8]) * 32))
    assert [r["expect"] for r in CASES["rows"]] == [
        "stellar/amount-mismatch",
        "stellar/asset-mismatch",
        "stellar/asset-mismatch",
        "stellar/payer-mismatch",
    ]


@pytest.mark.parametrize(("binding", "doc", "now"), PAIRINGS, ids=IDS)
def test_the_simulated_envelope_reaches_the_signer_with_the_account_as_payer(
    binding: Binding, doc: Any, now: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if now is not None:
        monkeypatch.setattr(_gate, "_now", lambda: now)
    inputs = {"simulatedXdr": V2["simulatedXdr"], "currentLedger": V2["currentLedger"]}
    out = run(lambda c: confirm(doc, binding, ACCOUNT, c, inputs), serving(ABC))
    assert isinstance(out, Confirmed), out
    assert out.chosen.choice["payer"] == PAYER
    assert out.request is not None and out.request["kind"] == "stellar-auth"


@pytest.mark.parametrize(("binding", "doc", "now"), PAIRINGS, ids=IDS)
def test_a_transfer_other_than_the_option_is_declined_before_the_signer(
    binding: Binding, doc: Any, now: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    if now is not None:
        monkeypatch.setattr(_gate, "_now", lambda: now)
    for row in CASES["rows"]:
        inputs = {"simulatedXdr": row["simulatedXdr"], "currentLedger": V2["currentLedger"]}
        signer = Recording(ACCOUNT, never)
        out = run(lambda c: transact(doc, binding, signer, c, inputs=inputs), serving(ABC))
        assert isinstance(out, Declined) and (out.code, out.detail) == ("offer-unreadable", row["expect"]), row["case"]
        assert signer.requests == []
        confirmed = run(lambda c: confirm(doc, binding, ACCOUNT, c, inputs), serving(ABC))
        assert isinstance(confirmed, Declined) and confirmed.detail == row["expect"], row["case"]


def test_the_build_compares_the_transfer_with_the_choices_payer() -> None:
    doc = x402_doc(X["V3"]["accepted"], X["fixed"]["resource"])
    choice = {
        "required": doc,
        "accepted": doc["accepts"][0],
        "simulatedXdr": V2["simulatedXdr"],
        "currentLedger": V2["currentLedger"],
    }
    assert not isinstance(X402_EXACT_STELLAR.build({**choice, "payer": PAYER}, H), Refusal)
    assert X402_EXACT_STELLAR.build(choice, H) == Refusal("stellar/payer-mismatch")
    assert X402_EXACT_STELLAR.build({**choice, "payer": CASES["otherPayer"]}, H) == Refusal("stellar/payer-mismatch")
