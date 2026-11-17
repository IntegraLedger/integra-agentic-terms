"""x402/exact/stellar/precondition, the agreement on Stellar: the buyer half's rows of the protocol package's
x402-exact-stellar-precondition.json, whose expected values that file's about names as stellar-sdk 13.0.0's output, and
the buyer piece paying it. The buyer's key is Ed25519 seed 05×32, the file's test value; Ed25519 signs
deterministically, so its signatures are the file's."""

import copy
import hashlib
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_STELLAR_PRECONDITION as BINDING
from integraledger_terms import Advertised, Refusal
from integraledger_terms.bindings._stellar import read_signed_payload, signed_payload
from integraledger_terms.bindings.x402_exact_stellar_precondition import StellarPreconditionUnsigned

import ed25519
from breadth import Pairing, build_and_sign, x402_doc
from support import hexb, load

V = load("x402-exact-stellar-precondition.json")
F: dict[str, Any] = V["fixed"]
B: dict[str, Any] = V["build"]
SEED = bytes([5]) * 32
REQUIRED = {"x402Version": 2, "resource": F["resource"], "accepts": [F["option"]]}


def choice(**change: Any) -> dict[str, Any]:
    """The build's choice from the file's fixed values and its build row, with change's members over it."""
    base = {
        "required": REQUIRED,
        "accepted": F["option"],
        "simulatedXdr": B["simulatedXdr"],
        "currentLedger": B["currentLedger"],
        "payer": F["buyer"],
    }
    return {**copy.deepcopy(base), **change}


def with_option(change: dict[str, Any]) -> dict[str, Any]:
    """The choice whose document offers, and whose accepted is, the file's option with change's members over it."""
    option = {**F["option"], **change}
    return choice(required={**REQUIRED, "accepts": [option]}, accepted=option)


def test_payload_rows() -> None:
    """Each payload row: H, then the int64 value, 8 bytes big-endian two's complement, and read back."""
    assert V["payload"]
    for row in V["payload"]:
        payload = signed_payload(row["h"], int(row["value"]))
        assert payload == hexb(row["payload"]), row["case"]
        read = read_signed_payload(payload)
        assert not isinstance(read, Refusal) and (read.h, read.value) == (row["h"], int(row["value"])), row["case"]


def test_build_row() -> None:
    """The preimage's SHA-256 and the payload are the file's; its signatures complete its envelope and payment, which
    bound reads H from and whose broadcaster is the payee."""
    unsigned = BINDING.build(choice(), F["H"])
    assert isinstance(unsigned, StellarPreconditionUnsigned), unsigned
    request = unsigned.request
    assert request["kind"] == "stellar-precondition"
    assert hashlib.sha256(request["preimage"]).hexdigest() == B["expectPreimageSha256"]
    assert "0x" + request["payload"].hex() == B["expectPayload"]
    payment = unsigned.complete({"entry": bytes.fromhex(B["entrySignature"]), "payload": bytes.fromhex(B["payloadSignature"])})
    assert not isinstance(payment, Refusal) and payment == B["expectPayment"]
    assert payment["payload"]["transaction"] == B["expectEnvelope"]
    assert BINDING.bound(payment) == F["H"]
    assert BINDING.broadcaster(payment) == "payee"


@pytest.mark.parametrize("row", V["refusedBuild"], ids=lambda r: r["case"])
def test_refused_build(row: dict[str, Any]) -> None:
    assert BINDING.build(choice(**row["change"]), F["H"]) == Refusal(row["expect"])


@pytest.mark.parametrize("row", V["refusedFilter"], ids=lambda r: r["case"])
def test_refused_filter(row: dict[str, Any]) -> None:
    """The option with one member changed, chosen: build refuses it with the filter's code before the transaction."""
    assert BINDING.build(with_option(row["change"]), F["H"]) == Refusal(row["expect"])


@pytest.mark.parametrize("row", V["acceptedFilter"], ids=lambda r: r["case"])
def test_accepted_filter(row: dict[str, Any]) -> None:
    option = {**F["option"], **row["change"]}
    assert isinstance(BINDING.read(x402_doc(option, F["resource"])), Advertised)


@pytest.mark.parametrize("row", V["refusedBound"], ids=lambda r: r["case"])
def test_refused_bound(row: dict[str, Any]) -> None:
    presented = copy.deepcopy(B["expectPayment"])
    presented["payload"]["transaction"] = row["envelope"]
    assert BINDING.bound(presented) == Refusal(row["expect"])


def answer(request: Any) -> Any:
    """The buyer's key signs the SHA-256 of the entry's preimage, and the payload raw."""
    assert request["kind"] == "stellar-precondition", request["kind"]
    entry = ed25519.sign(SEED, hashlib.sha256(hexb(request["preimage"])).digest())
    return {"entry": "0x" + entry.hex(), "payload": "0x" + ed25519.sign(SEED, hexb(request["payload"])).hex()}


def test_the_piece_pays_the_file_payment() -> None:
    """B6 through the piece: the request is the build row's, the test signer's answer is the file's two signatures, and
    the payment completed is the file's, with the document's extensions echoed."""
    p = Pairing(
        binding=BINDING,
        doc=x402_doc(F["option"], F["resource"]),
        account=f"{F['network']}:{F['buyer']}",
        answer=answer,
        inputs={"simulatedXdr": B["simulatedXdr"], "currentLedger": B["currentLedger"]},
    )

    def inspect(request: Any) -> None:
        assert hashlib.sha256(hexb(request["preimage"])).hexdigest() == B["expectPreimageSha256"]
        assert request["payload"] == B["expectPayload"]
        assert answer(request) == {"entry": "0x" + B["entrySignature"], "payload": "0x" + B["payloadSignature"]}

    signed, _ = build_and_sign(p, inspect)
    assert {k: v for k, v in signed.items() if k != "extensions"} == B["expectPayment"]
