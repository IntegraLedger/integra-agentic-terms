"""B2, B6, B10, B16, the payment identifier and the inputs rows for x402/exact/near, and the buyer half's vector rows.
Expected values are x402-exact-near.json's."""

import base64
import hashlib
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_NEAR, Refusal, _gate

import ed25519
from breadth import Pairing, build_and_sign, plant, x402_doc
from hbar_support import EVM_ACCOUNT, b10, b16, identifier_row, inputs_row
from support import hexb, load

N = load("x402-exact-near.json")
F: dict[str, Any] = N["fixed"]
SEED = bytes.fromhex(F["seedHex"])
NOW = 1790000000


def near_answer(request: Any) -> Any:
    if request["kind"] != "near-delegate":
        raise AssertionError(request["kind"])
    return {"keyType": 0, "bytes": "0x" + ed25519.sign(SEED, hexb(request["hash"])).hex()}


NEAR = Pairing(
    binding=X402_EXACT_NEAR,
    doc=x402_doc(F["O"], F["resource"]),
    account=f"{F['O']['network']}:{F['payer']}",
    answer=near_answer,
    inputs={"publicKey": F["publicKey"], "accessKeyNonce": F["accessKeyNonce"], "finalHeight": F["finalHeight"]},
)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)

def test_x402_exact_near_b6_request_is_the_vectors_and_signature_completes_v2() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "near-delegate"
        assert hexb(request["hash"]).hex() == N["V1"]["expectRequestHash"]
        sig = ed25519.sign(SEED, hexb(request["hash"])).hex()
        assert sig.startswith(N["V1"]["expectSignature"]["prefix"]) and sig.endswith(N["V1"]["expectSignature"]["suffix"])

    signed, _ = build_and_sign(NEAR, inspect)
    assert signed["payload"]["signedDelegateAction"] == N["V2"]["expectSignedDelegateAction"]


def test_x402_exact_near_b6_payment_identifier() -> None:
    identifier_row(NEAR)


def test_x402_exact_near_b10_http_link() -> None:
    b10(NEAR)


def test_x402_exact_near_b16_other_accounts() -> None:
    b16(NEAR, [EVM_ACCOUNT, f"near:mainnet:{F['payer']}"])


def test_x402_exact_near_inputs() -> None:
    inputs_row(NEAR, {"publicKey": F["publicKey"], "accessKeyNonce": "100"}, "x402/input-missing")
    inputs_row(NEAR, {"publicKey": F["publicKey"], "accessKeyNonce": 100, "finalHeight": "200000000"}, "x402/input-missing")


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def presented(sda: str) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": F["O"], "payload": {"signedDelegateAction": sda}}


def near_choice(option: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    offered = option if option is not None else F["O"]
    value: dict[str, Any] = {
        "required": {"x402Version": 2, "resource": F["resource"], "accepts": [offered]},
        "accepted": offered,
        "payer": F["payer"],
        "publicKey": F["publicKey"],
        "accessKeyNonce": int(F["accessKeyNonce"]),
        "finalHeight": int(F["finalHeight"]),
    }
    value.update(changes)
    return value


def test_x402_exact_near_v1_args_and_request_hash() -> None:
    from integraledger_terms.bindings.x402_exact_near import ft_transfer_args

    args = ft_transfer_args(F["O"]["payTo"], F["O"]["amount"], F["H"])
    assert isinstance(args, bytes)
    assert args.decode() == N["V1"]["expectArgsUtf8"]
    assert hashlib.sha256(args).hexdigest() == N["V1"]["expectArgsSha256"]
    unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert unsigned.request["hash"].hex() == N["V1"]["expectRequestHash"]
    sda = base64.b64decode(N["V2"]["expectSignedDelegateAction"])
    assert len(sda) - 65 == N["V1"]["expectDelegateActionBytes"]
    assert (1073742190).to_bytes(4, "little").hex() == N["V1"]["expectPrefix"]
    assert hashlib.sha256(bytes.fromhex(N["V1"]["expectPrefix"]) + sda[:-65]).hexdigest() == N["V1"]["expectRequestHash"]


def test_x402_exact_near_v2_complete_and_bound() -> None:
    unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete({"keyType": 0, "bytes": ed25519.sign(SEED, unsigned.request["hash"])})
    assert not isinstance(signed, Refusal)
    assert signed["payload"]["signedDelegateAction"] == N["V2"]["expectSignedDelegateAction"]
    assert X402_EXACT_NEAR.bound(signed) == N["V2"]["expectBound"]
    for row in N["V2"]["refusals"]:
        assert X402_EXACT_NEAR.bound(presented(row["signedDelegateAction"])) == Refusal(row["expect"]), row["case"]


def delegate_with_height(height: int) -> bytes:
    """V2's delegate action with its maxBlockHeight, the u64 before the 33-byte public key, set to height."""
    delegate = base64.b64decode(N["V2"]["expectSignedDelegateAction"])[:-65]
    at = len(delegate) - 33 - 8
    return delegate[:at] + height.to_bytes(8, "little") + delegate[at + 8 :]


def test_x402_exact_near_any_integer_timeout_and_a_window_of_at_least_one_block() -> None:
    # x402's scheme_exact_near maps maxTimeoutSeconds to max(1, ...) blocks, so read, build and bound take any safe
    # integer. The expected request hash is V2's delegate action with maxBlockHeight finalHeight + 1, under V1's prefix.
    prefix = bytes.fromhex(N["V1"]["expectPrefix"])
    final = int(F["finalHeight"])
    assert hashlib.sha256(prefix + delegate_with_height(final + 60)).hexdigest() == N["V1"]["expectRequestHash"]
    one_block = hashlib.sha256(prefix + delegate_with_height(final + 1)).hexdigest()
    for timeout in (1, 0, -60, -(2**53 - 1)):
        option = {**F["O"], "maxTimeoutSeconds": timeout}
        read = X402_EXACT_NEAR.read(x402_doc(option, F["resource"]))
        assert not isinstance(read, Refusal) and read.offer["options"] == [option], timeout
        unsigned = X402_EXACT_NEAR.build(near_choice(option), F["H"])
        assert not isinstance(unsigned, Refusal), timeout
        assert unsigned.request["hash"].hex() == one_block, timeout
        under = {**presented(N["V2"]["expectSignedDelegateAction"]), "accepted": option}
        assert X402_EXACT_NEAR.bound(under) == N["V2"]["expectBound"], timeout
    absent = {k: v for k, v in F["O"].items() if k != "maxTimeoutSeconds"}
    for option in [absent, *({**F["O"], "maxTimeoutSeconds": v} for v in ("60", 1.5, 2**53, None, True))]:
        assert X402_EXACT_NEAR.build(near_choice(option), F["H"]) == Refusal("near/option-malformed"), option


def test_x402_exact_near_agreed_refusals() -> None:
    for row in N["agreedRefusals"]["rows"]:
        if "option" in row:
            assert X402_EXACT_NEAR.build(near_choice(row["option"]), F["H"]) == Refusal(row["expect"]), row["case"]
        elif "signedDelegateAction" in row:
            assert X402_EXACT_NEAR.bound(presented(row["signedDelegateAction"])) == Refusal(row["expect"]), row["case"]
        elif "publicKey" in row:
            assert X402_EXACT_NEAR.build(near_choice(publicKey=row["publicKey"]), F["H"]) == Refusal(row["expect"])
        elif "signatureBytes" in row:
            unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
            assert not isinstance(unsigned, Refusal)
            answer = {"keyType": 0, "bytes": bytes(row["signatureBytes"])}
            assert unsigned.complete(answer) == Refusal(row["expect"])
