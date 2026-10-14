"""The gate's rows, as the TypeScript gate's tests run them, for mpp/charge/usdc/evm and mpp/charge/usdc/gateway
(pairings-b7.test.ts): B2 and B6. Expected values are the vector files' (M3 and M5); the key is the published Anvil key
#0."""

import copy
import json
from typing import Any

from eth_account import Account

import pytest

from integraledger_terms import MPP_CHARGE_USDC_EVM, MPP_CHARGE_USDC_GATEWAY, Refusal
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode, canonical_json
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings.mpp_charge_usdc import usdc_gateway_salt

from breadth import H, LINK, Pairing, build_and_sign, plant
from mpp_docs import issued, placed_doc
from support import digest, load, sign_typed

USDC_EVM = load("mpp-charge-usdc-evm.json")
GATEWAY = load("mpp-charge-usdc-gateway.json")


def doc_of(v: dict[str, Any], request_json: str) -> list[dict[str, Any]]:
    f = v["fixed"]
    return placed_doc(issued("usdc", "charge", request_json, f["realm"], f["expires"]), H, LINK)


def eip712(request: Any) -> str:
    assert request["kind"] == "eip712", request
    return sign_typed(request["typedData"])


EVM_P = Pairing(
    binding=MPP_CHARGE_USDC_EVM,
    doc=doc_of(USDC_EVM, USDC_EVM["M3"]["requestJson"]),
    account=f"eip155:84532:{USDC_EVM['fixed']['payer']}",
    answer=eip712,
    inputs={"tokenDomain": USDC_EVM["fixed"]["tokenDomain"]},
)

def test_mpp_charge_usdc_evm_b6_m3_nonce_and_digest() -> None:
    m3 = USDC_EVM["M3"]

    def inspect(request: Any) -> None:
        assert request["kind"] == "eip712"
        assert request["typedData"]["message"]["nonce"] == m3["expectNonce"]
        assert digest(request["typedData"]) == m3["expectDigest"]

    build_and_sign(EVM_P, inspect)


M5 = GATEWAY["M5"]
_BYTES32_FIELDS = (
    "sourceContract",
    "destinationContract",
    "sourceToken",
    "destinationToken",
    "sourceDepositor",
    "destinationRecipient",
    "sourceSigner",
    "destinationCaller",
)


def _own_inputs() -> dict[str, Any]:
    return {k: v for k, v in M5["saltInput"].items() if k != "recipient"}


def burn_intent_signature(burn_intent: dict[str, Any]) -> str:
    """The Anvil key's EIP-712 signature over the burn intent, domain {GatewayWallet, 1} only."""
    types = {
        "TransferSpec": [
            {"name": "version", "type": "uint32"},
            {"name": "sourceDomain", "type": "uint32"},
            {"name": "destinationDomain", "type": "uint32"},
            *({"name": name, "type": "bytes32"} for name in _BYTES32_FIELDS),
            {"name": "value", "type": "uint256"},
            {"name": "salt", "type": "bytes32"},
            {"name": "hookData", "type": "bytes"},
        ],
        "BurnIntent": [
            {"name": "maxBlockHeight", "type": "uint256"},
            {"name": "maxFee", "type": "uint256"},
            {"name": "spec", "type": "TransferSpec"},
        ],
    }
    spec = {**burn_intent["spec"], "value": int(burn_intent["spec"]["value"])}
    message = {"maxBlockHeight": int(burn_intent["maxBlockHeight"]), "maxFee": int(burn_intent["maxFee"]), "spec": spec}
    signed = Account.sign_typed_data(GATEWAY["fixed"]["payerKey"], {"name": "GatewayWallet", "version": "1"}, types, message)
    return "0x" + bytes(signed.signature).hex()


def gateway_answer(request: Any) -> dict[str, Any]:
    assert request["kind"] == "gateway-burn-intent", request
    salt = usdc_gateway_salt({**request["preimage"], **_own_inputs()})
    assert not isinstance(salt, Refusal), salt
    burn_intent = copy.deepcopy(M5["payload"]["authorization"]["transfer"]["burnIntent"])
    burn_intent["spec"]["salt"] = salt
    routes = {k: v for k, v in M5["payload"].items() if k not in ("authorization", "type")}
    return {"source": M5["source"], **routes, "burnIntent": burn_intent, "signature": burn_intent_signature(burn_intent)}


GATEWAY_P = Pairing(
    binding=MPP_CHARGE_USDC_GATEWAY,
    doc=doc_of(GATEWAY, M5["requestJson"]),
    account=M5["source"],
    answer=gateway_answer,
)

def test_mpp_charge_usdc_gateway_b6_the_clients_salt_is_m5s() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "gateway-burn-intent"
        assert json.loads(json.dumps(request)) == request
        assert request["preimage"]["requestHash"] == M5["expectRequestHash"]
        assert usdc_gateway_salt({**request["preimage"], **_own_inputs()}) == M5["expectSalt"]

    build_and_sign(GATEWAY_P, inspect)


_ABSENT = object()


# usdc reads externalId only through its Solana profile, where it is the carrier the payer signs as a memo: absent, or a
# string of at most 566 bytes (draft-solana-charge-00, which the Solana profile inherits). Each expected answer is the
# protocol package's pairingsOf over the profile's B6 offer with the member changed.
@pytest.mark.parametrize("profile", ["evm", "solana", "stacks", "gateway"])
@pytest.mark.parametrize("external_id", [5, "x" * 567, None, _ABSENT], ids=["5", "567 bytes", "null", "absent"])
def test_usdc_reads_external_id_only_through_its_solana_profile(profile: str, external_id: Any) -> None:
    v = load(f"mpp-charge-usdc-{profile}.json")
    placed = next(r for r in v["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]["challenge"]
    offer = {k: x for k, x in placed.items() if k not in ("id", "opaque")}
    raw = b64u_decode(offer["request"], 8192)
    assert raw is not None
    request = json.loads(raw)
    request.pop("externalId", None)
    if external_id is not _ABSENT:
        request["externalId"] = external_id
    offer["request"] = b64u_encode(canonical_json(request).encode("utf-8"))
    pairing = f"mpp/charge/usdc/{profile}"
    if profile == "solana" and external_id is not _ABSENT:
        assert pairings_of(offer) == Refusal("mpp/request-malformed")
    else:
        assert pairings_of(offer) == (pairing,)
