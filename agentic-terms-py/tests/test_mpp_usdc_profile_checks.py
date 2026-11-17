"""What MPP's usdc method requires of its EVM and Gateway profiles before either is named, as v00 of the draft states
it (draft-usdc-charge-00 at tempoxyz/mpp-specs 1f0574a): the EVM profile's decimals 6 and credentialTypes absent or
["authorization"] (lines 297-298), the Gateway profile's credentialTypes absent or ["transfer"] (line 414), and an EVM
currency that is the native USDC Circle publishes for the chainId (lines 300-301; Circle's USDC Contract Addresses, read
on 2026-11-17: Base 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, Base Sepolia
0x036CbD53842c5426634e7929541eC2318f3dCF7e). The requests are mpp-charge-usdc-evm.json's M3 and
mpp-charge-usdc-gateway.json's M5, with the member each case names changed."""

import json
from collections.abc import Callable
from typing import Any

from integraledger_terms import Refusal
from integraledger_terms.bindings._codec import canonical_json
from integraledger_terms.bindings._mpp import pairings_of

from mpp_docs import issued
from support import load

M3: dict[str, Any] = json.loads(load("mpp-charge-usdc-evm.json")["M3"]["requestJson"])
M5: dict[str, Any] = json.loads(load("mpp-charge-usdc-gateway.json")["M5"]["requestJson"])
BASE_SEPOLIA_USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"


def named(request: dict[str, Any], profile: str, edit: Callable[[dict[str, Any]], object]) -> Any:
    """pairings_of over the request, its profile's details edited, written in its RFC 8785 form."""
    changed = json.loads(json.dumps(request))
    edit(changed["methodDetails"][profile])
    return pairings_of(issued("usdc", "charge", canonical_json(changed)))


def test_the_evm_profile_takes_decimals_6_and_authorization_alone() -> None:
    assert named(M3, "evm", lambda d: None) == ("mpp/charge/usdc/evm",)
    assert named(M3, "evm", lambda d: d.pop("credentialTypes")) == ("mpp/charge/usdc/evm",)
    assert named(M3, "evm", lambda d: d.update(credentialTypes=["permit2"])) == Refusal("mpp/credential-types")
    assert named(M3, "evm", lambda d: d.update(decimals=18)) == Refusal("mpp/request-malformed")


def test_the_evm_currency_is_the_native_usdc_of_the_chain() -> None:
    def on(chain_id: int, currency: str) -> Any:
        request = {**M3, "currency": currency}
        return named(request, "evm", lambda d: d.update(chainId=chain_id))

    assert on(8453, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913") == ("mpp/charge/usdc/evm",)
    assert on(84532, BASE_SEPOLIA_USDC.lower()) == ("mpp/charge/usdc/evm",)
    assert on(8453, BASE_SEPOLIA_USDC) == Refusal("mpp/usdc-not-native")


def test_the_gateway_profile_takes_transfer_alone() -> None:
    assert named(M5, "gateway", lambda d: d.update(credentialTypes=["transfer"])) == ("mpp/charge/usdc/gateway",)
    refused = named(M5, "gateway", lambda d: d.update(credentialTypes=["authorization"]))
    assert refused == Refusal("mpp/credential-types")
