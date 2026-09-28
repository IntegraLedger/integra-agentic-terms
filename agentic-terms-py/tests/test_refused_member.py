"""A presented payment or credential that carries a refused member, the member refusals use, is refused by bound, as
@integraledger/lcp's refusal reference defines: an EIP-3009 payment is x402/payload-malformed, a Casper payment
casper/payload-malformed, and an MPP credential mpp/credential-malformed, whatever the member's value. Each payment is
its vector file's B6 row, which bound reads as the row's H without the member."""

import copy
from typing import Any

import pytest
from support import load

from integraledger_terms import (
    MPP_CHARGE_EVM_AUTHORIZATION,
    MPP_CHARGE_XRPL,
    X402_EXACT_CASPER,
    X402_EXACT_EIP155_EIP3009,
    Refusal,
)


def b6(name: str, pairing: str) -> tuple[dict[str, Any], str]:
    rows = load(name)["buyer"]["rows"]
    row = next(r for r in rows if r["name"] == "B6" and r["pairing"] == pairing)
    return row["input"]["presented"], row["expect"][0]["h"]


CASES = [
    ("x402-exact-eip155-eip3009.json", X402_EXACT_EIP155_EIP3009, "x402/payload-malformed"),
    ("x402-exact-casper.json", X402_EXACT_CASPER, "casper/payload-malformed"),
    ("mpp-charge-xrpl.json", MPP_CHARGE_XRPL, "mpp/credential-malformed"),
    ("mpp-charge-evm-authorization.json", MPP_CHARGE_EVM_AUTHORIZATION, "mpp/credential-malformed"),
]


@pytest.mark.parametrize(("name", "binding", "code"), CASES, ids=[c[0] for c in CASES])
def test_a_refused_member_is_refused(name: str, binding: Any, code: str) -> None:
    presented, h = b6(name, binding.id)
    assert binding.bound(copy.deepcopy(presented)) == h
    for value in (True, False, {"code": "x"}):
        assert binding.bound({**copy.deepcopy(presented), "refused": value}) == Refusal(code)
