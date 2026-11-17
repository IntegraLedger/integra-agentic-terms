"""mpp/charge/evm/permit2's bound reads the permit's nonce: the read keys on the Permit2 bit at the challenge hash, so a
permit signed under any other nonce is refused. The credential is mpp-charge-evm-permit2.json's buyer B6, and the nonce
and the refusal are its nonceNotChallengeHash row's: the value draft-evm-charge-00's permit2 payload example signs."""

import copy
from typing import Any

from integraledger_terms import MPP_CHARGE_EVM_PERMIT2, Refusal

from support import load

V = load("mpp-charge-evm-permit2.json")
B6: dict[str, Any] = next(r for r in V["buyer"]["rows"] if r["name"] == "B6")
ROW: dict[str, Any] = V["nonceNotChallengeHash"]


def test_a_permit_whose_nonce_is_not_the_challenge_hash_is_not_bound() -> None:
    presented = copy.deepcopy(B6["input"]["presented"])
    assert MPP_CHARGE_EVM_PERMIT2.bound(presented) == B6["expect"][0]["h"]
    presented["payload"]["permit"]["nonce"] = ROW["nonce"]
    assert MPP_CHARGE_EVM_PERMIT2.bound(presented) == Refusal(ROW["expect"]["code"])
