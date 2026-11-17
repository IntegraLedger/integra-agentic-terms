"""ucp/checkout/ap2-mandate's build and complete, buyer side, as ucp.json's V2, V4 and V5 rows state them: build writes
the checkout JWT, the business's detached authorization with the checkout reinserted (built.J), and its hash as the
claims the buyer's checkout mandate carries; complete pairs the signed mandate with that JWT, and refuses a mandate that
commits to another, as bound would. Every input and expected value is ucp.json's or ap2-checkout-mandate.json's."""

from typing import Any

from integraledger_terms import UCP_CHECKOUT_AP2_MANDATE, Advertised, Refusal
from integraledger_terms.bindings.ucp import UcpUnsigned, checkout_jwt

from support import load

UCP = load("ucp.json")
AP2 = load("ap2-checkout-mandate.json")
F: dict[str, Any] = UCP["fixed"]
J: str = UCP["built"]["J"]
M: str = UCP["built"]["M"]
SIGNED: dict[str, Any] = {**UCP["V2"]["expectCheckout"], "ap2": {"merchant_authorization": F["merchantAuthorization"]}}


def built() -> UcpUnsigned:
    r = UCP_CHECKOUT_AP2_MANDATE.read(SIGNED)
    assert isinstance(r, Advertised), r
    u = UCP_CHECKOUT_AP2_MANDATE.build(r.offer, F["H"])
    assert isinstance(u, UcpUnsigned), u
    return u


def test_v4_build_writes_the_checkout_jwt_and_its_hash_and_complete_pairs_the_mandate_with_it() -> None:
    assert checkout_jwt(SIGNED) == J
    assert len(J) == UCP["V2"]["expectJLength"]
    assert checkout_jwt(UCP["V2"]["expectCheckout"]) == Refusal("ucp/ap2-not-active")
    u = built()
    assert u.checkout is SIGNED
    claims = {"vct": "mandate.checkout.1", "checkout_jwt": J, "checkout_hash": UCP["V4"]["expectCheckoutHash"]}
    assert u.content == claims
    presented = u.complete(M)
    assert presented == {"checkout_mandate": M, "checkout_jwt": J}
    assert UCP_CHECKOUT_AP2_MANDATE.bound(presented) == UCP["V4"]["expectBound"]


def test_v5_complete_refuses_ap2s_published_chain_which_commits_to_another_checkout_jwt() -> None:
    """ap2-checkout-mandate.json V7's chained presentation discloses and commits to AP2's own checkout JWT, not to this
    checkout's, so complete refuses it as bound would."""
    assert built().complete(AP2["V7"]["token"]) == Refusal("ap2/checkout-not-latest")
