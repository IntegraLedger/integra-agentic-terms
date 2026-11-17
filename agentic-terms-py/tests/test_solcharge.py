"""The buyer pieces of mpp/charge/solana/unsponsored and mpp/subscription/solana, over the protocol package's
mpp-charge-solana.json and mpp-subscription-solana.json, as solcharge.test.ts runs them. The unsponsored charge is held
to that file's unsponsored credential, whose transaction is the stock @solana/mpp 0.7.0 client's composition for the
placed challenge, computed with @solana/kit 8.4.0 and not by the protocol package's builder: the payer pays its own fee,
and the transfer and memo it signs are the stock client's. The payer's key is x402-exact-solana.json's fixed.payerSeed,
whose address is the file's payer. The subscription's activation is the stock client's to compose and sign, so the gate
hands the signer nothing: its challenge is the file's, placed with H and the link. The account and inputs are each
file's B2 row's."""

import base64
from typing import Any

from breadth import H, LINK, Pairing, build_and_sign, confirms_only, never
from mpp_docs import lcp_carrier, place_carrier
from support import hexb, load
from test_sol import decompile, signing

from integraledger_terms import MPP_CHARGE_SOLANA_UNSPONSORED, MPP_SUBSCRIPTION_SOLANA, Refusal
from integraledger_terms.bindings import _svm

S = load("mpp-charge-solana.json")
X = load("x402-exact-solana.json")
SUB = load("mpp-subscription-solana.json")


def pointer(doc: Any, path: str) -> Any:
    """The value at an RFC 6901 JSON Pointer."""
    at = doc
    for part in path.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        at = at[int(key)] if isinstance(at, list) else at[key]
    return at


def b2(file: dict[str, Any], pairing: str) -> dict[str, Any]:
    found: list[dict[str, Any]] = [r for r in file["buyer"]["rows"] if r["pairing"] == pairing and r["name"] == "B2"]
    assert len(found) == 1, pairing
    return found[0]


def beyond_budget(instructions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The instructions other than the Compute Budget program's, whose prices and limits are each client's own."""
    return [ix for ix in instructions if ix["program"] != _svm.COMPUTE_BUDGET]


def test_mpp_charge_solana_unsponsored_the_payer_is_the_fee_payer_and_signs_the_stock_clients_transfer() -> None:
    u = S["unsponsored"]
    row = b2(S, "mpp/charge/solana/unsponsored")
    landed = _svm.decode_svm_tx(base64.b64decode(pointer(S, u["credential"])["payload"]["transaction"]))
    assert not isinstance(landed, Refusal), landed
    stock = decompile(landed.message)
    assert beyond_budget(stock["instructions"])

    def inspect(request: Any) -> None:
        assert request["kind"] == "solana-message"
        m = decompile(hexb(request["message"]))
        assert [m["feePayer"], stock["feePayer"]] == [u["expectReferenceFeePayer"], u["expectReferenceFeePayer"]]
        assert beyond_budget(m["instructions"]) == beyond_budget(stock["instructions"])

    p = Pairing(
        binding=MPP_CHARGE_SOLANA_UNSPONSORED,
        doc=[u["placed"]],
        account=row["input"]["account"],
        answer=signing(X["fixed"]["payerSeed"]),
        inputs=row["input"].get("inputs", {}),
    )
    signed, _ = build_and_sign(p, inspect)
    assert signed["payload"]["type"] == "transaction"


def test_mpp_subscription_solana_confirm_only_nothing_is_handed_to_the_signer() -> None:
    placed = place_carrier([SUB["challenge"]], H, LINK, SUB["challenge"], lcp_carrier(H, "svm/carrier-occupied"))
    assert isinstance(placed, list), placed
    confirmed = confirms_only(
        Pairing(binding=MPP_SUBSCRIPTION_SOLANA, doc=placed, account=b2(SUB, "mpp/subscription/solana")["input"]["account"], answer=never)
    )
    assert confirmed.chosen.pairing == "mpp/subscription/solana"
