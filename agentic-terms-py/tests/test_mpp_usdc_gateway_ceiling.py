"""mpp/charge/usdc/gateway's ceiling, as mpp-charge-usdc-gateway.json's ceiling rows state it: build is given the
network the burn intent spends from, the burnIntentExpirationHeight Circle Gateway's GET /v1/info serves for it and its
Gateway Wallet's withdrawalDelay(), and writes maxBlockHeight, their ceiling, into the request; complete refuses a
signed burn intent on another network or at another maxBlockHeight. Every input and expected value is the file's; the
burn intent is M5's, signed with the file's payer key."""

import copy
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_USDC_GATEWAY, Refusal

from test_mpp_usdc import GATEWAY, M5, burn_intent_signature, doc_of

CEILING: dict[str, Any] = GATEWAY["ceiling"]
H: str = GATEWAY["fixed"]["H"]
GOOD = {k: v for k, v in CEILING["good"].items() if k != "expectMaxBlockHeight"}
BURN_INTENT: dict[str, Any] = M5["payload"]["authorization"]["transfer"]["burnIntent"]
OWN = {k: v for k, v in M5["payload"].items() if k not in ("authorization", "type")}


def refusal(expect: dict[str, Any]) -> Refusal:
    assert expect["refused"] is True
    return Refusal(expect["code"])


def build(**served: Any) -> Any:
    challenge = doc_of(GATEWAY, M5["requestJson"])[0]
    return MPP_CHARGE_USDC_GATEWAY.build({"challenge": challenge, **served}, H)


def completed(burn_intent: dict[str, Any], **served: Any) -> Any:
    u = build(**{**GOOD, **served})
    assert not isinstance(u, Refusal), u
    signature = burn_intent_signature(BURN_INTENT)
    return u.complete({"source": M5["source"], **OWN, "burnIntent": burn_intent, "signature": signature})


def test_build_writes_the_ceiling_m5s_burn_intent_signs_and_complete_takes_it() -> None:
    u = build(**GOOD)
    assert not isinstance(u, Refusal), u
    assert u.request["maxBlockHeight"] == CEILING["good"]["expectMaxBlockHeight"] == BURN_INTENT["maxBlockHeight"]
    credential = completed(copy.deepcopy(BURN_INTENT))
    assert not isinstance(credential, Refusal), credential
    assert MPP_CHARGE_USDC_GATEWAY.bound(credential) == M5["expectBound"]


@pytest.mark.parametrize("row", CEILING["built"], ids=[r["case"] for r in CEILING["built"]])
def test_build_writes(row: dict[str, Any]) -> None:
    u = build(**{**GOOD, **{k: row[k] for k in ("burnIntentExpirationHeight", "withdrawalDelay")}})
    assert not isinstance(u, Refusal), u
    assert u.request["maxBlockHeight"] == row["expectMaxBlockHeight"]


@pytest.mark.parametrize("row", CEILING["buildRefusals"], ids=[r["case"] for r in CEILING["buildRefusals"]])
def test_build_refuses(row: dict[str, Any]) -> None:
    served = {**GOOD, **row.get("set", {})}
    served.pop(row.get("omit", ""), None)
    assert build(**served) == refusal(row["expect"])


def test_complete_refuses_a_credential_on_another_network_than_the_one_the_height_was_read_for() -> None:
    row = CEILING["sourceNetworkChanged"]
    assert OWN["sourceNetwork"] != row["choiceSourceNetwork"]
    assert completed(copy.deepcopy(BURN_INTENT), sourceNetwork=row["choiceSourceNetwork"]) == refusal(row["expect"])


@pytest.mark.parametrize("row", CEILING["completeRefusals"], ids=[r["case"] for r in CEILING["completeRefusals"]])
def test_complete_refuses(row: dict[str, Any]) -> None:
    """Each row changes M5's burn intent's maxBlockHeight; the stock row's is the stock client's own, which the row
    states, over M5's spec."""
    burn_intent = copy.deepcopy(BURN_INTENT)
    if row.get("stock") is True:
        burn_intent["maxBlockHeight"] = row["expectStockMaxBlockHeight"]
    elif row.get("omit") is True:
        del burn_intent["maxBlockHeight"]
    else:
        burn_intent["maxBlockHeight"] = row["set"]
    assert completed(burn_intent) == refusal(row["expect"])
