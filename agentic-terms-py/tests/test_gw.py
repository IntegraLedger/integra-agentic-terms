"""Circle Gateway's two forms on the buyer's side: the binding, piece and summary of x402/exact/eip155/gateway-batched,
and the served floor of it and of mpp/charge/usdc/gateway (terms' profile buyer-gate.md, rules 9 and 13). Every input is
lcp's: x402-exact-eip155-gateway-batched.json's S rows (the typed data Circle's own client, @circle-fin/x402-batching
4.0.0, handed its signer, the signature it returned and the payment it made), W, build, filter, eip3009Filter and bound
rows, and wallets rows (that client's network table); and mpp-charge-usdc-gateway.json's B2 row and its build's refusal
rows. Every expected value is the row's, or the profile's rule for the row's input."""

import copy
from typing import Any

import pytest
from breadth import Pairing, Recording, build_and_sign, run
from eth_account import Account
from eth_account.messages import encode_typed_data
from support import Link, load

import httpx
from integraledger_terms import (
    FLOOR_INPUTS,
    MPP_CHARGE_USDC_GATEWAY,
    X402_EXACT_EIP155_EIP3009,
    X402_EXACT_EIP155_GATEWAY_BATCHED,
    Declined,
    Refusal,
    _gate,
)
from integraledger_terms._summary import summary_of
from support import confirm, transact

PAIRING = "x402/exact/eip155/gateway-batched"
V = load("x402-exact-eip155-gateway-batched.json")
F = V["fixed"]
H: str = F["H"]
BATCHED = X402_EXACT_EIP155_GATEWAY_BATCHED


def doc_of(o: dict[str, Any]) -> dict[str, Any]:
    """The seller's document for one option, carrying H and the link as the file's B2 row's document does."""
    return {"x402Version": 2, "resource": F["resource"], "accepts": [o], "extensions": F["extensions"]}


def choice_of(o: dict[str, Any], **more: Any) -> dict[str, Any]:
    return {"required": doc_of(o), "accepted": o, "from": F["payer"], "now": F["now"], "minValiditySeconds": F["minValiditySeconds"], **more}


def at(pointer: str) -> Any:
    """The value at a JSON Pointer (RFC 6901) into the file."""
    v: Any = V
    for k in pointer.split("/")[1:]:
        v = v[int(k)] if isinstance(v, list) else v[k]
    return v


def with_set(v: Any, changes: dict[str, Any]) -> Any:
    """A copy of v with each dotted path set to its value, or removed where the value is None."""
    out = copy.deepcopy(v)
    for path, value in changes.items():
        *parents, last = path.split(".")
        o = out
        for k in parents:
            o = o[k]
        if value is None:
            o.pop(last, None)
        else:
            o[last] = value
    return out


def signs(request: Any) -> str:
    assert request["kind"] == "eip712", request
    signed = Account.sign_message(encode_typed_data(full_message=copy.deepcopy(request["typedData"])), F["payerKey"])
    return "0x" + bytes(signed.signature).hex()


def summary_values(o: dict[str, Any]) -> Any:
    unsigned = BATCHED.build(choice_of(o), H)
    assert not isinstance(unsigned, Refusal), unsigned
    shown = summary_of(PAIRING, {"kind": "eip712", "typedData": unsigned.typed_data}, b"a")
    return None if shown is None else (shown.asset.lower(), shown.network)


@pytest.mark.parametrize("row", V["S"], ids=[r["case"] for r in V["S"]])
def test_s_circles_authorization_built_signed_bound_and_shown(row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """The signer is handed the typed data Circle's client signs, its signature completes Circle's payment, bound reads
    H and the summary shows what the typed data signs."""
    o = F[row["option"]]
    a = row["payment"]["payload"]["authorization"]
    monkeypatch.setattr(_gate, "_now", lambda: F["now"])

    def inspect(request: Any) -> None:
        domain = request["typedData"]["domain"]
        assert {**domain, **({"salt": domain["salt"].lower()} if "salt" in domain else {})} == {
            **row["domain"], **({"salt": row["domain"]["salt"].lower()} if "salt" in row["domain"] else {})
        }
        assert signs(request) == row["signature"]
        shown = summary_of(PAIRING, request, b"a")
        assert shown is not None
        assert (shown.amount, [(p.account, p.amount) for p in shown.payees], shown.asset.lower(), shown.network) == (
            a["value"], [(a["to"], a["value"])], o["asset"].lower(), o["network"])
        assert (shown.validity.not_before, shown.validity.not_after, shown.validity.unit) == (a["validAfter"], a["validBefore"], "seconds")

    build_and_sign(Pairing(BATCHED, doc_of(o), f"{o['network']}:{F['payer']}", signs, {"minValiditySeconds": F["minValiditySeconds"]}), inspect)
    unsigned = BATCHED.build(choice_of(o), H)
    assert not isinstance(unsigned, Refusal)
    assert unsigned.complete(row["signature"]) == row["payment"]
    assert BATCHED.bound(row["payment"]) == H
    assert BATCHED.broadcaster(row["payment"]) == "payee"


@pytest.mark.parametrize("row", V["W"], ids=[r["case"] for r in V["W"]])
def test_w_the_validity_window(row: dict[str, Any]) -> None:
    o = {**F["O2"], "maxTimeoutSeconds": row["maxTimeoutSeconds"]}
    unsigned = BATCHED.build(choice_of(o, now=row["now"], minValiditySeconds=row["minValiditySeconds"]), H)
    assert not isinstance(unsigned, Refusal)
    m = unsigned.typed_data["message"]
    assert (str(m["validAfter"]), str(m["validBefore"])) == (row["validAfter"], row["validBefore"])


@pytest.mark.parametrize("row", V["build"], ids=[r["case"] for r in V["build"]])
def test_build_refuses_the_choice(row: dict[str, Any]) -> None:
    assert not isinstance(BATCHED.build(choice_of(F["O2"]), H), Refusal)
    assert BATCHED.build(with_set(choice_of(F["O2"]), row["set"]), H) == Refusal(row["expect"])


@pytest.mark.parametrize("row", V["filter"], ids=[r["case"] for r in V["filter"]])
def test_filter(row: dict[str, Any]) -> None:
    """An offered option is read and built; any other is not read, and build refuses it with the row's code."""
    o = row["option"]
    read, built = BATCHED.read(doc_of(o)), BATCHED.build(choice_of(o), H)
    if row["expect"] == "offered":
        assert not isinstance(read, Refusal) and not isinstance(built, Refusal)
    else:
        assert (read, built) == (Refusal("x402/no-payable-option"), Refusal(row["expect"]))


@pytest.mark.parametrize("row", V["eip3009Filter"], ids=[r["case"] for r in V["eip3009Filter"]])
def test_eip3009_refuses_the_batched_option(row: dict[str, Any]) -> None:
    o = row["option"]
    assert X402_EXACT_EIP155_EIP3009.read(doc_of(o)) == Refusal("x402/no-payable-option")
    choice = {"required": doc_of(o), "accepted": o, "from": F["payer"], "now": F["now"]}
    assert X402_EXACT_EIP155_EIP3009.build(choice, H) == Refusal(row["expect"])


@pytest.mark.parametrize("row", V["bound"], ids=[r["case"] for r in V["bound"]])
def test_bound(row: dict[str, Any]) -> None:
    got = BATCHED.bound(with_set(at(row["payment"]), row["set"]))
    assert got == (Refusal(row["expect"]) if row["expect"].startswith("x402/") else row["expect"])


@pytest.mark.parametrize("row", V["wallets"], ids=[r["name"] for r in V["wallets"]])
def test_wallets_the_summary_shows_each_networks_usdc(row: dict[str, Any]) -> None:
    """Version 1, whose domain names no token, shows the network's USDC; version 2 the token its salt names."""
    v1 = {**F["O1"], "network": row["network"], "asset": row["usdc"], "extra": {**F["O1"]["extra"], "verifyingContract": row["gatewayWallet"]}}
    v2 = {**v1, "extra": {**v1["extra"], "version": "2"}}
    assert [summary_values(v1), summary_values(v2)] == [(row["usdc"].lower(), row["network"])] * 2


# ── mpp/charge/usdc/gateway's served floor.

G = load("mpp-charge-usdc-gateway.json")
B2 = next(r for r in G["buyer"]["rows"] if r["name"] == "B2")["input"]


def test_floor_inputs_name_the_inputs_lcps_b2_row_gives_the_build() -> None:
    assert sorted(FLOOR_INPUTS["mpp/charge/usdc/gateway"]) == sorted(B2["inputs"])


@pytest.mark.parametrize("r", G["ceiling"]["buildRefusals"], ids=[r["case"] for r in G["ceiling"]["buildRefusals"]])
def test_a_floor_input_absent_or_of_another_form_is_floor_missing(r: dict[str, Any]) -> None:
    """Each refusal row that omits one input, or gives one in another form, is floor-missing naming it, before the offer
    is read; the row that gives both heights in form, whose sum the build refuses, passes the floor and meets B2's
    plant."""
    changed = [r["omit"]] if "omit" in r else list(r.get("set", {}))
    inputs = {**B2["inputs"], **r.get("set", {})}
    if "omit" in r:
        del inputs[r["omit"]]
    signer = Recording(B2["account"], lambda request: (_ for _ in ()).throw(AssertionError("no signer call")))
    link = Link(lambda request: httpx.Response(200, content=bytes.fromhex(B2["servesHex"])))
    out = run(lambda c: transact(copy.deepcopy(B2["doc"]), MPP_CHARGE_USDC_GATEWAY, signer, c, inputs=inputs), link)
    confirmed = run(lambda c: confirm(copy.deepcopy(B2["doc"]), MPP_CHARGE_USDC_GATEWAY, B2["account"], c, inputs), link)
    for got in (out, confirmed):
        assert isinstance(got, Declined)
        assert (got.code, got.detail) == ("floor-missing", changed[0]) if len(changed) == 1 else got.code == "hash-mismatch"
    assert (signer.requests, link.calls) == ([], 0 if len(changed) == 1 else 2)
