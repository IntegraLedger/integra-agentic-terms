"""spend-permissions/eip155's binding, buyer piece and approval summary, over the protocol package's
spend-permissions-eip155.json. The binding's read, build, bound and broadcaster run the file's rows as the protocol
package's own tests run them: its offer and the refusals of the offer, the body and the build, the returns of both routes
and the refusals of a return's JSON; each hash is viem 2.57.4's, which eth-account's hash of the typed data built here
also gives. The piece is paid on each route over the offer placed for the file's H, the account the file names: its
request is the file's build, the published key #0's eth-account signature is the file's signature, and the payment is
the file's return, whose base64url JSON is the file's Spend-Permission header; each summary member is the file's
permission member it names. The B2 and B6 rows run in test_buyer_rows.py."""

import asyncio
import base64
import copy
from typing import Any

import pytest
from breadth import ABC, Pairing, build_and_sign
from eth_account import Account
from eth_account.messages import encode_typed_data
from support import A, ACCOUNT, HASH_A, KEY, RESOURCE_REQUEST, CountingSigner, load, serving, sign_typed

from integraledger_terms import SPEND_PERMISSIONS_EIP155, Advertised, Declined, Payee, Refusal, Summary, ToSign, Validity, _gate, transact
from integraledger_terms._summary import summary_of
from integraledger_terms.bindings._codec import js_json

V = load("spend-permissions-eip155.json")
F = V["fixed"]
P = V["build"]["expect"]["permission"]
binding = SPEND_PERMISSIONS_EIP155


def changed(o: Any, path: list[str], value: Any = None, absent: bool = False) -> Any:
    """A copy of o with the member at path set to value, or removed where absent."""
    c = copy.deepcopy(o)
    x = c
    for k in path[:-1]:
        x = x[k]
    if absent:
        del x[path[-1]]
    else:
        x[path[-1]] = value
    return c


def expand(v: Any) -> Any:
    """A row's value with each {"$repeat": [s, n]} as s repeated n times, and each {"$repeat0x": [s, n]} with 0x before."""
    if isinstance(v, list):
        return [expand(x) for x in v]
    if not isinstance(v, dict):
        return v
    if "$repeat" in v:
        return v["$repeat"][0] * v["$repeat"][1]
    if "$repeat0x" in v:
        return "0x" + v["$repeat0x"][0] * v["$repeat0x"][1]
    return {k: expand(x) for k, x in v.items()}


def code(v: object) -> str | None:
    return v.code if isinstance(v, Refusal) else None


# ── The binding, over the file's rows.


def test_read_gives_the_file_s_offer() -> None:
    assert binding.read(F["body"]) == Advertised(h=F["H"], link=F["L"], offer=F["offer"])


@pytest.mark.parametrize("r", V["offerRefusals"], ids=lambda r: r["case"])
def test_read_refuses_the_offer(r: dict[str, Any]) -> None:
    assert code(binding.read(changed(F["body"], ["spendPermission", *r["path"]], r["value"]))) == r["expect"]


@pytest.mark.parametrize("r", V["readRefusals"], ids=lambda r: r["case"])
def test_read_refuses_the_body(r: dict[str, Any]) -> None:
    assert code(binding.read(changed(F["body"], r["path"], r.get("value"), r.get("absent") is True))) == r["expect"]


def test_build_gives_the_file_s_permission_hash_typed_data_and_approve_call() -> None:
    u = binding.build(V["build"]["choice"], F["H"])
    assert not isinstance(u, Refusal), u
    e = V["build"]["expect"]
    assert (u.permission, u.hash, u.approve) == (e["permission"], e["hash"], e["approve"])
    assert {k: u.typed_data[k] for k in e["typedData"]} == e["typedData"]
    signed = Account.sign_message(encode_typed_data(full_message=u.typed_data), KEY)
    assert "0x" + bytes(signed.message_hash).hex() == e["hash"]


@pytest.mark.parametrize("r", V["buildRefusals"], ids=lambda r: r["case"])
def test_build_refuses(r: dict[str, Any]) -> None:
    choice = {**V["build"]["choice"], **({"account": r["account"]} if "account" in r else {})}
    assert code(binding.build(choice, r.get("h", F["H"]))) == r["expect"]


@pytest.mark.parametrize("r", [r for r in V["headerRefusals"] if "json" in r], ids=lambda r: r["case"])
def test_bound_refuses_a_return(r: dict[str, Any]) -> None:
    assert code(binding.bound(expand(r["json"]))) == r["expect"]


def test_bound_gives_the_salt_and_broadcaster_names_who_sends_each_route() -> None:
    sig, tx = V["header"]["signature"]["return"], V["header"]["transaction"]["return"]
    assert (binding.bound(sig), binding.bound(tx)) == (F["H"], F["H"])
    other = V["buildRefusals"][0]["h"]
    assert code(binding.bound(sig, given={"act": "agreement", "h": other})) == "spend-permissions/not-bound"
    assert (binding.broadcaster(sig), binding.broadcaster(tx)) == ("payee", "payer")


# ── The piece, paid on each route, and its summary.


def body_for(h: str, accepts: list[str]) -> dict[str, Any]:
    """The file's body placed for h as the protocol package's advertise places it: salt h's decimal, legalContext's
    value h; the offer accepting accepts."""
    body: dict[str, Any] = copy.deepcopy(F["body"])
    offer = body["spendPermission"]
    offer["permission"]["salt"] = str(int(h, 16))
    offer["legalContext"]["value"] = h
    offer["accepts"] = accepts
    return body


def test_the_placement_is_the_file_s_body() -> None:
    assert body_for(F["H"], ["signature", "transaction"]) == F["body"]


SHOWN = Summary(
    payees=(Payee(account=P["spender"], amount=P["allowance"]),),
    period=P["period"],
    limit_per_period=P["allowance"],
    end=P["end"],
    asset=P["token"],
    network=F["network"],
    validity=Validity(not_before=P["start"], not_after=P["end"], unit="seconds"),
    atr=ABC,
)
# The permission stays drawable until its end, past the 600 s default, so the payment through the gate is given a
# ceiling of the permission's whole life, end less start.
CEILINGS = {binding.id: int(P["end"]) - int(P["start"])}


def header(signed: Any) -> str:
    """The Spend-Permission header's value: base64url without padding of the return's JSON."""
    return base64.urlsafe_b64encode(js_json(signed).encode("utf-8")).decode("ascii").rstrip("=")


def test_the_route_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: F["now"])
    assert ACCOUNT.lower() == f"{F['network']}:{F['account']}"

    def inspect(r: Any) -> None:
        assert r["kind"] == "eip712"
        assert sign_typed(r["typedData"]) == F["signature"]

    p = Pairing(
        binding=binding,
        doc=body_for(F["H"], ["signature", "transaction"]),
        account=ACCOUNT,
        answer=lambda r: sign_typed(r["typedData"]),
        placed=lambda h: body_for(h, ["signature", "transaction"]),
        ceilings=CEILINGS,
    )
    signed, request = build_and_sign(p, inspect)
    assert signed == V["header"]["signature"]["return"]
    assert header(signed) == V["header"]["signature"]["value"]
    assert summary_of(binding.id, request, ABC) == SHOWN


def test_the_route_transaction_where_the_offer_accepts_it_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: F["now"])
    sent = V["header"]["transaction"]["return"]["transaction"]
    chain = int(F["network"].split(":")[1])

    def inspect(r: Any) -> None:
        assert r == {"kind": "evm-call", "chainId": chain, "call": V["build"]["expect"]["approve"], "broadcast": True}

    p = Pairing(
        binding=binding,
        doc=body_for(F["H"], ["transaction"]),
        account=ACCOUNT,
        answer=lambda r: sent,
        placed=lambda h: body_for(h, ["transaction"]),
        ceilings=CEILINGS,
    )
    signed, request = build_and_sign(p, inspect)
    assert signed == V["header"]["transaction"]["return"]
    assert header(signed) == V["header"]["transaction"]["value"]
    assert summary_of(binding.id, request, ABC) == SHOWN


# The Spend Permission is the sale's agreement and never a charge (the pairing's data holds agreement.only): through
# transact the approver is asked about it as the act "agreement". The offer is the file's, placed for buyer.json's ATR A.
def test_transact_asks_the_approver_about_the_permission_as_the_agreement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: F["now"])
    asked: list[ToSign] = []

    def approver(t: ToSign) -> bool:
        asked.append(t)
        return False

    async def go() -> Any:
        async with serving(A).client() as client:
            return await transact(
                body_for(HASH_A, ["signature"]), binding, CountingSigner(), client,
                approver=approver, resource_request=RESOURCE_REQUEST, ceilings=CEILINGS,
            )

    out = asyncio.run(go())
    assert isinstance(out, Declined) and out.code == "not-approved", out
    assert [a.act for a in asked] == ["agreement"]
