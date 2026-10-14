"""The gate's rows, as the TypeScript gate's tests run them, for MPP's EVM charges (pairings-mpp.test.ts): B2 and B6 for
authorization and permit2, B16 for authorization, and the plant, MV11's call and the completed finish of transaction and
hash. Expected values are the vector files'; the key is the published Anvil key #0."""

import hashlib
from collections.abc import Iterator
from typing import Any

import pytest
from eth_account import Account

from integraledger_terms import (
    MPP_CHARGE_EVM_AUTHORIZATION,
    MPP_CHARGE_EVM_HASH,
    MPP_CHARGE_EVM_PERMIT2,
    MPP_CHARGE_EVM_TRANSACTION,
    Binding,
    Confirmed,
    Finished,
    confirm,
    finish,
    transact,
)
from integraledger_terms import _gate

from breadth import ABC, H, LINK, Pairing, Recording, build_and_sign, code, offered, plant, run
from mpp_docs import MC, issued, placed_doc
from support import digest, load, serving, sign_typed

AUTH = load("mpp-charge-evm-authorization.json")
PERMIT = load("mpp-charge-evm-permit2.json")
TX = load("mpp-charge-evm-transaction.json")
NOW: int = AUTH["fixed"]["now"]


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    yield


def account(chain: int, fixed: dict[str, Any]) -> str:
    return f"eip155:{chain}:{fixed['payer']}"


def doc_of(request_json: str) -> list[dict[str, Any]]:
    return placed_doc(issued("evm", "charge", request_json), H, LINK)


def eip712(request: Any) -> str:
    assert request["kind"] == "eip712", request
    return sign_typed(request["typedData"])


AUTHORIZATION = Pairing(
    binding=MPP_CHARGE_EVM_AUTHORIZATION,
    doc=doc_of(MC["fixed"]["R_E"]),
    account=account(84532, AUTH["fixed"]),
    answer=eip712,
    inputs={"tokenDomain": AUTH["fixed"]["tokenDomain"]},
)

PERMIT2 = Pairing(
    binding=MPP_CHARGE_EVM_PERMIT2,
    doc=doc_of(MC["fixed"]["R_E"]),
    account=account(84532, PERMIT["fixed"]),
    answer=eip712,
    inputs={"spender": PERMIT["fixed"]["spender"]},
)

def test_mpp_charge_evm_authorization_b6_mv5_digest_and_signature() -> None:
    mv5 = AUTH["MV5"]

    def inspect(request: Any) -> None:
        td = request["typedData"]
        assert digest(td) == mv5["expectDigest"]
        assert td["message"]["nonce"] == mv5["expectNonce"]
        assert eip712(request) == mv5["expectSignature"]

    signed, _ = build_and_sign(AUTHORIZATION, inspect)
    assert signed["source"] == mv5["expectSource"]
    assert signed["payload"]["validBefore"] == mv5["expectValidBefore"]


def test_mpp_charge_evm_authorization_b16_no_payable_option_before_any_fetch() -> None:
    p = AUTHORIZATION
    link = serving(ABC)
    assert code(run(lambda c: confirm(p.doc, p.binding, p.account, c), link)) == "no-payable-option"
    assert code(run(lambda c: confirm(p.doc, p.binding, account(1, AUTH["fixed"]), c, p.inputs), link)) == "no-payable-option"
    other = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x"
    assert code(run(lambda c: confirm(p.doc, p.binding, other, c), link)) == "no-payable-option"
    assert link.calls == 0

def test_mpp_charge_evm_permit2_b6_mv6_digest_and_signature() -> None:
    mv6 = PERMIT["MV6"]

    def inspect(request: Any) -> None:
        assert digest(request["typedData"]) == mv6["expectDigest"]
        assert eip712(request) == mv6["expectSignature"]

    build_and_sign(PERMIT2, inspect)


def signed_tx(request: Any) -> str:
    """The Anvil key's EIP-1559 transaction of the request's call, with MV11's fields."""
    assert request["kind"] == "evm-call", request
    t = TX["MV11"]["transaction"]
    signed = Account.sign_transaction(
        {
            "type": 2,
            "chainId": t["chainId"],
            "nonce": t["nonce"],
            "maxPriorityFeePerGas": int(t["maxPriorityFeePerGas"]),
            "maxFeePerGas": int(t["maxFeePerGas"]),
            "gas": t["gas"],
            "to": request["call"]["to"],
            "value": 0,
            "data": request["call"]["data"],
        },
        TX["fixed"]["payerKey"],
    )
    return "0x" + bytes(signed.raw_transaction).hex()


@pytest.mark.parametrize(
    ("binding", "broadcast"),
    [(MPP_CHARGE_EVM_TRANSACTION, False), (MPP_CHARGE_EVM_HASH, True)],
    ids=["transaction", "hash"],
)
def test_mpp_charge_evm_transaction_and_hash_b2_b6_finish_completes_on_the_agreement(binding: Binding, broadcast: bool) -> None:
    """For a pairing whose proof is the agreement, finish returns the completed payment without reading bound; the
    credential is {challenge, source, payload: {type: "transaction", signature}} or {..., payload: {type: "hash",
    hash}}. With no agreement URL offered, the gate declines agreement-not-offered before any signer call."""
    mv11 = TX["MV11"]

    def answer(request: Any) -> str:
        tx_hash: str = mv11["expectTxHash"]
        return tx_hash if broadcast else signed_tx(request)

    doc: Any = doc_of(TX["fixed"]["R_ENoTypes"])
    acct = account(84532, TX["fixed"])
    plant(Pairing(binding=binding, doc=doc, account=acct, answer=answer))
    signer = Recording(acct, answer)
    assert code(run(lambda c: transact(doc, binding, signer, c), serving(ABC))) == "agreement-not-offered"
    assert signer.requests == []
    confirmed = run(lambda c: confirm(doc, offered(binding), acct, c), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    r = confirmed.request
    assert r is not None and r["kind"] == "evm-call"
    assert r["call"]["data"] == mv11["expectCalldata"]
    assert r["broadcast"] is broadcast
    if not broadcast:
        raw = signed_tx(r)
        assert (len(raw) - 2) // 2 == mv11["expectRawLength"]
        assert "0x" + hashlib.sha256(bytes.fromhex(raw[2:])).hexdigest() == mv11["expectRawSha256"]
    answered = answer(r)
    done = finish(ABC, confirmed.chosen, answered, binding)
    assert isinstance(done, Finished), done
    assert done.h == H
    expected = {"type": "hash", "hash": answered} if broadcast else {"type": "transaction", "signature": answered}
    assert {k: done.signed["payload"][k] for k in expected} == expected

