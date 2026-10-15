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
    Refusal,
    confirm,
    finish,
    transact,
)
from integraledger_terms import _gate
from integraledger_terms.bindings._rlp import rlp_bytes, rlp_decode, rlp_list, rlp_uint_bytes

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


def test_mpp_charge_evm_transaction_complete_takes_an_eip1559_transaction_for_the_challenge_chain() -> None:
    """draft-evm-charge-00 (tempoxyz/mpp-specs 08e7dd87) L696-697 and L873-879: the transaction credential carries an
    EIP-1559 transaction, which the server deserializes and holds to methodDetails.chainId before it broadcasts. The
    build's complete reads it so: bytes that are not an EIP-1559 transaction are mpp/credential-malformed, and one for
    another chain is evm/chain-mismatch. The agreedRefusals rows' transactions are signed again here by the payer key
    with eth-account: row 0's are MV11's with each of its chainIds, and row 1's MV11's transfer as a legacy (EIP-155)
    and an EIP-2930 transaction, then MV11's followed by one zero byte."""
    rows = [r for r in TX["agreedRefusals"]["rows"] if "transactions" in r]
    assert [r["expect"] for r in rows] == ["evm/chain-mismatch", "mpp/credential-malformed"]
    t = TX["MV11"]["transaction"]
    fields = {"nonce": t["nonce"], "gas": t["gas"], "to": t["to"], "value": 0, "data": TX["MV11"]["expectCalldata"]}
    fees = {"maxPriorityFeePerGas": int(t["maxPriorityFeePerGas"]), "maxFeePerGas": int(t["maxFeePerGas"])}

    def signed(tx: dict[str, Any]) -> str:
        return "0x" + bytes(Account.sign_transaction(tx, TX["fixed"]["payerKey"]).raw_transaction).hex()

    mv11 = signed({"type": 2, "chainId": t["chainId"], **fields, **fees})
    assert "0x" + hashlib.sha256(bytes.fromhex(mv11[2:])).hexdigest() == TX["MV11"]["expectRawSha256"]
    assert [signed({"type": 2, "chainId": c, **fields, **fees}) for c in rows[0]["chainIds"]] == rows[0]["transactions"]
    priced = {"chainId": t["chainId"], **fields, "gasPrice": int(t["maxFeePerGas"])}
    legacy, eip2930 = signed(priced), signed({"type": 1, **priced, "accessList": []})
    assert [legacy, eip2930, mv11 + "00"] == rows[1]["transactions"]
    challenge = doc_of(TX["fixed"]["R_ENoTypes"])[0]
    payer = TX["fixed"]["payer"]
    u = MPP_CHARGE_EVM_TRANSACTION.build({"challenge": challenge, "from": payer, "now": NOW}, H)
    assert not isinstance(u, Refusal), u
    payload = {"type": "transaction", "signature": mv11}
    source = f"did:pkh:eip155:{t['chainId']}:{payer}"
    assert u.complete(mv11) == {"challenge": challenge, "source": source, "payload": payload}
    # An access list nests three lists deep in the transaction's list; a transaction that carries one is taken too.
    access = [{"address": t["to"], "storageKeys": [H]}]
    listed = signed({"type": 2, "chainId": t["chainId"], **fields, **fees, "accessList": access})
    assert not isinstance(u.complete(listed), Refusal)
    for row in rows:
        for wire in row["transactions"]:
            assert (row["expect"], wire, u.complete(wire)) == (row["expect"], wire, Refusal(row["expect"]))


def test_mpp_charge_evm_transaction_complete_takes_the_eip1559_form_only() -> None:
    """EIP-2718: a typed transaction's first byte names its type, and EIP-1559's is 0x02; EIP-1559: its payload is the
    RLP list of twelve fields, the destination and the data byte strings, the access list a list; RLP (the Yellow
    Paper, Appendix B): an integer is its big-endian bytes without a leading zero byte. Each wire here is MV11's
    transaction with one of those changed, and the build's complete refuses each mpp/credential-malformed: MV11's
    twelve fields under type 0x01; eleven fields, and thirteen; a list as the destination, and as the data; a byte
    string as the access list; a nonce with a leading zero byte. MV11's transfer signed for the chain above the
    challenge's is evm/chain-mismatch, as row 0's chain below it is."""
    t = TX["MV11"]["transaction"]
    fields = {"nonce": t["nonce"], "gas": t["gas"], "to": t["to"], "value": 0, "data": TX["MV11"]["expectCalldata"]}
    fees = {"maxPriorityFeePerGas": int(t["maxPriorityFeePerGas"]), "maxFeePerGas": int(t["maxFeePerGas"])}

    def signed(chain_id: int) -> str:
        tx = {"type": 2, "chainId": chain_id, **fields, **fees}
        return "0x" + bytes(Account.sign_transaction(tx, TX["fixed"]["payerKey"]).raw_transaction).hex()

    mv11 = signed(t["chainId"])
    top = rlp_decode(bytes.fromhex(mv11[4:]), 3)
    assert mv11[:4] == "0x02" and top is not None and top.items is not None and len(top.items) == 12
    raws = [item.raw for item in top.items]

    def typed(items: list[bytes], kind: str = "02") -> str:
        return "0x" + kind + rlp_list(items).hex()

    assert typed(raws) == mv11
    challenge = doc_of(TX["fixed"]["R_ENoTypes"])[0]
    u = MPP_CHARGE_EVM_TRANSACTION.build({"challenge": challenge, "from": TX["fixed"]["payer"], "now": NOW}, H)
    assert not isinstance(u, Refusal), u
    assert not isinstance(u.complete(mv11), Refusal)
    malformed = {
        "type 0x01": typed(raws, "01"),
        "eleven fields": typed(raws[:11]),
        "thirteen fields": typed([*raws, rlp_uint_bytes(0)]),
        "a list as the destination": typed([*raws[:5], rlp_list([]), *raws[6:]]),
        "a list as the data": typed([*raws[:7], rlp_list([]), *raws[8:]]),
        "a byte string as the access list": typed([*raws[:8], rlp_bytes(b""), *raws[9:]]),
        "a nonce with a leading zero byte": typed([raws[0], rlp_bytes(b"\x00"), *raws[2:]]),
    }
    for case, wire in malformed.items():
        assert (case, u.complete(wire)) == (case, Refusal("mpp/credential-malformed"))
    assert u.complete(signed(t["chainId"] + 1)) == Refusal("evm/chain-mismatch")
