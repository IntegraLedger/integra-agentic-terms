"""The gate's rows, as the TypeScript gate's tests run them, for x402 batch-settlement on EVM and Cloudflare: B2, B6,
B10 and B16, the deposit, and the drawn authorization salt. Expected digests, signatures, nonces and channel ids are the
vector file's; the keys are the published Anvil development keys the file names."""

import copy
import re
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import (
    X402_BATCH_SETTLEMENT_CLOUDFLARE,
    X402_BATCH_SETTLEMENT_EIP155,
    Binding,
    ChannelRef,
    Checked,
    Confirmed,
    Declined,
    Finished,
    Refusal,
    Transacted,
    _gate,
    check,
    confirm,
    finish,
    transact,
)

from integraledger_terms._keccak import keccak256
from integraledger_terms.bindings._batch_evm import CHANNEL_CONFIG_TYPEHASH, batch_channel_id, erc3009_deposit_nonce

from breadth import ABC, ABD, H, LINK, Pairing, Recording, build_and_sign, code, never, offered, plant, receipt, run, x402_doc
from support import load, serving

BV = load("x402-batch-settlement.json")
RESOURCE = BV["fixed"]["resource"]
E = BV["fixed"]["evm"]


def sign(key: str, typed_data: dict[str, Any]) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=copy.deepcopy(typed_data)), key)
    return "0x" + bytes(signed.signature).hex()


def digest(typed_data: dict[str, Any]) -> str:
    signable = encode_typed_data(full_message=copy.deepcopy(typed_data))
    return "0x" + bytes(Account.sign_message(signable, E["payerKey"]).message_hash).hex()


def http_link(doc: dict[str, Any]) -> dict[str, Any]:
    """The same document with its legal-context link written as http://."""
    out = copy.deepcopy(doc)
    out["extensions"]["legalContext"]["info"]["legalContextUrl"] = LINK.replace("https://", "http://")
    return out


def b10(doc: Any, binding: Binding, account: str, ns: str, inputs: dict[str, Any] | None = None) -> None:
    """The document with an http link is unreadable, detail <ns>/link-not-https, and nothing is fetched."""
    link = serving(ABC)
    out = run(lambda c: confirm(doc, binding, account, c, inputs), link)
    assert isinstance(out, Declined) and out.code == "offer-unreadable" and out.detail == f"{ns}/link-not-https", out
    assert link.calls == 0


def b16(doc: Any, binding: Binding, accounts: list[str], inputs: dict[str, Any] | None = None) -> None:
    """Each account is declined no-payable-option, and nothing is fetched."""
    link = serving(ABC)
    for account in accounts:
        assert code(run(lambda c: confirm(doc, binding, account, c, inputs), link)) == "no-payable-option"
    assert link.calls == 0


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: E["now"])


# ── x402/batch-settlement/eip155

EVM_DOC = x402_doc(E["option"], RESOURCE)
EVM_ACCOUNT = f"eip155:84532:{E['payer']}"
EVM_INPUTS = {"payerAuthorizer": E["payerAuthorizer"], "deposit": E["deposit"], "authSalt": E["authSalt"]}


def evm_answer(request: Any) -> list[str]:
    """The payer signs the token authorization; the payer authorizer signs the voucher (EB3, EB2)."""
    assert request["kind"] == "batch", request
    keys = [E["payerKey"], E["payerAuthorizerKey"]]
    return [sign(keys[i], q["typedData"]) for i, q in enumerate(request["requests"])]


EVM = Pairing(X402_BATCH_SETTLEMENT_EIP155, EVM_DOC, EVM_ACCOUNT, evm_answer, EVM_INPUTS)

def test_x402_batch_settlement_eip155_b6_build_and_sign() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "batch" and len(request["requests"]) == 2
        auth, voucher = request["requests"]
        assert auth["kind"] == "eip712" and voucher["kind"] == "eip712"
        assert digest(auth["typedData"]) == BV["EB3"]["digest"]
        assert auth["typedData"]["message"]["nonce"] == BV["EB3"]["depositNonce"]
        assert digest(voucher["typedData"]) == BV["EB2"]["digest"]
        assert evm_answer(request) == [BV["EB3"]["signature"], BV["EB2"]["signature"]]

    signed, _ = build_and_sign(EVM, inspect)
    payload = signed["payload"]
    assert payload["type"] == "deposit"
    assert payload["channelConfig"]["salt"] == H
    assert payload["voucher"] == {
        "channelId": BV["EB1"]["channelId"],
        "maxClaimableAmount": "1000",
        "signature": BV["EB2"]["signature"],
    }
    assert payload["deposit"]["authorization"]["erc3009Authorization"] == {
        "validAfter": "0",
        "validBefore": E["validBefore"],
        "salt": E["authSalt"],
        "signature": BV["EB3"]["signature"],
    }
    assert X402_BATCH_SETTLEMENT_EIP155.channel_kind(signed) == "open"
    assert X402_BATCH_SETTLEMENT_EIP155.channel_ref(signed) == ChannelRef(**BV["EB6"]["expectRef"])


def test_x402_batch_settlement_eip155_b10_http_link() -> None:
    b10(http_link(EVM_DOC), X402_BATCH_SETTLEMENT_EIP155, EVM_ACCOUNT, "x402", EVM_INPUTS)


def test_x402_batch_settlement_eip155_b16_other_namespace_and_chain() -> None:
    accounts = ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", f"eip155:1:{E['payer']}"]
    b16(EVM_DOC, X402_BATCH_SETTLEMENT_EIP155, accounts, EVM_INPUTS)


def test_x402_batch_settlement_eip155_the_deposit() -> None:
    """extra.minDeposit when present, the buyer's maximum refused before any fetch; the payer authorizer required."""
    link = serving(ABC)
    over = run(lambda c: confirm(EVM_DOC, X402_BATCH_SETTLEMENT_EIP155, EVM_ACCOUNT, c,
                                 {**EVM_INPUTS, "maxDeposit": "99999"}), link)  # fmt: skip
    assert isinstance(over, Declined) and over.code == "no-payable-option"
    assert over.detail == "x402/deposit-above-maximum"
    no_authorizer = run(lambda c: confirm(EVM_DOC, X402_BATCH_SETTLEMENT_EIP155, EVM_ACCOUNT, c,
                                          {"deposit": E["deposit"]}), link)  # fmt: skip
    assert isinstance(no_authorizer, Declined) and no_authorizer.detail == "x402/input-missing"
    assert link.calls == 0
    option = copy.deepcopy(E["option"])
    option["extra"]["minDeposit"] = "250000"
    with_min = x402_doc(option, RESOURCE)
    confirmed = run(lambda c: confirm(with_min, X402_BATCH_SETTLEMENT_EIP155, EVM_ACCOUNT, c,
                                      {**EVM_INPUTS, "deposit": "1"}), serving(ABC))  # fmt: skip
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.chosen.choice["deposit"] == "250000"


def test_x402_batch_settlement_eip155_an_absent_authorization_salt_is_drawn_once() -> None:
    """An absent authorization salt is drawn once, kept in chosen, and finish rebuilds the same request."""
    no_salt = {k: v for k, v in EVM_INPUTS.items() if k != "authSalt"}
    confirmed = run(lambda c: confirm(EVM_DOC, X402_BATCH_SETTLEMENT_EIP155, EVM_ACCOUNT, c, no_salt), serving(ABC))
    assert isinstance(confirmed, Confirmed) and confirmed.request is not None, confirmed
    salt = confirmed.chosen.choice["authSalt"]
    assert re.fullmatch(r"0x[0-9a-f]{64}", salt)
    chosen = copy.deepcopy(confirmed.chosen)
    done = finish(ABC, chosen, evm_answer(confirmed.request), X402_BATCH_SETTLEMENT_EIP155)
    assert isinstance(done, Finished), done
    assert done.signed["payload"]["deposit"]["authorization"]["erc3009Authorization"]["salt"] == salt


# ── x402/batch-settlement/cloudflare

CF_OPTION = BV["EC1"]["payload"]["accepted"]
CF_DOC = x402_doc(CF_OPTION, RESOURCE)
CF_ACCOUNT = "cloudflare:402:agent.example"

def test_x402_batch_settlement_cloudflare_b6_the_build_is_the_payment() -> None:
    """The build is the payment; EC1's echoed legal context; no signer call; check against abc and abd."""
    binding = X402_BATCH_SETTLEMENT_CLOUDFLARE
    confirmed = run(lambda c: confirm(CF_DOC, offered(binding), CF_ACCOUNT, c), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.request is None
    done = finish(ABC, copy.deepcopy(confirmed.chosen), None, binding)
    assert isinstance(done, Finished), done
    assert done.signed["payload"] == {"amount": "5", "asset": "USD"}
    assert done.signed["accepted"] == CF_OPTION
    assert done.signed["extensions"]["legalContext"]["info"] == BV["EC1"]["payload"]["extensions"]["legalContext"]["info"]
    signer = Recording(CF_ACCOUNT, never)
    whole = run(lambda c: transact(CF_DOC, offered(binding), signer, c), serving(ABC))
    assert isinstance(whole, Transacted), whole
    assert whole.agreement == receipt()
    assert signer.requests == []
    assert check(ABC, done.signed, binding) == Checked(h=H)
    assert code(check(ABD, done.signed, binding)) == "signed-not-bound"


def test_x402_batch_settlement_cloudflare_b10_http_link() -> None:
    b10(http_link(CF_DOC), X402_BATCH_SETTLEMENT_CLOUDFLARE, CF_ACCOUNT, "x402")


def test_x402_batch_settlement_cloudflare_b16_other_namespace_and_network() -> None:
    accounts = ["eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "cloudflare:403:agent.example"]
    b16(CF_DOC, X402_BATCH_SETTLEMENT_CLOUDFLARE, accounts)


# ── The bindings' buyer-side rows for these pairings.


def test_eb1_channel_id_and_eb5_eb8_config() -> None:
    assert "0x" + keccak256(E["channelConfigType"].encode()).hex() == CHANNEL_CONFIG_TYPEHASH
    assert batch_channel_id(E["chainId"], E["config"]) == BV["EB1"]["channelId"]
    assert batch_channel_id(8453, E["config"]) == BV["EB1"]["onBase8453"]
    assert batch_channel_id(E["chainId"], {**E["config"], "salt": BV["fixed"]["Hprime"]}) == BV["EB1"]["withHprime"]
    assert erc3009_deposit_nonce(BV["EB1"]["channelId"], E["authSalt"]) == BV["EB3"]["depositNonce"]


def test_eb4_permit2_deposit() -> None:
    option = copy.deepcopy(E["option"])
    option["extra"]["assetTransferMethod"] = "permit2"
    choice = {"required": x402_doc(option, RESOURCE), "accepted": option, "from": E["payer"], "now": E["now"],
              "payerAuthorizer": E["payerAuthorizer"], "deposit": int(E["deposit"]), "authSalt": E["authSalt"]}  # fmt: skip
    unsigned = X402_BATCH_SETTLEMENT_EIP155.build(choice, H)
    assert not isinstance(unsigned, Refusal), unsigned
    auth = unsigned.requests[0]["typedData"]
    assert auth["primaryType"] == "PermitWitnessTransferFrom"
    assert digest(auth) == BV["EB4"]["digest"]
    assert str(auth["message"]["nonce"]) == BV["EB4"]["nonce"] and str(auth["message"]["deadline"]) == BV["EB4"]["deadline"]


def test_eb6_kinds_bound_and_plant() -> None:
    confirmed = run(lambda c: confirm(EVM_DOC, X402_BATCH_SETTLEMENT_EIP155, EVM_ACCOUNT, c, EVM_INPUTS), serving(ABC))
    assert isinstance(confirmed, Confirmed) and confirmed.request is not None
    done = finish(ABC, confirmed.chosen, evm_answer(confirmed.request), X402_BATCH_SETTLEMENT_EIP155)
    assert isinstance(done, Finished)
    opening = done.signed
    binding = X402_BATCH_SETTLEMENT_EIP155
    assert binding.bound(opening) == BV["EB6"]["expectBound"]
    assert binding.channel_kind(opening) == BV["EB6"]["expectKindDeposit"]
    voucher = copy.deepcopy(opening)
    voucher["payload"] = {k: opening["payload"][k] for k in ("channelConfig", "voucher")} | {"type": "voucher"}
    assert binding.channel_kind(voucher) == BV["EB6"]["expectKindVoucher"]
    assert binding.bound_within(voucher) == BV["EB6"]["expectBoundWithin"]
    assert binding.bound(voucher) == Refusal("x402/not-an-opening")
    refund = copy.deepcopy(voucher)
    refund["payload"]["type"] = "refund"
    assert binding.channel_kind(refund) == BV["EB6"]["expectKindRefund"]
    refund["payload"]["amount"] = BV["EB6"]["refundAmount"]
    assert binding.channel_kind(refund) == BV["EB6"]["expectKindPartialRefund"]
    planted = copy.deepcopy(voucher)
    planted["payload"]["channelConfig"]["salt"] = BV["fixed"]["Hprime"]
    assert binding.bound_within(planted) == Refusal(BV["EB6"]["plant"]["expect"])
    planted["payload"]["voucher"]["channelId"] = BV["EB6"]["plant"]["matchedChannelId"]
    assert binding.bound_within(planted) == BV["EB6"]["plant"]["expectBoundWithinMatched"]


def test_ec1_cloudflare_bound() -> None:
    binding = X402_BATCH_SETTLEMENT_CLOUDFLARE
    payload = copy.deepcopy(BV["EC1"]["payload"])
    assert binding.bound(payload) == BV["EC1"]["expectBound"]
    del payload["extensions"]
    assert binding.bound(payload) == Refusal(BV["EC1"]["withoutExtensions"])
