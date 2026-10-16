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
    X402_BATCH_SETTLEMENT_SOLANA,
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
    """extra.minDeposit when present, else the buyer's deposit; the payer authorizer required before any fetch."""
    link = serving(ABC)
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


# ── A choice that is not an object.

PAIRINGS: dict[str, Any] = {
    b.id: b for b in (X402_BATCH_SETTLEMENT_EIP155, X402_BATCH_SETTLEMENT_SOLANA, X402_BATCH_SETTLEMENT_CLOUDFLARE)
}
CALLS = {"build": "build", "buildWithin": "build_within"}


def test_a_choice_that_is_not_an_object_is_not_v2() -> None:
    """The EVM build and build_within, and the Cloudflare build, answer x402/not-v2 before they read the choice, as
    @integraledger/lcp's evmBuild, evmBuildWithin and cfBuild do."""
    values: list[Any] = [None, "x", [], 42]
    for value in values:
        for call in (
            X402_BATCH_SETTLEMENT_EIP155.build,
            X402_BATCH_SETTLEMENT_EIP155.build_within,
            X402_BATCH_SETTLEMENT_CLOUDFLARE.build,
        ):
            assert call(value, H) == Refusal("x402/not-v2"), (call, value)


def test_agreed_refusals_with_a_choice() -> None:
    """The file holds agreedRefusals rows that carry a choice. The row's pairing runs its call, build or buildWithin,
    on that choice with H, and answers the row's refusal."""
    rows = [r for r in BV["agreedRefusals"]["rows"] if "choice" in r]
    assert rows, "no agreedRefusals row carries a choice"
    for row in rows:
        call = getattr(PAIRINGS[row["pairing"]], CALLS[row["call"]])
        assert call(copy.deepcopy(row["choice"]), H) == Refusal(row["expect"]), row["case"]


# ── The EVM agreedRefusals rows that carry their input in one member. Each test selects the rows by that member and
# runs each name in the row's calls, on EB2 and EB3's opening: the build of fixed.evm.option under H with fixed.evm's
# payer, payer authorizer, deposit, authSalt and now, completed with the payer's and the payer authorizer's signatures,
# with its ERC-3009 authorization and with a Permit2 one. The Python binding has no EVM reference: a row's reference is
# run by the TypeScript package's tests.

ZERO_ADDRESS = "0x" + "0" * 40
U128 = 2**128
U256 = 2**256
NOT_IN_PYTHON = {"reference"}


def evm_rows(member: str) -> list[dict[str, Any]]:
    """The x402/batch-settlement/eip155 agreedRefusals rows that carry member; there is at least one."""
    pairing = X402_BATCH_SETTLEMENT_EIP155.id
    rows = [r for r in BV["agreedRefusals"]["rows"] if member in r and r.get("pairing") == pairing]
    assert rows, f"no x402/batch-settlement/eip155 agreedRefusals row carries {member}"
    return rows


def evm_choice(option: dict[str, Any], **members: Any) -> dict[str, Any]:
    """EB2 and EB3's choice of option advertised under H, with members replaced."""
    doc = x402_doc(option, RESOURCE)
    choice = {"required": doc, "accepted": doc["accepts"][0], "from": E["payer"], "now": E["now"],
              "payerAuthorizer": E["payerAuthorizer"], "deposit": int(E["deposit"]), "authSalt": E["authSalt"]}  # fmt: skip
    return choice | members


def evm_opening(method: str | None = None) -> dict[str, Any]:
    """EB2 and EB3's opening, with a Permit2 deposit authorization when method is permit2."""
    option = copy.deepcopy(E["option"])
    if method is not None:
        option["extra"]["assetTransferMethod"] = method
    unsigned = X402_BATCH_SETTLEMENT_EIP155.build(evm_choice(option), H)
    assert not isinstance(unsigned, Refusal), unsigned
    token_auth, voucher = (r["typedData"] for r in unsigned.requests)
    payment = unsigned.complete([sign(E["payerKey"], token_auth), sign(E["payerAuthorizerKey"], voucher)])
    assert not isinstance(payment, Refusal), payment
    return payment


EVM_OPENINGS = {"eip3009": evm_opening(), "permit2": evm_opening("permit2")}


def eip712_channel_id(config: dict[str, Any]) -> str:
    """The channel id of a configuration on Base Sepolia: eth-account's EIP-712 hash of ChannelConfig under the channel
    contract's domain, the one EB1's channel id is of."""
    typed = {
        "domain": {"name": "x402 Batch Settlement", "version": "1", "chainId": E["chainId"],
                   "verifyingContract": "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003"},  # fmt: skip
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
            "ChannelConfig": [{"name": n, "type": "address"} for n in ("payer", "payerAuthorizer", "receiver",
                                                                         "receiverAuthorizer", "token")]
            + [{"name": "withdrawDelay", "type": "uint40"}, {"name": "salt", "type": "bytes32"}],
        },  # fmt: skip
        "primaryType": "ChannelConfig",
        "message": config,
    }
    return digest(typed)


def with_deposit(payment: dict[str, Any], **members: Any) -> dict[str, Any]:
    """The payment with members of its deposit, and of its deposit authorization's one form, replaced."""
    out = copy.deepcopy(payment)
    deposit = out["payload"]["deposit"]
    form = next(iter(deposit["authorization"].values()))
    for name, value in members.items():
        (deposit if name == "amount" else form)[name] = value
    return out


def test_agreed_refusals_an_evm_deposit_amount() -> None:
    """The rows with a depositAmount: bound of the opening, with either authorization, whose deposit.amount is the row's
    gives its refusal. The channel contract's deposit takes the amount as a uint128 and refuses 0 (x402-foundation/x402
    751590a2, contracts/evm/src/x402BatchSettlement.sol L202 and L213), so 1 and 2^128 - 1 give H."""
    rows = evm_rows("depositAmount")
    for form, opening in EVM_OPENINGS.items():
        for row in rows:
            assert set(row["calls"]) <= {"bound"} | NOT_IN_PYTHON, row["case"]
            assert X402_BATCH_SETTLEMENT_EIP155.bound(with_deposit(opening, amount=row["depositAmount"])) == Refusal(
                row["expect"]
            ), (form, row["case"])
        for amount in ("1", "340282366920938463463374607431768211455"):
            assert int(amount) in (1, U128 - 1)
            assert X402_BATCH_SETTLEMENT_EIP155.bound(with_deposit(opening, amount=amount)) == H, (form, amount)


def test_agreed_refusals_an_evm_validbefore_or_deadline() -> None:
    """The rows with a validBeforeOrDeadline: bound of the opening whose ERC-3009 validBefore, or Permit2 deadline, is
    the row's gives its refusal. The deposit collectors decode it as a uint256 (x402-foundation/x402 751590a2,
    contracts/evm/src/periphery/ERC3009DepositCollector.sol L41-42 and Permit2DepositCollector.sol L83-84), so
    2^256 - 1 gives H."""
    rows = evm_rows("validBeforeOrDeadline")
    largest = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    assert int(largest) == U256 - 1
    for form, opening in EVM_OPENINGS.items():
        name = "validBefore" if form == "eip3009" else "deadline"
        for row in rows:
            assert set(row["calls"]) <= {"bound"} | NOT_IN_PYTHON, row["case"]
            presented = with_deposit(opening, **{name: row["validBeforeOrDeadline"]})
            assert X402_BATCH_SETTLEMENT_EIP155.bound(presented) == Refusal(row["expect"]), (form, row["case"])
        assert X402_BATCH_SETTLEMENT_EIP155.bound(with_deposit(opening, **{name: largest})) == H, form


def test_agreed_refusals_an_evm_channel_config_the_deposit_refuses() -> None:
    """The rows with configMembers: each member set replaces those members of the opening's channelConfig, and the
    voucher carries the channel id of the configuration that results, so only the members' form decides. Each name in
    the row's calls refuses it with the row's code. The channel contract's deposit reverts InvalidChannel on a zero
    payer, receiver, receiverAuthorizer or token, and WithdrawDelayOutOfRange outside 900 to 2 592 000
    (x402-foundation/x402 751590a2, contracts/evm/src/x402BatchSettlement.sol L85-86 and L206-212), and takes a zero
    payerAuthorizer, so the delays 900 and 2 592 000 and a zero payerAuthorizer are read."""
    rows = evm_rows("configMembers")
    binding = X402_BATCH_SETTLEMENT_EIP155
    assert eip712_channel_id(E["config"]) == BV["EB1"]["channelId"]

    def runs(opening: dict[str, Any], members: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        presented = copy.deepcopy(opening)
        config = presented["payload"]["channelConfig"] | members
        presented["payload"]["channelConfig"] = config
        presented["payload"]["voucher"]["channelId"] = eip712_channel_id(config)
        w = {"required": EVM_DOC, "accepted": EVM_DOC["accepts"][0], "channelConfig": config,
             "maxClaimableAmount": int(BV["EB2"]["maxClaimableAmount"])}  # fmt: skip
        calls = {
            "bound": lambda: binding.bound(presented),
            "channel.ref": lambda: binding.channel_ref(presented),
            "channel.boundWithin": lambda: binding.bound_within(presented),
            "buildWithin": lambda: binding.build_within(w, H),
        }
        return config, calls

    for form, opening in EVM_OPENINGS.items():
        for row in rows:
            for members in row["configMembers"]:
                _, calls = runs(opening, members)
                assert set(row["calls"]) <= set(calls) | NOT_IN_PYTHON, row["case"]
                for name in row["calls"]:
                    if name not in NOT_IN_PYTHON:
                        assert calls[name]() == Refusal(row["expect"]), (form, name, members)
        for members in ({"withdrawDelay": 900}, {"withdrawDelay": 2592000}, {"payerAuthorizer": ZERO_ADDRESS}):
            config, calls = runs(opening, members)
            channel = eip712_channel_id(config).lower()
            assert calls["bound"]() == H, (form, members)
            assert calls["channel.ref"]() == ChannelRef("eip155:84532", channel), (form, members)
            assert calls["channel.boundWithin"]() == H, (form, members)
            assert not isinstance(calls["buildWithin"](), Refusal), (form, members)


def test_agreed_refusals_an_evm_bound_reads_the_channel_config_before_the_deposit() -> None:
    """The rows with configMembers: bound of the opening with each member set and no deposit authorization gives the
    row's refusal, not x402/deposit-authorization, as @integraledger/lcp's bound reads the channelConfig before the
    deposit."""
    for row in evm_rows("configMembers"):
        for members in row["configMembers"]:
            presented = copy.deepcopy(EVM_OPENINGS["eip3009"])
            config = presented["payload"]["channelConfig"] | members
            presented["payload"]["channelConfig"] = config
            presented["payload"]["voucher"]["channelId"] = eip712_channel_id(config)
            del presented["payload"]["deposit"]["authorization"]
            assert X402_BATCH_SETTLEMENT_EIP155.bound(presented) == Refusal(row["expect"]), members


def test_agreed_refusals_an_evm_build_with_a_zero_member() -> None:
    """The rows with zeroMembers: build of EB2 and EB3's choice with each named member the zero address, from in the
    choice, or payTo or asset in fixed.evm.option, gives the row's refusal: the channel contract's deposit refuses
    such a configuration (InvalidChannel). A zero payerAuthorizer builds."""
    rows = evm_rows("zeroMembers")
    build = X402_BATCH_SETTLEMENT_EIP155.build
    for row in rows:
        assert row["call"] == "build", row["case"]
        for member in row["zeroMembers"]:
            if member == "from":
                given = evm_choice(E["option"], **{"from": ZERO_ADDRESS})
            else:
                given = evm_choice(E["option"] | {member: ZERO_ADDRESS})
            assert build(given, H) == Refusal(row["expect"]), member
    assert not isinstance(build(evm_choice(E["option"], payerAuthorizer=ZERO_ADDRESS), H), Refusal)


def test_agreed_refusals_an_evm_refund_amount() -> None:
    """The rows with refundAmounts: channel_kind, and channel_ref, which gives channel_kind's refusal, of a refund that
    carries the opening's channelConfig and voucher, with each value as its amount, give the row's refusal. The channel
    contract's refund takes a uint128 and refuses 0 (x402-foundation/x402 751590a2,
    contracts/evm/src/x402BatchSettlement.sol L399, L418 and L555): a refund with no amount is the close, and the
    amounts 1 and 2^128 - 1 are within; channel_ref of each gives the opening's channel."""
    rows = evm_rows("refundAmounts")
    payload = EVM_OPENINGS["eip3009"]["payload"]

    def refund(*amount: Any) -> dict[str, Any]:
        out = copy.deepcopy(EVM_OPENINGS["eip3009"])
        out["payload"] = {"type": "refund", "channelConfig": payload["channelConfig"], "voucher": payload["voucher"]}
        if amount:
            out["payload"]["amount"] = amount[0]
        return out

    b = X402_BATCH_SETTLEMENT_EIP155
    members = {"channel.kind": b.channel_kind, "channel.ref": b.channel_ref}
    assert sorted(c for row in rows for c in row["calls"]) == ["channel.kind", "channel.ref"]
    for row in rows:
        for call in row["calls"]:
            for amount in row["refundAmounts"]:
                assert members[call](refund(amount)) == Refusal(row["expect"]), (row["case"], call, amount)
    opened = b.channel_ref(EVM_OPENINGS["eip3009"])
    assert not isinstance(opened, Refusal), opened
    assert b.channel_kind(refund()) == "close"
    assert b.channel_ref(refund()) == opened
    for amount in ("1", str(U128 - 1)):
        assert b.channel_kind(refund(amount)) == "within", amount
        assert b.channel_ref(refund(amount)) == opened, amount


def test_agreed_refusals_an_evm_payload_type_the_scheme_does_not_define() -> None:
    """The EVM rows with payloadTypes: channel.kind and channel.ref of EB2 and EB3's opening whose payload type is the
    row's give the row's refusal: channel.ref refuses a payment channel.kind refuses, with channel.kind's code."""
    rows = evm_rows("payloadTypes")
    assert len(rows) == 1
    b = X402_BATCH_SETTLEMENT_EIP155
    members = {"channel.kind": b.channel_kind, "channel.ref": b.channel_ref}
    for row in rows:
        assert row["calls"] == ["channel.kind", "channel.ref"], row["case"]
        for t in row["payloadTypes"]:
            out = copy.deepcopy(EVM_OPENINGS["eip3009"])
            out["payload"]["type"] = t
            for call in row["calls"]:
                assert members[call](out) == Refusal(row["expect"]), (row["case"], call, t)


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


def test_eb6_a_decimal_with_a_leading_zero_reads_as_its_value() -> None:
    """The opening with deposit amount 0100000 and validBefore 01790003600, or with 100000 written in 40 digits, gives
    EB6's H and channel: the deposit's decimals are read by their value."""
    opening = EVM_OPENINGS["eip3009"]
    assert opening["payload"]["deposit"]["amount"] == E["deposit"] == "100000"
    padded = with_deposit(opening, amount="0" + E["deposit"], validBefore="0" + E["validBefore"])
    wide = with_deposit(opening, amount=E["deposit"].rjust(40, "0"))
    assert len(wide["payload"]["deposit"]["amount"]) == 40
    for presented in (padded, wide):
        assert X402_BATCH_SETTLEMENT_EIP155.bound(presented) == BV["EB6"]["expectBound"]
        assert X402_BATCH_SETTLEMENT_EIP155.channel_ref(presented) == ChannelRef(**BV["EB6"]["expectRef"])


def test_eb9_the_evm_within_refund() -> None:
    """The file holds EB9 rows. build_within over EB1's channel with EB2's maxClaimableAmount, its one request
    completed with EB2's signature, gives the row's payment type and amount, or its refusal."""
    rows = BV.get("EB9", {}).get("rows", [])
    assert rows, "the vector file holds no EB9 rows"
    for row in rows:
        w: dict[str, Any] = {
            "required": EVM_DOC,
            "accepted": EVM_DOC["accepts"][0],
            "channelConfig": E["config"],
            "maxClaimableAmount": int(BV["EB2"]["maxClaimableAmount"]),
        }
        if "refund" in row:
            refund = copy.deepcopy(row["refund"])
            if isinstance(refund, dict) and isinstance(refund.get("amount"), str):
                refund["amount"] = int(refund["amount"])
            w["refund"] = refund
        unsigned = X402_BATCH_SETTLEMENT_EIP155.build_within(w, H)
        if isinstance(unsigned, Refusal):
            assert {"refused": True, "code": unsigned.code} == row["expect"], row["case"]
            continue
        payment = unsigned.complete([BV["EB2"]["signature"]])
        assert not isinstance(payment, Refusal), row["case"]
        payload = payment["payload"]
        assert payload["voucher"]["signature"] == BV["EB2"]["signature"], row["case"]
        assert {k: payload[k] for k in ("type", "amount") if k in payload} == row["expect"], row["case"]


def test_agreed_refusals_an_evm_auth_salt_that_is_not_a_hash() -> None:
    """The file holds the agreedRefusals row for an EVM build whose authSalt is not a string of 0x and 64 hex digits:
    build with authSalt [E["authSalt"]], a one-element list, or 42 gives the row's refusal."""
    rows = [r for r in BV["agreedRefusals"]["rows"] if r["case"].startswith("EVM build with an authSalt")]
    assert rows, "no agreedRefusals row names an EVM build's authSalt"
    choice = {"required": EVM_DOC, "accepted": EVM_DOC["accepts"][0], "from": E["payer"], "now": E["now"],
              "payerAuthorizer": E["payerAuthorizer"], "deposit": int(E["deposit"]), "authSalt": E["authSalt"]}  # fmt: skip
    assert not isinstance(X402_BATCH_SETTLEMENT_EIP155.build(choice, H), Refusal)
    salts: list[Any] = [[E["authSalt"]], 42]
    for salt in salts:
        assert X402_BATCH_SETTLEMENT_EIP155.build({**choice, "authSalt": salt}, H) == Refusal(rows[0]["expect"]), salt


def test_ec1_cloudflare_bound() -> None:
    binding = X402_BATCH_SETTLEMENT_CLOUDFLARE
    payload = copy.deepcopy(BV["EC1"]["payload"])
    assert binding.bound(payload) == BV["EC1"]["expectBound"]
    del payload["extensions"]
    assert binding.bound(payload) == Refusal(BV["EC1"]["withoutExtensions"])
