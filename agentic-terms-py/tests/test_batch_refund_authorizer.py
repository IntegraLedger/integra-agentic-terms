"""x402/batch-settlement/eip155 under an option in the scheme's refund-authorizer mode (x402-batch-settlement.json
EB10): the stock @x402/evm 2.31.0 client packs the channel salt from its entropy and the refund authorizer, and H is the
deposit authorization's salt, or the deposit permit's nonce. Every input and expected value is EB10's or the file's
fixed.evm; the payer and payer authorizer sign with the file's published Anvil development keys."""

import copy
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import X402_BATCH_SETTLEMENT_EIP155 as BINDING
from integraledger_terms import Refusal
from integraledger_terms.bindings._batch_evm import batch_channel_id, erc3009_deposit_nonce
from integraledger_terms.bindings.x402_batch_settlement_eip155 import packed_salt, refund_authorizer_of

from support import load

V = load("x402-batch-settlement.json")
R: dict[str, Any] = V["EB10"]
E: dict[str, Any] = V["fixed"]["evm"]
H: str = V["fixed"]["H"]
OPTION: dict[str, Any] = R["option"]
# The document as the pairing's advertise places H in it: EB10's payment carries its extensions.
DOC: dict[str, Any] = {
    "x402Version": 2,
    "resource": V["fixed"]["resource"],
    "accepts": [OPTION],
    "extensions": R["eip3009"]["expectPayload"]["extensions"],
}


def signed(key: str, typed_data: dict[str, Any]) -> tuple[str, str]:
    """The key's signature over the typed data and its EIP-712 digest, from eth-account."""
    s = Account.sign_message(encode_typed_data(full_message=copy.deepcopy(typed_data)), key)
    return "0x" + bytes(s.signature).hex(), "0x" + bytes(s.message_hash).hex()


def opening(method: str, auth_salt: str = R["packing"][0]["entropy"]) -> tuple[dict[str, Any], str]:
    """The opening build writes for fixed.evm's choice under EB10's option, signed, and the deposit authorization's
    digest."""
    permit2 = {**OPTION, "extra": {**OPTION["extra"], "assetTransferMethod": "permit2"}}
    accepted = OPTION if method == "eip3009" else permit2
    choice = {
        "required": {**DOC, "accepts": [accepted]},
        "accepted": accepted,
        "from": E["payer"],
        "now": E["now"],
        "payerAuthorizer": E["payerAuthorizer"],
        "deposit": int(E["deposit"]),
        "authSalt": auth_salt,
    }
    u = BINDING.build(choice, H)
    assert not isinstance(u, Refusal), u
    token_auth, voucher = (r["typedData"] for r in u.requests)
    (s1, digest), (s2, _) = signed(E["payerKey"], token_auth), signed(E["payerAuthorizerKey"], voucher)
    payment = u.complete([s1, s2])
    assert not isinstance(payment, Refusal), payment
    return payment, digest


def test_the_stock_clients_packed_salt_channel_id_and_deposit_nonce() -> None:
    ra = refund_authorizer_of(OPTION)
    assert ra is not None and ra == R["refundAuthorizer"].lower()
    for row in R["packing"]:
        config = row["expectChannelConfig"]
        assert packed_salt(row["entropy"], ra) == config["salt"].lower()
        assert batch_channel_id(E["chainId"], {**config, "salt": config["salt"].lower()}) == row["expectChannelId"]
        assert erc3009_deposit_nonce(row["expectChannelId"], H) == row["expectDepositNonce"]


def test_build_packs_the_channel_salt_and_puts_h_in_the_deposit_authorization() -> None:
    for row in R["packing"]:
        payment, _ = opening("eip3009", row["entropy"])
        p = payment["payload"]
        assert {k: str(v).lower() for k, v in p["channelConfig"].items()} == {
            k: str(v).lower() for k, v in row["expectChannelConfig"].items()
        }
        assert p["voucher"]["channelId"] == row["expectChannelId"]
        assert p["deposit"]["authorization"]["erc3009Authorization"]["salt"] == H
    for method in ("eip3009", "permit2"):
        payment, digest = opening(method)
        assert digest == R[method]["digest"], method
        assert payment == R[method]["expectPayload"], method
        assert BINDING.bound(payment) == R[method]["expectBound"], method


def test_bound_and_build_within_refuse_a_channel_whose_salt_does_not_end_in_the_refund_authorizer() -> None:
    """The opening the pairing wrote before this mode was read, its channel salt H unpacked, is not the mode's channel;
    a later payment under the mode carries no H."""
    payment, _ = opening("eip3009")
    p = payment["payload"]
    unpacked = {**p["channelConfig"], "salt": H}
    channel = batch_channel_id(E["chainId"], unpacked)
    unpacked_voucher = {**p["voucher"], "channelId": channel}
    planted = {**payment, "payload": {**p, "channelConfig": unpacked, "voucher": unpacked_voucher}}
    assert BINDING.bound(planted) == Refusal("x402/channel-id-mismatch")
    voucher = {**payment, "payload": {"type": "voucher", "channelConfig": p["channelConfig"], "voucher": p["voucher"]}}
    assert BINDING.bound_within(voucher) == Refusal("x402/not-bound-within")

    def within(config: dict[str, Any]) -> Any:
        within = {"required": DOC, "accepted": OPTION, "channelConfig": config, "maxClaimableAmount": 2000}
        return BINDING.build_within(within, H)

    u = within(p["channelConfig"])
    assert not isinstance(u, Refusal) and len(u.requests) == 1, u
    assert within(unpacked) == Refusal("x402/channel-id-mismatch")


def test_the_filter_refuses_an_option_whose_refund_authorizer_is_no_address() -> None:
    bad = {**OPTION, "extra": {**OPTION["extra"], "refundAuthorizer": "0x1234"}}
    assert BINDING.read({**DOC, "accepts": [bad]}) == Refusal("x402/no-payable-option")
