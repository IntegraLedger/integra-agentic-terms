"""The buyer's channel steps on x402/batch-settlement/eip155: a channel opened for a compared ATR is held with its bytes, later
vouchers are signed only under that hold, and the recorded charge stays within what was signed. Expected digests,
signatures and channel ids are the vector file's (EB1-EB6); the voucher ceiling is
x402 batch-settlement's client rule: "the client sets the voucher's `maxClaimableAmount` to `chargedCumulativeAmount +
amount`"."""

import asyncio
import base64
import copy
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import (
    X402_BATCH_SETTLEMENT_CLOUDFLARE,
    X402_BATCH_SETTLEMENT_EIP155,
    BatchUnsigned,
    ChannelHold,
    Declined,
    Refusal,
    Transacted,
    Within,
    _gate,
    open_channel,
    record_charge,
    transact,
    within,
)

from breadth import ABC, ABD, H, Recording, run, x402_doc
from support import load, serving

BV = load("x402-batch-settlement.json")
E = BV["fixed"]["evm"]
HPRIME: str = BV["fixed"]["Hprime"]
BINDING = X402_BATCH_SETTLEMENT_EIP155
EVM_DOC = x402_doc(E["option"], BV["fixed"]["resource"])
ACCOUNT = f"eip155:84532:{E['payer']}"
INPUTS = {"payerAuthorizer": E["payerAuthorizer"], "deposit": E["deposit"], "authSalt": E["authSalt"]}


def sign(key: str, typed_data: dict[str, Any]) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=copy.deepcopy(typed_data)), key)
    return "0x" + bytes(signed.signature).hex()


def digest(typed_data: dict[str, Any]) -> str:
    signable = encode_typed_data(full_message=copy.deepcopy(typed_data))
    return "0x" + bytes(Account.sign_message(signable, E["payerKey"]).message_hash).hex()


def answer(request: Any) -> list[str]:
    """The payer signs the deposit authorization; the payer authorizer signs every voucher."""
    assert request["kind"] == "batch", request
    requests = request["requests"]
    keys = [E["payerKey"], E["payerAuthorizerKey"]] if len(requests) == 2 else [E["payerAuthorizerKey"]]
    return [sign(keys[i], q["typedData"]) for i, q in enumerate(requests)]


def signer() -> Recording:
    return Recording(ACCOUNT, answer)


def doc_for(h: str) -> dict[str, Any]:
    return x402_doc(E["option"], BV["fixed"]["resource"], h=h, link=f"https://atr.seller.example/{h}")


def unwrap(value: Any) -> Any:
    assert not isinstance(value, Declined), value
    return value


def code(value: Any) -> str | None:
    return value.code if isinstance(value, Declined) else None


def run_within(hold: ChannelHold, binding: Any = BINDING, doc: Any = None, refund: Mapping[str, Any] | None = None,
               s: Recording | None = None) -> Any:  # fmt: skip
    return asyncio.run(within(EVM_DOC if doc is None else doc, hold, binding, s or signer(), refund))


def payload(signed: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = signed["payload"]
    return out


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: E["now"])


def evm_hold() -> tuple[ChannelHold, dict[str, Any]]:
    """A channel opened through the gate over abc, and held."""
    opened = run(lambda c: transact(EVM_DOC, BINDING, signer(), c, inputs=INPUTS), serving(ABC))
    assert isinstance(opened, Transacted) and opened.signed is not None, opened
    hold = unwrap(open_channel(opened.atr_bytes, opened.signed, BINDING))
    return json.loads(json.dumps(hold)), opened.signed


def only_request(s: Recording) -> dict[str, Any]:
    assert len(s.requests) == 1
    request = s.requests[0]
    assert request["kind"] == "batch" and len(request["requests"]) == 1 and request["requests"][0]["kind"] == "eip712"
    typed_data: dict[str, Any] = request["requests"][0]["typedData"]
    return typed_data


def test_open_channel_holds_the_bytes_the_opening_and_eb1s_channel() -> None:
    hold, _ = evm_hold()
    expected = {
        "pairing": "x402/batch-settlement/eip155",
        "network": BV["EB6"]["expectRef"]["network"],
        "channel": BV["EB6"]["expectRef"]["channel"],
        "h": H,
        "atr": base64.b64encode(ABC).decode(),
        "charged": "0",
        "signedMax": "1000",
    }
    assert {k: hold[k] for k in expected} == expected


def test_within_at_charged_0_signs_eb2s_voucher() -> None:
    hold, _ = evm_hold()
    s = signer()
    out = unwrap(run_within(hold, s=s))
    assert isinstance(out, Within)
    assert digest(only_request(s)) == BV["EB2"]["digest"]
    assert payload(out.signed)["type"] == "voucher"
    assert payload(out.signed)["voucher"]["signature"] == BV["EB2"]["signature"]
    assert BINDING.channel_kind(out.signed) == BV["EB6"]["expectKindVoucher"]
    assert BINDING.bound_within(out.signed) == BV["EB6"]["expectBoundWithin"]
    assert out.hold["signedMax"] == "1000"


def test_after_record_charge_1000_the_next_voucher_claims_2000() -> None:
    hold, _ = evm_hold()
    first = unwrap(run_within(hold))
    charged = unwrap(record_charge(first.hold, "1000"))
    assert charged["charged"] == "1000"
    s = signer()
    following = unwrap(run_within(charged, s=s))
    typed_data = only_request(s)
    assert typed_data["message"]["maxClaimableAmount"] == "2000"
    voucher = payload(following.signed)["voucher"]
    assert voucher["maxClaimableAmount"] == "2000"
    recovered = Account.recover_message(encode_typed_data(full_message=copy.deepcopy(typed_data)),
                                        signature=bytes.fromhex(voucher["signature"][2:]))  # fmt: skip
    assert recovered == E["payerAuthorizer"]
    assert following.hold["signedMax"] == "2000"


def test_eb6_kinds_a_full_refund_is_close_a_partial_refund_is_within() -> None:
    hold, _ = evm_hold()
    full = unwrap(run_within(hold, refund={}))
    assert payload(full.signed)["type"] == "refund"
    assert BINDING.channel_kind(full.signed) == BV["EB6"]["expectKindRefund"]
    partial = unwrap(run_within(hold, refund={"amount": BV["EB6"]["refundAmount"]}))
    assert payload(partial.signed)["amount"] == BV["EB6"]["refundAmount"]
    assert BINDING.channel_kind(partial.signed) == BV["EB6"]["expectKindPartialRefund"]


def test_a_refunds_voucher_claims_the_recorded_charge() -> None:
    hold, _ = evm_hold()
    first = unwrap(run_within(hold))
    charged = unwrap(record_charge(first.hold, "1000"))
    for refund in ({}, {"amount": BV["EB6"]["refundAmount"]}):
        s = signer()
        out = unwrap(run_within(charged, refund=refund, s=s))
        assert only_request(s)["message"]["maxClaimableAmount"] == "1000"
        assert payload(out.signed)["voucher"]["maxClaimableAmount"] == "1000"
        assert out.hold["signedMax"] == charged["signedMax"]
    none = unwrap(run_within(hold, refund={}))
    assert payload(none.signed)["voucher"]["maxClaimableAmount"] == "0"


def test_record_charge_between_the_recorded_charge_and_the_largest_signed() -> None:
    hold, _ = evm_hold()
    assert unwrap(record_charge(hold, "1000"))["charged"] == "1000"
    assert unwrap(record_charge(hold, "0"))["charged"] == "0"
    assert code(record_charge(hold, "1001")) == "offer-unreadable"
    assert code(record_charge(hold, "1e3")) == "offer-unreadable"
    assert code(record_charge(hold, "-1")) == "offer-unreadable"
    at500 = unwrap(record_charge(hold, "500"))
    assert code(record_charge(at500, "499")) == "offer-unreadable"


# ── plant: a voucher is signed only under the held agreement.


def test_a_within_challenge_advertising_h_prime() -> None:
    hold, _ = evm_hold()
    s = signer()
    assert code(run_within(hold, doc=doc_for(HPRIME), s=s)) == "hash-mismatch"
    assert s.requests == []


def test_a_hold_whose_channel_was_edited() -> None:
    hold, _ = evm_hold()
    s = signer()
    assert code(run_within({**hold, "channel": BV["EB1"]["withHprime"]}, s=s)) == "signed-not-bound"
    assert s.requests == []


def test_a_hold_whose_atr_bytes_were_edited() -> None:
    hold, _ = evm_hold()
    s = signer()
    assert code(run_within({**hold, "atr": base64.b64encode(ABD).decode()}, s=s)) == "hash-mismatch"
    assert s.requests == []


def test_a_hold_whose_opening_was_edited_to_eb6s_plant() -> None:
    hold, _ = evm_hold()
    opening = copy.deepcopy(hold["opening"])
    opening["payload"]["channelConfig"]["salt"] = HPRIME
    opening["payload"]["voucher"]["channelId"] = BV["EB6"]["plant"]["matchedChannelId"]
    s = signer()
    assert code(run_within({**hold, "opening": opening}, s=s)) == "signed-not-bound"
    assert s.requests == []


@dataclass(frozen=True)
class Planted:
    """The batch-settlement binding, with a build_within whose completed payment names another salt and channel."""

    salt: str
    channel_id: str
    id: str = BINDING.id

    def read(self, doc: Any) -> Any:
        return BINDING.read(doc)

    def bound(self, presented: Any) -> Any:
        return BINDING.bound(presented)

    def channel_kind(self, presented: Any) -> Any:
        return BINDING.channel_kind(presented)

    def channel_ref(self, presented: Any) -> Any:
        return BINDING.channel_ref(presented)

    def bound_within(self, presented: Any) -> Any:
        return BINDING.bound_within(presented)

    def build_within(self, w: Mapping[str, Any], h: str) -> Any:
        unsigned = BINDING.build_within(w, h)
        assert isinstance(unsigned, BatchUnsigned)

        def complete(signatures: Any) -> Any:
            p: Any = copy.deepcopy(unsigned.complete(signatures))
            p["payload"]["channelConfig"] = {**p["payload"]["channelConfig"], "salt": self.salt}
            p["payload"]["voucher"]["channelId"] = self.channel_id
            return p

        return BatchUnsigned(requests=unsigned.requests, complete=complete)


def test_a_signed_voucher_that_commits_to_another_agreement_is_dropped() -> None:
    hold, _ = evm_hold()
    for salt, channel_id in ((HPRIME, BV["EB1"]["channelId"]), (HPRIME, BV["EB6"]["plant"]["matchedChannelId"])):
        s = signer()
        out = run_within(hold, binding=Planted(salt, channel_id), s=s)
        assert code(out) == "signed-not-bound"
        assert len(s.requests) == 1
    matched = {**hold["opening"], "payload": {
        "type": "voucher",
        "channelConfig": {**hold["opening"]["payload"]["channelConfig"], "salt": HPRIME},
        "voucher": {"channelId": BV["EB6"]["plant"]["matchedChannelId"], "maxClaimableAmount": "1000",
                    "signature": BV["EB2"]["signature"]},
    }}  # fmt: skip
    assert BINDING.bound_within(matched) == BV["EB6"]["plant"]["expectBoundWithinMatched"]


def test_open_channel_refuses_other_bytes_a_non_opening_and_a_pairing_with_no_channel() -> None:
    hold, opening = evm_hold()
    assert code(open_channel(ABD, opening, BINDING)) == "signed-not-bound"
    voucher = unwrap(run_within(hold))
    assert code(open_channel(ABC, voucher.signed, BINDING)) == "signed-not-bound"
    assert code(open_channel(ABC, opening, X402_BATCH_SETTLEMENT_CLOUDFLARE)) == "pairing-not-supported"


@dataclass(frozen=True)
class NoWithin:
    """The batch-settlement binding without build_within."""

    id: str = BINDING.id

    def read(self, doc: Any) -> Any:
        return BINDING.read(doc)

    def bound(self, presented: Any) -> Any:
        return BINDING.bound(presented)

    def channel_kind(self, presented: Any) -> Any:
        return BINDING.channel_kind(presented)

    def channel_ref(self, presented: Any) -> Any:
        return BINDING.channel_ref(presented)

    def bound_within(self, presented: Any) -> Any:
        return BINDING.bound_within(presented)


def test_within_on_a_pairing_with_no_build_within_signs_nothing() -> None:
    hold, _ = evm_hold()
    s = signer()
    out = run_within(hold, binding=NoWithin(), s=s)
    assert isinstance(out, Declined) and out.code == "pairing-not-supported"
    assert s.requests == []
    assert not isinstance(BINDING.build_within({}, H), BatchUnsigned)
    assert isinstance(BINDING.build_within({}, H), Refusal)
