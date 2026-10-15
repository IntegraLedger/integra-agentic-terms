"""The buyer's channel steps on x402/batch-settlement/eip155: a channel opened for a compared ATR is held with its bytes, later
vouchers are signed only under that hold, and the recorded charge stays within what was signed. Expected digests,
signatures and channel ids are the vector file's (EB1-EB6); the voucher ceiling is
x402 batch-settlement's client rule: "the client sets the voucher's `maxClaimableAmount` to `chargedCumulativeAmount +
amount`"."""

import asyncio
import base64
import copy
import hashlib
import json
import math
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


# The code a seller answers a Solana refund with when the receiver's binding is unavailable (x402's
# scheme_batch_settlement_svm.md).
SOLANA_RETRY = "invalid_batch_settlement_svm_receiver_binding_unavailable"


@pytest.mark.parametrize(
    ("doc", "refund", "inputs"),
    [
        (EVM_DOC, {}, {"computeUnitLimit": -1}),
        ({**EVM_DOC, "error": SOLANA_RETRY}, {}, {}),
        (EVM_DOC, {"paymentResponse": {"success": False, "errorReason": SOLANA_RETRY}}, {}),
        (EVM_DOC, {"paymentResponse": "not a mapping"}, {"recentBlockhash": 7}),
    ],
    ids=["computeUnitLimit -1", "the Solana retry code as the error", "the Solana retry code as the errorReason",
         "a paymentResponse that is not a mapping, and a blockhash that is not a string"],  # fmt: skip
)
def test_an_evm_refund_reads_no_solana_refund_value_or_retry_code(
    doc: dict[str, Any], refund: dict[str, Any], inputs: dict[str, Any]
) -> None:
    # The refund values and the retry code are the Solana scheme's (x402's scheme_batch_settlement_svm.md): an EVM batch
    # refund reads none of them, and answers exactly as with none given.
    hold, _ = evm_hold()
    plain = signer()
    expected = payload(unwrap(run_within(hold, refund={}, s=plain)).signed)
    s = signer()
    out = unwrap(asyncio.run(within(doc, hold, BINDING, s, refund, inputs)))
    assert s.requests == plain.requests
    assert payload(out.signed) == expected


def test_record_charge_between_the_recorded_charge_and_the_largest_signed() -> None:
    hold, _ = evm_hold()
    assert unwrap(record_charge(hold, "1000"))["charged"] == "1000"
    assert unwrap(record_charge(hold, "0"))["charged"] == "0"
    assert code(record_charge(hold, "1001")) == "offer-unreadable"
    assert code(record_charge(hold, "1e3")) == "offer-unreadable"
    assert code(record_charge(hold, "-1")) == "offer-unreadable"
    at500 = unwrap(record_charge(hold, "500"))
    assert code(record_charge(at500, "499")) == "offer-unreadable"


def malformed_holds(hold: ChannelHold) -> list[tuple[str, Any]]:
    """Holds not of the form the channels guide states: a mapping whose pairing, network, channel, h, atr, charged and
    signedMax are strings, charged and signedMax decimals, and whose opening is a mapping."""

    def without(member: str) -> dict[str, Any]:
        return {k: v for k, v in hold.items() if k != member}

    members = ["pairing", "network", "channel", "h", "atr", "charged", "signedMax"]
    return [
        ("None", None),
        ("a list", [hold]),
        ("its JSON text", json.dumps(hold)),
        ("a number", 0),
        *[(f"no {k}", without(k)) for k in members],
        *[(f"{k} a number", {**hold, k: 1}) for k in members],
        *[(f"{k} None", {**hold, k: None}) for k in members],
        *[(f"{k} {v!r}", {**hold, k: v}) for k in ("charged", "signedMax") for v in ("", "-1", "1e3", "1.5", "0x10", " 1")],
        ("no opening", without("opening")),
        ("an opening of None", {**hold, "opening": None}),
        ("an opening that is a list", {**hold, "opening": [hold["opening"]]}),
        ("an opening that is its JSON text", {**hold, "opening": json.dumps(hold["opening"])}),
    ]


def test_a_hold_of_another_form_is_declined_by_within_and_record_charge() -> None:
    # A malformed hold is a counterparty's data, not a programming error: within and record_charge decline it, never
    # raising, and within calls no signer.
    hold, _ = evm_hold()
    expected = Declined("signed-not-bound", "The channel hold is malformed.")
    for name, value in malformed_holds(hold):
        s = signer()
        assert run_within(value, s=s) == expected, name
        assert s.requests == [], name
        assert record_charge(value, "0") == expected, name
    s = signer()
    assert isinstance(run_within(hold, s=s), Within)
    assert len(s.requests) == 1
    assert unwrap(record_charge(hold, "0"))["charged"] == "0"


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


@pytest.mark.parametrize(
    ("atr_bytes", "canonical", "atr"),
    [
        (b"A", "QQ==", "QR=="),
        (b"ab", "YWI=", "YWJ="),
        (b"A", "QQ==", "QQ="),
        (b"A", "QQ==", "QQ"),
        (b"ab", "YWI=", "YWI"),
        (b"ab", "YWI=", "YWI=="),
        (b"ab", "YWI=", "YW\nI="),
        (b"ab", "YWI=", "YW I="),
        (b"ab", "YWI=", "YWI=\t"),
        (b"ab", "YWI=", " YWI="),
        (b"??>", "Pz8+", "Pz8-"),
        (b"??>", "Pz8+", "Pz8+="),
        (b"??>", "Pz8+", "Pz8\u0100"),
    ],
    ids=[
        "a bit set past one byte",
        "a bit set past two bytes",
        "a pad missing",
        "no padding after one byte",
        "no padding after two bytes",
        "a pad too many",
        "a line break",
        "a space",
        "a trailing tab",
        "a leading space",
        "the URL-safe alphabet",
        "a pad after a full group",
        "a character outside Latin-1",
    ],
)
def test_a_hold_whose_atr_is_not_canonical_base64_is_unreadable(atr_bytes: bytes, canonical: str, atr: str) -> None:
    # A hold's atr is read as padded standard base64 in its canonical form only (RFC 4648 sections 3.5 and 4), as the
    # protocol package reads a rail's base64. Another spelling of the held bytes is unreadable before any signer call,
    # and none raises; the canonical one signs.
    doc = doc_for("0x" + hashlib.sha256(atr_bytes).hexdigest())
    opened = run(lambda c: transact(doc, BINDING, signer(), c, inputs=INPUTS), serving(atr_bytes))
    assert isinstance(opened, Transacted) and opened.signed is not None, opened
    hold = unwrap(open_channel(opened.atr_bytes, opened.signed, BINDING))
    assert hold["atr"] == canonical
    s = signer()
    assert run_within({**hold, "atr": atr}, doc=doc, s=s) == Declined("signed-not-bound", "The held ATR is unreadable.")
    assert s.requests == []
    s = signer()
    assert isinstance(run_within(hold, doc=doc, s=s), Within)
    assert len(s.requests) == 1


def test_a_hold_whose_opening_was_edited_to_eb6s_plant() -> None:
    hold, _ = evm_hold()
    opening = copy.deepcopy(hold["opening"])
    opening["payload"]["channelConfig"]["salt"] = HPRIME
    opening["payload"]["voucher"]["channelId"] = BV["EB6"]["plant"]["matchedChannelId"]
    s = signer()
    assert run_within({**hold, "opening": opening}, s=s) == Declined(
        "signed-not-bound", "The pairing does not read the held ATR's hash from the held opening."
    )
    assert s.requests == []


ZERO = "0x" + "00" * 65


@dataclass(frozen=True)
class Planted:
    """The batch-settlement binding, with a build_within whose completed payment names another salt and channel, or,
    with late, does so only once the answers are not all zero."""

    salt: str
    channel_id: str
    late: bool = False
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
            if self.late and signatures[0] == ZERO:
                return unsigned.complete(signatures)
            p: Any = copy.deepcopy(unsigned.complete(signatures))
            p["payload"]["channelConfig"] = {**p["payload"]["channelConfig"], "salt": self.salt}
            p["payload"]["voucher"]["channelId"] = self.channel_id
            return p

        return BatchUnsigned(requests=unsigned.requests, complete=complete)


def test_a_voucher_that_would_commit_to_another_agreement_is_refused_before_the_signer() -> None:
    hold, _ = evm_hold()
    plants = (
        (BV["EB1"]["channelId"], "offer-unreadable", "x402/channel-id-mismatch"),
        (BV["EB6"]["plant"]["matchedChannelId"], "no-payable-option", None),
    )
    for channel_id, decline, detail in plants:
        s = signer()
        out = run_within(hold, binding=Planted(HPRIME, channel_id), s=s)
        assert isinstance(out, Declined) and out.code == decline, out
        assert detail is None or out.detail == detail
        assert s.requests == []
    s = signer()
    out = run_within(hold, binding=Planted(HPRIME, BV["EB6"]["plant"]["matchedChannelId"], late=True), s=s)
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


@pytest.mark.parametrize("n", [math.nan, math.inf, -math.inf], ids=["NaN", "Infinity", "-Infinity"])
def test_open_channel_declines_an_opening_holding_a_number_that_is_not_finite(n: float) -> None:
    # RFC 8259 §6 permits no NaN or Infinity in JSON: the hold records the opening as JSON, so an opening holding such a
    # number is not held, as the TypeScript gate declines it.
    _, opening = evm_hold()
    held = unwrap(open_channel(ABC, {**opening, "extensions": {"n": 1}}, BINDING))
    assert held["opening"]["extensions"] == {"n": 1}
    out = open_channel(ABC, {**opening, "extensions": {"n": n}}, BINDING)
    assert out == Declined("signed-not-bound", "The opening is not plain JSON.")


def _nested(opening: dict[str, Any], levels: int) -> dict[str, Any]:
    # The opening is level 1 and its extensions level 2, so levels lists below them reach level levels + 2.
    n: object = 0
    for _ in range(levels):
        n = [n]
    return {**opening, "extensions": {"n": n}}


def test_open_channel_holds_an_opening_nested_64_levels_and_declines_one_nested_deeper() -> None:
    # The protocol package writes and reads no JSON whose arrays and objects nest more than 64 levels: the hold records
    # the opening as JSON, so an opening nested deeper is not held, at any depth, as the TypeScript gate declines it.
    # json.dumps never walks 100,000 levels, which this process (its recursion limit raised by an import) could not.
    _, opening = evm_hold()
    held = unwrap(open_channel(ABC, _nested(opening, 62), BINDING))
    assert json.dumps(held["opening"]["extensions"], separators=(",", ":")) == '{"n":' + "[" * 62 + "0" + "]" * 62 + "}"
    for levels in (63, 100_000):
        out = open_channel(ABC, _nested(opening, levels), BINDING)
        assert out == Declined("signed-not-bound", "The opening is not plain JSON.")


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
