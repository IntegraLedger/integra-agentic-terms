"""The gate's rows, as the TypeScript gate's tests run them, for MPP's sessions on EVM and Tempo and its Tempo
subscription (pairings-chan.test.ts): B2, B6, B10 and B16, and the v1 session's default chain. Expected values are the
vector files'; the key is the published Anvil key #0."""

import asyncio
import hashlib
import json
from collections.abc import Iterator
from typing import Any

import pytest
from eth_account import Account

from integraledger_terms import (
    MPP_SESSION_EVM,
    MPP_SESSION_TEMPO,
    MPP_SUBSCRIPTION_TEMPO,
    Binding,
    Confirmed,
    Declined,
    Transacted,
    BatchUnsigned,
    Refusal,
    Within,
    confirm,
    open_channel,
    record_charge,
    transact,
    within,
)
from integraledger_terms import _gate
from integraledger_terms._keccak import keccak256
from integraledger_terms.bindings._rlp import rlp_bytes, rlp_list, rlp_uint_bytes

from breadth import ABC, H, LINK, Pairing, Recording, build_and_sign, code, plant, run
from mpp_docs import http_doc, issued, placed_doc
from support import digest, load, serving, sign_typed

EVM = load("mpp-session-evm.json")
TEMPO = load("mpp-session-tempo.json")
SUB = load("mpp-subscription-tempo.json")
NOW: int = EVM["fixed"]["now"]
OTHER_NAMESPACE = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x"


@pytest.fixture(autouse=True)
def frozen(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)
    yield


def affix(value: str, e: dict[str, str]) -> None:
    assert value.startswith(e["prefix"]) and value.endswith(e["suffix"]), (value, e)


def b10(doc: Any, binding: Binding, account: str, inputs: dict[str, Any] | None = None) -> None:
    link = serving(ABC)
    http: Any = http_doc(doc)
    out = run(lambda c: confirm(http, binding, account, c, inputs), link)
    assert (code(out), getattr(out, "detail", None)) == ("offer-unreadable", "mpp/link-not-https")
    assert link.calls == 0


def b16(doc: Any, binding: Binding, accounts: list[str], inputs: dict[str, Any] | None = None) -> None:
    link = serving(ABC)
    for a in accounts:
        assert code(run(lambda c: confirm(doc, binding, a, c, inputs), link)) == "no-payable-option"
    assert link.calls == 0


def sig65(message_hash: bytes, key: str) -> str:
    """A 65-byte secp256k1 signature, r ‖ s ‖ v with v 27 or 28."""
    s = Account.unsafe_sign_hash(message_hash, key)
    r, s_, v = int(s.r), int(s.s), int(s.v)
    return "0x" + r.to_bytes(32, "big").hex() + s_.to_bytes(32, "big").hex() + bytes([v]).hex()


# ── mpp/session/evm.

EF = EVM["fixed"]
EVM_DOC = placed_doc(issued("evm", "session", EF["request"]), H, LINK)
EVM_ACCOUNT = f"eip155:84532:{EF['payer']}"
TX_HASH = "0x" + "ab" * 32


class EvmAnswer:
    """The Anvil key's answers, recorded: an EIP-712 signature, or TX_HASH for the open calls it broadcasts."""

    def __init__(self) -> None:
        self.seen: list[Any] = []

    def __call__(self, request: Any) -> str:
        self.seen.append(request)
        if request["kind"] == "evm-calls":
            return TX_HASH
        assert request["kind"] == "eip712", request
        return sign_typed(request["typedData"])


def evm_pairing(inputs: dict[str, Any], answer: Any) -> Pairing:
    return Pairing(binding=MPP_SESSION_EVM, doc=EVM_DOC, account=EVM_ACCOUNT, answer=answer, inputs=inputs)


AUTHORIZATION_INPUTS = {"deposit": EF["deposit"], "credentialType": "authorization", "tokenDomain": EF["tokenDomain"]}

def test_mpp_session_evm_b6_authorization_es4_funding_then_es5_voucher() -> None:
    answer = EvmAnswer()

    def inspect(request: Any) -> None:
        assert request["kind"] == "eip712"
        assert digest(request["typedData"]) == EVM["ES4"]["expectDigest"]
        assert request["typedData"]["message"]["nonce"] == EVM["ES3"]["expectNonce"]
        affix(sign_typed(request["typedData"]), EVM["ES4"]["expectSignature"])

    signed, _ = build_and_sign(evm_pairing(AUTHORIZATION_INPUTS, answer), inspect)
    voucher = answer.seen[1]
    assert voucher["kind"] == "eip712"
    assert digest(voucher["typedData"]) == EVM["ES5"]["expectVoucherDigest"]
    assert signed["payload"]["channelId"] == EVM["ES1"]["expectChannelId"]
    assert signed["payload"]["salt"] == H
    assert MPP_SESSION_EVM.channel.kind(signed) == "open"  # type: ignore[attr-defined]


def test_mpp_session_evm_b6_hash_es2_open_call_then_the_voucher() -> None:
    es2 = EVM["ES2"]

    def inspect(request: Any) -> None:
        assert request["kind"] == "evm-calls"
        assert request["broadcast"] is True
        open_call = request["calls"][1]
        assert (len(open_call["data"]) - 2) // 2 == es2["expectOpenLength"]
        assert open_call["data"][:10] == es2["expectOpenSelector"]
        assert open_call["data"].count(H[2:]) == es2["expectHOccurrences"]

    build_and_sign(evm_pairing({"deposit": EF["deposit"], "credentialType": "hash"}, EvmAnswer()), inspect)


def test_mpp_session_evm_b10_http_link() -> None:
    b10(EVM_DOC, MPP_SESSION_EVM, EVM_ACCOUNT, AUTHORIZATION_INPUTS)


def test_mpp_session_evm_b16_other_namespace_and_chain() -> None:
    b16(EVM_DOC, MPP_SESSION_EVM, [OTHER_NAMESPACE, f"eip155:1:{EF['payer']}"], AUTHORIZATION_INPUTS)


# ── mpp/session/tempo.

TF = TEMPO["fixed"]
TEMPO_DOC = placed_doc(issued("tempo", "session", TF["requestV2"]), H, LINK)
TEMPO_ACCOUNT = f"eip155:42431:{TF['payer']}"


def open_wire(request: Any) -> str:
    """TS2's wire: the open call in a 0x76 transaction, signed by the payer over keccak256(0x76 ‖ rlp(fields))."""
    assert request["kind"] == "tempo-call", request
    fields = [
        rlp_uint_bytes(request["chainId"]),
        rlp_uint_bytes(1),
        rlp_uint_bytes(2),
        rlp_uint_bytes(200000),
        rlp_list([rlp_list([rlp_bytes(bytes.fromhex(request["call"]["to"][2:])), rlp_bytes(b""), rlp_bytes(bytes.fromhex(request["call"]["data"][2:]))])]),
        rlp_list([]),
        rlp_uint_bytes(2**256 - 1),
        rlp_bytes(b""),
        rlp_uint_bytes(request["validBefore"]),
        rlp_bytes(b""),
        rlp_bytes(bytes.fromhex(TF["pathUSD"][2:])),
        rlp_bytes(b""),
        rlp_list([]),
    ]
    signature = sig65(keccak256(b"\x76" + rlp_list(fields)), TF["payerKey"])
    return "0x76" + rlp_list([*fields, rlp_bytes(bytes.fromhex(signature[2:]))]).hex()


class TempoAnswer:
    def __init__(self) -> None:
        self.seen: list[Any] = []

    def __call__(self, request: Any) -> str:
        self.seen.append(request)
        if request["kind"] == "tempo-call":
            return open_wire(request)
        assert request["kind"] == "eip712", request
        return sign_typed(request["typedData"])


def tempo_pairing(answer: Any, doc: Any = None) -> Pairing:
    return Pairing(
        binding=MPP_SESSION_TEMPO,
        doc=TEMPO_DOC if doc is None else doc,
        account=TEMPO_ACCOUNT,
        answer=answer,
        inputs={"deposit": TF["deposit"]},
    )

def test_mpp_session_tempo_b6_ts1_open_ts2_wire_then_ts4_voucher_over_ts3() -> None:
    answer = TempoAnswer()

    def inspect(request: Any) -> None:
        assert request["kind"] == "tempo-call"
        assert request["broadcast"] is False
        assert request["call"]["to"] == TF["escrowV2"]
        assert (len(request["call"]["data"]) - 2) // 2 == TEMPO["TS1"]["expectLength"]
        assert request["call"]["data"][:10] == TEMPO["TS1"]["expectSelector"]
        wire = bytes.fromhex(open_wire(request)[2:])
        assert len(wire) == TEMPO["TS2"]["expectLength"]
        assert "0x" + hashlib.sha256(wire).hexdigest() == TEMPO["TS2"]["expectSha256"]

    signed, _ = build_and_sign(tempo_pairing(answer), inspect)
    voucher = answer.seen[1]
    assert voucher["kind"] == "eip712"
    assert digest(voucher["typedData"]) == TEMPO["TS4"]["expectVoucher0"]
    assert signed["payload"]["channelId"] == TEMPO["TS3"]["expectChannelId"]
    channel = MPP_SESSION_TEMPO.channel  # type: ignore[attr-defined]
    assert channel.kind(signed) == "open"
    assert channel.bound_within(signed) == H


def test_mpp_session_tempo_b10_http_link() -> None:
    b10(TEMPO_DOC, MPP_SESSION_TEMPO, TEMPO_ACCOUNT, {"deposit": TF["deposit"]})


def test_mpp_session_tempo_b16_other_namespace_and_chain() -> None:
    b16(TEMPO_DOC, MPP_SESSION_TEMPO, [OTHER_NAMESPACE, f"eip155:1:{TF['payer']}"], {"deposit": TF["deposit"]})


def test_mpp_session_tempo_a_v1_session_naming_no_chain_pays_on_4217() -> None:
    request = json.loads(TF["requestV1"])
    del request["methodDetails"]["chainId"]
    v1: Any = placed_doc(issued("tempo", "session", json.dumps(request)), H, LINK)
    out = run(lambda c: confirm(v1, MPP_SESSION_TEMPO, f"eip155:4217:{TF['payer']}", c, {"deposit": TF["deposit"]}), serving(ABC))
    assert isinstance(out, Confirmed), out
    assert out.request is not None and out.request["kind"] == "tempo-call"
    assert out.request["chainId"] == 4217
    b16(v1, MPP_SESSION_TEMPO, [f"eip155:42431:{TF['payer']}"], {"deposit": TF["deposit"]})


# ── mpp/subscription/tempo.

SF = SUB["fixed"]
SUB_DOC = placed_doc(issued("tempo", "subscription", SF["request"]), H, LINK)
SUB_ACCOUNT = f"eip155:42431:{SF['payer']}"


def root_signature(request: Any) -> str:
    assert request["kind"] == "tempo-key-authorization", request
    return sig65(bytes.fromhex(request["digest"][2:]), SF["payerKey"])


SUB_P = Pairing(binding=MPP_SUBSCRIPTION_TEMPO, doc=SUB_DOC, account=SUB_ACCOUNT, answer=root_signature)

def test_mpp_subscription_tempo_b6_sub1_digest_with_witness_h() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "tempo-key-authorization"
        assert request["digest"] == SUB["SUB1"]["expectDigest"]
        assert request["authorization"]["witness"] == H

    signed, _ = build_and_sign(SUB_P, inspect)
    assert (len(signed["payload"]["signature"]) - 2) // 2 == SUB["SUB1"]["expectSignedLength"]
    channel = MPP_SUBSCRIPTION_TEMPO.channel  # type: ignore[attr-defined]
    assert channel.ref(signed) == {"network": "eip155:42431", "channel": SUB["SUB2"]["expectRefChannel"]}


def test_mpp_subscription_tempo_b10_http_link() -> None:
    b10(SUB_DOC, MPP_SUBSCRIPTION_TEMPO, SUB_ACCOUNT)


def test_mpp_subscription_tempo_b16_other_namespace_and_chain() -> None:
    b16(SUB_DOC, MPP_SUBSCRIPTION_TEMPO, [OTHER_NAMESPACE, f"eip155:1:{SF['payer']}"])


def tempo_hold() -> tuple[Pairing, dict[str, Any]]:
    p = tempo_pairing(TempoAnswer())
    opened = run(lambda c: transact(p.doc, p.binding, Recording(p.account, p.answer), c, inputs=p.inputs), serving(ABC))
    assert isinstance(opened, Transacted) and opened.signed is not None
    hold = open_channel(opened.atr_bytes, opened.signed, MPP_SESSION_TEMPO)
    assert not isinstance(hold, Declined), hold
    return p, hold


def test_mpp_session_tempo_the_channel_hold_and_a_pairing_with_no_build_within() -> None:
    # channels.test.ts, "mpp/session/tempo: the channel hold".
    p, hold = tempo_hold()
    assert hold["network"] == "eip155:42431"
    assert hold["channel"] == TEMPO["TS3"]["expectChannelId"]
    assert (hold["h"], hold["charged"], hold["signedMax"]) == (H, "0", "0")
    signer = Recording(p.account, p.answer)
    out = asyncio.run(within(p.doc, hold, WithoutWithin(MPP_SESSION_TEMPO), signer))
    assert isinstance(out, Declined) and out.code == "pairing-not-supported"
    assert signer.requests == []


class WithoutWithin:
    """The session binding without build_within, as channels.test.ts sets buildWithin undefined."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        if name == "build_within":
            raise AttributeError(name)
        return getattr(self._inner, name)


class SessionWithin:
    """The session binding with a build_within of the in-channel payment's shape: it records the
    SessionWithin the gate hands it and returns one eip712 request whose completion is the draft's {challenge,
    payload: {action, channelId, cumulativeAmount, signature, descriptor}}."""

    def __init__(self, inner: Any, refuse: str | None = None) -> None:
        self._inner = inner
        self._refuse = refuse
        self.handed: list[dict[str, Any]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def build_within(self, w: dict[str, Any], h: str) -> Any:
        self.handed.append(w)
        if self._refuse is not None:
            return Refusal(self._refuse)
        opened = w["opening"]["payload"]
        typed_data = {
            "domain": {"name": "TIP20 Channel Reserve", "version": "1", "chainId": 42431, "verifyingContract": TF["escrowV2"]},
            "types": {"Voucher": [{"name": "channelId", "type": "bytes32"}, {"name": "cumulativeAmount", "type": "uint96"}]},
            "primaryType": "Voucher",
            "message": {"channelId": opened["channelId"], "cumulativeAmount": w["cumulativeAmount"]},
        }

        def complete(signatures: Any) -> dict[str, Any]:
            payload = {"action": w["action"], "channelId": opened["channelId"],
                       "cumulativeAmount": str(w["cumulativeAmount"]), "signature": signatures[0]}  # fmt: skip
            if "descriptor" in opened:
                payload["descriptor"] = opened["descriptor"]
            return {"challenge": w["challenge"], "payload": payload}

        return BatchUnsigned(requests=[{"kind": "eip712", "typedData": typed_data}], complete=complete)


def test_mpp_session_tempo_within_hands_build_within_the_challenge_the_opening_the_amount_and_the_action() -> None:
    p, hold = tempo_hold()
    charged = record_charge({**hold, "signedMax": "500"}, "300")
    assert not isinstance(charged, Declined)
    binding = SessionWithin(MPP_SESSION_TEMPO)
    signer = Recording(p.account, lambda r: [sign_typed(q["typedData"]) for q in r["requests"]])
    out = asyncio.run(within(p.doc, charged, binding, signer))
    assert isinstance(out, Within), out
    assert binding.handed == [{"challenge": p.doc[0], "opening": hold["opening"], "cumulativeAmount": 400, "action": "voucher"}]
    assert out.signed["payload"]["action"] == "voucher" and out.signed["payload"]["cumulativeAmount"] == "400"
    assert out.hold == {**charged, "signedMax": "500"}

    closing = SessionWithin(MPP_SESSION_TEMPO)
    closed = asyncio.run(within(p.doc, charged, closing, signer, {}))
    assert isinstance(closed, Within), closed
    assert [(w["action"], w["cumulativeAmount"]) for w in closing.handed] == [("close", 300)]
    assert closed.signed["payload"]["action"] == "close"


def test_mpp_session_tempo_a_partial_refund_and_an_action_not_built_sign_nothing() -> None:
    p, hold = tempo_hold()
    signer = Recording(p.account, p.answer)
    partial = asyncio.run(within(p.doc, hold, SessionWithin(MPP_SESSION_TEMPO), signer, {"amount": "5"}))
    assert partial == Declined("pairing-not-supported", "mpp/within-action-not-built")
    refused = asyncio.run(within(p.doc, hold, SessionWithin(MPP_SESSION_TEMPO, "mpp/within-action-not-built"), signer))
    assert refused == Declined("pairing-not-supported", "mpp/within-action-not-built")
    assert signer.requests == []


def test_tempo_precompile_addresses_are_the_vectors() -> None:
    from integraledger_terms.bindings import _tempo

    assert _tempo.TIP20_CHANNEL_RESERVE == TEMPO["constants"]["expectTip20ChannelReserve"]
    assert _tempo.ACCOUNT_KEYCHAIN == TEMPO["constants"]["expectAccountKeychain"]
