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
from eth_utils.crypto import keccak

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
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.bindings._rlp import rlp_bytes, rlp_list, rlp_uint_bytes
from integraledger_terms.bindings._tempo import encode_key_authorization, tempo_channel_id

from breadth import ABC, H, LINK, Pairing, Recording, build_and_sign, code, plant, run
from mpp_docs import b64u, http_doc, issued, placed_doc
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


def test_mpp_session_evm_b6_permit2_es6_funding_then_es5_voucher() -> None:
    # ES6: the Permit2 opening signs PermitWitnessTransferFrom over the deposit, with the escrow as spender, H as the
    # nonce, and the channel's payee, salt and signer as its witness; the digest is eth-account's.
    answer = EvmAnswer()
    es6 = EVM["ES6"]

    def inspect(request: Any) -> None:
        assert request["kind"] == "eip712"
        typed = request["typedData"]
        affix("0x" + keccak256(es6["typeSignature"].encode("ascii")).hex(), es6["expectTypeHash"])
        assert str(typed["message"]["nonce"]) == es6["expectNonce"] == str(int(H, 16))
        assert typed["message"]["spender"] == EF["escrow"]
        assert digest(typed) == es6["expectDigest"]

    signed, _ = build_and_sign(evm_pairing({"deposit": EF["deposit"], "credentialType": "permit2"}, answer), inspect)
    assert [r["kind"] for r in answer.seen[:2]] == ["eip712", "eip712"]
    assert digest(answer.seen[1]["typedData"]) == EVM["ES5"]["expectVoucherDigest"]
    assert signed["payload"]["type"] == "permit2"
    assert signed["payload"]["channelId"] == EVM["ES1"]["expectChannelId"]
    assert signed["payload"]["salt"] == H
    assert MPP_SESSION_EVM.bound(signed) == H


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


# methodDetails.permit2Contract is the verifying contract the Permit2 opening signs, so the session's check reads it
# only where credentialTypes lists permit2 (an absent credentialTypes is ["hash"]), and after credentialTypes itself.
# Each expected answer is @integraledger/lcp's pairingsOf for the same challenge.
_UNREAD = ("mpp/session/evm",)


@pytest.mark.parametrize(
    ("types", "contract", "expect"),
    [
        (None, "x", _UNREAD),
        (["hash"], "0x1234", _UNREAD),
        (["authorization"], None, _UNREAD),
        (["hash", "authorization"], 7, _UNREAD),
        (["permit2"], "0x000000000022D473030F116dDEE9F6B43aC78BA3", _UNREAD),
        (["permit2"], "x", "mpp/request-malformed"),
        (["hash", "authorization", "permit2"], None, "mpp/request-malformed"),
        (["permit2", "hash"], [], "mpp/request-malformed"),
        ([], "x", "mpp/credential-types"),
        (["permit2", "bogus"], "x", "mpp/credential-types"),
        ("permit2", "x", "mpp/credential-types"),
    ],
)
def test_mpp_session_evm_permit2_contract_is_read_where_credential_types_lists_permit2(types: Any, contract: Any, expect: Any) -> None:
    request = json.loads(EF["request"])
    details = {k: v for k, v in request["methodDetails"].items() if k != "credentialTypes"}
    if types is not None:
        details["credentialTypes"] = types
    request["methodDetails"] = {**details, "permit2Contract": contract}
    out = pairings_of(issued("evm", "session", json.dumps(request)))
    assert out == (expect if isinstance(expect, tuple) else Refusal(expect))


# ── mpp/session/tempo.

TF = TEMPO["fixed"]
TEMPO_DOC = placed_doc(issued("tempo", "session", TF["requestV2"]), H, LINK)
TEMPO_ACCOUNT = f"eip155:42431:{TF['payer']}"


def open_wire(request: Any, signature: Any = None) -> str:
    """TS2's wire: the open call in a 0x76 transaction, signed by the payer over keccak256(0x76 ‖ rlp(fields)); or
    with the signature bytes signature(that hash) gives."""
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
    digest = keccak256(b"\x76" + rlp_list(fields))
    signed = bytes.fromhex(sig65(digest, TF["payerKey"])[2:]) if signature is None else signature(digest)
    return "0x76" + rlp_list([*fields, rlp_bytes(signed)]).hex()


class TempoAnswer:
    def __init__(self) -> None:
        self.seen: list[Any] = []

    def __call__(self, request: Any) -> str:
        self.seen.append(request)
        if request["kind"] == "tempo-call":
            return open_wire(request)
        assert request["kind"] == "eip712", request
        return sign_typed(request["typedData"])


def tempo_opening(
    request_text: str, chain: int, signature: Any = None, payer: str = TF["payer"], dirty: int | None = None
) -> dict[str, Any]:
    """The opening the binding's build writes for a challenge of request_text and payer, completed with its open call
    in a transaction of TS2's other fields for chain, signed with fixed.payerKey or as signature gives, and the payer's
    voucher. With dirty, the open call's argument word of that index has a non-zero first byte."""
    unsigned = MPP_SESSION_TEMPO.build(
        {"challenge": placed_doc(issued("tempo", "session", request_text), H, LINK)[0], "from": payer, "deposit": int(TF["deposit"])}, H
    )
    assert not isinstance(unsigned, Refusal), unsigned
    call = unsigned.funding["call"]
    if dirty is not None:
        at = 10 + 64 * dirty
        call = {**call, "data": call["data"][:at] + "01" + call["data"][at + 2 :]}
    signed_tx = open_wire({**unsigned.funding, "call": call, "chainId": chain}, signature)
    voucher = unsigned.voucher(signed_tx)
    assert not isinstance(voucher, Refusal), voucher
    opening = unsigned.complete(signed_tx, sign_typed(voucher))
    assert isinstance(opening, dict), opening
    return opening


def voucher_within(opening: dict[str, Any]) -> Any:
    """The Tempo session's build_within for a voucher of 1 on the opening's channel."""
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 1, "action": "voucher"}
    return MPP_SESSION_TEMPO.build_within(w, H)  # type: ignore[attr-defined]


def test_mpp_session_tempo_rows_whose_transaction_is_for_another_chain() -> None:
    # mpp-session-tempo.json's agreedRefusals rows with transactionChainId (draft-tempo-session-00 L315-316, L356-357
    # and L1227-1228, as the rows' about cites them): the transaction is signed for the challenge's chain.
    rows = [r for r in TEMPO["agreedRefusals"]["rows"] if "transactionChainId" in r]
    assert rows
    for row in rows:
        request_text = TF["requestV1"] if row.get("sessionProtocol") == "v1" else TF["requestV2"]
        assert MPP_SESSION_TEMPO.bound(tempo_opening(request_text, TF["chainId"])) == H
        opening = tempo_opening(request_text, row["transactionChainId"])
        assert MPP_SESSION_TEMPO.bound(opening) == Refusal(row["expect"]), row["case"]
        assert voucher_within(opening) == Refusal(row["expect"]), row["case"]


OPERATOR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"  # the published Anvil key #2's address, a test value


def with_descriptor(opening: dict[str, Any], members: dict[str, Any]) -> dict[str, Any]:
    """The opening with members in place of its descriptor's, and its channelId the draft's keccak256 over the
    descriptor so changed, the escrow and the chain (draft-tempo-session-00 L339-352)."""
    descriptor = {**opening["payload"]["descriptor"], **members}
    channel_id = tempo_channel_id({**descriptor, "escrow": TF["escrowV2"], "chainId": TF["chainId"]})
    return {**opening, "payload": {**opening["payload"], "descriptor": descriptor, "channelId": channel_id}}


def test_mpp_session_tempo_rows_whose_descriptor_names_another_payer_or_nonce_hash() -> None:
    # mpp-session-tempo.json's agreedRefusals rows that change the v2 descriptor's payer or expiringNonceHash
    # (draft-tempo-session-00 L366-367, L1181-1182 and L1186-1188, as the rows' about cites them): the payer is the
    # address the transaction recovers to, and the expiring nonce hash is the transaction's under that payer.
    opening = tempo_opening(TF["requestV2"], TF["chainId"])
    assert opening["payload"]["descriptor"]["expiringNonceHash"] == TEMPO["TS2"]["expectNonceHash"]
    assert MPP_SESSION_TEMPO.bound(opening) == H
    rows = [r for r in TEMPO["agreedRefusals"]["rows"] if {"payer", "expiringNonceHash"} >= set(r) - {"case", "expect"}]
    assert rows
    for row in rows:
        presented = with_descriptor(opening, {k: row[k] for k in ("payer", "expiringNonceHash") if k in row})
        assert MPP_SESSION_TEMPO.bound(presented) == Refusal(row["expect"]), row["case"]
        assert voucher_within(presented) == Refusal(row["expect"]), row["case"]


def test_mpp_session_tempo_rows_whose_opening_names_another_party_than_its_open_call() -> None:
    # mpp-session-tempo.json's agreedRefusals rows that change a v2 descriptor's payee, token or authorizedSigner, or a
    # v1 payload's channelId (draft-tempo-session-00 L865-871 and L1180-1183, as the rows' about cites them): the
    # descriptor matches the signed open call, and v1's channelId is computed from the payer the transaction recovers to.
    v2 = tempo_opening(TF["requestV2"], TF["chainId"])
    v1 = tempo_opening(TF["requestV1"], TF["chainId"])
    assert (MPP_SESSION_TEMPO.bound(v2), MPP_SESSION_TEMPO.bound(v1)) == (H, H)
    parties = [r for r in TEMPO["agreedRefusals"]["rows"] if "sessionProtocol" not in r and {"payee", "token", "authorizedSigner"} & set(r)]
    channels = [r for r in TEMPO["agreedRefusals"]["rows"] if r.get("sessionProtocol") == "v1" and "channelId" in r]
    assert parties and channels
    for row in parties:
        presented = with_descriptor(v2, {k: row[k] for k in ("payee", "token", "authorizedSigner") if k in row})
        assert MPP_SESSION_TEMPO.bound(presented) == Refusal(row["expect"]), row["case"]
    for row in channels:
        presented = {**v1, "payload": {**v1["payload"], "channelId": row["channelId"]}}
        assert MPP_SESSION_TEMPO.bound(presented) == Refusal(row["expect"]), row["case"]
        assert voucher_within(presented) == Refusal(row["expect"]), row["case"]


def test_mpp_session_tempo_an_open_call_argument_that_is_not_an_address_is_tx_malformed() -> None:
    # An ABI address word is the address in its last 20 bytes and zeros in its first 12 (Solidity ABI specification):
    # v2's open(payee, operator, token, deposit, salt, authorizedSigner) words 0, 1, 2 and 5, and v1's open(payee, token,
    # deposit, salt, authorizedSigner) words 0, 1 and 4. A deposit word is not an address.
    for request_text, words, deposit in ((TF["requestV2"], (0, 1, 2, 5), 3), (TF["requestV1"], (0, 1, 4), 2)):
        for i in words:
            assert MPP_SESSION_TEMPO.bound(tempo_opening(request_text, TF["chainId"], dirty=i)) == Refusal("tempo/tx-malformed")
        assert MPP_SESSION_TEMPO.bound(tempo_opening(request_text, TF["chainId"], dirty=deposit)) == H


ACCOUNT = bytes.fromhex(OPERATOR[2:])
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1's group order (SEC 2, 2.4.1)
CARRIED = bytes(range(1, 65))  # a public key's 64 coordinate bytes, a test value: its signature is not verified here


def k1(digest: bytes, v_of: Any = lambda parity: 27 + parity) -> bytes:
    """r || s || v of the payer key's signature over digest, v written as v_of(the y parity)."""
    raw = bytes.fromhex(sig65(digest, TF["payerKey"])[2:])
    return raw[:64] + bytes([v_of(raw[64] - 27)])


# The sender each signature form names, as Tempo reads its signatures (tempoxyz/tempo 9bb63953, tt_signature.rs):
# secp256k1's 65 bytes by recovery, v 0, 1, 27, 28 or 35 and above; P256 (0x01, 129 bytes) and WebAuthn (0x02, 128 to
# 2,048 bytes) by the key they carry, the address keccak256 of its coordinates names; a keychain signature (0x03, or
# 0x04 whose inner signature signs keccak256(0x04 || the hash || the account)) by its account. The payer is the published
# Anvil key #0's address, fixed.payer.
SENDERS: list[tuple[str, Any, str]] = [
    ("secp256k1, v 27 or 28", k1, TF["payer"]),
    ("secp256k1, v 0 or 1", lambda d: k1(d, lambda p: p), TF["payer"]),
    ("secp256k1, v 35 or 36", lambda d: k1(d, lambda p: 35 + p), TF["payer"]),
    ("secp256k1, v 37 or 38", lambda d: k1(d, lambda p: 37 + p), TF["payer"]),
    ("P256", lambda d: b"\x01" + bytes(64) + CARRIED + b"\x00", "0x" + keccak(CARRIED)[12:].hex()),
    ("WebAuthn of 128 bytes", lambda d: b"\x02" + CARRIED + CARRIED, "0x" + keccak(CARRIED)[12:].hex()),
    ("WebAuthn of 2048 bytes", lambda d: b"\x02" + bytes(1984) + CARRIED, "0x" + keccak(CARRIED)[12:].hex()),
    ("keychain", lambda d: b"\x03" + ACCOUNT + k1(d), OPERATOR),
    ("keychain v2", lambda d: b"\x04" + ACCOUNT + k1(keccak(b"\x04" + d + ACCOUNT)), OPERATOR),
    ("keychain over P256", lambda d: b"\x03" + ACCOUNT + b"\x01" + bytes(64) + CARRIED + b"\x00", OPERATOR),
]
NOT_SENDERS: list[tuple[str, Any]] = [
    ("secp256k1, v 29", lambda d: k1(d, lambda p: 29)),
    ("secp256k1, s in the upper half", lambda d: k1(d)[:32] + (N - int.from_bytes(k1(d)[32:64], "big")).to_bytes(32, "big") + bytes([55 - k1(d)[64]])),
    ("secp256k1, r 0", lambda d: bytes(32) + k1(d)[32:]),
    ("P256 of 128 bytes", lambda d: b"\x01" + bytes(64) + CARRIED),
    ("WebAuthn of 127 bytes", lambda d: b"\x02" + bytes(63) + CARRIED),
    ("WebAuthn of 2049 bytes", lambda d: b"\x02" + bytes(1985) + CARRIED),
    ("keychain of 10 account bytes", lambda d: b"\x03" + ACCOUNT[:10]),
    ("keychain over type 9", lambda d: b"\x03" + ACCOUNT + b"\x09" + bytes(64)),
    ("type 5", lambda d: b"\x05" + bytes(100)),
    ("type 9", lambda d: b"\x09" + bytes(129)),
    ("no bytes", lambda d: b""),
]


@pytest.mark.parametrize(("form", "signature", "sender"), SENDERS, ids=[s[0] for s in SENDERS])
def test_mpp_session_tempo_a_v2_descriptor_names_the_transaction_s_sender(form: str, signature: Any, sender: str) -> None:
    opening = tempo_opening(TF["requestV2"], TF["chainId"], signature, sender)
    assert opening["payload"]["descriptor"]["payer"] == sender
    assert MPP_SESSION_TEMPO.bound(opening) == H
    other = OPERATOR if sender != OPERATOR else TF["payer"]
    assert MPP_SESSION_TEMPO.bound(tempo_opening(TF["requestV2"], TF["chainId"], signature, other)) == Refusal("tempo/descriptor-mismatch")


@pytest.mark.parametrize(("form", "signature"), NOT_SENDERS, ids=[s[0] for s in NOT_SENDERS])
def test_mpp_session_tempo_a_signature_that_names_no_sender_is_tx_malformed(form: str, signature: Any) -> None:
    opening = tempo_opening(TF["requestV2"], TF["chainId"], signature)
    assert MPP_SESSION_TEMPO.bound(opening) == Refusal("tempo/tx-malformed")


def test_mpp_session_tempo_a_v2_descriptor_names_the_challenge_s_operator() -> None:
    # draft-tempo-session-00 requires a v2 credential's descriptor operator to be the challenge's methodDetails.operator,
    # the zero address where it names none. B6's opening names the zero address under a challenge naming none.
    channel = MPP_SESSION_TEMPO.channel  # type: ignore[attr-defined]
    b6 = next(r for r in TEMPO["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]
    assert (MPP_SESSION_TEMPO.bound(b6), channel.bound_within(b6)) == (H, H)
    named = json.loads(TF["requestV2"])
    named["methodDetails"]["operator"] = OPERATOR
    under_named = {**b6, "challenge": {**b6["challenge"], "request": b64u(json.dumps(named))}}
    descriptor = {**b6["payload"]["descriptor"], "operator": OPERATOR}
    channel_id = tempo_channel_id({**descriptor, "escrow": TF["escrowV2"], "chainId": TF["chainId"]})
    naming = {**b6, "payload": {**b6["payload"], "descriptor": descriptor, "channelId": channel_id}}
    for presented in (under_named, naming):
        assert MPP_SESSION_TEMPO.bound(presented) == Refusal("tempo/descriptor-mismatch")
        assert channel.bound_within(presented) == Refusal("tempo/descriptor-mismatch")
    # The binding's build writes the challenge's operator into the open call and the descriptor.
    for written in (OPERATOR, "0x" + OPERATOR[2:].lower()):
        named["methodDetails"]["operator"] = written
        opening = tempo_opening(json.dumps(named), TF["chainId"])
        assert opening["payload"]["descriptor"]["operator"] == written
        assert (MPP_SESSION_TEMPO.bound(opening), channel.bound_within(opening)) == (H, H)


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


SUB_B6 = next(r for r in SUB["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]


def sub1_with(member: str, value: Any) -> dict[str, Any]:
    """B6's credential with SUB1's key authorization, its member in place of SUB1's, signed by the payer key."""
    a = SUB["SUB1"]["authorization"]
    authorization = {
        **a,
        "chainId": int(a["chainId"]),
        "expiry": int(a["expiry"]),
        "limits": [{**lim, "limit": int(lim["limit"]), "period": int(lim["period"])} for lim in a["limits"]],
        member: value,
    }
    unsigned = encode_key_authorization(authorization)
    assert isinstance(unsigned, bytes), unsigned
    signed = encode_key_authorization(authorization, sig65(keccak256(unsigned), SF["payerKey"]))
    assert isinstance(signed, bytes), signed
    return {**SUB_B6, "payload": {"type": "keyAuthorization", "signature": "0x" + signed.hex()}}


def test_mpp_subscription_tempo_rows_whose_key_authorization_names_another_key() -> None:
    # mpp-subscription-tempo.json's agreedRefusals rows with keyId or keyType (draft-tempo-subscription-00 L463-466, as
    # the rows' about cites it): the key authorization authorizes the exact access key methodDetails.accessKey describes,
    # both its accessKeyAddress and its keyType.
    channel = MPP_SUBSCRIPTION_TEMPO.channel  # type: ignore[attr-defined]
    assert MPP_SUBSCRIPTION_TEMPO.bound(SUB_B6) == H
    rows = [r for r in SUB["agreedRefusals"]["rows"] if "keyId" in r or "keyType" in r]
    assert rows
    for row in rows:
        member = "keyId" if "keyId" in row else "keyType"
        presented = sub1_with(member, row[member])
        assert MPP_SUBSCRIPTION_TEMPO.bound(presented) == Refusal(row["expect"]), row["case"]
        assert channel.ref(presented) == Refusal(row["expect"]), row["case"]


def test_mpp_subscription_tempo_rows_whose_key_authorization_is_for_another_chain() -> None:
    # mpp-subscription-tempo.json's agreedRefusals rows with chainId (draft-tempo-subscription-00 L461-463, as the rows'
    # about cites it): the key authorization's chain ID is methodDetails.chainId.
    channel = MPP_SUBSCRIPTION_TEMPO.channel  # type: ignore[attr-defined]
    rows = [r for r in SUB["agreedRefusals"]["rows"] if "chainId" in r]
    assert rows
    for row in rows:
        presented = sub1_with("chainId", row["chainId"])
        assert MPP_SUBSCRIPTION_TEMPO.bound(presented) == Refusal(row["expect"]), row["case"]
        assert channel.ref(presented) == Refusal(row["expect"]), row["case"]


def test_mpp_subscription_tempo_the_issued_key_is_read_in_any_case_with_its_type() -> None:
    # Tempo's IAccountKeychain SignatureType numbers the key types (tempoxyz/tempo 9bb63953, account_keychain.rs lines
    # 24-28): secp256k1 0, P256 1, WebAuthn 2. The key id is the issued address's bytes, whatever case either writes.
    channel = MPP_SUBSCRIPTION_TEMPO.channel  # type: ignore[attr-defined]
    request = json.loads(SF["request"])
    key = request["methodDetails"]["accessKey"]
    upper = sub1_with("keyId", "0x" + key["accessKeyAddress"][2:].upper())
    assert MPP_SUBSCRIPTION_TEMPO.bound(upper) == H
    for key_type, number in (("secp256k1", 0), ("p256", 1), ("webAuthn", 2)):
        request["methodDetails"]["accessKey"] = {**key, "keyType": key_type}
        challenge = {**SUB_B6["challenge"], "request": b64u(json.dumps(request))}
        for n in (0, 1, 2):
            presented = {**sub1_with("keyType", n), "challenge": challenge}
            expected: Any = H if n == number else Refusal("tempo/key-not-authorized")
            assert (key_type, n, MPP_SUBSCRIPTION_TEMPO.bound(presented)) == (key_type, n, expected)
    # channel.ref reads the challenge without the pairing's filter: an accessKey that is not one is the filter's code.
    request["methodDetails"]["accessKey"] = {"accessKeyAddress": key["accessKeyAddress"]}
    unfiltered = {**sub1_with("keyType", 0), "challenge": {**SUB_B6["challenge"], "request": b64u(json.dumps(request))}}
    assert channel.ref(unfiltered) == Refusal("mpp/access-key-malformed")


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
