"""The gate's rows, as the TypeScript gate's tests run them, for MPP's sessions on EVM and Tempo and its Tempo
subscription (pairings-chan.test.ts): B2, B6, B10 and B16, and the v1 session's default chain. Expected values are the
vector files'; the key is the published Anvil key #0."""

import asyncio
import hashlib
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from eth_abi.abi import encode as abi_encode
from eth_account import Account
from eth_utils.crypto import keccak

from integraledger_terms import (
    MPP_SESSION_EVM,
    MPP_SESSION_HEDERA,
    MPP_SESSION_LIGHTNING,
    MPP_SESSION_SOLANA,
    MPP_SESSION_TEMPO,
    MPP_SESSION_XRPL,
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
from integraledger_terms.bindings._tempo import encode_key_authorization, expiring_nonce_hash, tempo_channel_id
from integraledger_terms.bindings.mpp_session import evm_channel_id

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


def tempo_signed(
    calls: list[tuple[str, str]], chain_id: int, valid_before: int, signature: Any = None, authorizations: list[bytes] | None = None
) -> tuple[str, bytes]:
    """A 0x76 transaction of TS2's other fields around calls, each (to, data) with no value, for chain_id, whose
    aa_authorization_list holds the RLP-encoded authorizations (none by default), signed by the payer over
    keccak256(0x76 ‖ rlp(fields)), or with the signature bytes signature(that hash) gives; and 0x76 ‖ rlp(fields), the
    bytes the sender signs."""
    fields = [
        rlp_uint_bytes(chain_id),
        rlp_uint_bytes(1),
        rlp_uint_bytes(2),
        rlp_uint_bytes(200000),
        rlp_list([rlp_list([rlp_bytes(bytes.fromhex(to[2:])), rlp_bytes(b""), rlp_bytes(bytes.fromhex(data[2:]))]) for to, data in calls]),
        rlp_list([]),
        rlp_uint_bytes(2**256 - 1),
        rlp_bytes(b""),
        rlp_uint_bytes(valid_before),
        rlp_bytes(b""),
        rlp_bytes(bytes.fromhex(TF["pathUSD"][2:])),
        rlp_bytes(b""),
        rlp_list(authorizations or []),
    ]
    signing = b"\x76" + rlp_list(fields)
    digest = keccak256(signing)
    signed = bytes.fromhex(sig65(digest, TF["payerKey"])[2:]) if signature is None else signature(digest)
    return "0x76" + rlp_list([*fields, rlp_bytes(signed)]).hex(), signing


def open_wire(request: Any, signature: Any = None) -> str:
    """TS2's wire: the open call in a 0x76 transaction, signed by the payer over keccak256(0x76 ‖ rlp(fields)); or
    with the signature bytes signature(that hash) gives."""
    assert request["kind"] == "tempo-call", request
    return tempo_signed([(request["call"]["to"], request["call"]["data"])], request["chainId"], request["validBefore"], signature)[0]


class TempoAnswer:
    def __init__(self) -> None:
        self.seen: list[Any] = []

    def __call__(self, request: Any) -> str:
        self.seen.append(request)
        if request["kind"] == "tempo-call":
            return open_wire(request)
        assert request["kind"] == "eip712", request
        return sign_typed(request["typedData"])


VOUCHER_SIGNATURE = "0x" + "66" * 65  # a test value: build's complete reads its length only


def tempo_built(request_text: str, payer: str = TF["payer"]) -> Any:
    """The binding's build for a challenge of request_text and payer."""
    unsigned = MPP_SESSION_TEMPO.build(
        {"challenge": placed_doc(issued("tempo", "session", request_text), H, LINK)[0], "from": payer, "deposit": int(TF["deposit"])}, H
    )
    assert not isinstance(unsigned, Refusal), unsigned
    return unsigned


def carrying(opening: dict[str, Any], wire: str) -> dict[str, Any]:
    """The opening, carrying wire in place of its transaction."""
    return {**opening, "payload": {**opening["payload"], "transaction": wire}}


def tempo_opening(
    request_text: str, chain: int, signature: Any = None, payer: str = TF["payer"], dirty: int | None = None
) -> dict[str, Any]:
    """The opening the binding's build writes for a challenge of request_text and payer, completed with its open call
    in a transaction of TS2's other fields for chain, signed with fixed.payerKey or as signature gives, and the payer's
    voucher. With dirty, the open call's argument word of that index has a non-zero first byte. Where complete refuses
    the transaction, as bound refuses the credential it would give, it is that credential (completed_for)."""
    unsigned = tempo_built(request_text, payer)
    call = unsigned.funding["call"]
    if dirty is not None:
        at = 10 + 64 * dirty
        call = {**call, "data": call["data"][:at] + "01" + call["data"][at + 2 :]}
    signed_tx = open_wire({**unsigned.funding, "call": call, "chainId": chain}, signature)
    voucher = unsigned.voucher(signed_tx)
    if isinstance(voucher, Refusal):
        by_payer = tempo_built(request_text)
        own = by_payer.complete(open_wire(by_payer.funding), VOUCHER_SIGNATURE)
        assert isinstance(own, dict), own
        return completed_for(own, signed_tx, payer, request_text)
    opening = unsigned.complete(signed_tx, sign_typed(voucher))
    assert isinstance(opening, dict), opening
    return opening


def voucher_within(opening: dict[str, Any]) -> Any:
    """The Tempo session's build_within for a voucher of 1 on the opening's channel."""
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 1, "action": "voucher"}
    return MPP_SESSION_TEMPO.build_within(w, H)  # type: ignore[attr-defined]


def test_mpp_session_tempo_rows_whose_transaction_is_for_another_chain() -> None:
    # mpp-session-tempo.json's agreedRefusals rows with transactionChainId (draft-tempo-session-00 L315-316, L356-357
    # and L1227-1228, as the rows' about cites them): the transaction is signed for the challenge's chain. build's
    # voucher and complete refuse a transaction signed for the row's chain with the row's code, and bound and
    # build_within refuse it in the credential complete gives for the transaction signed for the challenge's chain.
    rows = agreed_rows("the transactionChainId rows", lambda r: "transactionChainId" in r, exact=2, left=40)
    for row in rows:
        assert set(row) <= {"case", "sessionProtocol", "transactionChainId", "expect"}, row["case"]
        request_text = TF["requestV1"] if row.get("sessionProtocol") == "v1" else TF["requestV2"]
        unsigned = tempo_built(request_text)
        own = unsigned.complete(open_wire({**unsigned.funding, "chainId": TF["chainId"]}), VOUCHER_SIGNATURE)
        assert MPP_SESSION_TEMPO.bound(own) == H, row["case"]
        other = open_wire({**unsigned.funding, "chainId": row["transactionChainId"]})
        refused = Refusal(row["expect"])
        assert unsigned.voucher(other) == refused, row["case"]
        assert unsigned.complete(other, VOUCHER_SIGNATURE) == refused, row["case"]
        assert MPP_SESSION_TEMPO.bound(carrying(own, other)) == refused, row["case"]
        assert voucher_within(carrying(own, other)) == refused, row["case"]
        # "0x76", the type byte with no RLP list after it, and "0x", no bytes at all, decode as no Tempo transaction
        # (viem's tempo Transaction.deserialize reads neither): voucher and complete refuse each with
        # tempo/tx-malformed, the code bound gives the credential that carries it.
        for undecodable in ("0x76", "0x"):
            assert unsigned.voucher(undecodable) == Refusal("tempo/tx-malformed"), undecodable
            assert unsigned.complete(undecodable, VOUCHER_SIGNATURE) == Refusal("tempo/tx-malformed"), undecodable
            assert MPP_SESSION_TEMPO.bound(carrying(own, undecodable)) == Refusal("tempo/tx-malformed"), undecodable
    # A v1 challenge naming no chainId is on 4217 (draft-tempo-session-00 L613): a transaction signed for 42431 is
    # refused by complete, and by bound in the credential complete gives for the one signed for 4217.
    bare = json.loads(TF["requestV1"])
    del bare["methodDetails"]["chainId"]
    unsigned = tempo_built(json.dumps(bare))
    assert unsigned.funding["chainId"] == 4217
    on_default = unsigned.complete(open_wire(unsigned.funding), VOUCHER_SIGNATURE)
    assert MPP_SESSION_TEMPO.bound(on_default) == H
    off = open_wire({**unsigned.funding, "chainId": 42431})
    assert unsigned.complete(off, VOUCHER_SIGNATURE) == Refusal("tempo/tx-malformed")
    assert MPP_SESSION_TEMPO.bound(carrying(on_default, off)) == Refusal("tempo/tx-malformed")


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
# 2,048 bytes) by the key they carry, the address keccak256 of its coordinates names; a keychain signature, 0x04 whose
# inner signature signs keccak256(0x04 || the hash || the account), by its account. Tempo refuses the keychain form 0x03,
# whose inner signature signs the hash itself, once T1C is active (tempoxyz/tempo 7d4fd03, crates/revm/src/handler.rs,
# validate_version), as it is on chains 4217 and 42431, so 0x03 is among the forms that name no sender. The payer is the
# published Anvil key #0's address, fixed.payer.
SENDERS: list[tuple[str, Any, str]] = [
    ("secp256k1, v 27 or 28", k1, TF["payer"]),
    ("secp256k1, v 0 or 1", lambda d: k1(d, lambda p: p), TF["payer"]),
    ("secp256k1, v 35 or 36", lambda d: k1(d, lambda p: 35 + p), TF["payer"]),
    ("secp256k1, v 37 or 38", lambda d: k1(d, lambda p: 37 + p), TF["payer"]),
    ("P256", lambda d: b"\x01" + bytes(64) + CARRIED + b"\x00", "0x" + keccak(CARRIED)[12:].hex()),
    ("WebAuthn of 128 bytes", lambda d: b"\x02" + CARRIED + CARRIED, "0x" + keccak(CARRIED)[12:].hex()),
    ("WebAuthn of 2048 bytes", lambda d: b"\x02" + bytes(1984) + CARRIED, "0x" + keccak(CARRIED)[12:].hex()),
    ("keychain v2", lambda d: b"\x04" + ACCOUNT + k1(keccak(b"\x04" + d + ACCOUNT)), OPERATOR),
]
NOT_SENDERS: list[tuple[str, Any]] = [
    ("secp256k1, v 29", lambda d: k1(d, lambda p: 29)),
    ("secp256k1, s in the upper half", lambda d: k1(d)[:32] + (N - int.from_bytes(k1(d)[32:64], "big")).to_bytes(32, "big") + bytes([55 - k1(d)[64]])),
    ("secp256k1, r 0", lambda d: bytes(32) + k1(d)[32:]),
    ("P256 of 128 bytes", lambda d: b"\x01" + bytes(64) + CARRIED),
    ("WebAuthn of 127 bytes", lambda d: b"\x02" + bytes(63) + CARRIED),
    ("WebAuthn of 2049 bytes", lambda d: b"\x02" + bytes(1985) + CARRIED),
    ("keychain", lambda d: b"\x03" + ACCOUNT + k1(d)),
    ("keychain over P256", lambda d: b"\x03" + ACCOUNT + b"\x01" + bytes(64) + CARRIED + b"\x00"),
    ("keychain v2 of 10 account bytes", lambda d: b"\x04" + ACCOUNT[:10]),
    ("keychain v2 over type 9", lambda d: b"\x04" + ACCOUNT + b"\x09" + bytes(64)),
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
    # build's voucher and complete refuse the transaction, and bound refuses the credential complete gives for the
    # transaction the payer signs, carrying this one in its place.
    for request_text in (TF["requestV2"], TF["requestV1"]):
        unsigned = tempo_built(request_text)
        own = unsigned.complete(open_wire(unsigned.funding), VOUCHER_SIGNATURE)
        assert MPP_SESSION_TEMPO.bound(own) == H
        wire = open_wire(unsigned.funding, signature)
        assert unsigned.voucher(wire) == Refusal("tempo/tx-malformed")
        assert unsigned.complete(wire, VOUCHER_SIGNATURE) == Refusal("tempo/tx-malformed")
        assert MPP_SESSION_TEMPO.bound(carrying(own, wire)) == Refusal("tempo/tx-malformed")


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


def agreed_rows(name: str, keep: Callable[[dict[str, Any]], bool], exact: int, left: int) -> list[dict[str, Any]]:
    """The rows of mpp-session-tempo.json's agreedRefusals that keep selects by their members, never by their index.
    It prints how many rows it runs and how many it leaves to the other tests, and asserts both counts."""
    rows: list[dict[str, Any]] = TEMPO["agreedRefusals"]["rows"]
    kept = [r for r in rows if keep(r)]
    print(f"mpp-session-tempo.json agreedRefusals.rows, {name}: {len(kept)} run, {len(rows) - len(kept)} left to the other tests")
    assert (len(kept), len(rows) - len(kept)) == (exact, left), name
    return kept


def nine_word_id(descriptor: dict[str, Any]) -> str:
    """The v2 channel id draft-tempo-session-00 computes (L339-352): keccak256 of the descriptor's payer, payee,
    operator, token, salt, authorizedSigner and expiringNonceHash, the escrow and the chain, encoded with eth-abi."""
    types = ["address", "address", "address", "address", "bytes32", "address", "bytes32", "address", "uint256"]
    d = descriptor
    words = [d["payer"], d["payee"], d["operator"], d["token"], d["salt"], d["authorizedSigner"], d["expiringNonceHash"], TF["escrowV2"]]
    values = [bytes.fromhex(w[2:]) if len(w) == 66 else w.lower() for w in words]
    return "0x" + keccak(abi_encode(types, [*values, TF["chainId"]])).hex()


# The fault codes the draft's open verification gives each fault alone (draft-tempo-session-00 L1179-1188).
ALONE: dict[str, Callable[[bool], str]] = {
    "chain": lambda v1: "tempo/tx-malformed",
    "noOpen": lambda v1: "tempo/open-not-found",
    "twoOpens": lambda v1: "tempo/open-ambiguous",
    "length": lambda v1: "tempo/tx-malformed",
    "salt": lambda v1: "tempo/salt-not-bound",
    "word": lambda v1: "tempo/tx-malformed",
    "sender": lambda v1: "tempo/tx-malformed",
    "channelId": lambda v1: "mpp/channel-not-bound" if v1 else "tempo/descriptor-mismatch",
    "channelIdNotHash": lambda v1: "mpp/credential-malformed",
}


def faulted(v1: bool, faults: list[str]) -> dict[str, Any]:
    """build's opening from fixed.payer for the challenge of its protocol, fixed.requestV1 or fixed.requestV2, its open
    call in a transaction of TS2's other fields signed with fixed.payerKey, with each fault applied as the rows' about
    defines it: chain signs for 4217; noOpen sends the call to fixed.recipient; twoOpens puts it in twice; length
    appends one zero byte to its input; salt writes fixed.H2 as its salt word; word writes 0x01 as the first byte of its
    payee word; sender writes the signature's v as 29; channelId writes 0x followed by 32 bytes of 0x22 as the payload's
    channelId; channelIdNotHash writes 0x12. On v2 the descriptor is build's with expiringNonceHash that transaction's
    under fixed.payer (keccak256 of the bytes the sender signed and fixed.payer), and the payload's channelId, but for
    the two channelId faults, its channel id (nine_word_id)."""
    unsigned = tempo_built(TF["requestV1"] if v1 else TF["requestV2"])
    escrow = TF["escrowV1"] if v1 else TF["escrowV2"]
    own = unsigned.complete(open_wire(unsigned.funding), VOUCHER_SIGNATURE)
    data: str = unsigned.funding["call"]["data"]
    salt_at = 10 + 64 * (3 if v1 else 4)
    if "salt" in faults:
        data = data[:salt_at] + TF["H2"][2:] + data[salt_at + 64 :]
    if "word" in faults:
        data = data[:10] + "01" + data[12:]
    if "length" in faults:
        data = data + "00"
    call = (TF["recipient"] if "noOpen" in faults else escrow, data)
    signature = (lambda d: k1(d, lambda p: 29)) if "sender" in faults else None
    chain = 4217 if "chain" in faults else TF["chainId"]
    wire, signing = tempo_signed([call, call] if "twoOpens" in faults else [call], chain, unsigned.funding["validBefore"], signature)
    payload = {**own["payload"], "transaction": wire}
    if not v1:
        descriptor = {**own["payload"]["descriptor"], "expiringNonceHash": "0x" + keccak(signing + bytes.fromhex(TF["payer"][2:])).hex()}
        payload["descriptor"] = descriptor
        payload["channelId"] = nine_word_id(descriptor)
    if "channelId" in faults:
        payload["channelId"] = "0x" + "22" * 32
    if "channelIdNotHash" in faults:
        payload["channelId"] = "0x12"
    return {**own, "payload": payload}


def test_mpp_session_tempo_rows_with_two_faults_are_refused_for_the_one_the_draft_checks_first() -> None:
    # mpp-session-tempo.json's agreedRefusals rows with faults. draft-tempo-session-00 (L1179-1188) orders the open
    # verification: "Decode the signed transaction from `transaction`, verify it calls `open()` on the expected escrow
    # contract with correct parameters. Recover the `payer` address from the transaction, infer `authorizedSigner` from
    # the calldata, and compute `channelId` deterministically", then "For v2, servers MUST also verify the payload
    # `descriptor`, the computed `channelId`, the descriptor `expiringNonceHash`". Each fault alone is refused with its
    # own code, and the two together with the code of the one the draft checks first, the row's: by bound, and by
    # build_within, which reads the opening as bound does.
    rows = agreed_rows("the faults rows", lambda r: "faults" in r, exact=26, left=16)
    for v1 in (False, True):
        assert MPP_SESSION_TEMPO.bound(faulted(v1, [])) == H
    ts1 = tempo_built(TF["requestV2"]).funding
    assert ts1["call"]["data"] == TEMPO["TS1"]["expectCalldata"]
    signing = tempo_signed([(TF["escrowV2"], ts1["call"]["data"])], TF["chainId"], ts1["validBefore"])[1]
    assert "0x" + keccak(signing + bytes.fromhex(TF["payer"][2:])).hex() == TEMPO["TS2"]["expectNonceHash"]
    for row in rows:
        assert set(row) <= {"case", "sessionProtocol", "faults", "expect"}, row["case"]
        v1 = row.get("sessionProtocol") == "v1"
        faults = row["faults"]
        assert len(faults) == 2 and ALONE[faults[0]](v1) == row["expect"] != ALONE[faults[1]](v1), row["case"]
        for fault in faults:
            assert MPP_SESSION_TEMPO.bound(faulted(v1, [fault])) == Refusal(ALONE[fault](v1)), (row["case"], fault)
        both = faulted(v1, faults)
        assert MPP_SESSION_TEMPO.bound(both) == Refusal(row["expect"]), row["case"]
        assert voucher_within(both) == Refusal(row["expect"]), row["case"]


def completed_for(own: dict[str, Any], wire: str, from_: str, request_text: str) -> dict[str, Any]:
    """The credential the Tempo session build's complete writes for wire from from_ for a challenge of request_text,
    as own carries it from fixed.payer, whatever bound answers it: on v1 the channelId from_ opens with the challenge's
    values; on v2 the descriptor naming from_ as its payer, with the expiring nonce hash of wire under from_, and its
    channelId."""
    p = own["payload"]
    request = json.loads(request_text)
    md = request["methodDetails"]
    if "descriptor" not in p:
        payee, token, escrow = request["recipient"], request["currency"], md["escrowContract"]
        channel = evm_channel_id(from_, payee, token, H.lower(), p["authorizedSigner"], escrow, md["chainId"])
        assert isinstance(channel, str), channel
        return {**own, "payload": {**p, "transaction": wire, "channelId": channel}}
    nonce_hash = expiring_nonce_hash(bytes.fromhex(wire[2:]), from_)
    assert isinstance(nonce_hash, str), nonce_hash
    descriptor = {**p["descriptor"], "payer": from_, "expiringNonceHash": nonce_hash}
    channel = tempo_channel_id({**descriptor, "escrow": md["escrowContract"], "chainId": md["chainId"]})
    assert isinstance(channel, str), channel
    return {**own, "payload": {**p, "transaction": wire, "channelId": channel, "descriptor": descriptor}}


def test_mpp_session_tempo_build_refuses_a_transaction_with_the_code_bound_gives_its_credential() -> None:
    # mpp-session-tempo.json's agreedRefusals rows with from or padding. build's voucher and complete return no
    # credential bound refuses: each gives the code bound gives the credential complete would give for the transaction.
    # A row with from is build's opening from that address, its transaction signed with fixed.payerKey, so its sender,
    # fixed.payer, is not the payer the credential names: on v2 the descriptor's (draft-tempo-session-00 L1180-1183), on
    # v1 the payer of its channelId (L299-312). A row with padding is build's opening with a second call, to
    # fixed.recipient, whose input is that many zero bytes, so its credential is over the credential size bound, 64 KiB.
    # The same transaction without the row's change is completed, and gives H.
    rows = agreed_rows("the from and padding rows", lambda r: "from" in r or "padding" in r, exact=4, left=38)
    for row in rows:
        assert set(row) <= {"case", "sessionProtocol", "from", "padding", "expect"}, row["case"]
        assert ("from" in row) != ("padding" in row), row["case"]
        request_text = TF["requestV1"] if row.get("sessionProtocol") == "v1" else TF["requestV2"]
        by_payer = tempo_built(request_text)
        call = by_payer.funding["call"]
        own = by_payer.complete(open_wire(by_payer.funding), VOUCHER_SIGNATURE)
        assert MPP_SESSION_TEMPO.bound(own) == H, row["case"]
        from_ = row.get("from", TF["payer"])
        unsigned = tempo_built(request_text, from_)
        assert unsigned.funding["call"]["data"] == call["data"], row["case"]
        calls = [(call["to"], call["data"])]
        if "padding" in row:
            calls.append((TF["recipient"], "0x" + "00" * row["padding"]))
        wire = tempo_signed(calls, by_payer.funding["chainId"], by_payer.funding["validBefore"])[0]
        refused = Refusal(row["expect"])
        assert unsigned.voucher(wire) == refused, row["case"]
        assert unsigned.complete(wire, VOUCHER_SIGNATURE) == refused, row["case"]
        assert MPP_SESSION_TEMPO.bound(completed_for(own, wire, from_, request_text)) == refused, row["case"]
        if "from" in row:
            assert MPP_SESSION_TEMPO.bound(by_payer.complete(wire, VOUCHER_SIGNATURE)) == H, row["case"]


KEYCHAIN_VERSIONS = {"keychain-v1": 0x03, "keychain-v2": 0x04}


def keychain(form: str, digest: bytes, access_key: str) -> bytes:
    """A keychain signature for fixed.payer over digest, in the form the rows name, as ox's SignatureEnvelope.serialize
    writes it: the type byte (keychain-v1 0x03, keychain-v2 0x04), fixed.payer's 20 bytes, then access_key's secp256k1
    signature r ‖ s ‖ v (v 27 or 28) over the digest itself (0x03) or over keccak256(0x04 ‖ digest ‖ fixed.payer)
    (0x04)."""
    payer = bytes.fromhex(TF["payer"][2:])
    version = KEYCHAIN_VERSIONS[form]
    inner = digest if version == 0x03 else keccak(b"\x04" + digest + payer)
    return bytes([version]) + payer + bytes.fromhex(sig65(inner, access_key)[2:])


def entry_tuple(a: dict[str, Any]) -> list[bytes]:
    """An aa_authorization_list entry's [chainId, address, nonce], RLP-encoded each."""
    return [rlp_uint_bytes(a["chainId"]), rlp_bytes(bytes.fromhex(a["address"][2:])), rlp_uint_bytes(a["nonce"])]


def entry_hash(a: dict[str, Any]) -> bytes:
    """EIP-7702's signing hash of an entry: keccak256(0x05 ‖ rlp([chainId, address, nonce]))."""
    return keccak(b"\x05" + rlp_list(entry_tuple(a)))


def opened_carrying(own: dict[str, Any], wire: str, signing: bytes) -> dict[str, Any]:
    """The credential complete would give for wire: own, the credential complete gives for the transaction fixed.payer
    signs, carrying wire in its place, and on v2 the descriptor's expiringNonceHash keccak256 of the bytes wire's sender
    signed and fixed.payer, and the channel id the draft's over that descriptor (nine_word_id)."""
    payload = {**own["payload"], "transaction": wire}
    if "descriptor" in own["payload"]:
        descriptor = {**own["payload"]["descriptor"], "expiringNonceHash": "0x" + keccak(signing + bytes.fromhex(TF["payer"][2:])).hex()}
        payload["descriptor"] = descriptor
        payload["channelId"] = nine_word_id(descriptor)
    return {**own, "payload": payload}


def test_mpp_session_tempo_rows_whose_transaction_carries_a_0x03_keychain_signature() -> None:
    # mpp-session-tempo.json's agreedRefusals rows with senderSignature. Tempo's transaction specification (docs.tempo.xyz,
    # Tempo Transactions Specification, "Keychain" and "Transaction Validation", step 1): "The legacy `0x03` format is
    # rejected from T1C onward." tempoxyz/tempo 7d4fd03 activates T1C on chain 4217 at 1773327600 and on chain 42431 at
    # 1773068400 (crates/hardfork/src/constants.rs), and its handler refuses a 0x03 signature once T1C is active, the
    # sender's and each aa_authorization_list entry's (crates/revm/src/handler.rs, validate_version). An entry is
    # rlp([chain_id, address, nonce, signature]) (crates/primitives/src/transaction/tt_authorization.rs). Each row's
    # transaction hashes to its expectSha256 (GNU coreutils sha256sum over the bytes ox wrote): build's voucher and
    # complete refuse it, and bound and build_within refuse the credential complete would give for it. The same
    # opening with every signature in the 0x04 form completes, gives H and a voucher built within it.
    rows = agreed_rows("the senderSignature rows", lambda r: "senderSignature" in r, exact=4, left=38)
    for row in rows:
        assert set(row) <= {"case", "sessionProtocol", "senderSignature", "authorizationList", "accessKey", "expectSha256", "expect"}, row["case"]
        entries: list[dict[str, Any]] = row.get("authorizationList", [])
        for a in entries:
            assert set(a) == {"chainId", "address", "nonce", "signature"}, row["case"]
        forms = [row["senderSignature"], *(a["signature"] for a in entries)]
        assert forms.count("keychain-v1") == 1 and set(forms) <= set(KEYCHAIN_VERSIONS), row["case"]
        v1 = row.get("sessionProtocol") == "v1"
        unsigned = tempo_built(TF["requestV1"] if v1 else TF["requestV2"])
        own = unsigned.complete(open_wire(unsigned.funding), VOUCHER_SIGNATURE)
        call = (unsigned.funding["call"]["to"], unsigned.funding["call"]["data"])

        def transaction(as_form: Callable[[str], str]) -> tuple[str, bytes]:
            """The row's opening transaction, each signature in the form as_form gives for the row's."""
            listed = [rlp_list([*entry_tuple(a), rlp_bytes(keychain(as_form(a["signature"]), entry_hash(a), row["accessKey"]))]) for a in entries]

            def sign(digest: bytes) -> bytes:
                return keychain(as_form(row["senderSignature"]), digest, row["accessKey"])

            return tempo_signed([call], TF["chainId"], unsigned.funding["validBefore"], sign, listed)

        control, control_signing = transaction(lambda form: "keychain-v2")
        completed = unsigned.complete(control, VOUCHER_SIGNATURE)
        assert opened_carrying(own, control, control_signing) == completed, row["case"]
        assert not isinstance(unsigned.voucher(control), Refusal), row["case"]
        assert MPP_SESSION_TEMPO.bound(completed) == H, row["case"]
        assert not isinstance(voucher_within(completed), Refusal), row["case"]
        wire, signing = transaction(lambda form: form)
        assert "0x" + hashlib.sha256(bytes.fromhex(wire[2:])).hexdigest() == row["expectSha256"], row["case"]
        refused = Refusal(row["expect"])
        assert unsigned.voucher(wire) == refused, row["case"]
        assert unsigned.complete(wire, VOUCHER_SIGNATURE) == refused, row["case"]
        assert MPP_SESSION_TEMPO.bound(opened_carrying(own, wire, signing)) == refused, row["case"]
        assert voucher_within(opened_carrying(own, wire, signing)) == refused, row["case"]


def test_mpp_session_tempo_an_authorization_list_entry_is_read_for_its_signature_s_form_alone() -> None:
    # An entry that is not a list of four items whose fourth is a byte string holds no signature to read and is refused
    # tempo/tx-malformed; a 65-byte signature is secp256k1's whatever its first byte, as TempoSignature::from_bytes reads
    # it (tempoxyz/tempo 7d4fd03, crates/primitives/src/transaction/tt_signature.rs), and is not.
    unsigned = tempo_built(TF["requestV2"])
    own = unsigned.complete(open_wire(unsigned.funding), VOUCHER_SIGNATURE)
    call = (unsigned.funding["call"]["to"], unsigned.funding["call"]["data"])
    entry = {"chainId": TF["chainId"], "address": "0x" + "00" * 20, "nonce": 0}
    entry_signature = bytes.fromhex(sig65(entry_hash(entry), TF["payerKey"])[2:])
    starting_with_03 = b"\x03" + entry_signature[1:]
    assert len(starting_with_03) == 65
    wire, signing = tempo_signed([call], TF["chainId"], unsigned.funding["validBefore"], None, [rlp_list([*entry_tuple(entry), rlp_bytes(starting_with_03)])])
    assert unsigned.complete(wire, VOUCHER_SIGNATURE) == opened_carrying(own, wire, signing)
    assert MPP_SESSION_TEMPO.bound(opened_carrying(own, wire, signing)) == H
    malformed = Refusal("tempo/tx-malformed")
    for name, listed in (
        ("three items", rlp_list(entry_tuple(entry))),
        ("a list in place of the signature", rlp_list([*entry_tuple(entry), rlp_list([rlp_bytes(entry_signature)])])),
        ("a byte string in place of the entry", rlp_bytes(entry_signature)),
    ):
        wire, signing = tempo_signed([call], TF["chainId"], unsigned.funding["validBefore"], None, [listed])
        assert unsigned.voucher(wire) == malformed, name
        assert unsigned.complete(wire, VOUCHER_SIGNATURE) == malformed, name
        assert MPP_SESSION_TEMPO.bound(opened_carrying(own, wire, signing)) == malformed, name


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


KEY_AUTHORIZATIONS: dict[str, Any] = json.loads((Path(__file__).parent / "tempo_key_authorizations.json").read_text())


def answered(result: Any) -> Any:
    """A binding's answer as tempo_key_authorizations.json writes it: a refusal's code, else the value."""
    return result.code if isinstance(result, Refusal) else result


def test_mpp_subscription_tempo_key_authorization_rows() -> None:
    # tempo_key_authorizations.json's rows, each key authorization in B6's credential: a limit reads as [token, limit,
    # period] or [token, limit], an allowed call as [target, [[selector, [recipient, ...]], ...]], with a 20-byte token,
    # target and recipients, 4-byte selectors and canonical unsigned integers; any other form is
    # tempo/key-authorization-malformed, through bound and channel.ref alike.
    channel = MPP_SUBSCRIPTION_TEMPO.channel  # type: ignore[attr-defined]
    rows = KEY_AUTHORIZATIONS["rows"]
    assert {row["expect"]["bound"] == H for row in rows} == {True, False}
    got: dict[str, Any] = {}
    for row in rows:
        presented = {**SUB_B6, "payload": {"type": "keyAuthorization", "signature": row["signature"]}}
        bound, ref = MPP_SUBSCRIPTION_TEMPO.bound(presented), channel.ref(presented)
        got[row["case"]] = {"bound": answered(bound), "ref": answered(ref)}
    assert got == {row["case"]: row["expect"] for row in rows}


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


# ── channel_ref keys only a payment of the channel: one channel_kind refuses is refused with its code, an action the
# pairing's draft does not define among them. draft-tempo-session-00 and the EVM session draft define open, topUp,
# voucher and close (tempoxyz/mpp-specs 08e7dd87), and draft-tempo-subscription-00's one credential is the
# keyAuthorization; the Hedera, Solana, XRP Ledger and Lightning sessions' channel_ref refuse such a payment so. Each
# case changes the pairing's B6 opening (mpp-session.test.ts in @integraledger/lcp 0.4.1).

_RAILS = "mpp-session-hedera-solana-xrpl.json"
_SESSIONS: dict[str, Any] = {
    b.id: b
    for b in (
        MPP_SESSION_EVM,
        MPP_SESSION_TEMPO,
        MPP_SUBSCRIPTION_TEMPO,
        MPP_SESSION_HEDERA,
        MPP_SESSION_SOLANA,
        MPP_SESSION_XRPL,
        MPP_SESSION_LIGHTNING,
    )
}
REF_CASES: list[tuple[str, str, str, dict[str, Any]]] = [
    ("session/evm, an opening whose action is use", "mpp-session-evm.json", "mpp/session/evm", {"action": "use"}),
    ("session/evm, an opening whose action is bearer", "mpp-session-evm.json", "mpp/session/evm", {"action": "bearer"}),
    ("session/tempo, an opening whose action is use", "mpp-session-tempo.json", "mpp/session/tempo", {"action": "use"}),
    (
        "session/tempo, an opening whose action is bearer",
        "mpp-session-tempo.json",
        "mpp/session/tempo",
        {"action": "bearer"},
    ),
    (
        "subscription/tempo, a key authorization whose type is transaction",
        "mpp-subscription-tempo.json",
        "mpp/subscription/tempo",
        {"type": "transaction"},
    ),
    ("session/hedera, an opening whose action is use", _RAILS, "mpp/session/hedera", {"action": "use"}),
    ("session/solana, an opening whose action is bearer", _RAILS, "mpp/session/solana", {"action": "bearer"}),
    ("session/xrpl, an opening whose action is topUp", _RAILS, "mpp/session/xrpl", {"action": "topUp"}),
    (
        "session/lightning, an opening whose action is use",
        "mpp-session-lightning.json",
        "mpp/session/lightning",
        {"action": "use"},
    ),
]


@pytest.mark.parametrize(("file", "pairing", "change"), [c[1:] for c in REF_CASES], ids=[c[0] for c in REF_CASES])
def test_channel_ref_refuses_a_payment_channel_kind_refuses_with_its_code(
    file: str, pairing: str, change: dict[str, Any]
) -> None:
    assert len(REF_CASES) == 9
    binding = _SESSIONS[pairing]
    rows = load(file)["buyer"]["rows"]
    own = next(r for r in rows if r["name"] == "B6" and r.get("pairing") == pairing)["input"]["presented"]
    assert binding.channel_kind(own) == "open"
    assert not isinstance(binding.channel_ref(own), Refusal)
    c = {**own, "payload": {**own["payload"], **change}}
    assert binding.channel_kind(c) == Refusal("mpp/session-action")
    assert binding.channel_ref(c) == Refusal("mpp/session-action")
