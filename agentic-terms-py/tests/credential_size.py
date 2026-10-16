"""A credential's size as the credential size bound measures it, a challenge padded to bring a credential to a given
size, the buildChallenge rows' faults (mpp-challenge.json), and each MPP pairing whose build returns a complete that
makes a credential: its vector file, how it builds and completes on that file's B2 inputs and the payment its B6 row
carries, and the answer its bound gives that credential (credentialSize's about)."""

import base64
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from eth_account import Account

import integraledger_terms as terms
from integraledger_terms import Refusal
from integraledger_terms.bindings import _stellar_xdr as xdr
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode
from integraledger_terms.bindings._jose import js_length

from support import load

MC = load("mpp-challenge.json")
_A = load("mpp-charge-evm-authorization.json")
_TX = load("mpp-charge-evm-transaction.json")


def size_of(v: object) -> int:
    """A credential's size as credentialSize's about measures it, and as bound does."""
    if isinstance(v, str):
        return js_length(v) + 2
    if v is None or isinstance(v, (bool, int, float)):
        return 8
    if isinstance(v, list):
        return sum((size_of(x) for x in v), 2)
    if isinstance(v, Mapping):
        return sum((js_length(k) + 3 + size_of(x) for k, x in v.items()), 2)
    raise AssertionError(f"a credential holds {type(v).__name__}, which is not JSON")


def described(c: Mapping[str, Any], n: int) -> dict[str, Any]:
    """The challenge with a description of n characters, a member no pairing reads or hashes."""
    return {**c, "description": "d" * n}


def description_for(credential: object, size: int) -> int:
    """The description length that brings credential, made under a challenge with none, to size."""
    return size - size_of(credential) - (len("description") + 3) - 2


def with_fault(placed: Mapping[str, Any], row: Mapping[str, Any]) -> Any:
    """A placed challenge with a buildChallenge row's fault, as the section's about states it."""
    if "challenge" in row:
        return row["challenge"]
    if "id" in row and row["id"] is None:
        return {k: v for k, v in placed.items() if k != "id"}
    if "digest" in row:
        return {**placed, "digest": row["digest"]}
    if "opaque" in row and row["opaque"] is None:
        return {k: v for k, v in placed.items() if k != "opaque"}
    if "opaque" in row:
        return {**placed, "opaque": row["opaque"]}
    if "legalContext" in row:
        opaque = json.loads(b64u_decode(placed["opaque"]) or b"")
        text = json.dumps({**opaque, "legalContext": row["legalContext"]}, separators=(",", ":"))
        return {**placed, "opaque": b64u_encode(text.encode())}
    return described(placed, description_for({"challenge": placed, "payload": {}}, row["leastSize"]))


class BuildRefused(Exception):
    """A build's refusal, as built raises it, so that a run can tell it from its complete's answer (answered)."""

    def __init__(self, refusal: Refusal) -> None:
        super().__init__(refusal.code)
        self.refusal = refusal


# What a test does to the caller's objects once build has answered and before complete runs; none by default.
after_build: list[Callable[[], None]] = []


def built(u: Any) -> Any:
    """A build's answer, which these rows' inputs never have refused; then each after_build a test sets."""
    if isinstance(u, Refusal):
        raise BuildRefused(u)
    for hook in after_build:
        hook()
    return u


def answered(run: Callable[[], Any]) -> tuple[str, Any]:
    """What a run of build and complete gives: build's refusal, or complete's answer."""
    try:
        return "complete", run()
    except BuildRefused as e:
        return "build", e.refusal


def _decoded(c: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = json.loads(b64u_decode(c["request"]) or b"")
    return out


def _account(b2: Mapping[str, Any]) -> str:
    """The address of a CAIP-10 account: what follows its namespace and reference."""
    return ":".join(b2["input"]["account"].split(":")[2:])


def _sig65(message_hash: str, key: str) -> str:
    """A 65-byte secp256k1 signature, r, s and v (27 or 28), as viem's sign writes it."""
    s = Account.unsafe_sign_hash(bytes.fromhex(message_hash[2:]), key)
    return "0x" + int(s.r).to_bytes(32, "big").hex() + int(s.s).to_bytes(32, "big").hex() + bytes([int(s.v)]).hex()


def mv11_transaction() -> str:
    """MV11's EIP-1559 transaction, signed with fixed.payerKey by eth-account: the EVM transaction charge's complete
    reads the transaction's chain id, so it takes a transaction of the challenge's chain only."""
    t = _TX["MV11"]["transaction"]
    signed = Account.sign_transaction(
        {
            "type": 2,
            "chainId": t["chainId"],
            "nonce": t["nonce"],
            "maxPriorityFeePerGas": int(t["maxPriorityFeePerGas"]),
            "maxFeePerGas": int(t["maxFeePerGas"]),
            "gas": t["gas"],
            "to": t["to"],
            "value": 0,
            "data": _TX["MV11"]["expectCalldata"],
        },
        _TX["fixed"]["payerKey"],
    )
    wire = "0x" + bytes(signed.raw_transaction).hex()
    assert (len(wire) - 2) // 2 == _TX["MV11"]["expectRawLength"], "not MV11's transaction"
    return wire


Run = Callable[[Any, Mapping[str, Any], Mapping[str, Any]], Any]


@dataclass(frozen=True)
class Pairing:
    """A pairing's vector file, its binding, how its build and complete run under a challenge on its B2 row and B6
    payment, and the code its bound gives its credential where that is not H."""

    file: str
    binding: Any
    run: Run
    answer: str | None = None


def _evm(binding: Any, extra: Callable[[Mapping[str, Any]], dict[str, Any]], payment: Callable[[Any], Any]) -> Run:
    def run(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
        choice = {"challenge": challenge, "from": _account(b2), "now": b2["input"].get("now", 0), **extra(b2)}
        return built(binding.build(choice, b2["advertised"])).complete(payment(b6))

    return run


def _inputs(b2: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = b2["input"].get("inputs", {})
    return out


def _solana(binding: Any, own: Callable[[Mapping[str, Any]], Mapping[str, Any]]) -> Run:
    """The Solana charges' build, given the buyer's own decimals, token program and blockhash, read from the
    methodDetails of the challenge it is given, else, where that challenge has no request to read, of B2's. complete
    takes the payer's 64-byte signature, which it does not verify."""

    def run(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
        i = _inputs(b2)
        readable = isinstance(challenge, Mapping) and isinstance(challenge.get("request"), str)
        d = own(_decoded(challenge if readable else b2["input"]["doc"][0])["methodDetails"])
        choice = {
            "challenge": challenge,
            "payer": _account(b2),
            "computeUnitLimit": i["computeUnitLimit"],
            "computeUnitPrice": int(i["computeUnitPrice"]),
            "decimals": d.get("decimals"),
            "tokenProgram": d.get("tokenProgram"),
            "recentBlockhash": d.get("recentBlockhash"),
        }
        return built(binding.build(choice, b2["advertised"])).complete(bytes([0x11]) * 64)

    return run


def _stellar(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    i = _inputs(b2)
    choice = {
        "challenge": challenge,
        "payer": _account(b2),
        "now": b2["input"].get("now", 0),
        "simulatedXdr": i["simulatedXdr"],
        "currentLedger": i["currentLedger"],
    }
    return built(terms.MPP_CHARGE_STELLAR.build(choice, b2["advertised"])).complete(bytes([0x11]) * 64)


def _xrpl(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    i = _inputs(b2)
    choice = {"challenge": challenge, "account": _account(b2), "fee": i["fee"], "sequence": i["sequence"]}
    choice["lastLedgerSequence"] = i["lastLedgerSequence"]
    return built(terms.MPP_CHARGE_XRPL.build(choice, b2["advertised"])).complete(b6["payload"]["blob"])


def _stacks(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    u = built(terms.MPP_CHARGE_USDC_STACKS.build({"challenge": challenge, "from": _account(b2)}, b2["advertised"]))
    return u.complete(base64.b64decode(b6["payload"]["transaction"]))


def _gateway(b6: Mapping[str, Any]) -> dict[str, Any]:
    p = b6["payload"]
    transfer = p["authorization"]["transfer"]
    return {
        "source": b6.get("source"),
        "sourceNetwork": p["sourceNetwork"],
        "destinationNetwork": p["destinationNetwork"],
        "maxFee": p["maxFee"],
        "burnIntent": transfer["burnIntent"],
        "signature": transfer["signature"],
    }


def _session_evm(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    i = _inputs(b2)
    choice = {
        "challenge": challenge,
        "from": _account(b2),
        "now": b2["input"].get("now", 0),
        "deposit": int(i["deposit"]),
        "credentialType": i["credentialType"],
        "tokenDomain": i["tokenDomain"],
    }
    u = built(terms.MPP_SESSION_EVM.build(choice, b2["advertised"]))
    return u.complete(b6["payload"]["signature"], b6["payload"]["voucherSignature"])


def _session_tempo(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    choice = {
        "challenge": challenge,
        "from": _account(b2),
        "now": b2["input"].get("now", 0),
        "deposit": int(_inputs(b2)["deposit"]),
    }
    u = built(terms.MPP_SESSION_TEMPO.build(choice, b2["advertised"]))
    return u.complete(b6["payload"]["transaction"], b6["payload"]["signature"])


def _subscription(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    """The root key signs the digest: the B2 account's key, which is the authorization file's payer key."""
    choice = {"challenge": challenge, "from": _account(b2), "now": b2["input"].get("now", 0)}
    u = built(terms.MPP_SUBSCRIPTION_TEMPO.build(choice, b2["advertised"]))
    return u.complete(_sig65(u.request["digest"], _A["fixed"]["payerKey"]))


def _session_hedera(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    choice = {"challenge": challenge, "from": _account(b2), "deposit": int(_inputs(b2)["deposit"])}
    u = built(terms.MPP_SESSION_HEDERA.build(choice, b2["advertised"]))
    return u.complete({"openTx": b6["payload"]["txHash"], "signature": b6["payload"]["signature"]})


def _session_solana(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    """The Solana session's build reads no deposit: the channel client composes the open payload."""
    u = built(terms.MPP_SESSION_SOLANA.build({"challenge": challenge, "from": _account(b2)}, b2["advertised"]))
    return u.complete(b6["payload"])


def _session_xrpl(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
    i = _inputs(b2)
    xrpl = {**i["xrpl"], "publicKey": i["xrpl"]["publicKey"].removeprefix("0x")}
    choice = {"challenge": challenge, "from": _account(b2), "deposit": int(i["deposit"]), "xrpl": xrpl}
    u = built(terms.MPP_SESSION_XRPL.build(choice, b2["advertised"]))
    return u.complete({"signedBlob": b6["payload"]["transaction"], "claimSignature": b6["payload"]["signature"]})


def _lightning(binding: Any) -> Run:
    def run(challenge: Any, b2: Mapping[str, Any], b6: Mapping[str, Any]) -> Any:
        choice = {"challenge": challenge, **_inputs(b2)}
        return built(binding.build(choice, b2["advertised"])).complete(b6["payload"]["preimage"])

    return run


def _no_inputs(b2: Mapping[str, Any]) -> dict[str, Any]:
    return {}


def _signature(b6: Mapping[str, Any]) -> Any:
    return b6["payload"]["signature"]


# Each pairing whose build returns a complete that makes a credential (credentialSize's about), keyed by its id.
PAIRINGS: dict[str, Pairing] = {
    "mpp/charge/evm/authorization": Pairing(
        "mpp-charge-evm-authorization.json",
        terms.MPP_CHARGE_EVM_AUTHORIZATION,
        _evm(terms.MPP_CHARGE_EVM_AUTHORIZATION, lambda b2: {"tokenDomain": _inputs(b2)["tokenDomain"]}, _signature),
    ),
    "mpp/charge/evm/permit2": Pairing(
        "mpp-charge-evm-permit2.json",
        terms.MPP_CHARGE_EVM_PERMIT2,
        _evm(terms.MPP_CHARGE_EVM_PERMIT2, lambda b2: {"spender": _inputs(b2)["spender"]}, _signature),
    ),
    # No B6 row: the credential has no signed place for H. complete takes MV11's signed transaction, and H.
    "mpp/charge/evm/transaction": Pairing(
        "mpp-charge-evm-transaction.json",
        terms.MPP_CHARGE_EVM_TRANSACTION,
        _evm(terms.MPP_CHARGE_EVM_TRANSACTION, _no_inputs, lambda b6: mv11_transaction()),
        "mpp/no-signed-place",
    ),
    "mpp/charge/evm/hash": Pairing(
        "mpp-charge-evm-hash.json",
        terms.MPP_CHARGE_EVM_HASH,
        lambda c, b2, b6: _evm(terms.MPP_CHARGE_EVM_HASH, _no_inputs, lambda _: b2["advertised"])(c, b2, b6),
        "mpp/no-signed-place",
    ),
    "mpp/charge/tempo/memo": Pairing(
        "mpp-charge-tempo-memo.json",
        terms.MPP_CHARGE_TEMPO_MEMO,
        _evm(terms.MPP_CHARGE_TEMPO_MEMO, _no_inputs, _signature),
    ),
    # bound reads the push payment once its landed read is held.
    "mpp/charge/tempo/push": Pairing(
        "mpp-charge-tempo-push.json",
        terms.MPP_CHARGE_TEMPO_PUSH,
        _evm(terms.MPP_CHARGE_TEMPO_PUSH, _no_inputs, lambda b6: b6["payload"]["hash"]),
        "tempo/read-first",
    ),
    "mpp/charge/lightning": Pairing(
        "mpp-charge-lightning.json", terms.MPP_CHARGE_LIGHTNING, _lightning(terms.MPP_CHARGE_LIGHTNING)
    ),
    "mpp/session/lightning": Pairing(
        "mpp-session-lightning.json", terms.MPP_SESSION_LIGHTNING, _lightning(terms.MPP_SESSION_LIGHTNING)
    ),
    "mpp/charge/solana": Pairing(
        "mpp-charge-solana.json", terms.MPP_CHARGE_SOLANA, _solana(terms.MPP_CHARGE_SOLANA, lambda d: d)
    ),
    "mpp/charge/usdc/solana": Pairing(
        "mpp-charge-usdc-solana.json",
        terms.MPP_CHARGE_USDC_SOLANA,
        _solana(terms.MPP_CHARGE_USDC_SOLANA, lambda d: d["solana"]),
    ),
    # complete takes the payer's 64-byte signature, which it does not verify.
    "mpp/charge/stellar": Pairing("mpp-charge-stellar.json", terms.MPP_CHARGE_STELLAR, _stellar),
    "mpp/charge/xrpl": Pairing("mpp-charge-xrpl.json", terms.MPP_CHARGE_XRPL, _xrpl),
    "mpp/charge/usdc/evm": Pairing(
        "mpp-charge-usdc-evm.json",
        terms.MPP_CHARGE_USDC_EVM,
        _evm(terms.MPP_CHARGE_USDC_EVM, lambda b2: {"tokenDomain": _inputs(b2)["tokenDomain"]}, _signature),
    ),
    "mpp/charge/usdc/stacks": Pairing("mpp-charge-usdc-stacks.json", terms.MPP_CHARGE_USDC_STACKS, _stacks),
    "mpp/charge/usdc/gateway": Pairing(
        "mpp-charge-usdc-gateway.json",
        terms.MPP_CHARGE_USDC_GATEWAY,
        _evm(terms.MPP_CHARGE_USDC_GATEWAY, _no_inputs, _gateway),
    ),
    "mpp/session/evm": Pairing("mpp-session-evm.json", terms.MPP_SESSION_EVM, _session_evm),
    "mpp/session/tempo": Pairing("mpp-session-tempo.json", terms.MPP_SESSION_TEMPO, _session_tempo),
    "mpp/subscription/tempo": Pairing("mpp-subscription-tempo.json", terms.MPP_SUBSCRIPTION_TEMPO, _subscription),
    # bound reads the opening once its landed read is held.
    "mpp/session/hedera": Pairing(
        "mpp-session-hedera-solana-xrpl.json", terms.MPP_SESSION_HEDERA, _session_hedera, "hedera/read-first"
    ),
    "mpp/session/solana": Pairing("mpp-session-hedera-solana-xrpl.json", terms.MPP_SESSION_SOLANA, _session_solana),
    "mpp/session/xrpl": Pairing("mpp-session-hedera-solana-xrpl.json", terms.MPP_SESSION_XRPL, _session_xrpl),
}
assert len(PAIRINGS) == 21


def buyer(file: str, pairing: str, name: str) -> dict[str, Any] | None:
    """The buyer row name of file for pairing."""
    rows: list[dict[str, Any]] = load(file)["buyer"]["rows"]
    return next((r for r in rows if r["name"] == name and r.get("pairing") == pairing), None)


@dataclass(frozen=True)
class SetUp:
    """A pairing's placed challenge (B6's, else B2's first), H, and its build and complete under a given challenge."""

    placed: dict[str, Any]
    h: str
    complete: Callable[[Any], Any]
    answer: Any


def set_up(pairing: str) -> SetUp:
    p = PAIRINGS[pairing]
    b2 = buyer(p.file, pairing, "B2")
    assert b2 is not None, pairing
    b6 = buyer(p.file, pairing, "B6")
    presented = b6["input"]["presented"] if b6 is not None else None
    placed = presented["challenge"] if presented is not None else b2["input"]["doc"][0]
    payment: dict[str, Any] = {"payload": presented["payload"] if presented is not None else {}}
    if presented is not None and "source" in presented:
        payment["source"] = presented["source"]
    answer = b2["advertised"] if p.answer is None else Refusal(p.answer)
    return SetUp(placed, b2["advertised"], lambda c: p.run(c, b2, payment), answer)


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def footprinted(envelope: str, key_bytes: int) -> str:
    """The envelope with its v1 transaction's ext set to Soroban transaction data, as mpp-charge-stellar.json's
    completeXdr about states it: a footprint of one read-only contract-data key, whose contract is the contract id of
    32 bytes of 0x07, whose key is an ScVal of bytes holding key_bytes zero bytes, and whose durability is persistent,
    no read-write key, and zero instructions, read bytes, write bytes and resource fee. The transaction is read up to
    its ext with the package's XDR reader; what follows the ext, the signatures, is kept."""
    data = base64.b64decode(envelope)
    r = xdr.Reader(data)
    assert r.u32() == 2, "not a v1 envelope"
    xdr.muxed_account(r)
    r.u32()
    r.i64()
    xdr._preconditions(r)
    xdr._memo(r)
    for _ in range(r.count(100)):
        if r.flag():
            xdr.muxed_account(r)
        kind = r.enum(range(0, 27))
        if kind == 24:
            xdr._invoke(r)
        else:
            xdr._operation(r, kind)
    start = r.at
    xdr._transaction_ext(r)
    end = r.at
    key_val = _u32(13) + _u32(key_bytes) + bytes(key_bytes) + bytes(-key_bytes % 4)
    key = _u32(6) + _u32(1) + bytes([7]) * 32 + key_val + _u32(1)
    resources = _u32(1) + key + _u32(0) + _u32(0) * 3
    ext = _u32(1) + _u32(0) + resources + bytes(8)
    return base64.b64encode(data[:start] + ext + data[end:]).decode("ascii")
