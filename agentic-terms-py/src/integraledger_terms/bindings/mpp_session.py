"""The buyer half of MPP's session on EVM and Tempo, and subscription on Tempo. On the sessions the payer-signed
channel salt is H; on the subscription the payer's root key signs a key authorization whose witness is H. A later
request is classified by the channel's kind, and on Tempo v2 bound_within reads its descriptor's salt."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._keccak import keccak256
from .._types import Advertised, Refusal
from ._channel import BatchUnsigned, ChannelRef
from ._codec import hex_bytes, to_hex
from ._lcp import is_address, is_object, normal_hash
from ._mpp import (
    Echoed,
    MppUnsigned,
    credential_of,
    did_pkh_address,
    echoed_for,
    is_hex_bytes,
    offer_for,
    read,
    same_bytes,
    text,
)
from ._mpp_checks import (
    decode_object,
    hedera_session_network_of,
    positive_int,
    solana_network_of,
    unix_of,
    xrpl_network_of,
)
from ._mpp_evm import PERMIT2, ZERO_ADDRESS, address_word, permit2_typed_data, receive_typed_data, uint_word
from ._session_within import within_checks, within_unsigned
from ._svm import key_bytes, key_string
from ._tempo import (
    OPEN_V1_SELECTOR,
    OPEN_V2_SELECTOR,
    TRANSFER_WITH_MEMO_SELECTOR,
    decode_key_authorization,
    decode_tempo_tx,
    encode_key_authorization,
    expiring_nonce_hash,
    tempo_channel_id,
)

SESSION_EVM = "mpp/session/evm"
SESSION_TEMPO = "mpp/session/tempo"
SUBSCRIPTION = "mpp/subscription/tempo"

APPROVE_SELECTOR = "0x095ea7b3"
TEMPO_V1_DEFAULT_CHAIN = 4217
MAX_SIGNATURE = 8192
MAX_WIRE = 65_536
U96 = 1 << 96
U128 = 1 << 128
KEY_TYPES: Mapping[str, int] = {"secp256k1": 0, "p256": 1, "webAuthn": 2}
DAY = 86_400
WEEK = 604_800


@dataclass(frozen=True, slots=True)
class SessionUnsigned:
    """A session opening signed in two steps: the funding request, the voucher over the channel the funding opens,
    and the credential from both answers."""

    funding: dict[str, Any]
    voucher: Callable[[Any], dict[str, Any] | Refusal]
    complete: Callable[[Any, Any], dict[str, Any] | Refusal]


@dataclass(frozen=True, slots=True)
class Channel:
    """A channel pairing's reading of a later request: its kind (open, within or close), its network and channel,
    the hash a request within the channel is bound to, and when the channel ends."""

    kind: Callable[[Any], str | Refusal]
    ref: Callable[[Any], dict[str, str] | Refusal]
    bound_within: Callable[[Any], AtrHash | Refusal]
    until: Callable[[Any], int | None]


def evm_channel_id(payer: object, payee: object, token: object, salt: object, authorized_signer: object, escrow: object, chain_id: object) -> str | Refusal:
    """keccak256(abi.encode(payer, payee, token, salt, authorizedSigner, escrow, chainId)); also Tempo v1's."""
    s = normal_hash(salt)
    for a in (payer, payee, token, authorized_signer, escrow):
        if not is_address(a):
            return Refusal("mpp/input-malformed")
    if s is None or isinstance(chain_id, bool) or not isinstance(chain_id, int) or not 0 < chain_id <= 2**53 - 1:
        return Refusal("mpp/input-malformed")
    assert isinstance(payer, str) and isinstance(payee, str) and isinstance(token, str)
    assert isinstance(authorized_signer, str) and isinstance(escrow, str)
    return to_hex(
        keccak256(
            address_word(payer)
            + address_word(payee)
            + address_word(token)
            + bytes.fromhex(s[2:])
            + address_word(authorized_signer)
            + address_word(escrow)
            + uint_word(chain_id)
        )
    )


# ── The session parameters of a challenge, read without the offer checks.


@dataclass(frozen=True, slots=True)
class Params:
    method: str
    intent: str
    chain_id: int
    network: str
    escrow: str
    version: str
    request: dict[str, Any]
    details: Mapping[str, Any]


def params_of(c: object) -> Params | Refusal:
    if not is_object(c) or not isinstance(c.get("request"), str):
        return Refusal("mpp/credential-malformed")
    method, intent = c.get("method"), c.get("intent")
    if not ((intent == "session" and method in ("evm", "tempo")) or (intent == "subscription" and method == "tempo")):
        return Refusal("mpp/not-this-pairing")
    request = decode_object(c["request"])
    if request is None:
        return Refusal("mpp/request-malformed")
    md = request.get("methodDetails")
    details: Mapping[str, Any] = md if is_object(md) else {}
    chain_id = positive_int(details.get("chainId"))
    if chain_id is None and method == "tempo" and intent == "session" and "chainId" not in details:
        chain_id = TEMPO_V1_DEFAULT_CHAIN
    if chain_id is None:
        return Refusal("mpp/chain-id-required")
    version = "v2" if details.get("sessionProtocol") == "v2" else "v1"
    escrow = details.get("escrowContract")
    if intent == "session" and not is_address(escrow):
        return Refusal("mpp/escrow-malformed")
    return Params(
        method=str(method),
        intent=str(intent),
        chain_id=chain_id,
        network=f"eip155:{chain_id}",
        escrow=escrow if isinstance(escrow, str) and is_address(escrow) else ZERO_ADDRESS,
        version=version,
        request=request,
        details=details,
    )


def _payload_of(presented: object) -> Mapping[str, Any] | Refusal:
    if not is_object(presented) or not is_object(presented.get("payload")):
        return Refusal("mpp/credential-malformed")
    payload: Mapping[str, Any] = presented["payload"]
    return payload


def _voucher_data(name: str, width: str, chain_id: int, escrow: str, channel_id: str, cumulative: int = 0) -> dict[str, Any]:
    return {
        "domain": {"name": name, "version": "1", "chainId": chain_id, "verifyingContract": escrow},
        "primaryType": "Voucher",
        "types": {"Voucher": [{"name": "channelId", "type": "bytes32"}, {"name": "cumulativeAmount", "type": width}]},
        "message": {"channelId": channel_id, "cumulativeAmount": cumulative},
    }


def session_resume(c: object) -> ChannelRef | None | Refusal:
    """The network and channel a session challenge names for the client to resume, spelled as the pairing's
    channel_ref spells it: EVM, Tempo and Hedera in methodDetails.channelId (a bytes32, lower-case), Solana in
    methodDetails.channelId (a base58 address), XRPL in the request's channelId (64 hex characters, upper case). None
    when the challenge names no channel; refused for a challenge of no session pairing, or a channel or network that
    cannot be read."""
    method = c.get("method") if is_object(c) else None
    if method in ("hedera", "solana", "xrpl"):
        return _rail_session_resume(c)
    p = params_of(c)
    if isinstance(p, Refusal):
        return p
    if p.intent != "session":
        return Refusal("mpp/not-this-pairing")
    if "channelId" not in p.details:
        return None
    channel = normal_hash(p.details["channelId"])
    return Refusal("mpp/request-malformed") if channel is None else ChannelRef(network=p.network, channel=channel)


_HASH256 = re.compile(r"[0-9A-Fa-f]{64}")


def _rail_session_resume(c: Any) -> ChannelRef | None | Refusal:
    """session_resume on the Hedera, Solana and XRPL sessions: XRPL's request channelId, empty when it names none;
    the others' methodDetails.channelId."""
    if c.get("intent") != "session" or not isinstance(c.get("request"), str):
        return Refusal("mpp/not-this-pairing")
    request = decode_object(c["request"])
    if request is None:
        return Refusal("mpp/request-malformed")
    md = request.get("methodDetails", {})
    if not is_object(md):
        return Refusal("mpp/request-malformed")
    method = c["method"]
    if method == "xrpl":
        named = request.get("channelId", "")
        if named == "":
            return None
        if not isinstance(named, str) or _HASH256.fullmatch(named) is None:
            return Refusal("mpp/request-malformed")
        xrpl = xrpl_network_of(md)
        return xrpl if isinstance(xrpl, Refusal) else ChannelRef(xrpl, named.upper())
    if "channelId" not in md:
        return None
    if method == "hedera":
        channel = normal_hash(md["channelId"])
        if channel is None:
            return Refusal("mpp/request-malformed")
        hedera = hedera_session_network_of(md)
        return hedera if isinstance(hedera, Refusal) else ChannelRef(hedera, channel)
    key = key_bytes(md["channelId"])
    if key is None:
        return Refusal("mpp/request-malformed")
    solana = solana_network_of(md, True)
    if solana is None:
        return Refusal("svm/network-undeclared")
    return solana if isinstance(solana, Refusal) else ChannelRef(solana, key_string(key))


def _words(selector: str, parts: list[bytes]) -> str:
    return selector + b"".join(parts).hex()


def _deposit_of(choice: Mapping[str, Any], limit: int) -> int | None:
    deposit = choice.get("deposit")
    if isinstance(deposit, bool) or not isinstance(deposit, int) or not 0 < deposit < limit:
        return None
    return deposit


def _signer_of(choice: Mapping[str, Any]) -> str | None:
    signer = choice.get("authorizedSigner")
    signer = ZERO_ADDRESS if signer is None else signer
    return signer if is_address(signer) else None


def _ref_from(presented: Any) -> dict[str, str] | Refusal:
    """The network and the payload's channelId, lower-case."""
    payload = _payload_of(presented)
    if isinstance(payload, Refusal):
        return payload
    p = params_of(presented.get("challenge"))
    if isinstance(p, Refusal):
        return p
    channel = normal_hash(payload.get("channelId"))
    return Refusal("mpp/credential-malformed") if channel is None else {"network": p.network, "channel": channel}


def _not_bound_within(presented: Any) -> AtrHash | Refusal:
    return Refusal("mpp/not-bound-within")


def _no_end(presented: Any) -> int | None:
    return None


# ── mpp/session/evm.


@dataclass(frozen=True, slots=True)
class _Opening:
    kind: str
    o: Mapping[str, Any]


def _evm_opening(payload: Mapping[str, Any]) -> _Opening | Refusal:
    """The opening of an EVM session payload: the open payload, or a voucher's deposit whose action is open."""
    if payload.get("action") == "open":
        return _Opening(text(payload.get("type")), payload)
    deposit = payload.get("deposit")
    if payload.get("action") == "voucher" and is_object(deposit) and deposit.get("action") == "open":
        return _Opening(text(deposit.get("type")), deposit)
    return Refusal("mpp/not-an-opening")


def _evm_kind(presented: Any) -> str | Refusal:
    p = _payload_of(presented)
    if isinstance(p, Refusal):
        return p
    action = p.get("action")
    if action == "open":
        return "open"
    if action == "voucher":
        deposit = p.get("deposit")
        return "open" if is_object(deposit) and deposit.get("action") == "open" else "within"
    if action == "topUp":
        return "within"
    if action == "close":
        return "close"
    return Refusal("mpp/session-action")


def _evm_opened(presented: Mapping[str, Any]) -> Echoed | Refusal:
    """The echoed challenge, when the EVM opening's salt is H, its channel id agrees with the payer, salt and signer,
    and an authorization's nonce, or a Permit2 witness's salt, carries the channel."""
    e = echoed_for(presented, SESSION_EVM)
    if isinstance(e, Refusal):
        return e
    opening = _evm_opening(e.payload)
    if isinstance(opening, Refusal):
        return opening
    kind, o = opening.kind, opening.o
    if kind not in ("hash", "authorization", "permit2"):
        return Refusal("mpp/credential-type")
    salt = normal_hash(o.get("salt"))
    if salt is None:
        return Refusal("mpp/credential-malformed")
    if not hash_equals(salt, e.h):
        return Refusal("mpp/salt-not-this-hash")
    signer = o.get("authorizedSigner")
    signer = ZERO_ADDRESS if signer is None else signer
    if not is_address(signer):
        return Refusal("mpp/credential-malformed")
    auth: Mapping[str, Any] = o["authorization"] if is_object(o.get("authorization")) else {}
    if kind == "hash":
        payer = did_pkh_address(presented.get("source"))
        if payer is None:
            return Refusal("mpp/source-required")
    else:
        if not is_address(auth.get("from")):
            return Refusal("mpp/credential-malformed")
        payer = auth["from"]
    assert isinstance(payer, str)
    recipient, currency = text(e.checked.request.get("recipient")), text(e.checked.request.get("currency"))
    expect = evm_channel_id(
        payer, recipient, currency, e.h, signer, text(e.checked.details.get("escrowContract")), positive_int(e.checked.details.get("chainId"))
    )
    channel = normal_hash(e.payload.get("channelId"))
    if isinstance(expect, Refusal) or channel is None or not same_bytes(channel, expect):
        return Refusal("mpp/channel-not-bound")
    if kind == "authorization":
        nonce = to_hex(
            keccak256(
                address_word(payer)
                + address_word(recipient)
                + address_word(currency)
                + bytes.fromhex(e.h[2:])
                + address_word(str(signer))
            )
        )
        if not same_bytes(auth.get("nonce"), nonce):
            return Refusal("mpp/nonce-not-channel")
    if kind == "permit2":
        w = auth.get("witness")
        w_salt = normal_hash(w.get("salt")) if is_object(w) else None
        if w_salt is None or not hash_equals(w_salt, e.h):
            return Refusal("mpp/salt-not-this-hash")
    return e


def _evm_build_within(w: Any, h: AtrHash) -> BatchUnsigned | Refusal:
    """A voucher, or a close's final voucher, on the channel the held opening opened: Voucher(bytes32 channelId,uint128
    cumulativeAmount) under "EVM Payment Channel", with the channel id, the escrow and the chain from the opening."""
    o = within_checks(w, h, "session/evm", _evm_opened, U128)
    if isinstance(o, Refusal):
        return o
    channel = normal_hash(w["opening"]["payload"].get("channelId"))
    if channel is None:
        return Refusal("mpp/credential-malformed")
    chain_id = positive_int(o.checked.details.get("chainId"))
    escrow = text(o.checked.details.get("escrowContract"))
    assert chain_id is not None
    typed = _voucher_data("EVM Payment Channel", "uint128", chain_id, escrow, channel, w["cumulativeAmount"])
    return within_unsigned(w, typed, channel)


def _evm_bound(presented: Any) -> AtrHash | Refusal:
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    o = _evm_opened(c)
    return o if isinstance(o, Refusal) else o.h


def _evm_build(choice: Any, h: AtrHash) -> SessionUnsigned | Refusal:
    o = offer_for(choice, h, SESSION_EVM)
    if isinstance(o, Refusal):
        return o
    deposit = _deposit_of(choice, U128)
    if deposit is None:
        return Refusal("mpp/input-malformed")
    signer = _signer_of(choice)
    if signer is None:
        return Refusal("mpp/input-malformed")
    listed = o.details.get("credentialTypes")
    listed = ["hash"] if listed is None else listed
    kind = choice.get("credentialType")
    kind = (listed[0] if listed else None) if kind is None else kind
    if kind is None or kind not in listed:
        return Refusal("mpp/credential-types")
    chain_id = positive_int(o.details.get("chainId"))
    assert chain_id is not None
    escrow = text(o.details.get("escrowContract"))
    currency, recipient = text(o.request.get("currency")), text(o.request.get("recipient"))
    from_ = choice["from"]
    salt = h.lower()
    channel_id = evm_channel_id(from_, recipient, currency, salt, signer, escrow, chain_id)
    if isinstance(channel_id, Refusal):
        return channel_id
    deadline = o.expires
    challenge = dict(choice["challenge"])
    source = f"did:pkh:eip155:{chain_id}:{from_}"

    def voucher(funded: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(funded, 1, MAX_WIRE):
            return Refusal("mpp/credential-malformed")
        return _voucher_data("EVM Payment Channel", "uint128", chain_id, escrow, channel_id)

    base = {"action": "open", "channelId": channel_id, "cumulativeAmount": "0", "authorizedSigner": signer, "salt": salt}

    if kind == "hash":
        calls = [
            {"to": currency, "data": _words(APPROVE_SELECTOR, [address_word(escrow), uint_word(deposit)])},
            {
                "to": escrow,
                "data": _words(
                    OPEN_V1_SELECTOR,
                    [address_word(recipient), address_word(currency), uint_word(deposit), bytes.fromhex(salt[2:]), address_word(signer)],
                ),
            },
        ]

        def complete_hash(funded: Any, voucher_signature: Any) -> dict[str, Any] | Refusal:
            if normal_hash(funded) is None or not is_hex_bytes(voucher_signature, 65, MAX_SIGNATURE):
                return Refusal("mpp/credential-malformed")
            return {"challenge": challenge, "source": source, "payload": {**base, "type": "hash", "hash": funded, "signature": voucher_signature}}

        return SessionUnsigned({"kind": "evm-calls", "chainId": chain_id, "calls": calls, "broadcast": True}, voucher, complete_hash)

    typed_data: dict[str, Any] | Refusal
    authorization: dict[str, Any]
    if kind == "authorization":
        td = choice.get("tokenDomain")
        if (
            not is_object(td)
            or not isinstance(td.get("name"), str)
            or td["name"] == ""
            or not isinstance(td.get("version"), str)
            or td["version"] == ""
        ):
            return Refusal("mpp/input-malformed")
        nonce = to_hex(
            keccak256(address_word(from_) + address_word(recipient) + address_word(currency) + bytes.fromhex(salt[2:]) + address_word(signer))
        )
        typed_data = receive_typed_data(
            network=f"eip155:{chain_id}",
            asset=currency,
            name=td["name"],
            version=td["version"],
            from_=from_,
            to=escrow,
            value=str(deposit),
            valid_after=0,
            valid_before=deadline,
            nonce=nonce,
        )
        authorization = {"from": from_, "to": escrow, "value": str(deposit), "validAfter": "0", "validBefore": str(deadline), "nonce": nonce}
    else:
        contract = o.details.get("permit2Contract")
        typed_data = permit2_typed_data(
            chain_id=chain_id,
            permitted={"token": currency, "amount": deposit},
            spender=escrow,
            nonce=int(salt, 16),
            deadline=deadline,
            verifying_contract=contract if isinstance(contract, str) else PERMIT2,
            witness={
                "type": "ChannelOpenWitness",
                "fields": [
                    {"name": "payee", "type": "address"},
                    {"name": "salt", "type": "bytes32"},
                    {"name": "authorizedSigner", "type": "address"},
                ],
                "value": {"payee": recipient, "salt": salt, "authorizedSigner": signer},
            },
        )
        authorization = {
            "from": from_,
            "permitted": {"token": currency, "amount": str(deposit)},
            "nonce": str(int(salt, 16)),
            "deadline": str(deadline),
            "witness": {"payee": recipient, "salt": salt, "authorizedSigner": signer},
        }
    if isinstance(typed_data, Refusal):
        return typed_data

    def complete_signed(funded: Any, voucher_signature: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(funded, 65, MAX_SIGNATURE) or not is_hex_bytes(voucher_signature, 65, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        return {
            "challenge": challenge,
            "source": source,
            "payload": {**base, "type": kind, "authorization": authorization, "signature": funded, "voucherSignature": voucher_signature},
        }

    return SessionUnsigned({"kind": "eip712", "typedData": typed_data}, voucher, complete_signed)


# ── mpp/session/tempo.


def _tempo_kind(presented: Any) -> str | Refusal:
    p = _payload_of(presented)
    if isinstance(p, Refusal):
        return p
    action = p.get("action")
    if action == "open":
        return "open"
    if action in ("voucher", "topUp"):
        return "within"
    if action == "close":
        return "close"
    return Refusal("mpp/session-action")


_DESCRIPTOR_KEYS = ("payer", "payee", "operator", "token", "salt", "authorizedSigner", "expiringNonceHash")


def _descriptor_salt(payload: Mapping[str, Any], p: Params) -> AtrHash | Refusal:
    """The v2 descriptor's salt, when the descriptor's channel id is the payload's channel."""
    v = payload.get("descriptor")
    if not is_object(v) or not all(isinstance(v.get(k), str) for k in _DESCRIPTOR_KEYS):
        return Refusal("tempo/descriptor-mismatch")
    d = {k: v[k] for k in _DESCRIPTOR_KEYS}
    channel_id = tempo_channel_id({**d, "escrow": p.escrow, "chainId": p.chain_id})
    channel = normal_hash(payload.get("channelId"))
    salt = normal_hash(d["salt"])
    if isinstance(channel_id, Refusal) or channel is None or salt is None or not same_bytes(channel_id, channel):
        return Refusal("tempo/descriptor-mismatch")
    return salt


def _tempo_bound_within(presented: Any) -> AtrHash | Refusal:
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    payload = _payload_of(c)
    if isinstance(payload, Refusal):
        return payload
    p = params_of(c.get("challenge"))
    if isinstance(p, Refusal):
        return p
    if p.version != "v2":
        return Refusal("mpp/not-bound-within")
    return _descriptor_salt(payload, p)


def _tempo_opened(presented: Mapping[str, Any]) -> Echoed | Refusal:
    """The echoed challenge, when the signed transaction holds exactly one open call to the escrow whose salt word
    is H, and on v2 the descriptor's channel carries that salt."""
    e = echoed_for(presented, SESSION_TEMPO)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("action") != "open" or e.payload.get("type") != "transaction":
        return Refusal("mpp/not-an-opening")
    p = params_of(presented["challenge"])
    if isinstance(p, Refusal):
        return p
    wire = e.payload.get("transaction")
    if not isinstance(wire, str) or hex_bytes(wire) is None:
        return Refusal("mpp/credential-malformed")
    if (len(wire) - 2) // 2 > MAX_WIRE:
        return Refusal("tempo/tx-too-large")
    tx = decode_tempo_tx(bytes.fromhex(wire[2:]))
    if isinstance(tx, Refusal):
        return tx
    selector = OPEN_V2_SELECTOR if p.version == "v2" else OPEN_V1_SELECTOR
    opens = [
        c for c in tx.calls if c.to is not None and same_bytes(c.to, p.escrow) and len(c.input) >= 4 and to_hex(c.input[:4]) == selector
    ]
    if not opens:
        return Refusal("tempo/open-not-found")
    if len(opens) > 1:
        return Refusal("tempo/open-ambiguous")
    data = opens[0].input
    if len(data) != (196 if p.version == "v2" else 164):
        return Refusal("tempo/tx-malformed")
    salt_at = 4 + 32 * (4 if p.version == "v2" else 3)
    if not same_bytes(to_hex(data[salt_at : salt_at + 32]), e.h):
        return Refusal("tempo/salt-not-bound")
    if normal_hash(e.payload.get("channelId")) is None:
        return Refusal("mpp/credential-malformed")
    if p.version == "v2":
        salt = _descriptor_salt(e.payload, p)
        if isinstance(salt, Refusal) or not hash_equals(salt, e.h):
            return Refusal("tempo/descriptor-mismatch")
    return e


def _tempo_build_within(w: Any, h: AtrHash) -> BatchUnsigned | Refusal:
    """A voucher, or a close's final voucher, on the channel the held opening opened: under "Tempo Stream Channel"
    with uint128 on v1, and under "TIP20 Channel Reserve" with uint96 on v2, whose credential also carries the
    opening's descriptor. The channel id, the escrow, the chain and the descriptor come from the opening."""
    opening = w.get("opening") if is_object(w) else None
    version = params_of(opening.get("challenge")) if is_object(opening) else Refusal("mpp/input-malformed")
    limit = U96 if not isinstance(version, Refusal) and version.version == "v2" else U128
    o = within_checks(w, h, "session/tempo", _tempo_opened, limit)
    if isinstance(o, Refusal):
        return o
    p = params_of(w["opening"]["challenge"])
    channel = normal_hash(w["opening"]["payload"].get("channelId"))
    if isinstance(p, Refusal):
        return p
    assert channel is not None
    if p.version == "v2":
        typed = _voucher_data("TIP20 Channel Reserve", "uint96", p.chain_id, p.escrow, channel, w["cumulativeAmount"])
        return within_unsigned(w, typed, channel, w["opening"]["payload"].get("descriptor"))
    typed = _voucher_data("Tempo Stream Channel", "uint128", p.chain_id, p.escrow, channel, w["cumulativeAmount"])
    return within_unsigned(w, typed, channel)


def _tempo_bound(presented: Any) -> AtrHash | Refusal:
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    o = _tempo_opened(c)
    return o if isinstance(o, Refusal) else o.h


def _tempo_build(choice: Any, h: AtrHash) -> SessionUnsigned | Refusal:
    o = offer_for(choice, h, SESSION_TEMPO)
    if isinstance(o, Refusal):
        return o
    p = params_of(choice["challenge"])
    if isinstance(p, Refusal):
        return p
    deposit = _deposit_of(choice, U96 if p.version == "v2" else U128)
    if deposit is None:
        return Refusal("mpp/input-malformed")
    signer = _signer_of(choice)
    if signer is None:
        return Refusal("mpp/input-malformed")
    operator = p.details.get("operator")
    operator = ZERO_ADDRESS if not isinstance(operator, str) else operator
    currency, recipient = text(o.request.get("currency")), text(o.request.get("recipient"))
    salt = h.lower()
    from_ = choice["from"]
    salt_word = bytes.fromhex(salt[2:])
    if p.version == "v2":
        data = _words(
            OPEN_V2_SELECTOR,
            [address_word(recipient), address_word(operator), address_word(currency), uint_word(deposit), salt_word, address_word(signer)],
        )
    else:
        data = _words(
            OPEN_V1_SELECTOR,
            [address_word(recipient), address_word(currency), uint_word(deposit), salt_word, address_word(signer)],
        )
    challenge = dict(choice["challenge"])
    source = f"did:pkh:eip155:{p.chain_id}:{from_}"

    def opened(signed_tx: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(signed_tx, 1, MAX_WIRE):
            return Refusal("mpp/credential-malformed")
        wire = bytes.fromhex(signed_tx[2:])
        if p.version == "v1":
            channel_id = evm_channel_id(from_, recipient, currency, salt, signer, p.escrow, p.chain_id)
            return channel_id if isinstance(channel_id, Refusal) else {"channelId": channel_id}
        nonce_hash = expiring_nonce_hash(wire, from_)
        if isinstance(nonce_hash, Refusal):
            return nonce_hash
        descriptor = {
            "payer": from_,
            "payee": recipient,
            "operator": operator,
            "token": currency,
            "salt": salt,
            "authorizedSigner": signer,
            "expiringNonceHash": nonce_hash,
        }
        channel_id = tempo_channel_id({**descriptor, "escrow": p.escrow, "chainId": p.chain_id})
        return channel_id if isinstance(channel_id, Refusal) else {"channelId": channel_id, "descriptor": descriptor}

    def voucher(signed_tx: Any) -> dict[str, Any] | Refusal:
        c = opened(signed_tx)
        if isinstance(c, Refusal):
            return c
        if p.version == "v2":
            return _voucher_data("TIP20 Channel Reserve", "uint96", p.chain_id, p.escrow, c["channelId"])
        return _voucher_data("Tempo Stream Channel", "uint128", p.chain_id, p.escrow, c["channelId"])

    def complete(signed_tx: Any, voucher_signature: Any) -> dict[str, Any] | Refusal:
        c = opened(signed_tx)
        if isinstance(c, Refusal):
            return c
        if not is_hex_bytes(voucher_signature, 65, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        payload: dict[str, Any] = {
            "action": "open",
            "type": "transaction",
            "channelId": c["channelId"],
            "transaction": signed_tx,
            "authorizedSigner": signer,
        }
        if "descriptor" in c:
            payload["descriptor"] = c["descriptor"]
        payload["cumulativeAmount"] = "0"
        payload["signature"] = voucher_signature
        return {"challenge": challenge, "source": source, "payload": payload}

    funding = {
        "kind": "tempo-call",
        "chainId": p.chain_id,
        "call": {"to": p.escrow, "data": data},
        "validBefore": o.expires,
        "broadcast": False,
    }
    return SessionUnsigned(funding, voucher, complete)


# ── mpp/subscription/tempo.


def _subscription_kind(presented: Any) -> str | Refusal:
    p = _payload_of(presented)
    if isinstance(p, Refusal):
        return p
    return "open" if p.get("type") == "keyAuthorization" else Refusal("mpp/session-action")


def _subscription_witness(presented: Mapping[str, Any]) -> Echoed | Refusal:
    e = echoed_for(presented, SUBSCRIPTION)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "keyAuthorization":
        return Refusal("mpp/not-an-opening")
    signed = e.payload.get("signature")
    if not isinstance(signed, str):
        return Refusal("tempo/key-authorization-malformed")
    k = decode_key_authorization(signed)
    if isinstance(k, Refusal):
        return k
    if k.witness is None:
        return Refusal("tempo/no-witness")
    if not hash_equals(k.witness, e.h):
        return Refusal("tempo/witness-not-bound")
    return e


def _subscription_bound(presented: Any) -> AtrHash | Refusal:
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    w = _subscription_witness(c)
    return w if isinstance(w, Refusal) else w.h


def _subscription_ref(presented: Any) -> dict[str, str] | Refusal:
    payload = _payload_of(presented)
    if isinstance(payload, Refusal):
        return payload
    p = params_of(presented.get("challenge"))
    if isinstance(p, Refusal):
        return p
    if not isinstance(payload.get("signature"), str):
        return Refusal("tempo/key-authorization-malformed")
    k = decode_key_authorization(payload["signature"])
    return k if isinstance(k, Refusal) else {"network": p.network, "channel": k.digest}


def _subscription_until(presented: Any) -> int | None:
    p = params_of(presented.get("challenge")) if is_object(presented) else None
    if p is None or isinstance(p, Refusal):
        return None
    return unix_of(p.request.get("subscriptionExpires"))


def _subscription_build(choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    o = offer_for(choice, h, SUBSCRIPTION)
    if isinstance(o, Refusal):
        return o
    r = o.request
    key = o.details["accessKey"]
    chain_id = positive_int(o.details.get("chainId"))
    currency = text(r.get("currency"))
    expiry = unix_of(text(r.get("subscriptionExpires")))
    assert chain_id is not None and expiry is not None
    authorization: dict[str, Any] = {
        "chainId": chain_id,
        "keyType": KEY_TYPES[key["keyType"]],
        "keyId": key["accessKeyAddress"],
        "expiry": expiry,
        "limits": [
            {
                "token": currency,
                "limit": int(text(r.get("amount"))),
                "period": int(text(r.get("periodCount"))) * (WEEK if r.get("periodUnit") == "week" else DAY),
            }
        ],
        "allowedCalls": [
            {"target": currency, "selectorRules": [{"selector": TRANSFER_WITH_MEMO_SELECTOR, "recipients": [text(r.get("recipient"))]}]}
        ],
        "witness": h.lower(),
    }
    unsigned = encode_key_authorization(authorization)
    if isinstance(unsigned, Refusal):
        return unsigned
    challenge = dict(choice["challenge"])
    source = f"did:pkh:eip155:{chain_id}:{choice['from']}"

    def complete(root_signature: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(root_signature, 65, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        signed = encode_key_authorization(authorization, root_signature)
        if isinstance(signed, Refusal):
            return signed
        return {"challenge": challenge, "source": source, "payload": {"type": "keyAuthorization", "signature": to_hex(signed)}}

    request = {"kind": "tempo-key-authorization", "authorization": authorization, "digest": to_hex(keccak256(unsigned))}
    return MppUnsigned(request, complete)


# ── The bindings.


class _Held:
    """The channel members the buyer's channel steps call, read through the binding's channel."""

    __slots__ = ()

    @property
    def channel(self) -> Channel:
        raise NotImplementedError

    def channel_kind(self, presented: Any) -> str | Refusal:
        return self.channel.kind(presented)

    def channel_ref(self, presented: Any) -> ChannelRef | Refusal:
        ref = self.channel.ref(presented)
        return ref if isinstance(ref, Refusal) else ChannelRef(network=ref["network"], channel=ref["channel"])

    def bound_within(self, presented: Any) -> AtrHash | Refusal:
        return self.channel.bound_within(presented)


@dataclass(frozen=True, slots=True)
class MppSessionEvm(_Held):
    id: str = SESSION_EVM
    public_proof: bool = True

    @property
    def channel(self) -> Channel:
        return Channel(kind=_evm_kind, ref=_ref_from, bound_within=_not_bound_within, until=_no_end)

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> SessionUnsigned | Refusal:
        return _evm_build(choice, h)

    def build_within(self, w: Any, h: AtrHash) -> BatchUnsigned | Refusal:
        return _evm_build_within(w, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _evm_bound(presented)


@dataclass(frozen=True, slots=True)
class MppSessionTempo(_Held):
    id: str = SESSION_TEMPO
    public_proof: bool = True

    @property
    def channel(self) -> Channel:
        return Channel(kind=_tempo_kind, ref=_ref_from, bound_within=_tempo_bound_within, until=_no_end)

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> SessionUnsigned | Refusal:
        return _tempo_build(choice, h)

    def build_within(self, w: Any, h: AtrHash) -> BatchUnsigned | Refusal:
        return _tempo_build_within(w, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _tempo_bound(presented)


@dataclass(frozen=True, slots=True)
class MppSubscriptionTempo(_Held):
    id: str = SUBSCRIPTION
    public_proof: bool = True

    @property
    def channel(self) -> Channel:
        return Channel(kind=_subscription_kind, ref=_subscription_ref, bound_within=_not_bound_within, until=_subscription_until)

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _subscription_build(choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _subscription_bound(presented)
