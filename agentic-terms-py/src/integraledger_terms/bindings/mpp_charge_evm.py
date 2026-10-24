"""The buyer half of MPP's EVM charges: mpp/charge/evm/authorization (the signed EIP-3009 nonce is keccak256 of the
JSON array [id, realm] of the challenge), mpp/charge/evm/permit2 (the signed witness carries that value), and
mpp/charge/evm/transaction and mpp/charge/evm/hash (the ERC-20 transfer the buyer signs or broadcasts carries nothing
of H, so bound refuses mpp/no-signed-place)."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Refusal
from ._evm import PERMIT2, Witness, permit2_typed_data
from ._lcp import is_address, is_list, is_object, normal_hash
from ._mpp import (
    MppUnsigned,
    by_type,
    chain_of,
    challenge_hash,
    credential_of,
    echoed_for,
    expires_of,
    is_hex_bytes,
    measured,
    mpp_broadcaster,
    offer_for,
    read,
    same_bytes,
    text,
)
from ._mpp_evm import eip3009_typed_data, transfer_calldata
from ._rlp import rlp_decode, rlp_uint

AUTHORIZATION = "mpp/charge/evm/authorization"
PERMIT2_ID = "mpp/charge/evm/permit2"
TRANSACTION = "mpp/charge/evm/transaction"
HASH = "mpp/charge/evm/hash"

MAX_SIGNATURE = 8192
MAX_WIRE = 65_536
# Who broadcasts the EVM transaction and hash charges' credentials, by type: a signed transaction, the seller's server;
# a hash, the payer. Each of the two pairings takes either, as its read keys do.
_CALL_TYPES: Mapping[str, Broadcaster] = {"transaction": "payee", "hash": "payer"}
PAYMENT_WITNESS = [{"name": "challengeHash", "type": "bytes32"}, {"name": "externalId", "type": "string"}]


def did(chain_id: int, from_: str) -> str:
    return f"did:pkh:eip155:{chain_id}:{from_}"


def _read(doc: Any) -> Advertised | Refusal:
    return read(doc)


# ── mpp/charge/evm/authorization.


def _authorization_build(choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    o = offer_for(choice, h, AUTHORIZATION)
    if isinstance(o, Refusal):
        return o
    td = choice.get("tokenDomain")
    if (
        not is_object(td)
        or not isinstance(td.get("name"), str)
        or td["name"] == ""
        or not isinstance(td.get("version"), str)
        or td["version"] == ""
    ):
        return Refusal("mpp/input-malformed")
    chain_id = chain_of(o)
    challenge = dict(o.challenge)
    nonce = challenge_hash(challenge["id"], challenge["realm"])
    valid_before = expires_of(o)
    if isinstance(valid_before, Refusal):
        return valid_before
    from_ = choice["from"]
    typed_data = eip3009_typed_data(
        network=f"eip155:{chain_id}",
        asset=text(o.request.get("currency")),
        name=td["name"],
        version=td["version"],
        from_=from_,
        to=text(o.request.get("recipient")),
        value=text(o.request.get("amount")),
        valid_after=0,
        valid_before=valid_before,
        nonce=nonce,
    )
    if isinstance(typed_data, Refusal):
        return typed_data
    to, value = text(o.request.get("recipient")), text(o.request.get("amount"))

    def complete(signature: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(signature, 1, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        return measured({
            "challenge": challenge,
            "source": did(chain_id, from_),
            "payload": {
                "type": "authorization",
                "from": from_,
                "to": to,
                "value": value,
                "validAfter": "0",
                "validBefore": str(valid_before),
                "nonce": nonce,
                "signature": signature,
            },
        })

    return MppUnsigned({"kind": "eip712", "typedData": typed_data}, complete)


def _authorization_bound(presented: Any) -> AtrHash | Refusal:
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    e = echoed_for(c, AUTHORIZATION)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "authorization":
        return Refusal("mpp/credential-type")
    if normal_hash(e.payload.get("nonce")) is None:
        return Refusal("mpp/credential-malformed")
    expect = challenge_hash(c["challenge"]["id"], c["challenge"]["realm"])
    if not same_bytes(e.payload["nonce"], expect):
        return Refusal("mpp/nonce-not-challenge-hash")
    return e.h


@dataclass(frozen=True, slots=True)
class MppChargeEvmAuthorization:
    id: str = AUTHORIZATION
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _authorization_build(choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _authorization_bound(presented)

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payee broadcasts a credential of type authorization: the payer signs an EIP-3009 authorization, and the
        seller's server submits transferWithAuthorization with it. A credential of any other type gets
        mpp/credential-type, as bound refuses it."""
        return mpp_broadcaster(presented, by_type({"authorization": "payee"}))


# ── mpp/charge/evm/permit2.


def _permit2_build(choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    o = offer_for(choice, h, PERMIT2_ID)
    if isinstance(o, Refusal):
        return o
    spender = choice.get("spender")
    if not is_address(spender):
        return Refusal("mpp/input-malformed")
    assert isinstance(spender, str)
    chain_id = chain_of(o)
    currency = text(o.request.get("currency"))
    recipient = text(o.request.get("recipient"))
    amount = int(text(o.request.get("amount")))
    raw_splits = o.details.get("splits")
    splits = (
        [{"to": s["recipient"], "amount": int(s["amount"])} for s in raw_splits] if is_list(raw_splits) else None
    )
    primary = amount - sum(s["amount"] for s in splits or [])
    challenge = dict(o.challenge)
    challenge_hash_value = challenge_hash(challenge["id"], challenge["realm"])
    external_id = text(o.request.get("externalId"))
    deadline = expires_of(o)
    if isinstance(deadline, Refusal):
        return deadline
    nonce = int(challenge_hash_value, 16)
    transfers = [{"to": recipient, "amount": primary}, *(splits or [])]
    permitted: list[Mapping[str, Any]] = [{"token": currency, "amount": t["amount"]} for t in transfers]
    contract = o.details.get("permit2Address")
    typed_data = permit2_typed_data(
        chain_id=chain_id,
        permitted=permitted[0] if splits is None else permitted,
        spender=spender,
        nonce=nonce,
        deadline=deadline,
        verifying_contract=contract if isinstance(contract, str) else PERMIT2,
        witness=Witness(
            "PaymentWitness", PAYMENT_WITNESS, {"challengeHash": challenge_hash_value, "externalId": external_id}
        ),
    )
    if isinstance(typed_data, Refusal):
        return typed_data
    from_ = choice["from"]

    def complete(signature: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(signature, 1, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        return measured({
            "challenge": challenge,
            "source": did(chain_id, from_),
            "payload": {
                "type": "permit2",
                "permit": {
                    "permitted": [{"token": p["token"], "amount": str(p["amount"])} for p in permitted],
                    "nonce": str(nonce),
                    "deadline": str(deadline),
                },
                "transferDetails": [{"to": t["to"], "requestedAmount": str(t["amount"])} for t in transfers],
                "witness": {"challengeHash": challenge_hash_value, "externalId": external_id},
                "signature": signature,
            },
        })

    return MppUnsigned({"kind": "eip712", "typedData": typed_data}, complete)


def _permit2_bound(presented: Any) -> AtrHash | Refusal:
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    e = echoed_for(c, PERMIT2_ID)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "permit2":
        return Refusal("mpp/credential-type")
    w = e.payload.get("witness")
    if not is_object(w) or normal_hash(w.get("challengeHash")) is None:
        return Refusal("mpp/credential-malformed")
    expect = challenge_hash(c["challenge"]["id"], c["challenge"]["realm"])
    if not same_bytes(w["challengeHash"], expect):
        return Refusal("mpp/witness-not-challenge-hash")
    return e.h


@dataclass(frozen=True, slots=True)
class MppChargeEvmPermit2:
    id: str = PERMIT2_ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _permit2_build(choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _permit2_bound(presented)

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payee broadcasts a credential of type permit2: the payer signs a Permit2 transfer, and the seller's
        server, the spender it names, submits it to Permit2. A credential of any other type gets mpp/credential-type, as
        bound refuses it."""
        return mpp_broadcaster(presented, by_type({"permit2": "payee"}))


# ── mpp/charge/evm/transaction and mpp/charge/evm/hash.

# EIP-1559's transaction type, its EIP-2718 envelope byte; the places among its fields of the destination and data (byte
# strings), and of the access list.
_EIP1559_TYPE = 0x02
_EIP1559_BYTES = (5, 7)
_EIP1559_ACCESS_LIST = 8


def _eip1559_chain_id(wire: bytes) -> int | None:
    """The chain id of a signed EIP-1559 transaction: 0x02, then the RLP list of its twelve fields, chainId, nonce,
    maxPriorityFeePerGas, maxFeePerGas, gasLimit, destination, amount, data, accessList, signatureYParity, signatureR
    and signatureS (EIP-1559), each integer canonical and the access list a list. None for any other bytes."""
    if not wire or wire[0] != _EIP1559_TYPE:
        return None
    top = rlp_decode(wire[1:], 3)
    if top is None or top.items is None or len(top.items) != 12:
        return None
    for i, item in enumerate(top.items):
        if i == _EIP1559_ACCESS_LIST:
            if not item.is_list:
                return None
        elif i in _EIP1559_BYTES:
            if item.is_list:
                return None
        elif rlp_uint(item) is None:
            return None
    return rlp_uint(top.items[0])


def _call_build(pairing: str, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    """The call's request for the buyer's signer, on the challenge's chain. On hash, complete takes the transaction
    hash; on transaction, the signed transaction. It checks in bound's order: first bound's hold of the echoed challenge
    (echoed_for), which bound makes before its verdict, so a credential over the credential size bound is
    mpp/credential-malformed, as bound gives it; then the transaction, 1 to 65,536 bytes of hex, else
    mpp/credential-malformed, read as draft-evm-charge-00's transaction verification reads it before it broadcasts
    (L696-697 and L873-879 at tempoxyz/mpp-specs 08e7dd87): an EIP-1559 transaction, else mpp/credential-malformed,
    whose chain id is the challenge's methodDetails.chainId, else evm/chain-mismatch. bound reads nothing of it
    (mpp/no-signed-place)."""
    o = offer_for(choice, h, pairing)
    if isinstance(o, Refusal):
        return o
    chain_id = chain_of(o)
    data = transfer_calldata(text(o.request.get("recipient")), int(text(o.request.get("amount"))))
    challenge = dict(o.challenge)
    source = did(chain_id, choice["from"])
    broadcast = pairing == HASH

    def complete(signed_or_hash: Any) -> dict[str, Any] | Refusal:
        if broadcast:
            if normal_hash(signed_or_hash) is None:
                return Refusal("mpp/credential-malformed")
            hashed = {"type": "hash", "hash": signed_or_hash}
            return measured({"challenge": challenge, "source": source, "payload": hashed})
        signed = {"type": "transaction", "signature": signed_or_hash}
        credential = {"challenge": challenge, "source": source, "payload": signed}
        held = echoed_for(credential, pairing)
        if isinstance(held, Refusal):
            return held
        if not is_hex_bytes(signed_or_hash, 1, MAX_WIRE):
            return Refusal("mpp/credential-malformed")
        tx_chain = _eip1559_chain_id(bytes.fromhex(signed_or_hash[2:]))
        if tx_chain is None:
            return Refusal("mpp/credential-malformed")
        if tx_chain != chain_id:
            return Refusal("evm/chain-mismatch")
        return credential

    request = {
        "kind": "evm-call",
        "chainId": chain_id,
        "call": {"to": text(o.request.get("currency")), "data": data},
        "broadcast": broadcast,
    }
    return MppUnsigned(request, complete)


def _no_signed_place(presented: Any, pairing: str) -> AtrHash | Refusal:
    """The echoed challenge, held to pairing's filter (echoed_for); then mpp/no-signed-place: nothing the payer signed
    carries H."""
    e = echoed_for(presented, pairing)
    return e if isinstance(e, Refusal) else Refusal("mpp/no-signed-place")


@dataclass(frozen=True, slots=True)
class MppChargeEvmTransaction:
    id: str = TRANSACTION
    public_proof: bool = False

    def read(self, doc: Any) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _call_build(TRANSACTION, choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _no_signed_place(presented, TRANSACTION)

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """By the credential's type, as the read keys take either: transaction, "payee", a signed transaction the
        seller's server broadcasts; hash, "payer", a transaction the payer broadcast. A credential of any other type
        gets mpp/no-signed-place, the code bound gives every credential within its shape gate."""
        return mpp_broadcaster(presented, by_type(_CALL_TYPES, "mpp/no-signed-place"))


@dataclass(frozen=True, slots=True)
class MppChargeEvmHash:
    id: str = HASH
    public_proof: bool = False

    def read(self, doc: Any) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _call_build(HASH, choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _no_signed_place(presented, HASH)

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """By the credential's type, as the read keys take either: hash, "payer", a transaction the payer broadcast;
        transaction, "payee", a signed transaction the seller's server broadcasts. A credential of any other type gets
        mpp/no-signed-place, the code bound gives every credential within its shape gate."""
        return mpp_broadcaster(presented, by_type(_CALL_TYPES, "mpp/no-signed-place"))
