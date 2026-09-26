"""The buyer half of MPP's EVM charges: mpp/charge/evm/authorization (the signed EIP-3009 nonce is keccak256 of the
challenge's id and realm), mpp/charge/evm/permit2 (the signed witness carries that value), and
mpp/charge/evm/transaction and mpp/charge/evm/hash (the ERC-20 transfer the buyer signs or broadcasts carries nothing
of H, so bound refuses mpp/no-signed-place)."""

from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Refusal
from ._lcp import is_address, is_list, is_object, normal_hash
from ._mpp import (
    Checked,
    MppUnsigned,
    challenge_bound,
    challenge_hash,
    credential_of,
    echoed_for,
    is_hex_bytes,
    offer_for,
    read,
    same_bytes,
    text,
    TEMPO_DEFAULT_CHAIN,
)
from ._mpp_checks import positive_int
from ._mpp_evm import PERMIT2, eip3009_typed_data, permit2_typed_data, transfer_calldata

AUTHORIZATION = "mpp/charge/evm/authorization"
PERMIT2_ID = "mpp/charge/evm/permit2"
TRANSACTION = "mpp/charge/evm/transaction"
HASH = "mpp/charge/evm/hash"

MAX_SIGNATURE = 8192
MAX_WIRE = 65_536
PAYMENT_WITNESS = [{"name": "challengeHash", "type": "bytes32"}, {"name": "externalId", "type": "string"}]


def chain_of(c: Checked) -> int:
    """The challenge's methodDetails.chainId, or Tempo's default."""
    chain_id = positive_int(c.details.get("chainId"))
    return TEMPO_DEFAULT_CHAIN if chain_id is None else chain_id


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
    challenge = dict(choice["challenge"])
    nonce = challenge_hash(challenge["id"], challenge["realm"])
    valid_before = o.expires
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
        if not is_hex_bytes(signature, 65, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        return {
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
        }

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
    if primary <= 0:
        return Refusal("mpp/input-malformed")
    challenge = dict(choice["challenge"])
    challenge_hash_value = challenge_hash(challenge["id"], challenge["realm"])
    external_id = text(o.request.get("externalId"))
    deadline = o.expires
    nonce = int(challenge_hash_value, 16)
    transfers = [{"to": recipient, "amount": primary}, *(splits or [])]
    permitted = [{"token": currency, "amount": t["amount"]} for t in transfers]
    contract = o.details.get("permit2Address")
    typed_data = permit2_typed_data(
        chain_id=chain_id,
        permitted=permitted[0] if splits is None else permitted,
        spender=spender,
        nonce=nonce,
        deadline=deadline,
        verifying_contract=contract if isinstance(contract, str) else PERMIT2,
        witness={
            "type": "PaymentWitness",
            "fields": PAYMENT_WITNESS,
            "value": {"challengeHash": challenge_hash_value, "externalId": external_id},
        },
    )
    if isinstance(typed_data, Refusal):
        return typed_data
    from_ = choice["from"]

    def complete(signature: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(signature, 65, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        return {
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
        }

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


# ── mpp/charge/evm/transaction and mpp/charge/evm/hash.


def _call_build(pairing: str, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    o = offer_for(choice, h, pairing)
    if isinstance(o, Refusal):
        return o
    chain_id = chain_of(o)
    data = transfer_calldata(text(o.request.get("recipient")), int(text(o.request.get("amount"))))
    challenge = dict(choice["challenge"])
    source = did(chain_id, choice["from"])
    broadcast = pairing == HASH

    def complete(signed_or_hash: Any) -> dict[str, Any] | Refusal:
        if broadcast:
            if normal_hash(signed_or_hash) is None:
                return Refusal("mpp/credential-malformed")
            return {"challenge": challenge, "source": source, "payload": {"type": "hash", "hash": signed_or_hash}}
        if not is_hex_bytes(signed_or_hash, 1, MAX_WIRE):
            return Refusal("mpp/credential-malformed")
        return {"challenge": challenge, "source": source, "payload": {"type": "transaction", "signature": signed_or_hash}}

    request = {
        "kind": "evm-call",
        "chainId": chain_id,
        "call": {"to": text(o.request.get("currency")), "data": data},
        "broadcast": broadcast,
    }
    return MppUnsigned(request, complete)


def _no_signed_place(presented: Any) -> AtrHash | Refusal:
    b = challenge_bound(presented)
    return b if isinstance(b, Refusal) else Refusal("mpp/no-signed-place")


@dataclass(frozen=True, slots=True)
class MppChargeEvmTransaction:
    id: str = TRANSACTION
    public_proof: bool = False

    def read(self, doc: Any) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _call_build(TRANSACTION, choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _no_signed_place(presented)


@dataclass(frozen=True, slots=True)
class MppChargeEvmHash:
    id: str = HASH
    public_proof: bool = False

    def read(self, doc: Any) -> Advertised | Refusal:
        return _read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _call_build(HASH, choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _no_signed_place(presented)
