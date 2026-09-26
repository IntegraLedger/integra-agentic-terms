"""The buyer half of mpp/charge/tempo/memo and mpp/charge/tempo/push: the signed transferWithMemo carries MPP's
attribution memo, whose nonce is keccak256 of the challenge id. memo's payment is the signed 0x76 transaction; push's
is the hash of the transaction the buyer broadcast, bound by the memo topic of the landed receipt's TransferWithMemo
log."""

import re
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Refusal
from ._codec import to_hex
from ._lcp import is_list, is_object, normal_hash
from ._mpp import (
    Echoed,
    MppUnsigned,
    attribution_memo,
    check_attribution,
    credential_of,
    echoed_for,
    is_hex_bytes,
    offer_for,
    read,
    same_bytes,
    text,
)
from ._tempo import MAX_WIRE_BYTES, TRANSFER_WITH_MEMO_SELECTOR, TRANSFER_WITH_MEMO_TOPIC, decode_tempo_tx, memo_calldata
from .mpp_charge_evm import chain_of, did

MEMO = "mpp/charge/tempo/memo"
PUSH = "mpp/charge/tempo/push"

_HEX_EVEN = re.compile(r"0x[0-9a-fA-F]*")


def _build(pairing: str, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    o = offer_for(choice, h, pairing)
    if isinstance(o, Refusal):
        return o
    client_id = choice.get("clientId")
    if "clientId" in choice and not isinstance(client_id, str):
        return Refusal("mpp/input-malformed")
    chain_id = chain_of(o)
    challenge = dict(choice["challenge"])
    memo = attribution_memo(challenge["realm"], challenge["id"], client_id)
    recipient, amount = text(o.request.get("recipient")), int(text(o.request.get("amount")))
    data = memo_calldata(recipient, amount, memo)
    if isinstance(data, Refusal):
        return data
    source = did(chain_id, choice["from"])
    broadcast = pairing == PUSH

    def complete(signed_or_hash: Any) -> dict[str, Any] | Refusal:
        if broadcast:
            if normal_hash(signed_or_hash) is None:
                return Refusal("mpp/credential-malformed")
            return {"challenge": challenge, "source": source, "payload": {"type": "hash", "hash": signed_or_hash}}
        if not is_hex_bytes(signed_or_hash, 1, MAX_WIRE_BYTES):
            return Refusal("mpp/credential-malformed")
        return {"challenge": challenge, "source": source, "payload": {"type": "transaction", "signature": signed_or_hash}}

    request = {
        "kind": "tempo-call",
        "chainId": chain_id,
        "call": {"to": text(o.request.get("currency")), "data": data},
        "validBefore": o.expires,
        "broadcast": broadcast,
    }
    return MppUnsigned(request, complete)


def _signed_memo_call(presented: Any) -> Echoed | Refusal:
    """The echoed challenge, when the signed transaction holds exactly one transferWithMemo call to currency whose
    memo is this challenge's attribution memo."""
    e = echoed_for(presented, MEMO)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "transaction":
        return Refusal("mpp/credential-type")
    sig = e.payload.get("signature")
    if not isinstance(sig, str) or len(sig) % 2 != 0 or _HEX_EVEN.fullmatch(sig) is None:
        return Refusal("mpp/credential-malformed")
    if (len(sig) - 2) // 2 > MAX_WIRE_BYTES:
        return Refusal("tempo/tx-too-large")
    tx = decode_tempo_tx(bytes.fromhex(sig[2:]))
    if isinstance(tx, Refusal):
        return tx
    currency = text(e.checked.request.get("currency"))
    realm, id_ = presented["challenge"]["realm"], presented["challenge"]["id"]
    found = 0
    for call in tx.calls:
        if call.to is None or not same_bytes(call.to, currency) or len(call.input) != 100:
            continue
        if to_hex(call.input[:4]) != TRANSFER_WITH_MEMO_SELECTOR or any(call.input[4:16]):
            continue
        if check_attribution(to_hex(call.input[68:100]), realm, id_) is not True:
            continue
        found += 1
    if found == 0:
        return Refusal("tempo/memo-not-bound")
    if found > 1:
        return Refusal("tempo/ambiguous")
    return e


def _landed_memo_log(presented: Any) -> Echoed | Refusal:
    """The echoed challenge, when the landed receipt holds exactly one TransferWithMemo log from currency whose memo
    topic is this challenge's attribution memo."""
    e = echoed_for(presented, PUSH)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "hash":
        return Refusal("mpp/credential-type")
    landed = presented.get("landed")
    if not is_object(landed) or not is_list(landed.get("logs")):
        return Refusal("mpp/credential-malformed")
    currency = text(e.checked.request.get("currency"))
    realm, id_ = presented["challenge"]["realm"], presented["challenge"]["id"]
    found = 0
    for log in landed["logs"]:
        topics = log.get("topics") if is_object(log) else None
        if (
            is_list(topics)
            and len(topics) == 4
            and same_bytes(log.get("address"), currency)
            and same_bytes(topics[0], TRANSFER_WITH_MEMO_TOPIC)
            and isinstance(topics[3], str)
            and check_attribution(topics[3], realm, id_) is True
        ):
            found += 1
    if found == 0:
        return Refusal("tempo/memo-not-bound")
    if found > 1:
        return Refusal("tempo/ambiguous")
    return e


@dataclass(frozen=True, slots=True)
class MppChargeTempoMemo:
    id: str = MEMO
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _build(MEMO, choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        c = credential_of(presented)
        if isinstance(c, Refusal):
            return c
        m = _signed_memo_call(c)
        return m if isinstance(m, Refusal) else m.h


@dataclass(frozen=True, slots=True)
class MppChargeTempoPush:
    id: str = PUSH
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _build(PUSH, choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        c = credential_of(presented)
        if isinstance(c, Refusal):
            return c
        m = _landed_memo_log(c)
        return m if isinstance(m, Refusal) else m.h
