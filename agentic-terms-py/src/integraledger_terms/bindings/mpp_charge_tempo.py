"""The buyer half of mpp/charge/tempo/memo and mpp/charge/tempo/push: the signed transferWithMemo carries MPP's
attribution memo, whose nonce is keccak256 of the challenge id. memo's payment is the signed 0x76 transaction; push's
is the hash of the transaction the buyer broadcast, bound by the memo topic of the landed receipt's TransferWithMemo
log."""

import re
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Refusal
from ._codec import to_hex
from ._lcp import is_list, is_object, is_well_formed, normal_hash
from ._mpp import (
    Echoed,
    MppUnsigned,
    attribution_memo,
    by_type,
    chain_of,
    check_attribution,
    credential_of,
    echoed_for,
    expires_of,
    fetched_of,
    is_hex_bytes,
    mpp_broadcaster,
    offer_for,
    read,
    request_address,
    same_bytes,
    text,
)
from ._mpp_checks import tempo_splits
from ._mpp_evm import transfer_calldata
from ._tempo import MAX_WIRE_BYTES, TRANSFER_WITH_MEMO_SELECTOR, TRANSFER_WITH_MEMO_TOPIC, decode_tempo_tx, memo_calldata
from .mpp_charge_evm import did

MEMO = "mpp/charge/tempo/memo"
PUSH = "mpp/charge/tempo/push"

_HEX_EVEN = re.compile(r"0x[0-9a-fA-F]*")


def _build(pairing: str, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    """Without splits, a tempo-call: the one transferWithMemo of amount, carrying the attribution memo. With splits,
    tempo-calls: that call for amount less the splits, then one call per split in array order, transferWithMemo where
    the split names a memo and transfer otherwise, all on currency. The pairing's filter has read the splits. On push,
    complete takes the transaction hash; on memo, the signed transaction, read as bound reads it: one that is not hex
    bytes, or is over 64 KiB, is mpp/credential-malformed; one that does not decode, an empty one among them, gives
    decode_tempo_tx's refusal, tempo/tx-malformed; and one signed for a chain other than the request's chainId is
    tempo/tx-malformed."""
    o = offer_for(choice, h, pairing)
    if isinstance(o, Refusal):
        return o
    valid_before = expires_of(o)
    if isinstance(valid_before, Refusal):
        return valid_before
    client_id = choice.get("clientId")
    if "clientId" in choice and not is_well_formed(client_id):
        return Refusal("mpp/input-malformed")
    chain_id = chain_of(o)
    splits = tempo_splits(o.details)
    if isinstance(splits, Refusal):
        return splits
    challenge = dict(choice["challenge"])
    memo = attribution_memo(challenge["realm"], challenge["id"], client_id)
    primary = int(text(o.request.get("amount"))) - sum(s.amount for s in splits or [])
    data = memo_calldata(text(o.request.get("recipient")), primary, memo)
    if isinstance(data, Refusal):
        return data
    currency = text(o.request.get("currency"))
    calls = [{"to": currency, "data": data}]
    for s in splits or []:
        split = transfer_calldata(s.to, s.amount) if s.memo is None else memo_calldata(s.to, s.amount, s.memo)
        if isinstance(split, Refusal):
            return split
        calls.append({"to": currency, "data": split})
    source = did(chain_id, choice["from"])
    broadcast = pairing == PUSH

    def complete(signed_or_hash: Any) -> dict[str, Any] | Refusal:
        if broadcast:
            if normal_hash(signed_or_hash) is None:
                return Refusal("mpp/credential-malformed")
            return {"challenge": challenge, "source": source, "payload": {"type": "hash", "hash": signed_or_hash}}
        if not is_hex_bytes(signed_or_hash, 0, MAX_WIRE_BYTES):
            return Refusal("mpp/credential-malformed")
        tx = decode_tempo_tx(bytes.fromhex(signed_or_hash[2:]))
        if isinstance(tx, Refusal):
            return tx
        if tx.chain_id != chain_id:
            return Refusal("tempo/tx-malformed")
        return {"challenge": challenge, "source": source, "payload": {"type": "transaction", "signature": signed_or_hash}}

    shared = {"chainId": chain_id, "validBefore": valid_before, "broadcast": broadcast}
    if splits is None:
        return MppUnsigned({"kind": "tempo-call", "call": calls[0], **shared}, complete)
    return MppUnsigned({"kind": "tempo-calls", "calls": calls, **shared}, complete)


def _signed_memo_call(presented: Any) -> Echoed | Refusal:
    """The echoed challenge, when the signed transaction is for the challenge's chain and holds exactly one
    transferWithMemo call to currency whose memo is this challenge's attribution memo. draft-tempo-charge-00 binds a
    Tempo transaction to its chain id: a transaction signed for another chain is tempo/tx-malformed."""
    e = echoed_for(presented, MEMO)
    if isinstance(e, Refusal):
        return e
    currency = request_address(e.checked, "currency")
    if isinstance(currency, Refusal):
        return currency
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
    if tx.chain_id != chain_of(e.checked):
        return Refusal("tempo/tx-malformed")
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
    """The echoed challenge, when the landed receipt read for the credential and held in Held, as @integraledger/lcp
    holds it under the payment's own FETCHED member (fetched_of), holds exactly one TransferWithMemo log from currency
    whose memo topic is this challenge's attribution memo. A credential with no landed logs held in Held, which have
    not been read, is tempo/read-first; a landed member of the credential's own is not read."""
    e = echoed_for(presented, PUSH)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "hash":
        return Refusal("mpp/credential-type")
    landed = fetched_of(presented)
    if not is_object(landed) or not is_list(landed.get("logs")):
        return Refusal("tempo/read-first")
    currency = request_address(e.checked, "currency")
    if isinstance(currency, Refusal):
        return currency
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

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payee broadcasts a credential of type transaction: the seller's server broadcasts the signed transaction
        the credential carries. A credential of any other type gets mpp/credential-type, as bound refuses it."""
        return mpp_broadcaster(presented, by_type({"transaction": "payee"}))


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

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payer broadcasts a credential of type hash, and presents the transaction's hash. A credential of any
        other type gets mpp/credential-type, as bound refuses it."""
        return mpp_broadcaster(presented, by_type({"hash": "payer"}))
