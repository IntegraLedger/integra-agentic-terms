"""The buyer half of mpp/session/xrpl: the channel's opening is a PaymentChannelCreate whose one LCP memo carries the
ATR hash in full; the first claim, and each later claim, signs the channel id and an amount. The channel members read
a payment's channel, and build a later claim on the channel the held opening created. Nothing here fetches or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Json, Refusal
from ._channel import BatchUnsigned, ChannelKind, ChannelRef
from ._lcp import from_lcp_string, is_list, is_object, to_lcp_string
from ._mpp import Checked, chosen_for, credential_of, echoed_for, read
from ._mpp_checks import xrpl_network_of
from ._session_within import action_kind, echoed_details, within_checks
from ._xrpl import channel_id, claim_bytes, decode_presented, is_blob_hex

ID = "mpp/session/xrpl"
WITHIN_ACTIONS = ("voucher",)
U64_LIMIT = 1 << 64
_HASH256 = re.compile(r"[0-9A-Fa-f]{64}")

MAX_MEMOS = 8
_DROPS = re.compile(r"0|[1-9][0-9]{0,18}")
_BIGINT = re.compile(r"[+-]?[0-9]+|0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+|")
_JS_SPACE = " \t\n\v\f\r                 　﻿"


def _js_bigint(value: object) -> int:
    """A string read as an integer literal: whitespace trimmed, empty as 0, signed decimal digits, or 0x, 0o or 0b
    digits. Raises ValueError for anything else."""
    if not isinstance(value, str):
        raise ValueError("not a string")
    text = value.strip(_JS_SPACE)
    if _BIGINT.fullmatch(text) is None:
        raise ValueError("not an integer")
    if text == "":
        return 0
    if text[:2].lower() in ("0x", "0o", "0b"):
        return int(text[2:], {"x": 16, "o": 8, "b": 2}[text[1].lower()])
    return int(text)


def _u32(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    if isinstance(value, float) and not value.is_integer():
        return False
    return 0 <= value <= 0xFFFFFFFF


def lcp_memo(tx: Mapping[str, Any]) -> AtrHash | Refusal:
    """The hash of the exactly one memo, among at most 8, whose MemoData is UTF-8 that parses as an LCP string."""
    memos = tx.get("Memos")
    entries = memos if is_list(memos) else []
    if len(entries) > MAX_MEMOS:
        return Refusal("xrpl/memo-count")
    found: list[AtrHash] = []
    for m in entries:
        memo = m.get("Memo") if is_object(m) else None
        data = memo.get("MemoData") if is_object(memo) else None
        if not is_blob_hex(data):
            continue
        assert isinstance(data, str)
        try:
            text = bytes.fromhex(data).decode("utf-8")
        except UnicodeDecodeError:
            continue
        h = from_lcp_string(text)
        if h is not None:
            found.append(h)
    if not found:
        return Refusal("xrpl/no-memo")
    if len(found) > 1:
        return Refusal("xrpl/memo-count")
    return found[0]


@dataclass(frozen=True, slots=True)
class Opening:
    """A checked opening: its H, its echoed challenge checked, its payload and its signed transaction decoded."""

    h: AtrHash
    checked: Checked
    payload: Mapping[str, Any]
    tx: Mapping[str, Any]


def _sequence(tx: Mapping[str, Any]) -> object:
    """The creating transaction's sequence: Sequence, or TicketSequence when Sequence is 0."""
    sequence = tx.get("Sequence")
    return tx.get("TicketSequence") if sequence == 0 and not isinstance(sequence, bool) else sequence


def _opening(presented: object) -> Opening | Refusal:
    """The echoed challenge of an opening whose signed PaymentChannelCreate's one LCP memo is the challenge's H."""
    e = echoed_for(presented, ID)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("action") != "open":
        return Refusal("mpp/session-action")
    blob = e.payload.get("transaction")
    if not isinstance(blob, str):
        return Refusal("xrpl/blob-malformed")
    decoded = decode_presented(blob)
    if isinstance(decoded, Refusal):
        return decoded
    if decoded.tx.get("TransactionType") != "PaymentChannelCreate":
        return Refusal("xrpl/not-channel-create")
    h = lcp_memo(decoded.tx)
    if isinstance(h, Refusal):
        return h
    if not hash_equals(h, e.h):
        return Refusal("mpp/carrier-not-challenge")
    return Opening(e.h, e.checked, e.payload, decoded.tx)


@dataclass(frozen=True, slots=True)
class XrplSessionUnsigned:
    """The PaymentChannelCreate for the wallet to sign and the first claim's bytes, and how the signed blob and the
    claim's signature complete the opening."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]
    _source: str
    _amount: Any

    def complete(self, signed: object) -> dict[str, Any] | Refusal:
        """The opening credential, once its signed blob carries H in its one LCP memo."""
        if not is_object(signed):
            return Refusal("mpp/credential-malformed")
        blob, signature = signed.get("signedBlob"), signed.get("claimSignature")
        if not isinstance(blob, str) or not is_blob_hex(signature):
            return Refusal("mpp/credential-malformed")
        credential = {
            "challenge": self._challenge,
            "source": self._source,
            "payload": {"action": "open", "transaction": blob, "amount": self._amount, "signature": signature},
        }
        o = _opening(credential)
        return o if isinstance(o, Refusal) else credential


@dataclass(frozen=True, slots=True)
class MppSessionXrpl:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> XrplSessionUnsigned | Refusal:
        """The PaymentChannelCreate with one LCP memo carrying H, and the first claim's bytes on the channel it
        creates."""
        if not is_object(choice) or not is_object(choice.get("xrpl")):
            return Refusal("mpp/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        x: Mapping[str, Any] = choice["xrpl"]
        source_account, deposit = choice.get("from"), choice.get("deposit")
        public_key, fee = x.get("publicKey"), x.get("fee")
        if (
            not isinstance(source_account, str)
            or isinstance(deposit, bool)
            or not isinstance(deposit, int)
            or not 0 < deposit < 1 << 64
            or not is_blob_hex(public_key)
            or not isinstance(fee, str)
            or _DROPS.fullmatch(fee) is None
            or not _u32(x.get("settleDelay"))
            or not _u32(x.get("sequence"))
            or not _u32(x.get("lastLedgerSequence"))
            or ("cancelAfter" in x and not _u32(x["cancelAfter"]))
        ):
            return Refusal("mpp/input-malformed")
        assert isinstance(public_key, str)
        network = xrpl_network_of(checked.details)
        if isinstance(network, Refusal):
            return network
        destination = checked.request.get("recipient")
        channel = channel_id(source_account, destination, int(x["sequence"]))
        if isinstance(channel, Refusal):
            return channel
        drops = _js_bigint(checked.request.get("amount"))
        claim = claim_bytes(channel, drops)
        if isinstance(claim, Refusal):
            return claim
        tx: dict[str, Any] = {
            "TransactionType": "PaymentChannelCreate",
            "Flags": 0,
            "Account": source_account,
            "Amount": str(deposit),
            "Destination": destination,
            "SettleDelay": x["settleDelay"],
            "PublicKey": public_key.upper(),
        }
        if "cancelAfter" in x:
            tx["CancelAfter"] = x["cancelAfter"]
        tx["Memos"] = [{"Memo": {"MemoData": to_lcp_string(h).encode("utf-8").hex().upper()}}]
        tx["Fee"] = fee
        tx["Sequence"] = x["sequence"]
        tx["LastLedgerSequence"] = x["lastLedgerSequence"]
        return XrplSessionUnsigned(
            request={"kind": "xrpl-session-open", "txJson": tx, "claim": {"channelId": channel, "drops": drops, "bytes": claim}},
            _challenge=choice["challenge"],
            _source=f"did:pkh:xrpl:{network[len('xrpl:'):]}:{source_account}",
            _amount=checked.request.get("amount"),
        )

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """H from an opening's echoed challenge, once the signed PaymentChannelCreate's one LCP memo is that H. A
        multi-signed blob is xrpl/multisigned: the payer signs with a single key. The signature is not verified
        here."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        o = _opening(presented)
        return o if isinstance(o, Refusal) else o.h

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """open, close, or within for a voucher."""
        return action_kind(presented, WITHIN_ACTIONS)

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The network and the channel: on an open, its id derived from the signed blob; on a voucher or close, the
        payload's channelId in upper case, with the network read from the payment itself."""
        kind = action_kind(presented, WITHIN_ACTIONS)
        if isinstance(kind, Refusal):
            return kind
        assert is_object(presented)
        if kind != "open":
            d = echoed_details(presented, "xrpl")
            if isinstance(d, Refusal):
                return d
            network = xrpl_network_of(d)
            if isinstance(network, Refusal):
                return network
            c = presented["payload"].get("channelId")
            if not isinstance(c, str) or _HASH256.fullmatch(c) is None:
                return Refusal("mpp/credential-malformed")
            return ChannelRef(network, c.upper())
        e = echoed_for(presented, ID)
        if isinstance(e, Refusal):
            return e
        network = xrpl_network_of(e.checked.details)
        if isinstance(network, Refusal):
            return network
        blob = e.payload.get("transaction")
        if not isinstance(blob, str):
            return Refusal("xrpl/blob-malformed")
        decoded = decode_presented(blob)
        if isinstance(decoded, Refusal):
            return decoded
        channel = channel_id(decoded.tx.get("Account"), decoded.tx.get("Destination"), _sequence(decoded.tx))
        return channel if isinstance(channel, Refusal) else ChannelRef(network, channel)

    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A claim signs the channel id and an amount, no value holding H."""
        return Refusal("mpp/not-bound-within")

    def build_within(self, w: Mapping[str, Any], h: AtrHash) -> BatchUnsigned | Refusal:
        """A claim, or a close's final claim, on the channel the held opening created: one xrpl-claim request over the
        claim bytes (CLM\\0, the channel id, the drops), for the channel's key, with the channel id derived from the
        opening's signed blob."""
        o = within_checks(w, h, "session/xrpl", _opening, U64_LIMIT)
        if isinstance(o, Refusal):
            return o
        channel = channel_id(o.tx.get("Account"), o.tx.get("Destination"), _sequence(o.tx))
        if isinstance(channel, Refusal):
            return channel
        drops = w["cumulativeAmount"]
        claim = claim_bytes(channel, drops)
        if isinstance(claim, Refusal):
            return claim
        challenge = dict(w["challenge"])
        action = w["action"]

        def complete(signatures: Any) -> dict[str, Any] | Refusal:
            signature = signatures[0] if isinstance(signatures, (list, tuple)) and len(signatures) == 1 else None
            if not is_blob_hex(signature):
                return Refusal("mpp/credential-malformed")
            return {"challenge": challenge, "payload": {"action": action, "channelId": channel, "amount": str(drops), "signature": signature}}

        return BatchUnsigned(requests=[{"kind": "xrpl-claim", "channelId": channel, "drops": drops, "bytes": claim}], complete=complete)
