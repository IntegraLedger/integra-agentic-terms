"""The buyer half of the lcp MPP method's charge (lcp profile mpp-method-lcp.md), one pairing per rail, the rail named
by the request's methodDetails.rail: the method's credential, {type: "transaction", transaction}, the signed bytes the
party that submits sends unchanged; and the Hedera rail, mpp/charge/lcp/hedera, whose TransferTransaction body carries
the ATR hash as its memo. The method's filter is lcp_charge_pairings. Nothing here fetches, hashes, signs or
broadcasts, and no credential written here is of type hash: a hash credential names a payment its payer broadcast."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Refusal
from ._codec import b64_decode
from ._hedera_proto import (
    INT64_LIMIT,
    UINT64_LIMIT,
    account_amount,
    amount_of,
    complete_with,
    decode_hedera_tx,
    entity,
    is_entity,
    len_field,
    tx_id_field,
    v_field,
    write_body,
)
from ._lcp import is_object, normal_hash, to_lcp_string
from ._mpp import by_type, chosen_for, credential_of, echoed_for, fetched_of, measured, mpp_broadcaster, read

HEDERA = "mpp/charge/lcp/hedera"

_SUCCESS = "SUCCESS"
# A transaction id as the Mirror Node spells it, shard.realm.num-seconds-nanos, and a consensus timestamp.
_ENTITY = r"(?:0|[1-9][0-9]{0,18})\.(?:0|[1-9][0-9]{0,18})\.(?:0|[1-9][0-9]{0,18})"
_MIRROR_ID = re.compile(_ENTITY + r"-[0-9]{1,19}-[0-9]{1,9}")
_TIMESTAMP = re.compile(r"[0-9]{1,19}\.[0-9]{9}")
_DURATION = re.compile(r"0|[1-9][0-9]{0,2}")
_MAX_FEE = re.compile(r"0|[1-9][0-9]{0,19}")


# ── The method.


def lcp_payload_type(payload: Mapping[str, Any]) -> Literal["transaction", "hash"] | Refusal:
    """The payload type of a credential of the method: transaction, the bytes the payer signed, or hash, a payment its
    payer broadcast; any other is mpp/credential-type."""
    kind = payload.get("type")
    if kind == "transaction":
        return "transaction"
    if kind == "hash":
        return "hash"
    return Refusal("mpp/credential-type")


def lcp_credential(challenge: Mapping[str, Any], transaction: str) -> dict[str, Any] | Refusal:
    """The credential a rail's client completes: the chosen challenge as build held it and the payload
    {type: "transaction", transaction}, measured against the credential bound as bound measures it
    (mpp/credential-malformed)."""
    return measured({"challenge": dict(challenge), "payload": {"type": "transaction", "transaction": transaction}})


# ── The Hedera rail.


def _whole(value: object) -> int | None:
    """An integer given as an int or an integral float, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _valid_inputs(c: Mapping[str, Any]) -> bool:
    """The payer and the node entity ids; the valid start's seconds an int below 2^63 and its nanos 0 to 999,999,999;
    the maximum fee an int below 2^64; and a token's decimals, where given, a u32."""
    vs = c.get("validStart")
    if not is_entity(c.get("payer")) or not is_entity(c.get("node")) or not is_object(vs):
        return False
    seconds, nanos, max_fee = vs.get("seconds"), _whole(vs.get("nanos")), c.get("maxFee")
    if isinstance(seconds, bool) or not isinstance(seconds, int) or not 0 <= seconds < INT64_LIMIT:
        return False
    if nanos is None or not 0 <= nanos <= 999_999_999:
        return False
    if isinstance(max_fee, bool) or not isinstance(max_fee, int) or not 0 <= max_fee < UINT64_LIMIT:
        return False
    if "decimals" in c:
        decimals = _whole(c.get("decimals"))
        if decimals is None or not 0 <= decimals <= 0xFFFFFFFF:
            return False
    return True


def _transfer(asset: str, payer: str, pay_to: str, amount: int, decimals: int | None) -> bytes:
    """CryptoTransferTransactionBody: the payer's debit and the payee's credit of amount, in HBAR (transfers, 1) where
    asset is 0.0.0, else in the token's list (tokenTransfers, 2), with its expected decimals where given."""
    if asset == "0.0.0":
        return len_field(1, len_field(1, account_amount(payer, -amount)) + len_field(1, account_amount(pay_to, amount)))
    token_list = (
        len_field(1, entity(asset))
        + len_field(2, account_amount(payer, -amount))
        + len_field(2, account_amount(pay_to, amount))
        + (b"" if decimals is None else len_field(4, v_field(1, decimals)))
    )
    return len_field(2, token_list)


def _memo_carries(memo: bytes, h: AtrHash) -> AtrHash | Refusal:
    """H where memo is byte for byte H's LCP string in lower-case hex: an empty memo is hedera/no-memo, any other
    hedera/memo-not-lcp."""
    if memo == b"":
        return Refusal("hedera/no-memo")
    return h if memo == to_lcp_string(h).encode("utf-8") else Refusal("hedera/memo-not-lcp")


def _is_landed(e: Mapping[str, Any]) -> bool:
    """A Mirror Node entry of the form fetchPresented writes: result SUCCESS, nonce 0, not scheduled, a memo_base64 that
    is null or a string, and the transaction id, valid start, valid duration, maximum fee and node in their forms."""
    nonce = e.get("nonce")
    return (
        e.get("result") == _SUCCESS
        and isinstance(nonce, (int, float))
        and not isinstance(nonce, bool)
        and nonce == 0
        and e.get("scheduled") is False
        and "memo_base64" in e
        and (e["memo_base64"] is None or isinstance(e["memo_base64"], str))
        and isinstance(e.get("transaction_id"), str)
        and _MIRROR_ID.fullmatch(e["transaction_id"]) is not None
        and isinstance(e.get("valid_start_timestamp"), str)
        and _TIMESTAMP.fullmatch(e["valid_start_timestamp"]) is not None
        and isinstance(e.get("valid_duration_seconds"), str)
        and _DURATION.fullmatch(e["valid_duration_seconds"]) is not None
        and isinstance(e.get("max_fee"), str)
        and _MAX_FEE.fullmatch(e["max_fee"]) is not None
        and is_entity(e.get("node"))
    )


def _landed_memo(credential: Mapping[str, Any]) -> bytes | Refusal:
    """The memo of the landed entry read for a hash credential, held as the protocol package holds it under the
    payment's own FETCHED member (fetched_of), {entry}, else hedera/read-first; a memo_base64 that is not standard
    base64 is hedera/unreadable, and a null one an empty memo."""
    held = fetched_of(credential)
    entry = held.get("entry") if is_object(held) else None
    if not is_object(entry) or not _is_landed(entry):
        return Refusal("hedera/read-first")
    memo = entry["memo_base64"]
    if memo is None:
        return b""
    data = b64_decode(memo)
    return Refusal("hedera/unreadable") if data is None else data


@dataclass(frozen=True, slots=True)
class LcpHederaUnsigned:
    """The body the buyer signs, and how its signature completes the credential."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]

    def complete(self, s: object) -> dict[str, Any] | Refusal:
        """The credential {type: "transaction", transaction}, transaction the base64 of the wire Transaction the one
        signature completes, measured against the credential bound (mpp/credential-malformed); a signature pair of the
        wrong key or signature length is hedera/tx-malformed. s is {publicKey, signature, type} with the key and the
        signature as bytes."""
        body = self.request["bodyBytes"]
        assert isinstance(body, bytes)
        transaction = complete_with(body, s)
        return transaction if isinstance(transaction, Refusal) else lcp_credential(self._challenge, transaction)


@dataclass(frozen=True, slots=True)
class MppChargeLcpHedera:
    id: str = HEDERA
    coverage: Coverage = "full"
    agreement: AgreementData | None = AgreementData(floor="1")

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash, act: Act | None = None) -> LcpHederaUnsigned | Refusal:
        """The body the buyer signs (lcp profile mpp-method-lcp.md, rule 12), from the chosen challenge held as bound
        holds an echoed one, whose id must derive from h (mpp/id-not-ours): the transaction id naming feePayerAccountId
        where feePayer is true, else the buyer; the node; the maximum fee; a valid duration of 120 seconds; H's LCP
        string as the memo; and the buyer's debit and the recipient's credit of amount in currency. A choice that is not
        an object, or whose payer, node, valid start, maximum fee or decimals is not of its form, is
        mpp/input-malformed; a payer that is feePayerAccountId is hedera/payer-not-buyer, and one that is the recipient
        hedera/transfer-mismatch. It reads no clock; complete writes the credential."""
        if not is_object(choice):
            return Refusal("mpp/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, HEDERA)
        if isinstance(checked, Refusal):
            return checked
        if not _valid_inputs(choice):
            return Refusal("mpp/input-malformed")
        r, d = checked.request, checked.details
        payer = choice["payer"]
        fee_payer = d["feePayerAccountId"] if d.get("feePayer") is True else payer
        if d.get("feePayer") is True and payer == fee_payer:
            return Refusal("hedera/payer-not-buyer")
        if payer == r["recipient"]:
            return Refusal("hedera/transfer-mismatch")
        nh = normal_hash(h)
        amount = amount_of(r["amount"])
        assert nh is not None and amount is not None
        vs = choice["validStart"]
        decimals = _whole(choice["decimals"]) if "decimals" in choice else None
        body = write_body(
            tx_id_field(vs["seconds"], _whole(vs["nanos"]) or 0, fee_payer),
            choice["node"],
            choice["maxFee"],
            to_lcp_string(nh),
            _transfer(r["currency"], payer, r["recipient"], amount, decimals),
        )
        return LcpHederaUnsigned(request={"kind": "hedera-body", "bodyBytes": body}, _challenge=checked.challenge)

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H from the echoed challenge, once the memo of the body the payer signed, or of the landed entry read for a
        hash credential (else hedera/read-first), is byte for byte H's LCP string in lower-case hex (lcp profile
        mpp-method-lcp.md, rule 14). The echoed challenge is held to the method's filter and the payload's type to
        transaction or hash. No transfer, amount, payer or signature is read, and the act changes nothing: the
        single-use value is the transaction id, never H."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        e = echoed_for(presented, HEDERA)
        if isinstance(e, Refusal):
            return e
        kind = lcp_payload_type(e.payload)
        if isinstance(kind, Refusal):
            return kind
        if kind == "hash":
            memo = _landed_memo(shaped)
            return memo if isinstance(memo, Refusal) else _memo_carries(memo, e.h)
        wire = b64_decode(e.payload.get("transaction"))
        if wire is None:
            return Refusal("hedera/tx-malformed")
        bodies = decode_hedera_tx(wire)
        if isinstance(bodies, Refusal):
            return bodies
        return _memo_carries(bodies[0].memo.encode("utf-8"), e.h)

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """By the credential's type: transaction, "payee", the party that submits sends the buyer's bytes unchanged;
        hash, "payer", the payer broadcast the body. A credential of any other type gets mpp/credential-type, as bound
        refuses it."""
        return mpp_broadcaster(presented, by_type({"transaction": "payee", "hash": "payer"}))
