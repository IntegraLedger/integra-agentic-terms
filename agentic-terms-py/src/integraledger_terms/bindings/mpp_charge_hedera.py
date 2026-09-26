"""The buyer half of mpp/charge/hedera: read, build with complete, and bound. The payer signs a Hedera CryptoTransfer
whose memo is MPP's attribution memo for the chosen challenge; H rides in the challenge, whose id derives from it, and
the memo's nonce is keccak256 of that id. Nothing here fetches, hashes the ATR or signs."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._hedera_proto import (
    INT64_LIMIT,
    UINT64_LIMIT,
    account_amount,
    decode_hedera_tx,
    entity,
    from_base64,
    len_field,
    tx_id_field,
    write_body,
)
from ._lcp import is_object
from ._mpp import attribution_memo, challenge_bound, check_attribution, credential_of, read
from ._mpp_checks import decode_object, hedera_charge_legs
from .x402_exact_hedera import HederaUnsigned, is_entity

ID = "mpp/charge/hedera"

_ATTRIBUTION = re.compile(r"0x[0-9a-fA-F]{64}")


def _whole(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def build_charge(challenge: object, request: object, c: object) -> HederaUnsigned | Refusal:
    """The body the payer signs for an MPP Hedera charge: the payer's own transaction id, MPP's attribution memo for
    this challenge as the memo, and the token transfers of currency: the payer's debit, the recipient's remainder and
    each split. With credentialType hash the request carries broadcast: true, for a signer that signs and broadcasts
    the body; with transaction, the default, the signature completes the transaction."""
    if not is_object(challenge) or not isinstance(challenge.get("id"), str) or not isinstance(challenge.get("realm"), str):
        return Refusal("mpp/challenge-malformed")
    if not is_object(request):
        return Refusal("hedera/option-malformed")
    legs = hedera_charge_legs(request)
    if isinstance(legs, Refusal):
        return legs
    currency, amount, every = legs
    vs = c.get("validStart") if is_object(c) else None
    if not is_object(c) or not is_entity(c.get("payer")) or not is_entity(c.get("node")) or not is_object(vs):
        return Refusal("hedera/option-malformed")
    seconds, nanos, max_fee, client_id = vs.get("seconds"), _whole(vs.get("nanos")), c.get("maxFee"), c.get("clientId")
    if (
        not isinstance(seconds, int)
        or isinstance(seconds, bool)
        or not 0 <= seconds < INT64_LIMIT
        or nanos is None
        or not 0 <= nanos <= 999_999_999
        or not isinstance(max_fee, int)
        or isinstance(max_fee, bool)
        or not 0 <= max_fee < UINT64_LIMIT
        or ("clientId" in c and not isinstance(client_id, str))
        or ("credentialType" in c and c["credentialType"] not in ("transaction", "hash"))
        or any(account == c["payer"] for account, _ in every)
    ):
        return Refusal("hedera/option-malformed")
    memo = attribution_memo(challenge["realm"], challenge["id"], client_id if isinstance(client_id, str) else None)
    payer: str = c["payer"]
    token_list = len_field(1, entity(currency)) + len_field(2, account_amount(payer, -amount))
    token_list += b"".join(len_field(2, account_amount(account, a)) for account, a in every)
    tx_id = tx_id_field(seconds, nanos, payer)
    body = write_body(tx_id, c["node"], max_fee, memo, len_field(2, token_list))
    if c.get("credentialType") == "hash":
        return HederaUnsigned(request={"kind": "hedera-body", "bodyBytes": body, "broadcast": True})
    return HederaUnsigned(request={"kind": "hedera-body", "bodyBytes": body})


def _request_of(challenge: Mapping[str, Any]) -> dict[str, Any] | None:
    return decode_object(challenge.get("request"))


@dataclass(frozen=True, slots=True)
class MppChargeHedera:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash) -> HederaUnsigned | Refusal:
        """The chosen challenge's id and realm, its decoded request, and the payer's values, built as build_charge
        builds them. The body carries no hash of its own: the challenge's id derives from it."""
        challenge = choice.get("challenge") if is_object(choice) else None
        request = _request_of(challenge) if is_object(challenge) else None
        if not is_object(choice) or not is_object(challenge) or request is None or not isinstance(challenge.get("id"), str):
            return Refusal("mpp/choice-malformed")
        keys = ("payer", "node", "validStart", "maxFee", "clientId", "credentialType")
        c = {k: choice[k] for k in keys if k in choice}
        return build_charge({"id": challenge["id"], "realm": challenge.get("realm")}, request, c)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash from the echoed challenge, once the payer's memo is this challenge's attribution memo: from the
        signed body (type transaction), or from the landed entry's memo written beside the credential (type hash).
        No transfer, amount, payer or signature is read."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        b = challenge_bound(credential)
        if isinstance(b, Refusal):
            return b
        challenge, payload = credential["challenge"], credential["payload"]
        if challenge.get("method") != "hedera" or challenge.get("intent") != "charge":
            return Refusal("mpp/not-this-pairing")
        kind = payload.get("type")
        if kind not in ("transaction", "hash"):
            return Refusal("mpp/credential-type")
        if kind == "transaction":
            wire = from_base64(payload.get("transaction"))
            if wire is None:
                return Refusal("hedera/tx-malformed")
            decoded = decode_hedera_tx(wire)
            if isinstance(decoded, Refusal):
                return decoded
            memo = decoded[0].memo
        else:
            landed = credential.get("landed")
            landed_memo = landed.get("memo") if is_object(landed) else None
            if not isinstance(landed_memo, str):
                return Refusal("hedera/read-first")
            memo = landed_memo
        if _ATTRIBUTION.fullmatch(memo) is None:
            return Refusal("mpp/attribution-malformed")
        ok = check_attribution(memo, challenge["realm"], challenge["id"])
        return b.h if ok is True else ok if isinstance(ok, Refusal) else Refusal("mpp/attribution-mismatch")
