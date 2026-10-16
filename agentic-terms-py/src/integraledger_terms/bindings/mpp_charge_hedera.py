"""The buyer half of mpp/charge/hedera: read, build with complete, and bound. The payer signs a Hedera CryptoTransfer
whose memo is MPP's attribution memo for the chosen challenge; H rides in the challenge, whose id derives from it, and
the memo's nonce is keccak256 of that id. Nothing here fetches, hashes the ATR or signs."""

import re
from dataclasses import dataclass

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._codec import b64_decode
from ._hedera_proto import (
    INT64_LIMIT,
    UINT64_LIMIT,
    account_amount,
    decode_hedera_tx,
    entity,
    is_entity,
    len_field,
    tx_id_field,
    write_body,
)
from ._lcp import is_object, is_well_formed
from ._mpp import (
    attribution_memo,
    by_type,
    challenge_bound,
    check_attribution,
    checked_for,
    chosen_for,
    credential_of,
    fetched_of,
    mpp_broadcaster,
    read,
)
from ._mpp_checks import hedera_charge_request_legs
from .x402_exact_hedera import HederaUnsigned

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


def build_charge(choice: object, h: object) -> HederaUnsigned | Refusal:
    """The body the payer signs for an MPP Hedera charge: the payer's own transaction id, MPP's attribution memo for
    this challenge as the memo, and the token transfers of currency: the payer's debit, the recipient's remainder and
    each split. The chosen challenge is held as bound holds an echoed one (chosen_for), with bound's code for each
    fault, in bound's order, and its id must derive from h, else mpp/id-not-ours; the request, id and realm are read
    from the snapshot it holds. A choice that is not an object, and every other input the choice carries, is
    hedera/option-malformed. With credentialType hash, the default when none is named, the request carries
    broadcast: true, for a signer that signs and broadcasts the body; with transaction (pull) the signature completes
    the transaction."""
    if not is_object(choice):
        return Refusal("hedera/option-malformed")
    checked = chosen_for(choice.get("challenge"), h, ID)
    if isinstance(checked, Refusal):
        return checked
    challenge, c = checked.challenge, choice
    legs = hedera_charge_request_legs(checked.request)
    if isinstance(legs, Refusal):
        return legs
    currency, amount, every = legs
    vs = c.get("validStart")
    if not is_entity(c.get("payer")) or not is_entity(c.get("node")) or not is_object(vs):
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
        or ("clientId" in c and not is_well_formed(client_id))
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
    if c.get("credentialType") != "transaction":
        return HederaUnsigned(request={"kind": "hedera-body", "bodyBytes": body, "broadcast": True})
    return HederaUnsigned(request={"kind": "hedera-body", "bodyBytes": body})


@dataclass(frozen=True, slots=True)
class MppChargeHedera:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash) -> HederaUnsigned | Refusal:
        """The chosen challenge, held as bound holds an echoed one, and the payer's values, built as build_charge
        builds them. The body carries no hash of its own: the challenge's id derives from it."""
        return build_charge(choice, h)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash from the echoed challenge, held to the pairing's filter (checked_for), once the payer's memo is this
        challenge's attribution memo: from the signed body (type transaction), or from the landed entry's memo read for
        the credential and held in Held, as @integraledger/lcp holds it under the payment's own FETCHED member (type
        hash, fetched_of; else hedera/read-first, and a landed member of the credential's own is not read). No transfer,
        amount, payer or signature is read."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        b = challenge_bound(credential)
        if isinstance(b, Refusal):
            return b
        challenge, payload = credential["challenge"], credential["payload"]
        if challenge.get("method") != "hedera" or challenge.get("intent") != "charge":
            return Refusal("mpp/not-this-pairing")
        held = checked_for(challenge, self.id)
        if isinstance(held, Refusal):
            return held
        kind = payload.get("type")
        if kind not in ("transaction", "hash"):
            return Refusal("mpp/credential-type")
        if kind == "transaction":
            wire = b64_decode(payload.get("transaction"))
            if wire is None:
                return Refusal("hedera/tx-malformed")
            decoded = decode_hedera_tx(wire)
            if isinstance(decoded, Refusal):
                return decoded
            memo = decoded[0].memo
        else:
            landed = fetched_of(credential)
            landed_memo = landed.get("memo") if is_object(landed) else None
            if not isinstance(landed_memo, str):
                return Refusal("hedera/read-first")
            memo = landed_memo
        if _ATTRIBUTION.fullmatch(memo) is None:
            return Refusal("mpp/attribution-malformed")
        ok = check_attribution(memo, challenge["realm"], challenge["id"])
        return b.h if ok is True else ok if isinstance(ok, Refusal) else Refusal("mpp/attribution-mismatch")

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """By the credential's type, as the charge's build writes the request: hash, the default, whose request carries
        broadcast true, "payer", a body the payer's signer broadcast, presented by its transaction id; transaction,
        whose request carries no broadcast, "payee", a signed transaction the seller's server broadcasts. A credential
        of any other type gets mpp/credential-type, as bound refuses it."""
        return mpp_broadcaster(presented, by_type({"transaction": "payee", "hash": "payer"}))
