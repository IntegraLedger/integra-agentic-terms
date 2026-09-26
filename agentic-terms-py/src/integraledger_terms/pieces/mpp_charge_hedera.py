"""The buyer piece for mpp/charge/hedera: the transaction body whose memo is MPP's attribution memo for the chosen
challenge, read on the account's own network where the challenge names no chainId, handed to the payer as hedera-body.
The node, the valid start, the maximum fee, the optional client id and the optional credentialType are the buyer's.
- credentialType transaction (the default, pull): the signer answers {publicKey, signature, type} with 0x hex bytes,
  and the credential is {challenge, payload: {type: "transaction", transaction}}, the signed body in base64.
- credentialType hash (push): the request carries broadcast: true; the signer signs and broadcasts the body and answers
  {transactionId}, which must name the body's payer and valid start. The credential is {challenge, payload: {type:
  "hash", transactionId}}, and landed beside it holds the network and the body's memo, which bound reads. The signer
  moves the payment, so a decline keeps it."""

import re
from collections.abc import Mapping
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Binding, Chosen, Inputs, Json, Refusal, Signature, Step
from ..bindings._mpp import attribution_memo
from ..bindings._mpp_checks import hedera_charge_network
from ..bindings.mpp_charge_hedera import ID, build_charge
from ._common import account_of, bigint_of, bytes_of, choice_of, inputs_of
from ._mpp import MppRail, MppRailPiece, request_of
from .x402_exact_hedera import HEDERA_ENTITY

_KEY_TYPES = ("ed25519", "ecdsa-secp256k1")
_CREDENTIAL_TYPES = ("transaction", "hash")
# A Hedera transaction id, shard.realm.num@seconds.nanos.
_TX_ID = re.compile(r"((?:0|[1-9][0-9]{0,18})\.(?:0|[1-9][0-9]{0,18})\.(?:0|[1-9][0-9]{0,18}))@(0|[1-9][0-9]{0,18})\.([0-9]{1,9})")


def _inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    read = inputs_of(
        given,
        ID,
        {
            "node": "string",
            "validStart": "object",
            "maxFee": "decimal",
            "clientId": "optional-string",
            "credentialType": "optional-string",
        },
    )
    if isinstance(read, Refusal):
        return read
    if "credentialType" in read and read["credentialType"] not in _CREDENTIAL_TYPES:
        return Refusal("mpp/input-malformed")
    valid_start = inputs_of(read["validStart"], ID, {"seconds": "decimal", "nanos": "uint"})
    if isinstance(valid_start, Refusal):
        return valid_start
    return {**read, "validStart": valid_start}


def _revive(c: dict[str, Any]) -> Any:
    vs = c.get("validStart")
    seconds = bigint_of(vs.get("seconds")) if isinstance(vs, Mapping) else None
    max_fee = bigint_of(c.get("maxFee"))
    if not isinstance(vs, Mapping) or seconds is None or max_fee is None:
        return Refusal("mpp/choice-malformed")
    return {**c, "validStart": {**vs, "seconds": seconds}, "maxFee": max_fee}


def _answer(signature: Signature) -> dict[str, Any] | Refusal:
    """{publicKey, signature, type} with the key and signature as bytes."""
    if not isinstance(signature, Mapping):
        return Refusal("mpp/credential-malformed")
    public_key = bytes_of(signature.get("publicKey"))
    data = bytes_of(signature.get("signature"))
    kind = signature.get("type")
    if public_key is None or data is None or not isinstance(kind, str) or kind not in _KEY_TYPES:
        return Refusal("mpp/credential-malformed")
    return {"publicKey": public_key, "signature": data, "type": kind}


def _is_push(c: Mapping[str, Any] | None) -> bool:
    return c is not None and c.get("credentialType") == "hash"


def _pushed_id(signature: Signature, c: Mapping[str, Any]) -> str | Refusal:
    """The push answer's transaction id, when it names the body's payer and valid start."""
    tx_id = signature.get("transactionId") if isinstance(signature, Mapping) else None
    m = _TX_ID.fullmatch(tx_id) if isinstance(tx_id, str) else None
    if m is None or not isinstance(tx_id, str):
        return Refusal("mpp/credential-malformed")
    vs = c.get("validStart")
    seconds = bigint_of(vs.get("seconds")) if isinstance(vs, Mapping) else None
    nanos = vs.get("nanos") if isinstance(vs, Mapping) else None
    if m.group(1) != c.get("payer") or seconds is None or int(m.group(2)) != seconds or int(m.group(3).ljust(9, "0")) != nanos:
        return Refusal("hedera/tx-mismatch")
    return tx_id


def _complete(unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
    c = choice_of(chosen)
    challenge = c.get("challenge") if c is not None else None
    if c is None or not isinstance(challenge, Mapping):
        return Refusal("mpp/choice-malformed")
    if _is_push(c):
        tx_id = _pushed_id(signature, c)
        if isinstance(tx_id, Refusal):
            return tx_id
        client_id = c.get("clientId") if isinstance(c.get("clientId"), str) else None
        memo = attribution_memo(str(challenge.get("realm")), str(challenge.get("id")), client_id)
        return {
            "challenge": challenge,
            "payload": {"type": "hash", "transactionId": tx_id},
            "landed": {"network": c.get("network"), "memo": memo},
        }
    a = _answer(signature)
    if isinstance(a, Refusal):
        return a
    transaction = unsigned.complete(a)
    if isinstance(transaction, Refusal):
        return transaction
    return {"challenge": challenge, "payload": {"type": "transaction", "transaction": transaction}}


class MppChargeHederaPiece(MppRailPiece):
    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        """The rail's choice, with the account's network, which the challenge's network equals, for a push
        credential's landed."""
        chosen = super().choose(read, account, inputs, now, ref, doc)
        a = account_of(account)
        if isinstance(chosen, Refusal) or a is None:
            return chosen
        return Chosen(pairing=chosen.pairing, choice={**chosen.choice, "network": a.network}, ref=chosen.ref)

    def moves(self, request: Json) -> bool:
        return isinstance(request, Mapping) and request.get("broadcast") is True

    def sent(self, signed: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in signed.items() if k != "landed"}

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        """The binding's build, called with the chosen challenge's id and realm, its decoded request, and the payer's
        values, credentialType among them. The body carries no hash of its own: the challenge's id derives from it, and
        bound reads it there."""
        if isinstance(choice, Refusal):
            return choice
        challenge = choice.get("challenge") if isinstance(choice, Mapping) else None
        request = request_of(challenge)
        if not isinstance(challenge, Mapping) or request is None or not isinstance(challenge.get("id"), str):
            return Refusal("mpp/choice-malformed")
        keys = ("payer", "node", "validStart", "maxFee", "clientId", "credentialType")
        c = {k: choice[k] for k in keys if k in choice}
        return build_charge({"id": challenge["id"], "realm": challenge.get("realm")}, request, c)


PIECE = MppChargeHederaPiece(
    MppRail(
        pairing=ID,
        namespace="hedera",
        address=HEDERA_ENTITY,
        payer="payer",
        now=False,
        inputs=_inputs,
        revive=_revive,
        complete=_complete,
        network=lambda c, account_network: hedera_charge_network(request_of(c) or {}, account_network),
    )
)
