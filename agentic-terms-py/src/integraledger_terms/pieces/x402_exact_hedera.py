"""The buyer piece for x402/exact/hedera: the transaction body whose memo is the hash's LCP string, signed by the payer
as hedera-body, and the payment whose payload.transaction is the signed transaction in base64. The node, the valid
start and the maximum fee are the buyer's; the signer answers {publicKey, signature, type} with 0x hex bytes."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal, Signature
from ..bindings.x402_exact_hedera import EXACT
from ._common import bigint_of, bytes_of, inputs_of
from ._x402_rail import Rail, RailPiece

# A Hedera entity id, shard.realm.num.
HEDERA_ENTITY = re.compile(r"[0-9]{1,20}\.[0-9]{1,20}\.[0-9]{1,20}")
_KEY_TYPES = ("ed25519", "ecdsa-secp256k1")


def _inputs(accepted: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    read = inputs_of(given, EXACT, {"node": "string", "validStart": "object", "maxFee": "decimal", "decimals": "optional-uint"})
    if isinstance(read, Refusal):
        return read
    valid_start = inputs_of(read["validStart"], EXACT, {"seconds": "decimal", "nanos": "uint"})
    if isinstance(valid_start, Refusal):
        return valid_start
    return {**read, "validStart": valid_start}


def _revive(c: dict[str, Any]) -> dict[str, Any] | Refusal:
    vs = c.get("validStart")
    seconds = bigint_of(vs.get("seconds")) if isinstance(vs, Mapping) else None
    max_fee = bigint_of(c.get("maxFee"))
    if not isinstance(vs, Mapping) or seconds is None or max_fee is None:
        return Refusal("x402/choice-malformed")
    return {**c, "validStart": {**vs, "seconds": seconds}, "maxFee": max_fee}


def _answer(signature: Signature) -> Any:
    """{publicKey, signature, type} with the key and signature as bytes."""
    if not isinstance(signature, Mapping):
        return Refusal("x402/signature-malformed")
    public_key = bytes_of(signature.get("publicKey"))
    data = bytes_of(signature.get("signature"))
    kind = signature.get("type")
    if public_key is None or data is None or not isinstance(kind, str) or kind not in _KEY_TYPES:
        return Refusal("x402/signature-malformed")
    return {"publicKey": public_key, "signature": data, "type": kind}


PIECE = RailPiece(
    Rail(
        pairing=EXACT,
        namespace="hedera",
        address=HEDERA_ENTITY,
        payer="payer",
        now=False,
        inputs=_inputs,
        revive=_revive,
        answer=_answer,
        payload=lambda transaction: {"transaction": transaction},
    )
)
