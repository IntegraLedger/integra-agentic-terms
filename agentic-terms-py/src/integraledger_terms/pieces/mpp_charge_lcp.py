"""The buyer pieces of the lcp MPP method's charge, one per rail. The protocol package's build, mirrored in
bindings/mpp_charge_lcp.py, holds the chosen challenge to the method's filter, refuses one whose id is not the hash's,
and writes what the buyer signs; its complete writes the credential {type: "transaction", transaction}. The piece never
broadcasts and never writes a hash credential.

mpp/charge/lcp/hedera: the TransactionBody whose memo is the hash's LCP string, debiting the buyer's account alone,
handed to the signer as hedera-body. The node, the valid start and the maximum fee are the buyer's, and a token's
decimals where it gives them; the signer answers {publicKey, signature, type}, the key and signature as 0x hex."""

from collections.abc import Mapping
from typing import Any

from .._types import Inputs, Refusal, Signature
from ..bindings._hedera_proto import ENTITY
from ..bindings.mpp_charge_lcp import HEDERA
from ._common import InputKind, bigint_of, bytes_of, inputs_of
from ._mpp import MppRail, MppRailPiece, complete_with

_KEY_TYPES = ("ed25519", "ecdsa-secp256k1")


def _hedera_inputs(request: Mapping[str, Any], given: Inputs) -> dict[str, Any] | Refusal:
    """The node, the valid start {seconds, nanos}, the maximum fee and, for a token, its decimals."""
    spec: dict[str, InputKind] = {"node": "string", "validStart": "object", "maxFee": "decimal", "decimals": "optional-uint"}
    read = inputs_of(given, HEDERA, spec)
    if isinstance(read, Refusal):
        return read
    valid_start = inputs_of(read["validStart"], HEDERA, {"seconds": "decimal", "nanos": "uint"})
    if isinstance(valid_start, Refusal):
        return valid_start
    return {**read, "validStart": valid_start}


def _hedera_revive(c: dict[str, Any]) -> dict[str, Any] | Refusal:
    """The choice as the build takes it: the valid start's seconds and the maximum fee as ints."""
    vs = c.get("validStart")
    seconds = bigint_of(vs.get("seconds")) if isinstance(vs, Mapping) else None
    max_fee = bigint_of(c.get("maxFee"))
    if not isinstance(vs, Mapping) or seconds is None or max_fee is None:
        return Refusal("mpp/choice-malformed")
    return {**c, "validStart": {**vs, "seconds": seconds}, "maxFee": max_fee}


def _hedera_answer(signature: Signature) -> Any:
    """{publicKey, signature, type} with the key and signature as bytes, as the build's complete takes them."""
    if not isinstance(signature, Mapping):
        return Refusal("mpp/credential-malformed")
    public_key = bytes_of(signature.get("publicKey"))
    data = bytes_of(signature.get("signature"))
    kind = signature.get("type")
    if public_key is None or data is None or not isinstance(kind, str) or kind not in _KEY_TYPES:
        return Refusal("mpp/credential-malformed")
    return {"publicKey": public_key, "signature": data, "type": kind}


HEDERA_PIECE = MppRailPiece(
    MppRail(
        pairing=HEDERA,
        namespace="hedera",
        address=ENTITY,
        payer="payer",
        now=False,
        inputs=_hedera_inputs,
        revive=_hedera_revive,
        complete=complete_with(_hedera_answer),
    )
)
