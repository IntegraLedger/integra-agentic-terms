"""The buyer piece for x402/exact/near: the request is the NEP-461 hash of the delegate action whose one ft_transfer
carries the ATR hash in its memo. The buyer supplies its key and the key's nonce and the final block height from its
RPC; the key answers {keyType, bytes}, with the 64- or 65-byte signature as 0x hex."""

import re
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_exact_near import ID
from ._base import BasePiece
from ._common import bigint_of, bytes_of, choice_of, inputs_of
from ._x402_account_rails import identified, rail_option

_NEAR_ACCOUNT = re.compile(r"[a-z0-9._-]{2,64}")


class X402ExactNearPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        o = rail_option(read, account, ("near",), ID, lambda a: _NEAR_ACCOUNT.fullmatch(a) is not None)
        if isinstance(o, Refusal):
            return o
        given = inputs_of(inputs, ID, {"publicKey": "string", "accessKeyNonce": "decimal", "finalHeight": "decimal"})
        if isinstance(given, Refusal):
            return given
        return Chosen(ID, {"required": o.required, "accepted": o.accepted, "payer": o.address, **given}, ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = choice_of(chosen)
        nonce = bigint_of(c.get("accessKeyNonce")) if c is not None else None
        height = bigint_of(c.get("finalHeight")) if c is not None else None
        if c is None or nonce is None or height is None:
            return Refusal("x402/choice-malformed")
        return {**c, "accessKeyNonce": nonce, "finalHeight": height}

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, dict):
            return Refusal("x402/signature-malformed")
        key_type = signature.get("keyType")
        data = bytes_of(signature.get("bytes"))
        if key_type not in (0, 1) or isinstance(key_type, bool) or data is None:
            return Refusal("x402/signature-malformed")
        return identified(unsigned.complete({"keyType": key_type, "bytes": data}), chosen)


PIECE = X402ExactNearPiece()
