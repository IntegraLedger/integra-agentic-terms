"""The buyer piece for x402/exact/tvm: the request is the representation hash of the W5 request whose one Jetton
transfer carries the ATR hash's text comment as its forward payload. The payer's wallet is the account's raw address.
The buyer supplies walletId, seqno, jettonWallet and attachNanotons from its RPC, and, for a wallet not yet deployed,
its stateInit as a base64 bag of cells; the wallet key answers its 64-byte Ed25519 signature as 0x hex."""

import re
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_exact_tvm import ID
from ._base import BasePiece
from ._common import bigint_of, bytes_of, choice_of, inputs_of
from ._x402_account_rails import identified, rail_option

_RAW_ADDRESS = re.compile(r"-?[0-9]{1,10}:[0-9a-fA-F]{64}")


class X402ExactTvmPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        o = rail_option(read, account, ("tvm",), ID, lambda a: _RAW_ADDRESS.fullmatch(a) is not None)
        if isinstance(o, Refusal):
            return o
        given = inputs_of(
            inputs,
            ID,
            {
                "walletId": "uint",
                "seqno": "uint",
                "jettonWallet": "string",
                "attachNanotons": "decimal",
                "stateInit": "optional-string",
            },
        )
        if isinstance(given, Refusal):
            return given
        return Chosen(ID, {"required": o.required, "accepted": o.accepted, "wallet": o.address, "now": now, **given}, ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = choice_of(chosen)
        attach = bigint_of(c.get("attachNanotons")) if c is not None else None
        if c is None or attach is None:
            return Refusal("x402/choice-malformed")
        return {**c, "attachNanotons": attach}

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        data = bytes_of(signature, 64)
        if data is None:
            return Refusal("x402/signature-malformed")
        return identified(unsigned.complete(data), chosen)


PIECE = X402ExactTvmPiece()
