"""The buyer piece for x402/exact/tron/lcp-trc20-memo: the request is the id of the TRC-20 transfer whose memo is the
ATR hash. The buyer supplies a recent block (refBlock, {number, id}) and the transaction's feeLimit from its FullNode;
the transaction's timestamp is the gate's clock in milliseconds. The payer's key answers its 65-byte secp256k1
signature r ‖ s ‖ v over the id as 0x hex."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.x402_exact_tron_lcp_trc20_memo import ID
from ._base import BasePiece
from ._common import bigint_of, bytes_of, choice_of, inputs_of
from ._x402_account_rails import identified, rail_option

_TRON_ADDRESS = re.compile(r"T[1-9A-HJ-NP-Za-km-z]{33}")


def _ref_block_of(v: object) -> dict[str, Any] | None:
    """A block reference {number, id}: the number as a decimal string and the 32-byte id as 0x hex."""
    if not isinstance(v, Mapping):
        return None
    number = bigint_of(v.get("number"))
    block_id = v.get("id")
    if number is None or bytes_of(block_id, 32) is None:
        return None
    return {"number": number, "id": block_id}


class X402ExactTronLcpTrc20MemoPiece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        o = rail_option(read, account, ("tron",), ID, lambda a: _TRON_ADDRESS.fullmatch(a) is not None)
        if isinstance(o, Refusal):
            return o
        given = inputs_of(inputs, ID, {"refBlock": "object", "feeLimit": "decimal"})
        if isinstance(given, Refusal):
            return given
        if _ref_block_of(given["refBlock"]) is None:
            return Refusal("x402/input-missing")
        choice = {"required": o.required, "accepted": o.accepted, "payer": o.address, "now": str(now * 1000), **given}
        return Chosen(ID, choice, ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        c = choice_of(chosen)
        ref_block = _ref_block_of(c.get("refBlock")) if c is not None else None
        now = bigint_of(c.get("now")) if c is not None else None
        fee_limit = bigint_of(c.get("feeLimit")) if c is not None else None
        if c is None or ref_block is None or now is None or fee_limit is None:
            return Refusal("x402/choice-malformed")
        return {**c, "refBlock": ref_block, "now": now, "feeLimit": fee_limit}

    def request(self, unsigned: Any) -> dict[str, Any]:
        request: dict[str, Any] = unsigned.request
        return request

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        data = bytes_of(signature, 65)
        if data is None:
            return Refusal("x402/signature-malformed")
        return identified(unsigned.complete(data), chosen)


PIECE = X402ExactTronLcpTrc20MemoPiece()
