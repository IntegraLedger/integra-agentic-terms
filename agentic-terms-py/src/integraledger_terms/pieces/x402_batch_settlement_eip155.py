"""The gate's buyer piece for x402/batch-settlement/eip155: the first option on the signer's chain; the opening's
token authorization and first voucher, signed in order, with the channel's configuration and the deposit's salt beside
them for the approval summary; the deposit from extra.minDeposit or the buyer's input; and the authorization salt,
drawn once and kept in chosen."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Binding, Chosen, Inputs, Json, Refusal, Signature
from ..bindings._channel import BatchUnsigned
from ..bindings.x402_batch_settlement_eip155 import ID
from ._base import BasePiece
from ._batch import batch_complete, deposit_of, optional_inputs, random_salt32, revive_decimals
from ._common import first_option

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH32 = re.compile(r"0x[0-9a-fA-F]{64}")
_ZERO_ADDRESS = re.compile(r"0x0{40}")


@dataclass(frozen=True, slots=True)
class _Opening:
    """The build's opening, with the salt of its ERC-3009 deposit's nonce."""

    unsigned: BatchUnsigned
    auth_salt: Any


def _deposit_salt(choice: Any, h: AtrHash) -> Any:
    """The salt of the opening's ERC-3009 deposit nonce, keccak256(abi.encode(channelId, salt)): H in the scheme's
    refund-authorizer mode, an option whose extra.voucherManager is "facilitator" and whose extra.refundAuthorizer is an
    address other than the zero address (the protocol package's x402-batch-settlement-eip155 profile, rule 7), and
    otherwise the choice's authSalt."""
    c = choice if isinstance(choice, Mapping) else {}
    accepted = c.get("accepted")
    extra = accepted.get("extra") if isinstance(accepted, Mapping) else None
    extra = extra if isinstance(extra, Mapping) else {}
    ra = extra.get("refundAuthorizer")
    mode = (
        extra.get("voucherManager") == "facilitator"
        and isinstance(ra, str)
        and _EVM_ADDRESS.fullmatch(ra) is not None
        and _ZERO_ADDRESS.fullmatch(ra) is None
    )
    return h if mode else c.get("authSalt")


class X402BatchSettlementEip155Piece(BasePiece):
    pairing = ID

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        option = first_option(read, account, "eip155", self.pairing, _EVM_ADDRESS)
        if isinstance(option, Refusal):
            return Refusal("x402/no-payable-option")
        given = optional_inputs(inputs, "x402", {"payerAuthorizer": _EVM_ADDRESS, "authSalt": _HASH32})
        if isinstance(given, Refusal):
            return given
        if "payerAuthorizer" not in given:
            return Refusal("x402/input-missing")
        deposit = deposit_of(option.accepted, inputs)
        if isinstance(deposit, Refusal):
            return deposit
        choice = {
            "required": option.required,
            "accepted": option.accepted,
            "from": option.address,
            "now": now,
            "payerAuthorizer": given["payerAuthorizer"],
            "deposit": deposit,
            "authSalt": given["authSalt"] if "authSalt" in given else random_salt32(),
        }
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return revive_decimals(chosen, ["deposit"])

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        unsigned = binding.build(choice, h)
        return unsigned if isinstance(unsigned, Refusal) else _Opening(unsigned, _deposit_salt(choice, h))

    def request(self, unsigned: Any) -> dict[str, Any]:
        """The build's two requests as one batch request, with the channel's config and the deposit's authSalt."""
        assert isinstance(unsigned, _Opening)
        out: dict[str, Any] = {"kind": "batch", "requests": list(unsigned.unsigned.requests)}
        if unsigned.unsigned.config is not None:
            out["config"] = dict(unsigned.unsigned.config)
        if isinstance(unsigned.auth_salt, str):
            out["authSalt"] = unsigned.auth_salt
        return out

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        assert isinstance(unsigned, _Opening)
        return batch_complete(unsigned.unsigned, signature, chosen)


PIECE = X402BatchSettlementEip155Piece()
