"""The buyer half of the pairing x402/exact/solana: read, build with complete, and bound.

The ATR hash rides as the option's extra.memo in LCP string form, which the payer writes as the transaction's one Memo
instruction. Nothing here fetches, hashes an ATR or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._lcp import is_object, to_lcp_string
from ._svm import (
    TOKEN,
    TOKEN_2022,
    SvmBuildInput,
    SvmSigning,
    SvmTx,
    SvmUnsigned,
    build_svm_message,
    decode_svm_tx,
    integer_of,
    is_key,
    is_solana_network,
    memo_length,
    svm_carrier,
    to_base64,
    wire_of,
)
from ._x402 import chosen, filter_of, is_v2, payment_with, read_for

ID = "x402/exact/solana"
MAX_MEMO = 256
U64_LIMIT = 1 << 64
_DECIMAL = re.compile(r"[0-9]{1,20}")


def pairs(option: Mapping[str, Any]) -> bool:
    """The pairing's filter: scheme exact, a solana network, base58 keys for asset, payTo and extra.feePayer, and
    extra.memo, when present, a string of at most 256 UTF-8 bytes."""
    if not is_object(option) or option.get("scheme") != "exact":
        return False
    if not is_solana_network(option.get("network")):
        return False
    if not is_key(option.get("asset")) or not is_key(option.get("payTo")):
        return False
    extra = option.get("extra")
    if not is_object(extra) or not is_key(extra.get("feePayer")):
        return False
    if "memo" in extra and (not isinstance(extra["memo"], str) or memo_length(extra["memo"]) > MAX_MEMO):
        return False
    return True


def payable(option: Mapping[str, Any]) -> bool:
    """The amount is a u64 in decimal."""
    amount = option.get("amount")
    return isinstance(amount, str) and _DECIMAL.fullmatch(amount) is not None and int(amount) < U64_LIMIT


_THIS = filter_of(pairs)
_read = read_for(_THIS)


def bound_of(accepted: Mapping[str, Any], tx: SvmTx) -> AtrHash | Refusal:
    """The hash in the one memo, which must equal the option's extra.memo."""
    carrier = svm_carrier(tx)
    if isinstance(carrier, Refusal):
        return carrier
    extra = accepted.get("extra")
    if not is_object(extra) or carrier.memo != extra.get("memo"):
        return Refusal("svm/carrier-mismatch")
    return carrier.h


@dataclass(frozen=True, slots=True)
class X402ExactSolana:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return _read(doc)

    def build(self, choice: Json, h: AtrHash) -> SvmUnsigned | Refusal:
        """The v0 message the payer signs for the chosen option, whose one memo is the option's extra.memo."""
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        if not payable(accepted):
            return Refusal("x402/option-malformed")
        extra = accepted["extra"]
        memo = extra.get("memo")
        if memo != to_lcp_string(h):
            return Refusal("svm/carrier-mismatch")
        token_program = choice.get("tokenProgram")
        if token_program not in (TOKEN, TOKEN_2022):
            return Refusal("svm/input-malformed")
        payer: Any = choice.get("payer")
        blockhash: Any = choice.get("recentBlockhash")
        limit = choice.get("computeUnitLimit")
        price = choice.get("computeUnitPrice")
        message = build_svm_message(
            SvmBuildInput(
                fee_payer=extra["feePayer"],
                payer=payer,
                mint=accepted["asset"],
                token_program=token_program,
                decimals=integer_of(choice.get("decimals")),
                pay_to=accepted["payTo"],
                amount=int(accepted["amount"]),
                recent_blockhash=blockhash,
                memo=memo,
                compute_unit_limit=40_000 if limit is None else integer_of(limit),
                compute_unit_price=1 if price is None else price,
            )
        )
        if isinstance(message, Refusal):
            return message
        signing = SvmSigning(message, payer)

        def complete(signature: bytes) -> dict[str, Any] | Refusal:
            wire = signing.wire(signature)
            if isinstance(wire, Refusal):
                return wire
            return payment_with(required, accepted, {"transaction": to_base64(wire)})

        return SvmUnsigned(signing.request, complete)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the one memo of the transaction the payer signed, which must equal the option's extra.memo.
        Neither signature is verified here."""
        if not is_v2(presented):
            return Refusal("x402/not-v2")
        accepted = presented.get("accepted")
        if not is_object(accepted) or not pairs(accepted):
            return Refusal("x402/option-not-this-pairing")
        payload = presented.get("payload")
        if not is_object(payload):
            return Refusal("x402/payload-malformed")
        wire = wire_of(payload.get("transaction"))
        if isinstance(wire, Refusal):
            return wire
        tx = decode_svm_tx(wire)
        if isinstance(tx, Refusal):
            return tx
        return bound_of(accepted, tx)
