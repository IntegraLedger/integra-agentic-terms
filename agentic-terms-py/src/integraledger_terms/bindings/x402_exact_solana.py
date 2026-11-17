"""The buyer half of the pairing x402/exact/solana: read, build with complete, and bound.

The ATR hash rides as the option's extra.memo in LCP string form, which the payer writes as the transaction's one Memo
instruction. Nothing here fetches, hashes an ATR or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._lcp import is_object, normal_hash, to_lcp_string
from ._svm import (
    COMPUTE_BUDGET,
    MEMO_V4,
    X402_V1,
    SvmBuildInput,
    SvmSigning,
    SvmTx,
    SvmUnsigned,
    build_svm_message,
    built_version,
    decode_svm_tx,
    integer_of,
    is_key,
    is_payer_input,
    is_solana_network,
    key_bytes,
    memo_length,
    static_nonce,
    svm_carrier,
    svm_option_filter,
    to_base64,
    version_not_admitted,
    wire_of,
)
from ._x402 import (
    accepted_by,
    chosen,
    filter_of,
    is_amount,
    is_v2,
    payment_with,
    read_for,
    timeout_seconds,
    x402_broadcaster,
)

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
    """The amount is "0" or a positive amount (is_amount), a u64 in decimal, and the timeout a positive safe integer. A
    zero TransferChecked lands, and @x402/svm 2.31.0's exact facilitator compares the transfer's amount with the
    option's by equality, so an option at "0", the pairing's agreement floor, is payable."""
    amount = option.get("amount")
    return (
        (amount == "0" or is_amount(amount))
        and isinstance(amount, str)
        and _DECIMAL.fullmatch(amount) is not None
        and int(amount) < U64_LIMIT
        and timeout_seconds(option.get("maxTimeoutSeconds")) is not None
    )


# The pairing's one option filter, which read, build and bound apply: an option of this pairing whose amount build can
# pay and whose timeout is a positive safe integer (payable), else x402/option-malformed; then one that no Solana build
# honours (unbuilt_option: an extra.transactionVersions that admits neither version, or an extra.splits) is refused.
_THIS = svm_option_filter(filter_of(pairs, payable))
_read = read_for(_THIS)
_MEMO_V4_KEY = key_bytes(MEMO_V4)
_COMPUTE_BUDGET_KEY = key_bytes(COMPUTE_BUDGET)


def not_admitted(tx: SvmTx) -> Refusal | None:
    """svm/instruction-not-admitted where the transaction holds an instruction @x402/svm 2.31.0's exact facilitator
    does not admit under any configuration, else None: a Memo v4 instruction, since every verify path of that
    facilitator requires exactly one Memo instruction of the program MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr, equal
    to extra.memo, and the carrier admits one memo of either program, so a Memo v4 instruction beside it is no payment
    that facilitator and this package both take; and, in a version-1 message, a Compute Budget instruction, which it
    refuses before any other check."""
    v1 = tx.message[:1] == b"\x81"
    for ix in tx.instructions:
        program = tx.keys[ix.program] if ix.program < len(tx.keys) else None
        if program is None:
            continue
        if program == _MEMO_V4_KEY or (v1 and program == _COMPUTE_BUDGET_KEY):
            return Refusal("svm/instruction-not-admitted")
    return None


def bound_of(accepted: Mapping[str, Any], tx: SvmTx) -> AtrHash | Refusal:
    """The hash in the one memo, which must equal the option's extra.memo, in a message whose durable nonce account, if
    it uses one, is a static key (the RecentBlockhashes sysvar may come from a lookup table), whose version the option's
    extra.transactionVersions admits (version_not_admitted), and which holds no instruction the stock facilitator never
    admits (not_admitted)."""
    from_table = static_nonce(tx)
    if from_table is not None:
        return from_table
    version = version_not_admitted(accepted.get("extra"), tx, "x402")
    if version is not None:
        return version
    unadmitted = not_admitted(tx)
    if unadmitted is not None:
        return unadmitted
    carrier = svm_carrier(tx)
    if isinstance(carrier, Refusal):
        return carrier
    extra = accepted.get("extra")
    if not is_object(extra) or carrier.memo != extra.get("memo"):
        return Refusal("svm/carrier-mismatch")
    return carrier.h


# The agreement this pairing's payment can itself be, as @integraledger/lcp's registry states it.
AGREEMENT = AgreementData(floor="0")


@dataclass(frozen=True, slots=True)
class X402ExactSolana:
    id: str = ID
    coverage: Coverage = "full"
    agreement: AgreementData | None = AGREEMENT

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return _read(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> SvmUnsigned | Refusal:
        """The message the payer signs for the chosen option, whose one memo is the option's extra.memo: version 1
        where the option's extra.transactionVersions holds 1, as @x402/svm 2.31.0's exact client writes it, else v0
        (built_version). H is checked first, then the form of the choice's payer, token program, decimals, blockhash and
        compute budget (is_payer_input), then its document and option, then the option's memo against H."""
        if normal_hash(h) is None:
            return Refusal("x402/payload-malformed")
        if not is_object(choice):
            return Refusal("x402/not-v2")
        decimals = integer_of(choice.get("decimals"))
        byte = isinstance(decimals, int) and not isinstance(decimals, bool) and 0 <= decimals <= 255
        if not is_payer_input(choice) or not byte:
            return Refusal("svm/input-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        extra = accepted["extra"]
        version = built_version(extra)
        if version is None:
            return Refusal("x402/option-malformed")
        memo = extra.get("memo")
        if memo != to_lcp_string(h):
            return Refusal("svm/carrier-mismatch")
        token_program: Any = choice.get("tokenProgram")
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
                decimals=decimals,
                pay_to=accepted["payTo"],
                amount=int(accepted["amount"]),
                recent_blockhash=blockhash,
                memo=memo,
                compute_unit_limit=40_000 if limit is None else integer_of(limit),
                compute_unit_price=1 if price is None else price,
                v1=X402_V1 if version == 1 else None,
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

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """The hash in the one memo of the transaction the payer signed, which must equal the option's extra.memo.
        Neither signature is verified here."""
        if not is_v2(presented):
            return Refusal("x402/not-v2")
        accepted = accepted_by(presented.get("accepted"), _THIS)
        if isinstance(accepted, Refusal):
            return accepted
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

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's facilitator, the option's feePayer, co-signs and sends the transaction the
        payer signed. The payment is held to x402_shape's gate, the one bound applies first; any other gets its
        refusal."""
        return x402_broadcaster(presented, "payee")
