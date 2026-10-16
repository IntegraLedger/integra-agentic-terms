"""The buyer half of the pairing x402/upto/solana: read, build with complete, and bound.

The ATR hash rides as the option's extra.memo in LCP string form, which the payer writes as the one Memo instruction of
the transaction that opens a one-request payment channel escrowing the signed maximum. Nothing here fetches, hashes an
ATR or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._lcp import is_object, normal_hash, safe_int, to_lcp_string
from ._svm import (
    TOKEN,
    TOKEN_2022,
    ChannelBuildInput,
    ChannelOpen,
    SvmSigning,
    SvmUnsigned,
    build_channel_message,
    channel_instruction,
    channel_pda,
    decode_svm_tx,
    integer_of,
    is_key,
    is_payer_input,
    is_solana_network,
    is_u64,
    memo_length,
    static_nonce,
    svm_carrier,
    to_base64,
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

ID = "x402/upto/solana"
MAX_MEMO = 256
MAX_SAFE_INTEGER = 2**53 - 1
U64_LIMIT = 1 << 64
_U64_DECIMAL = re.compile(r"[0-9]{1,20}")


def pairs(option: Mapping[str, Any]) -> bool:
    """The pairing's filter: scheme upto, a solana network, base58 keys for asset, payTo, extra.feePayer and
    extra.receiverAuthorizer, a positive extra.withdrawDelay, a known extra.tokenProgram, extra.memo of at most 256
    UTF-8 bytes when present, and extra.paymentFlow absent or escrow."""
    if not is_object(option) or option.get("scheme") != "upto" or not is_solana_network(option.get("network")):
        return False
    if not is_key(option.get("asset")) or not is_key(option.get("payTo")):
        return False
    extra = option.get("extra")
    if not is_object(extra) or not is_key(extra.get("feePayer")) or not is_key(extra.get("receiverAuthorizer")):
        return False
    delay = safe_int(extra.get("withdrawDelay"))
    if delay is None or delay <= 0:
        return False
    if extra.get("tokenProgram") not in (TOKEN, TOKEN_2022):
        return False
    if "memo" in extra and (not isinstance(extra["memo"], str) or memo_length(extra["memo"]) > MAX_MEMO):
        return False
    if "paymentFlow" in extra and extra["paymentFlow"] != "escrow":
        return False
    return True


def payable(option: Mapping[str, Any]) -> bool:
    """The amount is a positive u64 in decimal (is_amount) and the timeout a positive safe integer."""
    amount = option.get("amount")
    return (
        is_amount(amount)
        and _U64_DECIMAL.fullmatch(amount) is not None
        and int(amount) < U64_LIMIT
        and timeout_seconds(option.get("maxTimeoutSeconds")) is not None
    )


# The pairing's one option filter, which read, build and bound apply: an option of this pairing whose amount build can
# pay (payable), else x402/option-malformed.
_THIS = filter_of(pairs, payable)
_read = read_for(_THIS)


@dataclass(frozen=True, slots=True)
class X402UptoSolana:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return _read(doc)

    def build(self, choice: Json, h: AtrHash) -> SvmUnsigned | Refusal:
        """The open message the payer signs: the channel escrows the option's amount, and its one memo is
        extra.memo. The payload carries openSlot as a JSON number, so an openSlot above 2^53 - 1 is
        svm/input-malformed. H is checked first, then the form of the choice's payer, token program, blockhash and
        compute budget (is_payer_input), nonce, openSlot and now, then its document and option, then the option's memo
        against H and its token program against the choice's."""
        if normal_hash(h) is None:
            return Refusal("x402/payload-malformed")
        if not is_object(choice):
            return Refusal("x402/not-v2")
        now = safe_int(choice.get("now"))
        nonce: Any = choice.get("nonce")
        open_slot: Any = choice.get("openSlot")
        if (
            not is_payer_input(choice)
            or not is_u64(nonce)
            or not is_u64(open_slot)
            or open_slot > MAX_SAFE_INTEGER
            or now is None
            or now < 0
        ):
            return Refusal("svm/input-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        extra = accepted["extra"]
        memo = extra.get("memo")
        if memo != to_lcp_string(h):
            return Refusal("svm/carrier-mismatch")
        token_program: Any = choice.get("tokenProgram")
        if token_program != extra["tokenProgram"]:
            return Refusal("svm/input-malformed")
        fee_payer: str = extra["feePayer"]
        signer: str = extra["receiverAuthorizer"]
        payer: Any = choice.get("payer")
        blockhash: Any = choice.get("recentBlockhash")
        channel = channel_pda(payer, fee_payer, accepted["asset"], signer, nonce, open_slot)
        if isinstance(channel, Refusal):
            return channel
        amount = int(accepted["amount"])
        limit, price = choice.get("computeUnitLimit"), choice.get("computeUnitPrice")
        message = build_channel_message(
            ChannelBuildInput(
                fee_payer=fee_payer,
                payer=payer,
                mint=accepted["asset"],
                token_program=token_program,
                recent_blockhash=blockhash,
                memo=memo,
                compute_unit_limit=200_000 if limit is None else integer_of(limit),
                compute_unit_price=1 if price is None else price,
                instruction=ChannelOpen(
                    channel=channel,
                    signer=signer,
                    salt=nonce,
                    deposit=amount,
                    grace_period=integer_of(extra["withdrawDelay"]),
                    open_slot=open_slot,
                    recipient=accepted["payTo"],
                ),
            )
        )
        if isinstance(message, Refusal):
            return message
        valid_after = safe_int(extra.get("validAfter"))
        timeout = safe_int(accepted["maxTimeoutSeconds"])
        assert timeout is not None
        signing = SvmSigning(message, payer)

        def complete(signature: bytes) -> dict[str, Any] | Refusal:
            wire = signing.wire(signature)
            if isinstance(wire, Refusal):
                return wire
            return payment_with(
                required,
                accepted,
                {
                    "from": payer,
                    "maxAmount": accepted["amount"],
                    "expiresAt": now + timeout,
                    "validAfter": valid_after if valid_after is not None else now,
                    "nonce": str(nonce),
                    "openSlot": open_slot,
                    "channelId": channel,
                    "deposit": accepted["amount"],
                    "authorizedSigner": signer,
                    "openTransaction": to_base64(wire),
                },
            )

        return SvmUnsigned(signing.request, complete)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the one memo of the open transaction the payer signed, which must equal the option's
        extra.memo. No signature is verified here."""
        if not is_v2(presented):
            return Refusal("x402/not-v2")
        accepted = accepted_by(presented.get("accepted"), _THIS)
        if isinstance(accepted, Refusal):
            return accepted
        payload = presented.get("payload")
        if not is_object(payload):
            return Refusal("x402/payload-malformed")
        wire = wire_of(payload.get("openTransaction"))
        if isinstance(wire, Refusal):
            return wire
        tx = decode_svm_tx(wire)
        if isinstance(tx, Refusal):
            return tx
        from_table = static_nonce(tx)
        if from_table is not None:
            return from_table
        carrier = svm_carrier(tx)
        if isinstance(carrier, Refusal):
            return carrier
        if carrier.memo != accepted["extra"].get("memo"):
            return Refusal("svm/carrier-mismatch")
        ix = channel_instruction(tx)
        if isinstance(ix, Refusal) or ix.kind != "open":
            return Refusal("x402/not-an-opening")
        return carrier.h

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's facilitator, the option's feePayer, co-signs and sends the opening the
        payer signed, and settles the metered amount in a later transaction. The payment is held to x402_shape's gate,
        the one bound applies first; any other gets its refusal."""
        return x402_broadcaster(presented, "payee")
