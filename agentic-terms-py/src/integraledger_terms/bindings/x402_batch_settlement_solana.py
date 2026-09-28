"""The buyer half of the pairing x402/batch-settlement/solana: read, build with complete, bound, and the channel
members (build_within, channel_kind, channel_ref, bound_within).

The ATR hash rides as the option's extra.memo in LCP string form, which the payer writes as the one Memo instruction of
the transaction that opens the payment channel. Later vouchers are paid under the channel the opening named. Nothing
here fetches, hashes an ATR or signs.
"""

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._batch import SCHEME, is_delay, payable, payload_of
from ._channel import BatchUnsigned, ChannelKind, ChannelRef
from ._lcp import is_list, is_object, safe_int, to_lcp_string
from ._svm import (
    TOKEN,
    TOKEN_2022,
    ChannelBuildInput,
    ChannelOpen,
    ChannelRequestClose,
    SvmTx,
    build_channel_message,
    channel_instruction,
    channel_pda,
    channel_voucher_message,
    decode_svm_tx,
    integer_of,
    is_key,
    is_solana_network,
    key_string,
    memo_length,
    signature_bytes,
    signed_wire,
    static_nonce,
    svm_carrier,
    to_base64,
    wire_of,
)
from ._x402 import chosen, filter_of, payment_with, read_for

ID = "x402/batch-settlement/solana"
MAX_MEMO = 256
MAX_SAFE_INTEGER = 2**53 - 1
U64_LIMIT = 1 << 64
_U64_DECIMAL = re.compile(r"[0-9]{1,20}")
_NUMERIC = re.compile(r"\s*[-+]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?\s*")


def _js_number(value: object) -> float | None:
    """The number a relational comparison reads from a JSON value: numbers as they are, booleans and null as 0 or 1,
    a numeric string as its number, the empty string as 0; None where the comparison reads NaN."""
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, int):
        return float(value) if abs(value) <= 2**1023 else (math.inf if value > 0 else -math.inf)
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        if value.strip() == "":
            return 0.0
        return float(value) if _NUMERIC.fullmatch(value) else None
    return None


def pairs(option: Mapping[str, Any]) -> bool:
    """The pairing's filter: scheme batch-settlement on a solana network, base58 keys for asset, payTo and
    extra.feePayer, a known extra.tokenProgram, extra.withdrawDelay in 900-2 592 000 and not below maxTimeoutSeconds,
    extra.paymentFlow absent or authorization, and extra.memo of at most 256 UTF-8 bytes when present."""
    if not is_object(option) or option.get("scheme") != SCHEME or not is_object(option.get("extra")):
        return False
    extra = option["extra"]
    if not is_solana_network(option.get("network")):
        return False
    if not is_key(option.get("asset")) or not is_key(option.get("payTo")) or not is_key(extra.get("feePayer")):
        return False
    if extra.get("tokenProgram") not in (TOKEN, TOKEN_2022):
        return False
    if not is_delay(extra.get("withdrawDelay")):
        return False
    if "maxTimeoutSeconds" in option:
        timeout = _js_number(option["maxTimeoutSeconds"])
        if timeout is not None and float(extra["withdrawDelay"]) < timeout:
            return False
    if "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return False
    if "memo" in extra and (not isinstance(extra["memo"], str) or memo_length(extra["memo"]) > MAX_MEMO):
        return False
    return True


_THIS = filter_of(pairs)
_read = read_for(_THIS)


@dataclass(frozen=True, slots=True)
class _Config:
    payer: str
    payer_authorizer: str
    token: str
    salt: int
    open_slot: int


def _config(value: object) -> _Config | None:
    """A channelConfig with its members in their rail forms, or None."""
    if not is_object(value):
        return None

    def u64(v: object) -> bool:
        return isinstance(v, str) and _U64_DECIMAL.fullmatch(v) is not None and int(v) < U64_LIMIT

    open_slot = safe_int(value.get("openSlot"))
    if not (
        is_key(value.get("payer"))
        and is_key(value.get("payerAuthorizer"))
        and is_key(value.get("receiver"))
        and ("receiverAuthorizer" not in value or is_key(value["receiverAuthorizer"]))
        and is_key(value.get("token"))
        and safe_int(value.get("withdrawDelay")) is not None
        and u64(value.get("salt"))
        and open_slot is not None
        and open_slot >= 0
    ):
        return None
    return _Config(value["payer"], value["payerAuthorizer"], value["token"], int(value["salt"]), open_slot)


_ABSENT = object()


def _tx_of(payload: Mapping[str, Any]) -> SvmTx | None | Refusal:
    """A payment's decoded transaction, from deposit.transaction or a refund's transaction, when present."""
    deposit = payload.get("deposit")
    text = deposit.get("transaction", _ABSENT) if is_object(deposit) else payload.get("transaction", _ABSENT)
    if text is _ABSENT:
        return None
    wire = wire_of(text)
    if isinstance(wire, Refusal):
        return wire
    return decode_svm_tx(wire)


def _signatures(signatures: object, count: int) -> list[bytes] | None:
    if not is_list(signatures) or len(signatures) != count:
        return None
    out = [signature_bytes(s) for s in signatures]
    return None if any(s is None for s in out) else [s for s in out if s is not None]


@dataclass(frozen=True, slots=True)
class X402BatchSettlementSolana:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return _read(doc)

    def build(self, choice: Json, h: AtrHash) -> BatchUnsigned | Refusal:
        """The opening: the open transaction, then the first voucher, each for the payer or its authorizer to sign."""
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        if not payable(accepted) or int(accepted["amount"]) >= U64_LIMIT:
            return Refusal("x402/option-malformed")
        extra = accepted["extra"]
        memo = extra.get("memo")
        if memo != to_lcp_string(h):
            return Refusal("svm/carrier-mismatch")
        deposit: Any = choice.get("deposit")
        token_program: Any = choice.get("tokenProgram")
        if (
            token_program != extra["tokenProgram"]
            or not isinstance(deposit, int)
            or isinstance(deposit, bool)
            or not 0 < deposit < U64_LIMIT
        ):
            return Refusal("svm/input-malformed")
        fee_payer: str = extra["feePayer"]
        payer: Any = choice.get("payer")
        authorizer: Any = choice.get("payerAuthorizer")
        salt: Any = choice.get("salt")
        open_slot: Any = choice.get("openSlot")
        blockhash: Any = choice.get("recentBlockhash")
        channel = channel_pda(payer, fee_payer, accepted["asset"], authorizer, salt, open_slot)
        if isinstance(channel, Refusal):
            return channel
        if open_slot > MAX_SAFE_INTEGER:
            return Refusal("svm/input-malformed")
        limit, price = choice.get("computeUnitLimit"), choice.get("computeUnitPrice")
        delay = safe_int(extra["withdrawDelay"])
        assert delay is not None
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
                    signer=authorizer,
                    salt=salt,
                    deposit=deposit,
                    grace_period=delay,
                    open_slot=open_slot,
                    recipient=accepted["payTo"],
                ),
            )
        )
        if isinstance(message, Refusal):
            return message
        amount = int(accepted["amount"])
        voucher_message = channel_voucher_message(channel, amount, 0)
        assert voucher_message is not None
        config: dict[str, Any] = {"payer": payer, "payerAuthorizer": authorizer, "receiver": accepted["payTo"]}
        if isinstance(extra.get("receiverAuthorizer"), str):
            config["receiverAuthorizer"] = extra["receiverAuthorizer"]
        config.update(
            {
                "token": accepted["asset"],
                "withdrawDelay": extra["withdrawDelay"],
                "salt": str(salt),
                "openSlot": open_slot,
            }
        )

        def complete(signatures: object) -> dict[str, Any] | Refusal:
            sigs = _signatures(signatures, 2)
            if sigs is None:
                return Refusal("svm/input-malformed")
            wire = signed_wire(message, payer, sigs[0])
            if isinstance(wire, Refusal):
                return wire
            voucher = {
                "channelId": channel,
                "maxClaimableAmount": str(amount),
                "expiresAt": 0,
                "signature": key_string(sigs[1]),
            }
            return payment_with(
                required,
                accepted,
                {
                    "type": "deposit",
                    "channelConfig": config,
                    "voucher": voucher,
                    "deposit": {"amount": str(deposit), "transaction": to_base64(wire)},
                },
            )

        return BatchUnsigned(
            [
                {"kind": "solana-message", "message": message},
                {"kind": "ed25519-raw", "message": voucher_message, "signer": authorizer},
            ],
            complete,
        )

    def build_within(self, w: Json, h: AtrHash) -> BatchUnsigned | Refusal:
        """A later voucher, or a full refund, for a channel this buyer opened. The refund is a request_close message
        for the payer: the Compute Budget prefix, request_close with the payer (read-only signer) and the channel
        (writable), then one Memo v3 with extra.memo when the option carries one. Its payload carries no amount and no
        voucher."""
        required, accepted = w.get("required"), w.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        channel_config = w.get("channelConfig")
        config = _config(channel_config)
        if config is None:
            return Refusal("x402/payload-malformed")
        channel = channel_pda(
            config.payer, accepted["extra"]["feePayer"], config.token, config.payer_authorizer, config.salt,
            config.open_slot,
        )  # fmt: skip
        if isinstance(channel, Refusal):
            return channel
        if "refund" in w:
            refund = w["refund"]
            if not is_object(refund) or "amount" in refund:
                return Refusal("svm/input-malformed")
            extra = accepted["extra"]
            blockhash = extra.get("recentBlockhash")
            if not isinstance(blockhash, str):
                blockhash = w.get("recentBlockhash")
            if not isinstance(blockhash, str):
                return Refusal("svm/input-malformed")
            memo = extra.get("memo")
            limit, price = w.get("computeUnitLimit"), w.get("computeUnitPrice")
            refund_tx = build_channel_message(
                ChannelBuildInput(
                    fee_payer=extra["feePayer"],
                    payer=config.payer,
                    mint=config.token,
                    token_program=extra["tokenProgram"],
                    recent_blockhash=blockhash,
                    memo=memo if isinstance(memo, str) else None,
                    compute_unit_limit=200_000 if limit is None else integer_of(limit),
                    compute_unit_price=1 if price is None else price,
                    instruction=ChannelRequestClose(channel=channel),
                )
            )
            if isinstance(refund_tx, Refusal):
                return refund_tx

            def close(signatures: object) -> dict[str, Any] | Refusal:
                sigs = _signatures(signatures, 1)
                if sigs is None:
                    return Refusal("svm/input-malformed")
                wire = signed_wire(refund_tx, config.payer, sigs[0])
                if isinstance(wire, Refusal):
                    return wire
                return payment_with(
                    required,
                    accepted,
                    {"type": "refund", "channelConfig": channel_config, "transaction": to_base64(wire)},
                )

            return BatchUnsigned([{"kind": "solana-message", "message": refund_tx}], close)
        max_claimable = w.get("maxClaimableAmount")
        if not isinstance(max_claimable, int) or isinstance(max_claimable, bool) or not 0 <= max_claimable < U64_LIMIT:
            return Refusal("svm/input-malformed")
        message = channel_voucher_message(channel, max_claimable, 0)
        assert message is not None

        def voucher(signatures: object) -> dict[str, Any] | Refusal:
            sigs = _signatures(signatures, 1)
            if sigs is None:
                return Refusal("svm/input-malformed")
            return payment_with(
                required,
                accepted,
                {
                    "type": "voucher",
                    "channelConfig": channel_config,
                    "voucher": {
                        "channelId": channel,
                        "maxClaimableAmount": str(max_claimable),
                        "expiresAt": 0,
                        "signature": key_string(sigs[0]),
                    },
                },
            )

        return BatchUnsigned([{"kind": "ed25519-raw", "message": message, "signer": config.payer_authorizer}], voucher)

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """open for a deposit whose channel instruction is open; within for a top_up deposit or a voucher; close
        for a refund."""
        x = payload_of(presented, pairs)
        if isinstance(x, Refusal):
            return x
        kind = x[1].get("type")
        if kind == "voucher":
            return "within"
        if kind == "refund":
            return "close"
        if kind == "deposit":
            tx = _tx_of(x[1])
            if tx is None or isinstance(tx, Refusal):
                return Refusal("x402/payload-malformed")
            ix = channel_instruction(tx)
            if isinstance(ix, Refusal):
                return ix
            if ix.kind == "open":
                return "open"
            if ix.kind == "top_up":
                return "within"
        return Refusal("x402/channel-kind-unknown")

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The channel PDA from the payment's config, which must equal its voucher's id and its channel
        instruction's account."""
        x = payload_of(presented, pairs)
        if isinstance(x, Refusal):
            return x
        accepted, payload = x
        config = _config(payload.get("channelConfig"))
        if config is None:
            return Refusal("x402/payload-malformed")
        pda = channel_pda(
            config.payer, accepted["extra"]["feePayer"], config.token, config.payer_authorizer, config.salt,
            config.open_slot,
        )  # fmt: skip
        if isinstance(pda, Refusal):
            return pda
        if "voucher" in payload:
            voucher = payload["voucher"]
            if not is_object(voucher) or voucher.get("channelId") != pda:
                return Refusal("svm/channel-id-mismatch")
        tx = _tx_of(payload)
        if isinstance(tx, Refusal):
            return tx
        if tx is not None:
            ix = channel_instruction(tx)
            if isinstance(ix, Refusal):
                return ix
            if ix.channel != pda:
                return Refusal("svm/channel-id-mismatch")
        return ChannelRef(accepted["network"], pda)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the one memo of the opening the payer signed, which must equal the option's extra.memo, for a
        deposit whose channel instruction is open and whose channel the config names. No signature is verified
        here."""
        x = payload_of(presented, pairs)
        if isinstance(x, Refusal):
            return x
        accepted, payload = x
        if payload.get("type") != "deposit":
            return Refusal("x402/not-an-opening")
        tx = _tx_of(payload)
        if tx is None:
            return Refusal("x402/payload-malformed")
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
        if isinstance(ix, Refusal):
            return ix
        if ix.kind != "open":
            return Refusal("x402/not-an-opening")
        ref = self.channel_ref(presented)
        if isinstance(ref, Refusal):
            return ref
        return carrier.h

    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A voucher signs no commitment to the hash: the channel is found by channel_ref alone."""
        return Refusal("x402/not-bound-within")
