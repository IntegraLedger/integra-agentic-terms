"""The buyer half of the pairing x402/batch-settlement/solana: read, build with complete, bound, and the channel
members (build_within, channel_kind, channel_ref, bound_within).

The ATR hash rides as the option's extra.memo in LCP string form, which the payer writes as a Memo instruction of the
transaction that opens the payment channel, beside x402's binding memo for extra.receiverAuthorizer. Later vouchers are
paid under the channel the opening named. Nothing here fetches, hashes an ATR or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._batch import SCHEME, batch_broadcaster, is_delay, payable, payload_of
from ._channel import BatchUnsigned, ChannelKind, ChannelRef
from ._lcp import is_list, is_object, normal_hash, safe_int, to_lcp_string
from ._svm import (
    TOKEN,
    TOKEN_2022,
    U32_LIMIT,
    Carrier,
    ChannelBuildInput,
    ChannelOpen,
    ChannelRequestClose,
    SvmTx,
    build_channel_message,
    channel_instruction,
    channel_message,
    channel_pda,
    channel_voucher_message,
    decode_svm_tx,
    integer_of,
    is_curve_key,
    is_key,
    is_payer_input,
    is_solana_network,
    is_u64,
    key_string,
    memo_carrier,
    memo_data,
    memo_length,
    signature_bytes,
    signed_wire,
    static_nonce,
    to_base64,
    wire_of,
)
from ._x402 import chosen, filter_of, payment_with, read_for

ID = "x402/batch-settlement/solana"
MAX_MEMO = 256
MAX_SAFE_INTEGER = 2**53 - 1
U64_LIMIT = 1 << 64
# x402's receiver-authorizer binding memo: this prefix, then the base58 key.
BINDING_MEMO_PREFIX = "x402:batch-settlement:svm:rcvauth:v1:"
_BINDING_MEMO_PREFIX_BYTES = BINDING_MEMO_PREFIX.encode()
_U64_DECIMAL = re.compile(r"[0-9]{1,20}")


def pairs(option: Mapping[str, Any]) -> bool:
    """The pairing's filter: scheme batch-settlement on a solana network, base58 keys for asset, payTo,
    extra.feePayer and extra.receiverAuthorizer, extra.voucherSigner absent or client, a known extra.tokenProgram,
    extra.withdrawDelay in 900-2 592 000 and not below a maxTimeoutSeconds that is a number, extra.paymentFlow absent
    or authorization, and extra.memo of at most 256 UTF-8 bytes when present. A maxTimeoutSeconds of another type is
    never converted to compare: the option is named, and the pairing's filter refuses it x402/option-malformed, so read
    does not offer it."""
    if not is_object(option) or option.get("scheme") != SCHEME or not is_object(option.get("extra")):
        return False
    extra = option["extra"]
    if not is_solana_network(option.get("network")):
        return False
    if not is_key(option.get("asset")) or not is_key(option.get("payTo")) or not is_key(extra.get("feePayer")):
        return False
    if not is_key(extra.get("receiverAuthorizer")):
        return False
    if "voucherSigner" in extra and extra["voucherSigner"] != "client":
        return False
    if extra.get("tokenProgram") not in (TOKEN, TOKEN_2022):
        return False
    if not is_delay(extra.get("withdrawDelay")):
        return False
    timeout = option.get("maxTimeoutSeconds")
    if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and extra["withdrawDelay"] < timeout:
        return False
    if "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return False
    if "memo" in extra and (not isinstance(extra["memo"], str) or memo_length(extra["memo"]) > MAX_MEMO):
        return False
    return True


def _payable(option: Mapping[str, Any]) -> bool:
    """What build can pay: payable, with the amount below 2^64, the voucher's u64."""
    return payable(option) and int(option["amount"]) < U64_LIMIT


# The pairing's one option filter, which read, build, build_within, bound and the channel reads apply.
_THIS = filter_of(pairs, _payable)
_read = read_for(_THIS)


@dataclass(frozen=True, slots=True)
class _Config:
    payer: str
    payer_authorizer: str
    token: str
    salt: int
    open_slot: int


def _config(value: object) -> _Config | None:
    """A channelConfig as the payment-channels program's open takes it (solana-foundation/payment-channels
    0c07d5751c8972abf6a219570a3f39a72f46f879, the revision x402 751590a2 pins, instructions/open.rs), with its members
    in their rail forms, or None: its keys, with a payerAuthorizer that is a point on the Ed25519 curve, since open
    refuses an authorized signer off it; a decimal u64 salt; an openSlot that is a safe integer of at least 0; and a
    withdrawDelay that is a positive integer below 2^32, since grace_period is a u32 that open refuses as 0. It does
    not compare the payer with the option's extra.feePayer, which open also requires to differ: that comparison is the
    facilitator's."""
    if not is_object(value):
        return None

    def u64(v: object) -> bool:
        return isinstance(v, str) and _U64_DECIMAL.fullmatch(v) is not None and int(v) < U64_LIMIT

    open_slot = safe_int(value.get("openSlot"))
    delay = safe_int(value.get("withdrawDelay"))
    if not (
        is_key(value.get("payer"))
        and is_curve_key(value.get("payerAuthorizer"))
        and is_key(value.get("receiver"))
        and ("receiverAuthorizer" not in value or is_key(value["receiverAuthorizer"]))
        and is_key(value.get("token"))
        and delay is not None
        and 1 <= delay < U32_LIMIT
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


def _payload_kind(payload: Mapping[str, Any]) -> ChannelKind | Refusal:
    """channel_kind's read of the payload, which reads no option; broadcaster makes it too. A deposit with no
    transaction that decodes is x402/payload-malformed, and one whose channel instruction does not read gets that
    refusal. Any other type, and a deposit whose channel instruction is a request_close, is
    x402/channel-kind-unknown."""
    kind = payload.get("type")
    if kind == "voucher":
        return "within"
    if kind == "refund":
        return "close"
    if kind == "deposit":
        tx = _tx_of(payload)
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


def _opening_carrier(tx: SvmTx) -> Carrier | Refusal:
    """The opening's memos: exactly one receiver-authorizer binding memo, whose key is not read, and exactly one other
    Memo instruction, which carries the ATR hash in LCP string form. Any other count is svm/memo-count."""
    memos = memo_data(tx)
    others = [d for d in memos if not d.startswith(_BINDING_MEMO_PREFIX_BYTES)]
    if len(others) != 1 or len(memos) != 2:
        return Refusal("svm/memo-count")
    return memo_carrier(others[0])


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
        """The opening: the open transaction, then the first voucher, each for the payer or its authorizer to sign. The
        transaction ends with two v3 Memo instructions: extra.memo, then x402's binding memo for
        extra.receiverAuthorizer. A payerAuthorizer that is not a point on the Ed25519 curve, which the program's open
        refuses as the authorized signer, is svm/input-malformed. H is checked first, then the form of the choice's
        payer, token program, blockhash and compute budget (is_payer_input), deposit, payerAuthorizer, salt and
        openSlot, then its document and option, then the option's memo against H and its token program against the
        choice's."""
        if normal_hash(h) is None:
            return Refusal("x402/payload-malformed")
        if not is_object(choice):
            return Refusal("x402/not-v2")
        deposit: Any = choice.get("deposit")
        authorizer: Any = choice.get("payerAuthorizer")
        salt: Any = choice.get("salt")
        open_slot: Any = choice.get("openSlot")
        if (
            not is_payer_input(choice)
            or not isinstance(deposit, int)
            or isinstance(deposit, bool)
            or not 0 < deposit < U64_LIMIT
            or not is_curve_key(authorizer)
            or not is_u64(salt)
            or not is_u64(open_slot)
            or open_slot > MAX_SAFE_INTEGER
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
        payer: Any = choice.get("payer")
        blockhash: Any = choice.get("recentBlockhash")
        channel = channel_pda(payer, fee_payer, accepted["asset"], authorizer, salt, open_slot)
        if isinstance(channel, Refusal):
            return channel
        limit, price = choice.get("computeUnitLimit"), choice.get("computeUnitPrice")
        delay = safe_int(extra["withdrawDelay"])
        assert delay is not None
        receiver_authorizer: str = extra["receiverAuthorizer"]
        message = channel_message(
            ChannelBuildInput(
                fee_payer=fee_payer,
                payer=payer,
                mint=accepted["asset"],
                token_program=token_program,
                recent_blockhash=blockhash,
                memo=None,
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
            ),
            [memo, BINDING_MEMO_PREFIX + receiver_authorizer],
        )
        if isinstance(message, Refusal):
            return message
        amount = int(accepted["amount"])
        voucher_message = channel_voucher_message(channel, amount, 0)
        assert voucher_message is not None
        config = {
            "payer": payer,
            "payerAuthorizer": authorizer,
            "receiver": accepted["payTo"],
            "receiverAuthorizer": receiver_authorizer,
            "token": accepted["asset"],
            "withdrawDelay": extra["withdrawDelay"],
            "salt": str(salt),
            "openSlot": open_slot,
        }

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
        """A later voucher, or a full refund, for a channel this buyer opened. Each carries the voucher for
        maxClaimableAmount, signed by the payer authorizer, with expiresAt 0. A refund carries no amount; with
        w's recentBlockhash it also carries a request_close message for the payer, signed first: the Compute Budget
        prefix, request_close with the payer (read-only signer) and the channel (writable), then one Memo v3 with
        extra.memo when the option carries one."""
        if not is_object(w):
            return Refusal("x402/not-v2")
        required, accepted = w.get("required"), w.get("accepted")
        ok = chosen(required, accepted, _THIS)
        if ok is not True:
            return ok
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
        max_claimable = w.get("maxClaimableAmount")
        if not isinstance(max_claimable, int) or isinstance(max_claimable, bool) or not 0 <= max_claimable < U64_LIMIT:
            return Refusal("svm/input-malformed")
        voucher_message = channel_voucher_message(channel, max_claimable, 0)
        assert voucher_message is not None
        voucher_request = {"kind": "ed25519-raw", "message": voucher_message, "signer": config.payer_authorizer}

        def voucher_of(signature: bytes) -> dict[str, Any]:
            return {
                "channelId": channel,
                "maxClaimableAmount": str(max_claimable),
                "expiresAt": 0,
                "signature": key_string(signature),
            }

        if "refund" in w:
            refund = w["refund"]
            if not is_object(refund) or "amount" in refund:
                return Refusal("svm/input-malformed")
            if "recentBlockhash" not in w:

                def cooperative(signatures: object) -> dict[str, Any] | Refusal:
                    sigs = _signatures(signatures, 1)
                    if sigs is None:
                        return Refusal("svm/input-malformed")
                    payload = {"type": "refund", "channelConfig": channel_config, "voucher": voucher_of(sigs[0])}
                    return payment_with(required, accepted, payload)

                return BatchUnsigned([voucher_request], cooperative)
            extra = accepted["extra"]
            memo = extra.get("memo")
            limit, price = w.get("computeUnitLimit"), w.get("computeUnitPrice")
            refund_tx = build_channel_message(
                ChannelBuildInput(
                    fee_payer=extra["feePayer"],
                    payer=config.payer,
                    mint=config.token,
                    token_program=extra["tokenProgram"],
                    recent_blockhash=w["recentBlockhash"],
                    memo=memo if isinstance(memo, str) else None,
                    compute_unit_limit=200_000 if limit is None else integer_of(limit),
                    compute_unit_price=1 if price is None else price,
                    instruction=ChannelRequestClose(channel=channel),
                )
            )
            if isinstance(refund_tx, Refusal):
                return refund_tx

            def close(signatures: object) -> dict[str, Any] | Refusal:
                sigs = _signatures(signatures, 2)
                if sigs is None:
                    return Refusal("svm/input-malformed")
                wire = signed_wire(refund_tx, config.payer, sigs[0])
                if isinstance(wire, Refusal):
                    return wire
                payload = {
                    "type": "refund",
                    "channelConfig": channel_config,
                    "voucher": voucher_of(sigs[1]),
                    "transaction": to_base64(wire),
                }
                return payment_with(required, accepted, payload)

            return BatchUnsigned([{"kind": "solana-message", "message": refund_tx}, voucher_request], close)

        def voucher(signatures: object) -> dict[str, Any] | Refusal:
            sigs = _signatures(signatures, 1)
            if sigs is None:
                return Refusal("svm/input-malformed")
            payload = {"type": "voucher", "channelConfig": channel_config, "voucher": voucher_of(sigs[0])}
            return payment_with(required, accepted, payload)

        return BatchUnsigned([voucher_request], voucher)

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts every payment type channel_kind takes: the seller's facilitator, the feePayer, co-signs
        and sends the deposit and top-up transactions the payer signed, redeems vouchers when it settles, and sends the
        refund. A payment of any other type gets x402/not-an-opening, as bound refuses it (batch_broadcaster)."""
        return batch_broadcaster(presented, _payload_kind)

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        """open for a deposit whose channel instruction is open; within for a top_up deposit or a voucher; close
        for a refund. The payment is held to the pairing's filter first (payload_of), and its payload read by
        _payload_kind."""
        x = payload_of(presented, _THIS)
        if isinstance(x, Refusal):
            return x
        return _payload_kind(x[1])

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        """The channel PDA from the payment's config, which must equal its voucher's id and its channel
        instruction's account. A config that is not one, such as one whose payerAuthorizer is not a point on the
        Ed25519 curve or whose withdrawDelay is not a positive integer below 2^32, is x402/payload-malformed."""
        x = payload_of(presented, _THIS)
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
        """The hash in the seller memo of the opening the payer signed, which must equal the option's extra.memo, for a
        deposit whose channel instruction is open and whose channel the config names. The opening carries exactly one
        binding memo, whose key is not read, beside that one memo. No signature is verified here."""
        x = payload_of(presented, _THIS)
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
        ix = channel_instruction(tx)
        if isinstance(ix, Refusal):
            return ix
        if ix.kind != "open":
            return Refusal("x402/not-an-opening")
        carrier = _opening_carrier(tx)
        if isinstance(carrier, Refusal):
            return carrier
        if carrier.memo != accepted["extra"].get("memo"):
            return Refusal("svm/carrier-mismatch")
        ref = self.channel_ref(presented)
        if isinstance(ref, Refusal):
            return ref
        return carrier.h

    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        """A voucher signs no commitment to the hash: the channel is found by channel_ref alone."""
        return Refusal("x402/not-bound-within")
