"""The buyer half of x402/batch-settlement/eip155: read, build with complete, bound, and the channel members.

The ATR hash is the channel configuration's salt. The channel id is the EIP-712 digest of that configuration, the
opening's token authorization commits to the channel id, and every voucher signs it. Nothing here fetches, hashes an
ATR or signs.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._batch import SCHEME, U128_LIMIT, is_decimal, is_delay, is_hex_signature, payable, payload_of
from ._batch_evm import (
    ERC3009_DEPOSIT_COLLECTOR,
    PERMIT2_DEPOSIT_COLLECTOR,
    batch_channel_id,
    erc3009_deposit_nonce,
    is_channel_config,
    is_hash32,
    voucher_request,
)
from ._channel import BatchUnsigned, ChannelKind, ChannelRef
from ._evm import Witness, bytes_of, eip3009_typed_data, permit2_typed_data
from ._lcp import chain_id_of, is_address, is_object, normal_hash, safe_int
from ._x402 import chosen, filter_of, payment_with, read_for

ID = "x402/batch-settlement/eip155"
_ZERO = "0x" + "0" * 40


def _non_empty(value: object) -> bool:
    return isinstance(value, str) and value != ""


def is_pairing(option: Mapping[str, Any]) -> bool:
    """The option names x402/batch-settlement/eip155: scheme batch-settlement on an eip155 network; asset, payTo and a
    non-zero receiverAuthorizer as addresses; a withdrawDelay in range; the token's name and version; a known
    transfer method and flow."""
    if not is_object(option) or option.get("scheme") != SCHEME or not is_object(option.get("extra")):
        return False
    extra = option["extra"]
    if chain_id_of(option.get("network")) is None:
        return False
    if not is_address(option.get("asset")) or not is_address(option.get("payTo")):
        return False
    receiver_authorizer = extra.get("receiverAuthorizer")
    if not is_address(receiver_authorizer) or receiver_authorizer.lower() == _ZERO:
        return False
    if not is_delay(extra.get("withdrawDelay")):
        return False
    if not _non_empty(extra.get("name")) or not _non_empty(extra.get("version")):
        return False
    if "assetTransferMethod" in extra and extra["assetTransferMethod"] not in ("eip3009", "permit2"):
        return False
    if "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return False
    return True


_FILTER = filter_of(is_pairing)


def _same_bytes(a: object, b: object) -> bool:
    x, y = bytes_of(a), bytes_of(b)
    return x is not None and y is not None and x == y


def channel_ref(presented: object) -> ChannelRef | Refusal:
    """The channel id of a payment's config, which must equal its voucher's channel id, lower-case."""
    got = payload_of(presented, is_pairing)
    if isinstance(got, Refusal):
        return got
    accepted, payload = got
    config = payload.get("channelConfig")
    if not is_channel_config(config):
        return Refusal("x402/payload-malformed")
    voucher = payload.get("voucher")
    if not is_object(voucher) or not isinstance(voucher.get("channelId"), str):
        return Refusal("x402/payload-malformed")
    chain_id = chain_id_of(accepted.get("network"))
    assert chain_id is not None
    channel_id = batch_channel_id(chain_id, config)
    if isinstance(channel_id, Refusal):
        return channel_id
    if not _same_bytes(channel_id, voucher["channelId"]):
        return Refusal("x402/channel-id-mismatch")
    return ChannelRef(network=accepted["network"], channel=channel_id.lower())


def channel_kind(presented: object) -> ChannelKind | Refusal:
    """deposit is the opening; voucher, and a refund naming an amount, are within; a full refund is the close."""
    got = payload_of(presented, is_pairing)
    if isinstance(got, Refusal):
        return got
    payload = got[1]
    kind = payload.get("type")
    if kind == "deposit":
        return "open"
    if kind == "voucher":
        return "within"
    if kind == "refund":
        return "close" if "amount" not in payload else "within"
    return Refusal("x402/channel-kind-unknown")


def _deposit_of(payload: Mapping[str, Any]) -> Refusal | None:
    """The opening's deposit: a decimal amount and exactly one of the ERC-3009 and Permit2 authorizations."""
    deposit = payload.get("deposit")
    if not is_object(deposit) or not is_decimal(deposit.get("amount")):
        return Refusal("x402/payload-malformed")
    authorization = deposit.get("authorization")
    if not is_object(authorization):
        return Refusal("x402/deposit-authorization")
    if ("erc3009Authorization" in authorization) == ("permit2Authorization" in authorization):
        return Refusal("x402/deposit-authorization")
    if "erc3009Authorization" in authorization:
        e = authorization["erc3009Authorization"]
        if not is_object(e) or not is_decimal(e.get("validBefore")) or not is_hash32(e.get("salt")):
            return Refusal("x402/payload-malformed")
        return None
    p = authorization["permit2Authorization"]
    if not is_object(p) or not is_decimal(p.get("deadline")):
        return Refusal("x402/payload-malformed")
    return None


def _salt(payload: Mapping[str, Any]) -> AtrHash:
    salt = normal_hash(payload["channelConfig"]["salt"])
    assert salt is not None
    return salt


def bound(presented: object) -> AtrHash | Refusal:
    """The opening's salt, once its config hashes to the voucher's channel id. No signature is verified here."""
    got = payload_of(presented, is_pairing)
    if isinstance(got, Refusal):
        return got
    payload = got[1]
    if payload.get("type") != "deposit":
        return Refusal("x402/not-an-opening")
    if not is_channel_config(payload.get("channelConfig")):
        return Refusal("x402/payload-malformed")
    deposit = _deposit_of(payload)
    if deposit is not None:
        return deposit
    ref = channel_ref(presented)
    if isinstance(ref, Refusal):
        return ref
    return _salt(payload)


def bound_within(presented: object) -> AtrHash | Refusal:
    """A later payment's salt, once its config hashes to its voucher's channel id."""
    ref = channel_ref(presented)
    if isinstance(ref, Refusal):
        return ref
    got = payload_of(presented, is_pairing)
    assert not isinstance(got, Refusal)
    return _salt(got[1])


def _uint(value: object, low: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value < U128_LIMIT


def build(c: Json, h: AtrHash) -> BatchUnsigned | Refusal:
    """The opening's two requests, in order: the deposit's token authorization, then the first voucher."""
    required, accepted = c.get("required"), c.get("accepted")
    ok = chosen(required, accepted, _FILTER)
    if ok is not True:
        return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
    assert is_object(required) and is_object(accepted)
    if not payable(accepted):
        return Refusal("x402/option-malformed")
    salt = normal_hash(h)
    payer, payer_authorizer, auth_salt = c.get("from"), c.get("payerAuthorizer"), c.get("authSalt")
    if salt is None or not is_address(payer) or not is_address(payer_authorizer) or not is_hash32(auth_salt):
        return Refusal("x402/option-malformed")
    deposit = c.get("deposit")
    if not _uint(deposit, 1):
        return Refusal("x402/option-malformed")
    assert isinstance(deposit, int)
    now = safe_int(c.get("now"))
    if now is None or now < 0:
        return Refusal("x402/option-malformed")
    extra = accepted["extra"]
    chain_id = chain_id_of(accepted["network"])
    assert chain_id is not None
    config: dict[str, Any] = {
        "payer": payer,
        "payerAuthorizer": payer_authorizer,
        "receiver": accepted["payTo"],
        "receiverAuthorizer": extra["receiverAuthorizer"],
        "token": accepted["asset"],
        "withdrawDelay": int(extra["withdrawDelay"]),
        "salt": salt,
    }
    channel_id = batch_channel_id(chain_id, config)
    if isinstance(channel_id, Refusal):
        return channel_id
    timeout = safe_int(accepted["maxTimeoutSeconds"])
    assert timeout is not None
    deadline = now + timeout
    permit2 = extra.get("assetTransferMethod") == "permit2"
    if permit2:
        token_auth = permit2_typed_data(
            chain_id=chain_id,
            permitted={"token": config["token"], "amount": deposit},
            spender=PERMIT2_DEPOSIT_COLLECTOR,
            nonce=int(auth_salt[2:], 16),
            deadline=deadline,
            witness=Witness("DepositWitness", ({"name": "channelId", "type": "bytes32"},), {"channelId": channel_id}),
        )
    else:
        nonce = erc3009_deposit_nonce(channel_id, auth_salt)
        if isinstance(nonce, Refusal):
            return nonce
        token_auth = eip3009_typed_data(
            "ReceiveWithAuthorization",
            network=accepted["network"],
            asset=config["token"],
            name=extra["name"],
            version=extra["version"],
            from_=payer,
            to=ERC3009_DEPOSIT_COLLECTOR,
            value=str(deposit),
            valid_after=0,
            valid_before=deadline,
            nonce=nonce,
        )
    if isinstance(token_auth, Refusal):
        return token_auth
    amount = int(accepted["amount"])
    requests = [
        {"kind": "eip712", "typedData": token_auth},
        {"kind": "eip712", "typedData": voucher_request(chain_id, channel_id, amount)},
    ]

    def complete(signatures: Any) -> dict[str, Any] | Refusal:
        if not isinstance(signatures, list) or len(signatures) != 2:
            return Refusal("x402/signature-malformed")
        s1, s2 = signatures
        if not is_hex_signature(s1) or not is_hex_signature(s2):
            return Refusal("x402/signature-malformed")
        authorization: dict[str, Any] = (
            {
                "permit2Authorization": {
                    "from": payer,
                    "permitted": {"token": config["token"], "amount": str(deposit)},
                    "spender": PERMIT2_DEPOSIT_COLLECTOR,
                    "nonce": str(int(auth_salt[2:], 16)),
                    "deadline": str(deadline),
                    "witness": {"channelId": channel_id},
                    "signature": s1,
                }
            }
            if permit2
            else {
                "erc3009Authorization": {
                    "validAfter": "0",
                    "validBefore": str(deadline),
                    "salt": auth_salt,
                    "signature": s1,
                }
            }
        )
        return payment_with(
            required,
            accepted,
            {
                "type": "deposit",
                "channelConfig": dict(config),
                "voucher": {"channelId": channel_id, "maxClaimableAmount": str(amount), "signature": s2},
                "deposit": {"amount": str(deposit), "authorization": authorization},
            },
        )

    return BatchUnsigned(requests=requests, complete=complete)


def build_within(w: Mapping[str, Any], h: AtrHash) -> BatchUnsigned | Refusal:
    """A later voucher, or a refund, for a channel opened under h: one request, the voucher."""
    required, accepted = w.get("required"), w.get("accepted")
    ok = chosen(required, accepted, _FILTER)
    if ok is not True:
        return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
    assert is_object(required) and is_object(accepted)
    config = w.get("channelConfig")
    if not is_channel_config(config):
        return Refusal("x402/payload-malformed")
    if normal_hash(config["salt"]) != normal_hash(h):
        return Refusal("x402/channel-id-mismatch")
    max_claimable = w.get("maxClaimableAmount")
    if not _uint(max_claimable, 0):
        return Refusal("x402/option-malformed")
    assert isinstance(max_claimable, int)
    refund = w.get("refund")
    refund_amount = refund.get("amount") if is_object(refund) else None
    if refund_amount is not None and not _uint(refund_amount, 1):
        return Refusal("x402/option-malformed")
    chain_id = chain_id_of(accepted["network"])
    assert chain_id is not None
    channel_id = batch_channel_id(chain_id, config)
    if isinstance(channel_id, Refusal):
        return channel_id

    def complete(signatures: Any) -> dict[str, Any] | Refusal:
        if not isinstance(signatures, list) or len(signatures) != 1 or not is_hex_signature(signatures[0]):
            return Refusal("x402/signature-malformed")
        voucher = {"channelId": channel_id, "maxClaimableAmount": str(max_claimable), "signature": signatures[0]}
        payload: dict[str, Any]
        if refund is None:
            payload = {"type": "voucher", "channelConfig": config, "voucher": voucher}
        else:
            payload = {"type": "refund", "channelConfig": config, "voucher": voucher}
            if refund_amount is not None:
                payload["amount"] = str(refund_amount)
        return payment_with(required, accepted, payload)

    return BatchUnsigned(requests=[{"kind": "eip712", "typedData": voucher_request(chain_id, channel_id, max_claimable)}],
                         complete=complete)  # fmt: skip


@dataclass(frozen=True, slots=True)
class X402BatchSettlementEip155:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when the legal context names one, and the options this pairing can pay."""
        return read_for(_FILTER)(doc)

    def build(self, choice: Json, h: AtrHash) -> BatchUnsigned | Refusal:
        return build(choice, h)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        return bound(presented)

    def build_within(self, w: Mapping[str, Any], h: AtrHash) -> BatchUnsigned | Refusal:
        return build_within(w, h)

    def channel_kind(self, presented: Json) -> ChannelKind | Refusal:
        return channel_kind(presented)

    def channel_ref(self, presented: Json) -> ChannelRef | Refusal:
        return channel_ref(presented)

    def bound_within(self, presented: Json) -> AtrHash | Refusal:
        return bound_within(presented)
