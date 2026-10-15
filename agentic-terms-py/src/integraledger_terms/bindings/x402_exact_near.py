"""The buyer half of x402/exact/near: read, build with complete, and bound. The payer signs a NEP-366 delegate action
for one NEP-141 ft_transfer whose memo argument is the ATR hash's LCP string. Nothing here fetches or signs."""

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._borsh_near import (
    U64_LIMIT,
    U128_LIMIT,
    DelegateAction,
    FunctionCall,
    decode_signed_delegate,
    delegate_hash,
    encode_signed_delegate,
    public_key_of,
)
from ._codec import b64_decode, js_json
from ._jose import js_length, parse_json
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._x402 import chosen, is_amount, payment_with, presented_with, read_for, timeout_seconds

ID = "x402/exact/near"
FT_TRANSFER_GAS = 30_000_000_000_000
MAX_SDA_BASE64 = 8192
MAX_ARGS_BYTES = 4096

_ACCOUNT = re.compile(r"[a-z0-9._-]{2,64}")
_DECIMAL = re.compile(r"[0-9]{1,78}")


def _account(value: object) -> bool:
    return isinstance(value, str) and _ACCOUNT.fullmatch(value) is not None


def _decimal_below(value: object, limit: int) -> int | None:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        return None
    n = int(value)
    return n if n < limit else None


def check(o: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """True for an exact option on near:mainnet or near:testnet that this pairing pays."""
    if not is_object(o) or o.get("scheme") != "exact":
        return Refusal("x402/option-not-this-pairing")
    network = o.get("network")
    if not isinstance(network, str) or not network.startswith("near:"):
        return Refusal("x402/option-not-this-pairing")
    extra = o.get("extra")
    if "extra" in o and not is_object(extra):
        return Refusal("near/option-malformed")
    if is_object(extra) and "assetTransferMethod" in extra:
        return Refusal("x402/option-not-this-pairing")
    if is_object(extra) and "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return Refusal("x402/option-not-this-pairing")
    if network not in ("near:mainnet", "near:testnet"):
        return Refusal("near/network-malformed")
    if not _account(o.get("asset")) or not _account(o.get("payTo")):
        return Refusal("near/option-malformed")
    if not is_amount(o.get("amount")) or _decimal_below(o.get("amount"), U128_LIMIT) is None:
        return Refusal("near/option-malformed")
    if timeout_seconds(o.get("maxTimeoutSeconds")) is None:
        return Refusal("near/option-malformed")
    return True


def ft_transfer_args(pay_to: str, amount: str, h: AtrHash) -> bytes | Refusal:
    """ft_transfer's arguments: receiver_id, amount and memo, in that order, as JSON.stringify writes them. A value
    that is not a 32-byte hash is x402/payload-malformed."""
    nh = normal_hash(h)
    if nh is None:
        return Refusal("x402/payload-malformed")
    return js_json({"receiver_id": pay_to, "amount": amount, "memo": to_lcp_string(nh)}).encode("utf-8")



def _memo_of(args: bytes) -> AtrHash | Refusal:
    """The hash in the memo of a JSON object of ft_transfer arguments, strict UTF-8 text whose leading byte-order mark
    is a character, so arguments that begin with one are not JSON."""
    if len(args) > MAX_ARGS_BYTES:
        return Refusal("near/args-malformed")
    try:
        text = args.decode("utf-8")
    except UnicodeDecodeError:
        return Refusal("near/args-malformed")
    parsed = parse_json(text)
    if not isinstance(parsed, dict):
        return Refusal("near/args-malformed")
    memo = parsed.get("memo")
    if not isinstance(memo, str):
        return Refusal("near/memo-missing")
    h = from_lcp_string(memo)
    return h if h is not None else Refusal("near/memo-not-lcp")


def near_carrier(signed_delegate_action: object) -> AtrHash | Refusal:
    """The hash in a SignedDelegateAction, padded standard base64 in its canonical form (RFC 4648 §3.5) of at most
    8192 UTF-16 code units, whose one action is a FunctionCall of ft_transfer with a JSON object of arguments whose memo
    is an LCP string. The bytes must be exactly the borsh encoding of what is read, every string in it UTF-8."""
    if not isinstance(signed_delegate_action, str):
        return Refusal("near/sda-malformed")
    if js_length(signed_delegate_action) > MAX_SDA_BASE64:
        return Refusal("near/sda-too-large")
    data = None if signed_delegate_action == "" else b64_decode(signed_delegate_action)
    if data is None:
        return Refusal("near/sda-malformed")
    decoded = decode_signed_delegate(data)
    if decoded is None:
        return Refusal("near/sda-malformed")
    da = decoded[0]
    if len(da.actions) != 1:
        return Refusal("near/actions")
    call = da.actions[0][1]
    if not isinstance(call, FunctionCall) or call.method_name != "ft_transfer":
        return Refusal("near/not-ft-transfer")
    return _memo_of(call.args)


@dataclass(frozen=True, slots=True)
class NearUnsigned:
    """The SHA-256 of the NEP-461-prefixed delegate action, which the key signs, and how the signature completes the
    payment."""

    request: dict[str, Any]
    _delegate: DelegateAction
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signature: object) -> dict[str, Any] | Refusal:
        """Takes {keyType: 0 for Ed25519 or 1 for secp256k1, bytes: its 64- or 65-byte signature}. keyType is a JSON
        number: an integral float reads as its integer."""
        if not is_object(signature) or not isinstance(signature.get("bytes"), bytes):
            return Refusal("x402/signature-malformed")
        key_type, data = safe_int(signature.get("keyType")), signature["bytes"]
        if key_type is None or (key_type, len(data)) not in ((0, 64), (1, 65)):
            return Refusal("x402/signature-malformed")
        sda = base64.b64encode(encode_signed_delegate(self._delegate, key_type, data)).decode("ascii")
        return payment_with(self._required, self._accepted, {"signedDelegateAction": sda})


def _big(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class X402ExactNear:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the options this pairing pays, in document order."""
        return read_for(check)(doc)

    def build(self, c: Json, h: AtrHash) -> NearUnsigned | Refusal:
        """The delegate action for the chosen option: one ft_transfer whose memo is the hash's LCP string, with the
        key's next nonce and a window of maxTimeoutSeconds blocks past the final height."""
        if not is_object(c):
            return Refusal("x402/option-malformed")
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, check)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        payer = c.get("payer")
        if not isinstance(payer, str) or not _account(payer):
            return Refusal("x402/option-malformed")
        key = public_key_of(c.get("publicKey"))
        if key is None:
            return Refusal("x402/option-malformed")
        nonce = c.get("accessKeyNonce")
        if not isinstance(nonce, int) or not _big(nonce) or nonce < 0 or nonce + 1 >= U64_LIMIT:
            return Refusal("x402/option-malformed")
        # x402's NEAR scheme opens max(1, ceil(maxTimeoutSeconds / estimatedBlockSeconds)) blocks; with one-second
        # blocks and the positive timeout the filter holds, that is maxTimeoutSeconds blocks.
        window = timeout_seconds(accepted.get("maxTimeoutSeconds"))
        assert window is not None
        height = c.get("finalHeight")
        if not isinstance(height, int) or not _big(height) or height < 0 or height + window >= U64_LIMIT:
            return Refusal("x402/option-malformed")
        args = ft_transfer_args(accepted["payTo"], accepted["amount"], nh)
        if isinstance(args, Refusal):
            return args
        call = FunctionCall("ft_transfer", args, FT_TRANSFER_GAS, 1)
        delegate = DelegateAction(payer, accepted["asset"], ((2, call),), nonce + 1, height + window, key)
        request = {"kind": "near-delegate", "hash": delegate_hash(delegate)}
        return NearUnsigned(request=request, _delegate=delegate, _required=required, _accepted=accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the memo of the ft_transfer the payer's delegate action signs. The signature is not verified
        here."""
        p = presented_with(presented, check)
        if isinstance(p, Refusal):
            return p
        sda = p[1].get("signedDelegateAction")
        if not isinstance(sda, str):
            return Refusal("x402/payload-malformed")
        return near_carrier(sda)
