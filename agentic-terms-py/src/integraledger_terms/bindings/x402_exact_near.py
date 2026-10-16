"""The buyer half of x402/exact/near: read, build with complete, and bound. The payer signs a NEP-366 delegate action
for one NEP-141 ft_transfer whose memo argument is the ATR hash's LCP string. Nothing here fetches or signs."""

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Json, Refusal
from ._borsh_near import (
    U64_LIMIT,
    U128_LIMIT,
    DelegateAction,
    FunctionCall,
    decode_signed_delegate,
    delegate_hash,
    encode_signed_delegate,
    is_near_account_id,
    is_near_ed25519_signature,
    public_key_of,
)
from ._codec import b64_decode, js_json
from ._jose import js_length, member_names, parse_json
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._x402 import chosen, is_amount, payment_with, presented_with, read_for, timeout_seconds, x402_broadcaster

ID = "x402/exact/near"
FT_TRANSFER_GAS = 30_000_000_000_000
MAX_SDA_BASE64 = 8192
MAX_ARGS_BYTES = 4096

_DECIMAL = re.compile(r"[0-9]{1,78}")
# The keys the token contract's ft_transfer reads.
_TRANSFER_KEYS = frozenset({"receiver_id", "amount", "memo"})
# u128::from_str's text: an optional '+', then one or more ASCII digits.
_U128_TEXT = re.compile(r"\+?[0-9]+")


def _decimal_below(value: object, limit: int) -> int | None:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        return None
    n = int(value)
    return n if n < limit else None


def _is_transfer_amount(value: object) -> bool:
    """True for an amount the option filter serves and ft_transfer_args writes: the canonical decimal string of a
    positive integer (is_amount) below 2^128, so no sign, point, exponent, space or leading zero."""
    return is_amount(value) and _decimal_below(value, U128_LIMIT) is not None


def check(o: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """True for an exact option on near:mainnet or near:testnet that this pairing pays: its asset and payTo are each
    a NEAR account id (is_near_account_id), or the option is near/option-malformed."""
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
    if not is_near_account_id(o.get("asset")) or not is_near_account_id(o.get("payTo")):
        return Refusal("near/option-malformed")
    if not _is_transfer_amount(o.get("amount")):
        return Refusal("near/option-malformed")
    if timeout_seconds(o.get("maxTimeoutSeconds")) is None:
        return Refusal("near/option-malformed")
    return True


def ft_transfer_args(pay_to: str, amount: str, h: AtrHash) -> bytes | Refusal:
    """ft_transfer's arguments: receiver_id, amount and memo, in that order, as JSON.stringify writes them. A pay_to
    that is not a NEAR account id is near/option-malformed, as the option filter answers an option carrying it, since
    the token contract reads receiver_id as an AccountId. So is an amount that is not the canonical decimal string of
    a positive integer below 2^128 (no sign, no leading zero, not "0"), within the U128 the contract reads amount as.
    Then a value that is not a 32-byte hash is x402/payload-malformed."""
    if not is_near_account_id(pay_to):
        return Refusal("near/option-malformed")
    if not _is_transfer_amount(amount):
        return Refusal("near/option-malformed")
    nh = normal_hash(h)
    if nh is None:
        return Refusal("x402/payload-malformed")
    return js_json({"receiver_id": pay_to, "amount": amount, "memo": to_lcp_string(nh)}).encode("utf-8")


def _token_reads(text: str, parsed: Mapping[str, Any]) -> bool:
    """True for ft_transfer arguments the token contract reads. near-sdk reads a JSON method's arguments with
    serde_json::from_slice into a struct serde derives from the method's parameters, here receiver_id: AccountId,
    amount: U128 and memo: Option<String>, and it refuses unknown keys only for a method marked
    deny_unknown_arguments. serde_json reads each key of the object as a string, refusing an escape that decodes to a
    lone surrogate. The derived reader refuses a key it names that appears twice, and skips any other key each time it
    appears. AccountId is a NEAR account id; U128 is a string that Rust's u128::from_str reads: an optional '+', then
    one or more ASCII digits, leading zeros allowed, at most 2^128 - 1. The memo is read after, by _memo_of."""
    named: set[str] = set()
    for key in member_names(text):
        if any("\ud800" <= c <= "\udfff" for c in key):
            return False
        if key not in _TRANSFER_KEYS:
            continue
        if key in named:
            return False
        named.add(key)
    if not is_near_account_id(parsed.get("receiver_id")):
        return False
    amount = parsed.get("amount")
    if not isinstance(amount, str) or _U128_TEXT.fullmatch(amount) is None:
        return False
    digits = amount.removeprefix("+").lstrip("0")
    return len(digits) <= len(str(U128_LIMIT)) and int(digits or "0") < U128_LIMIT


def _memo_of(args: bytes) -> AtrHash | Refusal:
    """The hash in the memo of ft_transfer arguments read only as the token contract reads them: strict UTF-8 JSON
    text of at most 4096 bytes, whose leading byte-order mark is a character, so arguments that begin with one are not
    JSON, and whose value is an object that _token_reads takes; anything else is near/args-malformed. Then a memo that
    is not a string is near/memo-missing, and one that is not an LCP string near/memo-not-lcp."""
    if len(args) > MAX_ARGS_BYTES:
        return Refusal("near/args-malformed")
    try:
        text = args.decode("utf-8")
    except UnicodeDecodeError:
        return Refusal("near/args-malformed")
    parsed = parse_json(text)
    if not isinstance(parsed, dict) or not _token_reads(text, parsed):
        return Refusal("near/args-malformed")
    memo = parsed.get("memo")
    if not isinstance(memo, str):
        return Refusal("near/memo-missing")
    h = from_lcp_string(memo)
    return h if h is not None else Refusal("near/memo-not-lcp")


_DELEGATE_REFUSED = {
    "malformed": "near/sda-malformed",
    "action-count": "near/actions",
    "not-function-call": "near/not-ft-transfer",
}


def near_carrier(signed_delegate_action: object) -> AtrHash | Refusal:
    """The hash in a SignedDelegateAction, padded standard base64 in its canonical form (RFC 4648 §3.5) of at most
    8192 UTF-16 code units, whose one action is a FunctionCall of ft_transfer with a JSON object of arguments whose
    receiver_id is a NEAR account id and whose memo is an LCP string. The bytes are read in the order nearcore reads
    them: the sender and the receiver, where one that is not UTF-8, or not a NEAR account id, is near/sda-malformed,
    then the count of actions, where a count other than one is near/actions, then the action's variant index, where
    any index other than FunctionCall's is near/not-ft-transfer, the bytes after it unread. Otherwise the bytes must be
    exactly the borsh encoding of what is read, every string in it UTF-8, the key and the signature each Ed25519 or
    secp256k1, and an Ed25519 signature's last byte below 0x20, as nearcore reads one, or they are near/sda-malformed.
    The arguments are strict UTF-8 JSON text whose leading byte-order mark is kept as a character, so arguments that
    begin with one are near/args-malformed. So are arguments the token contract refuses: it reads them as near-sdk does,
    with serde's derived reader over receiver_id: AccountId, amount: U128 and memo: Option<String>. Those are arguments
    whose object names receiver_id, amount or memo more than once, each key read with its escapes decoded, or has a key
    that decodes to a lone surrogate, or whose receiver_id is not a NEAR account id, or whose amount is not a string of
    an optional '+' and one or more ASCII digits below 2^128, leading zeros allowed (Rust's u128::from_str). Any other
    key is ignored, however often it repeats. Then a memo that is not a string is near/memo-missing, and one that is not
    an LCP string near/memo-not-lcp. The amount is not compared with the option's. A NEAR account id is 2 to 64
    characters, each a lowercase ASCII letter, a digit, '-', '_' or '.', where a separator ('-', '_' or '.') is never
    first, never last, and never follows another (near-account-id's AccountId)."""
    if not isinstance(signed_delegate_action, str):
        return Refusal("near/sda-malformed")
    if js_length(signed_delegate_action) > MAX_SDA_BASE64:
        return Refusal("near/sda-too-large")
    data = None if signed_delegate_action == "" else b64_decode(signed_delegate_action)
    if data is None:
        return Refusal("near/sda-malformed")
    decoded = decode_signed_delegate(data)
    if isinstance(decoded, str):
        return Refusal(_DELEGATE_REFUSED[decoded])
    call = decoded[0].function_call
    if call.method_name != "ft_transfer":
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
        number: an integral float reads as its integer. An Ed25519 signature whose last byte is 0x20 or more is
        x402/signature-malformed: nearcore reads none, and a valid signature never has one."""
        if not is_object(signature) or not isinstance(signature.get("bytes"), bytes):
            return Refusal("x402/signature-malformed")
        key_type, data = safe_int(signature.get("keyType")), signature["bytes"]
        ed25519 = key_type == 0 and is_near_ed25519_signature(data)
        if key_type is None or not (ed25519 or (key_type == 1 and len(data) == 65)):
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
        key's next nonce and a window of maxTimeoutSeconds blocks past the final height. publicKey is read as
        nearcore's PublicKey::from_str reads it: the key type before the first ':', ed25519 or secp256k1 in ASCII
        letters of either case, or no key type, which is Ed25519; then the base58 of exactly that type's key size, 32
        bytes or 64. Any other text is x402/option-malformed."""
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
        if not is_near_account_id(payer):
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
        delegate = DelegateAction(payer, accepted["asset"], call, nonce + 1, height + window, key)
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

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: a relayer of the seller's facilitator submits the delegate action the payer signed. The
        payment is held to x402_shape's gate, the one bound applies first; any other gets its refusal."""
        return x402_broadcaster(presented, "payee")
