"""The buyer half of the pairing x402/exact/ccd: read, build with complete, and bound.

The ATR hash rides in LCP's string form, as a CBOR text string, in the memo of the one transfer the sender signs.
Nothing here fetches, hashes the ATR or signs.

The signed transaction is read in x402's wire form, the JSON-serialized V1 sponsored transaction: with
@concordium/web-sdk, JSON.parse(Transaction.toJSONString(tx)). A value that is not JSON data is
ccd/transaction-malformed, never an exception.
"""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._cbor import UNDEFINED, CborMap, decode_cbor, is_tag, map_get
from ._codec import b58_decode, canonical_or_none
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._x402 import chosen, filter_of, payment_with, read_for

ID = "x402/exact/ccd"

_NETWORK = re.compile(r"ccd:[0-9a-f]{32}")
_TOKEN = re.compile(r"[\x21-\x7e]{1,128}")
_DECIMAL = re.compile(r"[0-9]{1,20}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2})*")
MAX_ADDRESS = 64
MAX_MEMO = 256
MAX_OPERATIONS = 4096
MAX_TRANSACTION = 16384
_UINT64_LIMIT = 1 << 64
_TEXT_PREFIX = bytes([0x78, 0x4D])
_TAG24_PREFIX = bytes([0xD8, 0x18, 0x58, 0x4F])


def ccd_memo(h: AtrHash) -> bytes:
    """The CBOR text string of the hash's LCP string: 78 4d and the 77 ASCII bytes."""
    return _TEXT_PREFIX + to_lcp_string(h).encode()


def plt_memo(h: AtrHash) -> bytes:
    """CBOR tag 24 around a byte string holding ccd_memo(h): d8 18 58 4f and the 79 bytes."""
    return _TAG24_PREFIX + ccd_memo(h)


def memo_carrier(memo: bytes) -> AtrHash | Refusal:
    """The hash a memo carries: exactly one CBOR text string, nothing after it, whose bytes are ccd_memo of the hash it
    names (LCP's string form with lowercase hex, under the preferred two-byte head)."""
    v = decode_cbor(memo) if len(memo) <= MAX_MEMO else None
    if not isinstance(v, str):
        return Refusal("ccd/memo-not-cbor-text")
    h = from_lcp_string(v)
    return h if h is not None and memo == ccd_memo(h) else Refusal("ccd/memo-not-lcp")


def _account_shape(s: object) -> bytes | None:
    """The 37 bytes a base58 account address decodes to, when their version byte is 1; the checksum is not checked."""
    if not isinstance(s, str) or len(s) == 0 or len(s) > MAX_ADDRESS:
        return None
    raw = b58_decode(s)
    return raw if raw is not None and len(raw) == 37 and raw[0] == 0x01 else None


def account_bytes(address: object) -> bytes | Refusal:
    """The 32 bytes of a base58check account address whose version byte is 1."""
    raw = _account_shape(address)
    if raw is None:
        return Refusal("ccd/address-malformed")
    twice = hashlib.sha256(hashlib.sha256(raw[:33]).digest()).digest()
    if twice[:4] != raw[33:37]:
        return Refusal("ccd/address-malformed")
    return raw[1:33]


def _is_account(v: object) -> bool:
    return isinstance(v, str) and not isinstance(account_bytes(v), Refusal)


def ccd_option(o: object) -> bool:
    """The pairing's filter: an exact option on a ccd: network, for CCD or a token symbol, whose payTo and
    extra.feePayer are base58check account addresses."""
    if not is_object(o):
        return False
    extra = o.get("extra")
    network, asset, amount = o.get("network"), o.get("asset"), o.get("amount")
    timeout = safe_int(o.get("maxTimeoutSeconds"))
    return (
        o.get("scheme") == "exact"
        and isinstance(network, str)
        and _NETWORK.fullmatch(network) is not None
        and isinstance(asset, str)
        and _TOKEN.fullmatch(asset) is not None
        and _is_account(o.get("payTo"))
        and is_object(extra)
        and _is_account(extra.get("feePayer"))
        and isinstance(amount, str)
        and _DECIMAL.fullmatch(amount) is not None
        and int(amount) < _UINT64_LIMIT
        and timeout is not None
        and timeout > 0
    )


CHECK = filter_of(ccd_option)


def _hex_bytes(v: object, limit: int) -> bytes | Refusal:
    if not isinstance(v, str) or _HEX.fullmatch(v) is None:
        return Refusal("ccd/transaction-malformed")
    if len(v) // 2 > limit:
        return Refusal("ccd/too-large")
    return bytes.fromhex(v)


def _memo_blob(v: object) -> bytes | Refusal:
    """The memo bytes of a transfer-with-memo payload in the SDK's JSON form: hex of a 2-byte big-endian length, then
    exactly that many bytes, at most 256."""
    b = _hex_bytes(v, MAX_MEMO + 2)
    if isinstance(b, Refusal):
        return b
    if len(b) < 2:
        return Refusal("ccd/transaction-malformed")
    n = int.from_bytes(b[:2], "big")
    if n > MAX_MEMO:
        return Refusal("ccd/too-large")
    if len(b) != 2 + n:
        return Refusal("ccd/transaction-malformed")
    return b[2:]


def _is_one(v: object) -> bool:
    return not isinstance(v, bool) and isinstance(v, (int, float)) and v == 1


def _token_transfer(ops: bytes) -> AtrHash | Refusal:
    """The carrier in the memo of the one transfer operation of a PLT TokenUpdate, with its recipient and amount
    mantissa read as the transfer's shape requires."""
    v = decode_cbor(ops)
    if not isinstance(v, list):
        return Refusal("ccd/operations-malformed")
    if len(v) != 1:
        return Refusal("ccd/operation-count")
    op = v[0]
    if not isinstance(op, CborMap) or len(op.pairs) != 1 or not (isinstance(op.pairs[0][0], str) and op.pairs[0][0] == "transfer"):
        return Refusal("ccd/operation-count")
    body = op.pairs[0][1]
    if not isinstance(body, CborMap):
        return Refusal("ccd/operations-malformed")

    memo = map_get(body, "memo")
    if memo is UNDEFINED:
        return Refusal("ccd/no-memo")
    memo_bytes = memo.value if is_tag(memo, 24) else memo
    if not isinstance(memo_bytes, bytes):
        return Refusal("ccd/operations-malformed")
    carrier = memo_carrier(memo_bytes)
    if isinstance(carrier, Refusal):
        return carrier

    recipient = map_get(body, "recipient")
    account = (
        map_get(recipient.value, 3) if is_tag(recipient, 40307) and isinstance(recipient.value, CborMap) else None
    )
    if not isinstance(account, bytes) or len(account) != 32:
        return Refusal("ccd/operations-malformed")

    amount = map_get(body, "amount")
    fraction = amount.value if is_tag(amount, 4) else None
    if not isinstance(fraction, list) or len(fraction) != 2:
        return Refusal("ccd/operations-malformed")
    mantissa = fraction[1]
    if isinstance(mantissa, bool) or not isinstance(mantissa, int) or mantissa < 0:
        return Refusal("ccd/operations-malformed")
    return carrier


def _json_size(value: object) -> int | None:
    """The UTF-8 length of a JSON value's serialization, or None for a value that is not JSON data: a type JSON has
    no value for, a non-finite number, a string that is not well formed, a member name that is not a string, or
    nesting past 64 levels."""
    text = canonical_or_none(value)
    return None if text is None else len(text.encode("utf-8"))


def _signed(presented: object) -> AtrHash | Refusal:
    """The carrier of the signed transaction's one transfer, after the transaction's shape, sender and transfer are
    read as reference reads them."""
    if not is_object(presented) or safe_int(presented.get("x402Version")) != 2:
        return Refusal("x402/not-v2")
    if not ccd_option(presented.get("accepted")):
        return Refusal("x402/option-not-this-pairing")
    payload = presented.get("payload")
    tx = payload.get("signedTransaction") if is_object(payload) else None
    if not is_object(tx):
        return Refusal("ccd/transaction-malformed")
    size = _json_size(tx)
    if size is None:
        return Refusal("ccd/transaction-malformed")
    if size > MAX_TRANSACTION:
        return Refusal("ccd/too-large")
    if not _is_one(tx.get("version")):
        return Refusal("ccd/not-v1")
    header, body = tx.get("header"), tx.get("payload")
    if not is_object(header) or not is_object(body):
        return Refusal("ccd/transaction-malformed")
    expiry = safe_int(header.get("expiry"))
    if expiry is None or expiry < 0:
        return Refusal("ccd/transaction-malformed")
    sender = header.get("sender")
    checked = account_bytes(sender) if isinstance(sender, str) else Refusal("ccd/address-malformed")
    if isinstance(checked, Refusal):
        return checked

    kind = body.get("type")
    if kind == "transferWithMemo":
        memo = _memo_blob(body.get("memo"))
        if isinstance(memo, Refusal):
            return memo
        carrier = memo_carrier(memo)
        if isinstance(carrier, Refusal):
            return carrier
        to = body.get("toAddress")
        receiver = account_bytes(to) if isinstance(to, str) else Refusal("ccd/address-malformed")
        if isinstance(receiver, Refusal):
            return receiver
        amount = body.get("amount")
        if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None or int(amount) >= _UINT64_LIMIT:
            return Refusal("ccd/transaction-malformed")
        return carrier
    if kind == "tokenUpdate":
        ops = _hex_bytes(body.get("operations"), MAX_OPERATIONS)
        if isinstance(ops, Refusal):
            return ops
        return _token_transfer(ops)
    if kind == "transfer":
        return Refusal("ccd/no-memo")
    return Refusal("ccd/payload-kind")


@dataclass(frozen=True, slots=True)
class CcdUnsigned:
    """The transfer the buyer's wallet assembles and signs, and the payment its signed transaction completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signed_transaction: Json) -> dict[str, Any] | Refusal:
        """The payment, for the sender-signed V1 sponsored transaction in x402's wire form: with @concordium/web-sdk,
        JSON.parse(Transaction.toJSONString(tx)). A value that is not a JSON object is ccd/transaction-malformed."""
        if not is_object(signed_transaction) or _json_size(signed_transaction) is None:
            return Refusal("ccd/transaction-malformed")
        return payment_with(self._required, self._accepted, {"signedTransaction": signed_transaction})


@dataclass(frozen=True, slots=True)
class X402ExactCcd:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(CHECK)(doc)

    def build(self, choice: Json, h: AtrHash) -> CcdUnsigned | Refusal:
        """One transfer to payTo whose memo carries the hash."""
        c = choice if is_object(choice) else {}
        required, accepted = c.get("required"), c.get("accepted")
        wrong = chosen(required, accepted, CHECK)
        if wrong is not True:
            return wrong if isinstance(wrong, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        sponsor = accepted["extra"]["feePayer"]
        now = safe_int(c.get("now"))
        if now is None or now < 0:
            return Refusal("ccd/option-malformed")
        if normal_hash(h) is None:
            return Refusal("ccd/memo-not-lcp")
        timeout = safe_int(accepted["maxTimeoutSeconds"])
        assert timeout is not None
        request = {
            "kind": "ccd-transfer",
            "network": accepted["network"],
            "sponsor": sponsor,
            "toAddress": accepted["payTo"],
            "asset": accepted["asset"],
            "amount": accepted["amount"],
            "memo": ccd_memo(h) if accepted["asset"] == "CCD" else plt_memo(h),
            "expiresBy": now + timeout,
        }
        return CcdUnsigned(request=request, _required=required, _accepted=accepted)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """The hash inside what the sender signed, in x402's wire form: the one transfer's memo. No signature is
        verified here."""
        return _signed(presented)
