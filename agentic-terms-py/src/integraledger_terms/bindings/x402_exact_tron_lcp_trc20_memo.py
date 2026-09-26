"""The buyer half of x402/exact/tron/lcp-trc20-memo: read, build with complete, and bound. The payer signs a TRC-20
transfer whose memo, raw_data.data, is the ATR hash's LCP string. Nothing here fetches or signs."""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._tron_proto import (
    INT64_LIMIT,
    SIGNATURE_BYTES,
    TronRaw,
    base58_shape,
    decode_tron_tx,
    encode_transaction,
    encode_tron_raw,
    tron_address,
)
from ._x402 import chosen, payment_with, presented_with, read_for

ID = "x402/exact/tron/lcp-trc20-memo"
LCP_TRC20_MEMO = "lcp-trc20-memo"
TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
CALL_DATA_BYTES = 68
MAX_TIMEOUT_SECONDS = 86_340
MAX_FEE_LIMIT = 15_000_000_000
UINT256_LIMIT = 1 << 256

_NETWORK = re.compile(r"tron:(0|[1-9][0-9]{0,15})")
_BLOCK_ID = re.compile(r"0x[0-9a-fA-F]{64}")
_DECIMAL = re.compile(r"[0-9]{1,78}")
_MAX_SAFE_INTEGER = 2**53 - 1
_BOM = b"\xef\xbb\xbf"


def check(o: Mapping[str, Any]) -> bool | Refusal | None:
    """True for an exact lcp-trc20-memo option on a tron: network that this pairing pays."""
    if not is_object(o) or o.get("scheme") != "exact":
        return Refusal("x402/option-not-this-pairing")
    network = o.get("network")
    if not isinstance(network, str) or not network.startswith("tron:"):
        return Refusal("x402/option-not-this-pairing")
    extra = o.get("extra")
    if not is_object(extra) or extra.get("assetTransferMethod") != LCP_TRC20_MEMO:
        return Refusal("x402/option-not-this-pairing")
    if "paymentFlow" in extra and extra["paymentFlow"] not in ("authorization", "upfront"):
        return Refusal("x402/option-not-this-pairing")
    m = _NETWORK.fullmatch(network)
    if m is None or int(m.group(1)) > _MAX_SAFE_INTEGER:
        return Refusal("tron/network-malformed")
    if base58_shape(o.get("asset")) is None or base58_shape(o.get("payTo")) is None:
        return Refusal("tron/address-malformed")
    amount = o.get("amount")
    if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None or int(amount) >= UINT256_LIMIT:
        return Refusal("tron/option-malformed")
    t = safe_int(o.get("maxTimeoutSeconds"))
    if t is None or not 1 <= t <= MAX_TIMEOUT_SECONDS:
        return Refusal("tron/option-malformed")
    return True


def _memo_hash(data: bytes) -> AtrHash | None:
    """The hash of a memo holding an LCP string in strict UTF-8; a leading byte-order mark is dropped."""
    try:
        text = (data[len(_BOM) :] if data.startswith(_BOM) else data).decode("utf-8")
    except UnicodeDecodeError:
        return None
    return from_lcp_string(text)


def _int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class TronUnsigned:
    """The 32-byte transaction id the payer signs, and how the signature completes the payment."""

    request: dict[str, Any]
    _raw_bytes: bytes
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signature: object) -> dict[str, Any] | Refusal:
        """Takes the 65-byte secp256k1 signature r ‖ s ‖ v, v in {0, 1, 27, 28}."""
        if not isinstance(signature, bytes) or len(signature) != SIGNATURE_BYTES:
            return Refusal("tron/signature-malformed")
        if signature[64] not in (0, 1, 27, 28):
            return Refusal("tron/signature-malformed")
        transaction = encode_transaction(self._raw_bytes, [signature]).hex()
        return payment_with(self._required, self._accepted, {"transaction": transaction})


@dataclass(frozen=True, slots=True)
class X402ExactTronLcpTrc20Memo:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the options this pairing pays, in document order."""
        return read_for(check)(doc)

    def build(self, c: Json, h: AtrHash) -> TronUnsigned | Refusal:
        """The unsigned transaction for the chosen option: one TriggerSmartContract calling transfer(payTo, amount)
        on the token, with the hash's LCP string as its memo."""
        if not is_object(c):
            return Refusal("x402/option-malformed")
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, check)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        owner = tron_address(c.get("payer"))
        if isinstance(owner, Refusal):
            return owner
        asset = tron_address(accepted.get("asset"))
        if isinstance(asset, Refusal):
            return asset
        pay_to = tron_address(accepted.get("payTo"))
        if isinstance(pay_to, Refusal):
            return pay_to
        fee_limit = c.get("feeLimit")
        if not isinstance(fee_limit, int) or not _int(fee_limit) or not 1 <= fee_limit <= MAX_FEE_LIMIT:
            return Refusal("tron/fee-limit")
        ref_block = c.get("refBlock")
        number = ref_block.get("number") if is_object(ref_block) else None
        if not isinstance(number, int) or not _int(number) or not 0 <= number < INT64_LIMIT:
            return Refusal("tron/tx-malformed")
        assert is_object(ref_block)
        block_id = ref_block.get("id")
        if not isinstance(block_id, str) or _BLOCK_ID.fullmatch(block_id) is None:
            return Refusal("tron/tx-malformed")
        now = c.get("now")
        if not isinstance(now, int) or not _int(now) or now < 1:
            return Refusal("tron/tx-malformed")
        timeout = safe_int(accepted.get("maxTimeoutSeconds"))
        assert timeout is not None
        expiration = now + timeout * 1000
        if expiration >= INT64_LIMIT:
            return Refusal("tron/tx-malformed")
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        amount = int(accepted["amount"])
        call_data = TRANSFER_SELECTOR + bytes(12) + pay_to[1:] + amount.to_bytes(32, "big")
        raw = TronRaw(
            ref_block_bytes=number.to_bytes(8, "big")[6:8],
            ref_block_hash=bytes.fromhex(block_id[2:])[8:16],
            expiration=expiration,
            data=to_lcp_string(nh).encode("utf-8"),
            owner=owner,
            contract_address=asset,
            call_data=call_data,
            timestamp=now,
            fee_limit=fee_limit,
        )
        raw_bytes = encode_tron_raw(raw)
        request = {"kind": "tron-txid", "txid": hashlib.sha256(raw_bytes).digest()}
        return TronUnsigned(request=request, _raw_bytes=raw_bytes, _required=required, _accepted=accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash in the memo of the transaction the payer signed, whose one contract calls transfer. The
        signature is not verified here."""
        p = presented_with(presented, check)
        if isinstance(p, Refusal):
            return p
        transaction = p[1].get("transaction")
        if not isinstance(transaction, str):
            return Refusal("x402/payload-malformed")
        tx = decode_tron_tx(transaction)
        if isinstance(tx, Refusal):
            return tx
        raw = tx[0]
        if len(raw.call_data) != CALL_DATA_BYTES or raw.call_data[:4] != TRANSFER_SELECTOR:
            return Refusal("tron/not-transfer")
        h = _memo_hash(raw.data)
        return h if h is not None else Refusal("tron/memo-not-lcp")
