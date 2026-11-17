"""The buyer half of x402/exact/tron/lcp-trc20-memo: read, build with complete, and bound. The payer signs a TRC-20
transfer whose memo, raw_data.data, is the ATR hash's LCP string. Nothing here fetches or signs."""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._codec import b58_encode
from ._tron_proto import (
    INT64_LIMIT,
    MAX_TX_HEX,
    SIGNATURE_BYTES,
    TronRaw,
    decode_raw,
    decode_tron_tx,
    encode_transaction,
    encode_tron_raw,
    tron_address,
)
from ._x402 import chosen, is_amount, payment_with, presented_with, read_for, timeout_seconds, x402_broadcaster

ID = "x402/exact/tron/lcp-trc20-memo"
LCP_TRC20_MEMO = "lcp-trc20-memo"
TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")
CALL_DATA_BYTES = 68
MAX_TIMEOUT_SECONDS = 86_340
MAX_FEE_LIMIT = 15_000_000_000
UINT256_LIMIT = 1 << 256
# The contracts a run has shown to succeed and log Transfer on a transfer(to, 0), each by its network and its
# base58check address, as @integraledger/lcp's TRON_ZERO_SHOWN lists them: the option filter admits "0" for these alone,
# every other contract taking one base unit. Empty until a run on a test network shows one.
TRON_ZERO_SHOWN: tuple[tuple[str, str], ...] = ()

_NETWORK = re.compile(r"tron:(0|[1-9][0-9]{0,15})")
_BLOCK_ID = re.compile(r"0x[0-9a-fA-F]{64}")
_DECIMAL = re.compile(r"[0-9]{1,78}")
_MAX_SAFE_INTEGER = 2**53 - 1


def check(o: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """True for an exact lcp-trc20-memo option on a tron: network that this pairing pays, whose asset and payTo are
    base58check addresses, and whose amount is positive, or "0" on a contract TRON_ZERO_SHOWN names."""
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
    if isinstance(tron_address(o.get("asset")), Refusal) or isinstance(tron_address(o.get("payTo")), Refusal):
        return Refusal("tron/address-malformed")
    amount = o.get("amount")
    zero = amount == "0" and (network, o.get("asset")) in TRON_ZERO_SHOWN
    if not zero and (not is_amount(amount) or _DECIMAL.fullmatch(amount) is None or int(amount) >= UINT256_LIMIT):
        return Refusal("tron/option-malformed")
    t = timeout_seconds(o.get("maxTimeoutSeconds"))
    if t is None or t > MAX_TIMEOUT_SECONDS:
        return Refusal("tron/option-malformed")
    return True


def _memo_hash(data: bytes) -> AtrHash | None:
    """The hash of a memo holding an LCP string in strict UTF-8. A leading byte-order mark is a character, so a memo
    that begins with one holds no hash."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return from_lcp_string(text)


def _int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _base58check(payload: bytes) -> str:
    """Bytes in base58check: the bytes and the first four of SHA-256 twice over them, in base58."""
    return b58_encode(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4])


@dataclass(frozen=True, slots=True)
class TronRequest:
    """What tron_request reads of a tron-txid request's raw data, as @integraledger/lcp's tronRequest gives it: txid,
    its SHA-256, which is the request's txid when the bytes are its rawBytes; raw, every field the bytes hold, which
    are all the fields decode_raw admits: the reference block's bytes and hash, expiration and timestamp in
    milliseconds, the memo data, fee_limit in sun, and the one contract, a TriggerSmartContract with no call value
    from owner to contract_address whose call data is transfer(address,uint256); and read from them, payer, the owner,
    and asset, the contract, in base58check; pay_to, the transfer's recipient, its address word's last 20 bytes under
    0x41, in base58check; amount, the transfer's value, in decimal; and h, the hash the memo carries."""

    txid: bytes
    raw: TronRaw
    payer: str
    asset: str
    pay_to: str
    amount: str
    h: AtrHash


def tron_request(raw_bytes: object) -> TronRequest | Refusal:
    """Reads the raw_data a tron-txid request carries, as decode_tron_tx reads a signed transaction's and bound reads
    its call and memo, with their codes: call data that is not transfer(address,uint256) is tron/not-transfer, and a
    memo that holds no LCP string tron/memo-not-lcp. Bytes longer than the longest transaction decode_tron_tx reads,
    4,096 bytes, are tron/tx-too-large, and a value that is not bytes tron/tx-malformed."""
    if not isinstance(raw_bytes, bytes):
        return Refusal("tron/tx-malformed")
    if len(raw_bytes) > MAX_TX_HEX // 2:
        return Refusal("tron/tx-too-large")
    raw = decode_raw(raw_bytes)
    if isinstance(raw, Refusal):
        return raw
    call = raw.call_data
    if len(call) != CALL_DATA_BYTES or call[:4] != TRANSFER_SELECTOR:
        return Refusal("tron/not-transfer")
    h = _memo_hash(raw.data)
    if h is None:
        return Refusal("tron/memo-not-lcp")
    return TronRequest(
        txid=hashlib.sha256(raw_bytes).digest(),
        raw=raw,
        payer=_base58check(raw.owner),
        asset=_base58check(raw.contract_address),
        pay_to=_base58check(b"\x41" + call[16:36]),
        amount=str(int.from_bytes(call[36:], "big")),
        h=h,
    )


@dataclass(frozen=True, slots=True)
class TronUnsigned:
    """What the payer signs, the request: rawBytes, the transaction's raw_data as encode_tron_raw writes it, and txid,
    its SHA-256, the 32-byte transaction id, which tron_request reads; and how the signature completes the payment."""

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
    coverage: Coverage = "full"
    agreement: AgreementData | None = AgreementData(floor="1")

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the options this pairing pays, in document order."""
        return read_for(check)(doc)

    def build(self, c: Json, h: AtrHash, act: Act | None = None) -> TronUnsigned | Refusal:
        """The unsigned transaction for the chosen option: one TriggerSmartContract calling transfer(payTo, amount)
        on the token, with the hash's LCP string as its memo. H is checked first, then the form of the choice's payer,
        fee limit, reference block and now, then its document and option, then the expiration now and the option's
        timeout give."""
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        if not is_object(c):
            return Refusal("x402/option-malformed")
        owner = tron_address(c.get("payer"))
        if isinstance(owner, Refusal):
            return owner
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
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, check)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        asset = tron_address(accepted.get("asset"))
        if isinstance(asset, Refusal):
            return asset
        pay_to = tron_address(accepted.get("payTo"))
        if isinstance(pay_to, Refusal):
            return pay_to
        timeout = safe_int(accepted.get("maxTimeoutSeconds"))
        assert timeout is not None
        expiration = now + timeout * 1000
        if expiration >= INT64_LIMIT:
            return Refusal("tron/tx-malformed")
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
        request = {"kind": "tron-txid", "txid": hashlib.sha256(raw_bytes).digest(), "rawBytes": raw_bytes}
        return TronUnsigned(request=request, _raw_bytes=raw_bytes, _required=required, _accepted=accepted)

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
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

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's facilitator broadcasts the TRC-20 transfer the payer signed. The payment
        is held to x402_shape's gate, the one bound applies first; any other gets its refusal."""
        return x402_broadcaster(presented, "payee")
