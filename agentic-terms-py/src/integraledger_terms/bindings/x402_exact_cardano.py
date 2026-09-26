"""The buyer half of the pairing x402/exact/cardano: read, build with complete, and bound.

The ATR hash rides as a CIP-20 message (metadata label 674) that the payer's signed body commits to through
auxiliary_data_hash. Nothing here fetches, hashes the ATR or signs.
"""

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._cbor_spans import CborError, Item, SpanReader
from ._lcp import from_lcp_string, is_object, normal_hash
from ._rail_bytes import base64_bytes
from ._x402 import chosen, payment_with, presented_with, read_for

ID = "x402/exact/cardano"

# CIP-20 line 1 of the carrier; line 2 is the hash's 64 lower-case hex digits.
LCP_MARKER = "lcp:sha256:0x"
MAX_TX_BYTES = 64 * 1024
MAX_NONCE = 256
NETWORKS = {
    "cardano:mainnet": "cardano:mainnet",
    "cardano:preprod": "cardano:preprod",
    "cardano:preview": "cardano:preview",
    "cip34:1-764824073": "cardano:mainnet",
    "cip34:0-1": "cardano:preprod",
    "cip34:0-2": "cardano:preview",
}
_METHODS = ("script", "masumi")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_DECIMAL = re.compile(r"[0-9]{1,78}")
_LABEL_MESSAGE = 674
_TAG_ALONZO_AUX = 259


def auxiliary_data(h: AtrHash) -> bytes | Refusal:
    """The exact auxiliary data the payer attaches: #6.259({0: {674: {"msg": [LCP_MARKER, <64 hex>]}}}). A value that
    is not a 32-byte hash is x402/payload-malformed."""
    hex_ = normal_hash(h)
    if hex_ is None:
        return Refusal("x402/payload-malformed")
    return (
        bytes([0xD9, 0x01, 0x03, 0xA1, 0x00, 0xA1, 0x19, 0x02, 0xA2, 0xA1, 0x63]) + b"msg" + bytes([0x82])
        + bytes([0x60 + len(LCP_MARKER)]) + LCP_MARKER.encode() + bytes([0x78, 0x40]) + hex_[2:].encode()
    )  # fmt: skip


def _blake256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def _metadata_of(aux: Item) -> Item | None:
    """The metadata map of the three auxiliary data forms: a map, [metadata, scripts], or tag 259 with key 0."""
    if aux.kind == "map":
        return aux
    if aux.kind == "array":
        first: Item | None = aux.items[0] if aux.items else None
        return first if first is not None and first.kind == "map" else None
    if aux.kind == "tag" and aux.value == _TAG_ALONZO_AUX and aux.items[0].kind == "map":
        for k, v in aux.items[0].items:
            if k.kind == "uint" and k.value == 0 and v.kind == "map":
                return v  # type: ignore[no-any-return]
    return None


def _carrier(aux: Item) -> AtrHash | Refusal:
    """The one LCP_MARKER line followed by 64 lower-case hex digits in label 674's "msg" lines."""
    metadata = _metadata_of(aux)
    found: list[AtrHash] = []
    if metadata is not None:
        for label, value in metadata.items:
            if label.kind != "uint" or label.value != _LABEL_MESSAGE or value.kind != "map":
                continue
            for key, lines in value.items:
                if key.kind != "text" or key.value != "msg" or lines.kind != "array":
                    continue
                items = lines.items
                for i in range(len(items) - 1):
                    a, b = items[i], items[i + 1]
                    if a.kind != "text" or a.value != LCP_MARKER or b.kind != "text" or _HEX64.fullmatch(b.value) is None:
                        continue
                    h = from_lcp_string(LCP_MARKER + b.value)
                    if h is not None:
                        found.append(h)
    if not found:
        return Refusal("cardano/hash-not-carried")
    if len(found) > 1:
        return Refusal("cardano/ambiguous")
    return found[0]


@dataclass(frozen=True, slots=True)
class CardanoTx:
    tx_id: str
    ttl_slot: int | None
    h: AtrHash | Refusal


def _decode_bytes(data: bytes) -> CardanoTx | Refusal:
    try:
        r = SpanReader(data)
        top = r.item(0)
        if r.at != len(data):
            return Refusal("cardano/tx-malformed")
    except CborError:
        return Refusal("cardano/tx-malformed")
    if top.kind != "array" or len(top.items) != 4:
        return Refusal("cardano/tx-malformed")
    body, _, valid, aux = top.items
    if body.kind != "map" or not (valid.kind == "simple" and valid.value in (20, 21)):
        return Refusal("cardano/tx-malformed")
    fields: dict[int, Item] = {}
    for k, v in body.items:
        if k.kind != "uint" or k.value in fields:
            return Refusal("cardano/tx-malformed")
        fields[k.value] = v
    ttl = fields.get(3)
    if ttl is not None and ttl.kind != "uint":
        return Refusal("cardano/tx-malformed")
    aux_hash = fields.get(7)
    tx_id = "0x" + _blake256(data[body.start : body.end]).hex()
    ttl_slot = None if ttl is None else ttl.value

    if aux_hash is None or (aux.kind == "simple" and aux.value == 22):
        return Refusal("cardano/aux-missing")
    if aux_hash.kind != "bytes" or len(aux_hash.value) != 32:
        return Refusal("cardano/tx-malformed")
    if _blake256(data[aux.start : aux.end]) != aux_hash.value:
        return Refusal("cardano/aux-hash-mismatch")
    return CardanoTx(tx_id=tx_id, ttl_slot=ttl_slot, h=_carrier(aux))


def decode_cardano_tx(transaction: object) -> CardanoTx | Refusal:
    """A base64 transaction [body, witness set, bool, auxiliary data / nil], each item's bytes kept as received. The
    id is the Blake2b-256 of the body's bytes; the auxiliary data must hash to the body's key 7."""
    data = base64_bytes(transaction, MAX_TX_BYTES)
    if data == "too-large":
        return Refusal("cardano/tx-too-large")
    if data == "malformed":
        return Refusal("cardano/tx-malformed")
    assert isinstance(data, bytes)
    return _decode_bytes(data)


def cardano_option_check(option: object) -> Refusal | None:
    """None for an option this pairing can pay, or the refusal naming why not."""
    if not is_object(option) or option.get("scheme") != "exact":
        return Refusal("x402/option-not-this-pairing")
    network = option.get("network")
    if not isinstance(network, str) or not (network.startswith("cardano:") or network.startswith("cip34:")):
        return Refusal("x402/option-not-this-pairing")
    if network not in NETWORKS:
        return Refusal("cardano/network-malformed")
    if "extra" in option and not is_object(option["extra"]):
        return Refusal("x402/option-not-this-pairing")
    extra = option.get("extra")
    if is_object(extra) and "assetTransferMethod" in extra and extra["assetTransferMethod"] not in _METHODS:
        return Refusal("x402/option-not-this-pairing")
    if is_object(extra) and "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return Refusal("x402/option-not-this-pairing")
    amount = option.get("amount")
    if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None:
        return Refusal("x402/option-not-this-pairing")
    return None


def _check(option: Mapping[str, Any]) -> bool | Refusal | None:
    refused = cardano_option_check(option)
    return True if refused is None else refused


def _presented_tx(presented: object) -> CardanoTx | Refusal:
    parts = presented_with(presented, _check)
    if isinstance(parts, Refusal):
        return parts
    _, payload, _ = parts
    transaction, nonce = payload.get("transaction"), payload.get("nonce")
    if not isinstance(transaction, str):
        return Refusal("x402/payload-malformed")
    if not isinstance(nonce, str) or len(nonce.encode("utf-16-le", "surrogatepass")) // 2 > MAX_NONCE:
        return Refusal("x402/payload-malformed")
    return decode_cardano_tx(transaction)


def _bound(presented: object) -> AtrHash | Refusal:
    tx = _presented_tx(presented)
    return tx if isinstance(tx, Refusal) else tx.h


def _reference_refuses(presented: object) -> bool:
    """Whether reference refuses the payment: its transaction does not decode, or has no TTL."""
    tx = _presented_tx(presented)
    return isinstance(tx, Refusal) or tx.ttl_slot is None


@dataclass(frozen=True, slots=True)
class CardanoUnsigned:
    """The wallet request, the scheme's payment with a TTL and these auxiliary data, and the payment the wallet's
    signed transaction completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _expected: AtrHash

    def complete(self, signed: Mapping[str, str]) -> dict[str, Any] | Refusal:
        """The payment, when what the payer signed carries the built hash and has a TTL."""
        payment = payment_with(self._required, self._accepted, signed)
        got = _bound(payment)
        if isinstance(got, Refusal) or got != self._expected or _reference_refuses(payment):
            return Refusal("x402/signed-not-bound")
        return payment


@dataclass(frozen=True, slots=True)
class X402ExactCardano:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(_check)(doc)

    def build(self, choice: Json, h: AtrHash) -> CardanoUnsigned | Refusal:
        """The wallet request: the scheme's payment with a TTL, and these auxiliary data committed in the signed
        body."""
        c = choice if is_object(choice) else {}
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _check)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        expected = normal_hash(h)
        if expected is None:
            return Refusal("x402/payload-malformed")
        aux = auxiliary_data(expected)
        if isinstance(aux, Refusal):
            return aux
        request = {"kind": "cardano-transaction", "accepted": accepted, "auxiliaryData": aux}
        return CardanoUnsigned(request=request, _required=required, _accepted=accepted, _expected=expected)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """The hash in the CIP-20 message the signed body commits to. Witnesses are not verified here."""
        return _bound(presented)
