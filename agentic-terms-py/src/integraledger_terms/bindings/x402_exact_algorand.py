"""The buyer half of the pairing x402/exact/algorand: read, build with complete, and bound.

The payer signs an asset transfer whose note is the ATR hash's LCP string; with the option's fee payer, it is grouped
after that fee payer's zero payment, which carries both fees. Nothing here fetches or signs.
"""

import base64
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from . import _algorand
from ._codec import b64_encode
from ._lcp import from_lcp_string, is_list, is_object, normal_hash, safe_int, to_lcp_string
from ._x402 import chosen, payment_with, presented_with, read_for

ID = "x402/exact/algorand"

_NETWORK = re.compile(r"algorand:([-_a-zA-Z0-9]{32})")
_ASSET = re.compile(r"0|[1-9][0-9]{0,19}")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_UINT64_LIMIT = 1 << 64
MAX_GROUP = 16
MAX_ENTRY = 8192
MAX_NOTE = 4096
MAX_TXN_LIFE = 1000


def _uint64(value: object) -> int | None:
    if not isinstance(value, str) or _ASSET.fullmatch(value) is None:
        return None
    number = int(value)
    return number if number < _UINT64_LIMIT else None


def _base64(value: object) -> bytes | None:
    """Standard padded base64, or None."""
    if not isinstance(value, str) or len(value) % 4 != 0 or _BASE64.fullmatch(value) is None:
        return None
    return base64.b64decode(value)


def check(option: Mapping[str, Any]) -> bool | Refusal | None:
    """The pairing's option filter: True for an option it serves, a refusal naming why an option on an algorand
    network cannot be served, and None for any other option."""
    network = option.get("network") if is_object(option) else None
    if not isinstance(network, str) or not network.startswith("algorand:") or option.get("scheme") != "exact":
        return None
    extra = option.get("extra")
    if "extra" in option and not is_object(extra):
        return Refusal("avm/option-malformed")
    if _NETWORK.fullmatch(network) is None:
        return Refusal("avm/network-malformed")
    extra_map: Mapping[str, Any] = extra if is_object(extra) else {}
    if "assetTransferMethod" in extra_map:
        return Refusal("avm/option-malformed")
    if "paymentFlow" in extra_map and extra_map["paymentFlow"] != "authorization":
        return Refusal("avm/option-malformed")
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    if (
        _uint64(option.get("asset")) is None
        or not _algorand.is_address(option.get("payTo"))
        or ("feePayer" in extra_map and not _algorand.is_address(extra_map["feePayer"]))
        or _uint64(option.get("amount")) is None
        or timeout is None
        or timeout <= 0
    ):
        return Refusal("avm/option-malformed")
    return True


@dataclass(frozen=True, slots=True)
class Carried:
    h: AtrHash


def carrier(payload: object) -> Carried | Refusal:
    """The hash in paymentGroup[paymentIndex]'s note, decoded as a signed asset transfer."""
    if not is_object(payload) or not is_list(payload.get("paymentGroup")):
        return Refusal("avm/txn-malformed")
    group = payload["paymentGroup"]
    if len(group) < 1 or len(group) > MAX_GROUP:
        return Refusal("avm/group-too-large")
    index = safe_int(payload.get("paymentIndex"))
    if index is None or index < 0 or index >= len(group):
        return Refusal("avm/index-out-of-range")
    entry = group[index]
    if not isinstance(entry, str) or len(entry) > MAX_ENTRY:
        return Refusal("avm/txn-malformed")
    data = _base64(entry)
    if data is None:
        return Refusal("avm/txn-malformed")
    try:
        txn = _algorand.read_signed(data)
    except (_algorand.Malformed, RecursionError):
        return Refusal("avm/txn-malformed")
    if txn.kind != "axfer":
        return Refusal("avm/not-axfer")
    if len(txn.note) > MAX_NOTE:
        return Refusal("avm/txn-malformed")
    try:
        note = txn.note.decode("utf-8")
    except UnicodeDecodeError:
        return Refusal("avm/note-not-lcp")
    h = from_lcp_string(note)
    return Refusal("avm/note-not-lcp") if h is None else Carried(h)


@dataclass(frozen=True, slots=True)
class AvmUnsigned:
    """The bytes the payer signs, and how the signature completes the payment."""

    request: dict[str, Any]
    _group: tuple[_algorand.Transaction, ...]
    _index: int
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signature: object) -> dict[str, Any] | Refusal:
        """The payment with each transaction as a base64 msgpack SignedTxn, the payer's with its 64-byte signature."""
        if not isinstance(signature, bytes) or len(signature) != 64:
            return Refusal("avm/signature-malformed")
        group = [b64_encode(t.signed(signature if i == self._index else None)) for i, t in enumerate(self._group)]
        return payment_with(self._required, self._accepted, {"paymentIndex": self._index, "paymentGroup": group})


def _is_uint(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


@dataclass(frozen=True, slots=True)
class X402ExactAlgorand:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        return read_for(check)(doc)

    def build(self, choice: Json, h: AtrHash) -> AvmUnsigned | Refusal:
        """The asset transfer with the hash's LCP string as its note, and the fee payer's zero payment first when the
        option names a fee payer."""
        if not is_object(choice):
            return Refusal("avm/option-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, check)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        payer = _algorand.decode_address(choice.get("payer"))
        pr = choice.get("params")
        if (
            payer is None
            or not is_object(pr)
            or not _is_uint(pr.get("firstValid"))
            or not _is_uint(pr.get("minFee"))
            or not _is_uint(pr.get("feePerByte"))
            or not isinstance(pr.get("genesisId"), str)
        ):
            return Refusal("avm/option-malformed")
        genesis = _base64(pr.get("genesisHash"))
        if genesis is None or len(genesis) != 32:
            return Refusal("avm/network-mismatch")
        reference = _NETWORK.fullmatch(accepted["network"])
        assert reference is not None
        if pr["genesisHash"].replace("+", "-").replace("/", "_")[:32] != reference.group(1):
            return Refusal("avm/network-mismatch")

        first = pr["firstValid"]
        base = _algorand.Params(
            first_valid=first,
            last_valid=first + min(safe_int(accepted["maxTimeoutSeconds"]) or 0, MAX_TXN_LIFE),
            genesis_id=pr["genesisId"],
            genesis_hash=genesis,
            fee=pr["feePerByte"],
            flat=False,
            min_fee=pr["minFee"],
        )
        receiver = _algorand.decode_address(accepted["payTo"])
        asset, amount = _uint64(accepted["asset"]), _uint64(accepted["amount"])
        assert receiver is not None and asset is not None and amount is not None
        note = to_lcp_string(nh).encode("utf-8")
        extra = accepted.get("extra")
        fee_payer = _algorand.decode_address(extra.get("feePayer")) if is_object(extra) and "feePayer" in extra else None

        def transfer(params: _algorand.Params) -> _algorand.Transaction:
            return _algorand.axfer(payer, receiver, asset, amount, note, params)

        group: Sequence[_algorand.Transaction]
        try:
            if fee_payer is None:
                group, index = (transfer(base),), 0
            else:
                fee = _algorand.zero_pay(fee_payer, base).fee + transfer(base).fee
                group = (_algorand.zero_pay(fee_payer, replace(base, fee=fee, flat=True)), transfer(replace(base, fee=0, flat=True)))
                grp = _algorand.group_id(group)
                for txn in group:
                    txn.group = grp
                index = 1
            to_sign = group[index].bytes_to_sign()
        except (ValueError, TypeError, OverflowError):
            return Refusal("avm/option-malformed")
        return AvmUnsigned(
            request={"kind": "algorand-txn", "bytes": to_sign},
            _group=tuple(group),
            _index=index,
            _required=required,
            _accepted=accepted,
        )

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The payment transaction's note, as a hash. Amount, receiver, asset, fee payer and sender are not read, and
        no signature is verified here."""
        p = presented_with(presented, check)
        if isinstance(p, Refusal):
            return p
        carried = carrier(p[1])
        return carried if isinstance(carried, Refusal) else carried.h
