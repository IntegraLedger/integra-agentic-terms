"""The buyer half of the pairing x402/exact/algorand: read, build with complete, and bound.

The payer signs an asset transfer whose note is the ATR hash's LCP string; with the option's fee payer, it is grouped
after that fee payer's zero payment, which carries both fees. Nothing here fetches or signs.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Literal

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from . import _algorand
from ._codec import b64_decode, b64_encode
from ._lcp import from_lcp_string, is_list, is_object, is_well_formed, normal_hash, safe_int, to_lcp_string
from ._x402 import chosen, payment_with, presented_with, read_for

ID = "x402/exact/algorand"

_NETWORK = re.compile(r"algorand:([-_a-zA-Z0-9]{32})")
_ASSET = re.compile(r"0|[1-9][0-9]{0,19}")
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


def _presentable(option: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """The option's scheme, network, asset, payTo and extra (its fee payer, no transfer method, and no flow other than
    "authorization"): what bound requires of the option a presented payment echoes. bound reads the signed
    transaction, not the option's amount or timeout, so neither is checked here."""
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
    if (
        _uint64(option.get("asset")) is None
        or not _algorand.is_address(option.get("payTo"))
        or ("feePayer" in extra_map and not _algorand.is_address(extra_map["feePayer"]))
    ):
        return Refusal("avm/option-malformed")
    return True


def check(option: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    """The pairing's option filter: True for an option it serves, a refusal naming why an option on an algorand
    network cannot be served, and None for any other option. It applies what bound requires of an echoed option, then
    the amount as a decimal below 2^64 and maxTimeoutSeconds a positive safe integer, which build writes into the
    asset transfer and its last valid round: read and build apply it."""
    presentable = _presentable(option)
    if presentable is not True:
        return presentable
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    if _uint64(option.get("amount")) is None or timeout is None or timeout <= 0:
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
    data = b64_decode(entry)
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
        option names a fee payer. The suggested parameters' genesis id is written as each transaction's gen, a msgpack
        string, so one holding a lone surrogate, which UTF-8 cannot encode, is avm/option-malformed, and so is one whose
        UTF-8 is longer than 200 bytes and begins with the byte-order mark, which algosdk's decoder drops: each entry
        it writes is read back with _algorand.unpack, the msgpack read carrier makes before it reads the transaction,
        so build writes no string bound refuses."""
        if not is_object(choice):
            return Refusal("avm/option-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, check)
        if ok is not True:
            return ok
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
            or not is_well_formed(pr.get("genesisId"))
        ):
            return Refusal("avm/option-malformed")
        genesis = b64_decode(pr.get("genesisHash"))
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
            for txn in group:
                _algorand.unpack(txn.signed(None))
            to_sign = group[index].bytes_to_sign()
        except (ValueError, TypeError, OverflowError, _algorand.Malformed):
            return Refusal("avm/option-malformed")
        return AvmUnsigned(
            request={"kind": "algorand-txn", "bytes": to_sign},
            _group=tuple(group),
            _index=index,
            _required=required,
            _accepted=accepted,
        )

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The payment transaction's note, as a hash. The echoed option needs a valid scheme, network, asset, payTo and
        extra; its amount and timeout are not read. The transaction's amount, receiver, asset, fee payer and sender are
        not read, and no signature is verified here."""
        p = presented_with(presented, _presentable)
        if isinstance(p, Refusal):
            return p
        carried = carrier(p[1])
        return carried if isinstance(carried, Refusal) else carried.h
