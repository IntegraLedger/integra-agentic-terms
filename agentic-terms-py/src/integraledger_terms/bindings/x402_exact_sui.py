"""The buyer half of the pairing x402/exact/sui: read, build with complete, and bound.

The ATR hash rides as the one Pure input of the payer's programmable transaction that no command uses. Nothing here
fetches, hashes the ATR or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._bcs import BcsError
from ._jose import js_length
from ._lcp import is_object, normal_hash
from ._rail_bytes import U64_LIMIT, base64_bytes, decimal_below
from ._sui_tx import (
    TRANSACTION_DATA,
    TRANSACTION_EXPIRATION,
    TRANSACTION_KIND,
    command_arguments,
    parse_transaction_data,
    sui_digest,
)
from ._url import read_url
from ._x402 import chosen, is_amount, payment_with, presented_with, read_for, timeout_seconds, x402_broadcaster

ID = "x402/exact/sui"

MAX_TX_BYTES = 128 * 1024
NETWORKS = ("sui:mainnet", "sui:testnet", "sui:devnet")
_PAY_TO = re.compile(r"0x[0-9a-f]{64}")
_IDENT = "[A-Za-z_][A-Za-z0-9_]*"
_COIN_TYPE = re.compile(rf"0x[0-9a-fA-F]{{1,64}}::{_IDENT}::{_IDENT}")


@dataclass(frozen=True, slots=True)
class SuiTx:
    """A decoded TransactionData: the bytes as received, their digest, the unused Pure inputs, and the epoch bound."""

    data: bytes
    digest: str
    unused_pure: tuple[bytes, ...]
    until_epoch: int | None


def decode_sui_tx(transaction: object) -> SuiTx | Refusal:
    """A base64 TransactionData V1 with a programmable kind. A programmable transaction with a type (a call's type
    argument, a vector's element type, a funds withdrawal's type) that has a node at depth 16, Sui's type depth limit,
    is sui/tx-malformed, the code of bytes that do not decode. A V1 TransactionData of another kind is
    sui/not-programmable, answered from its kind's tag before its body is decoded."""
    data = base64_bytes(transaction, MAX_TX_BYTES)
    if data == "too-large":
        return Refusal("sui/tx-too-large")
    if data == "malformed":
        return Refusal("sui/tx-malformed")
    assert isinstance(data, bytes)
    # TransactionData opens with two BCS enum tags, one byte each: its version, V1 (0), and its kind,
    # ProgrammableTransaction (0). Another kind is answered from its tag: no type of its body is read.
    if len(data) > 1 and data[0] == 0 and data[1] != 0:
        return Refusal("sui/not-programmable")
    try:
        parsed = parse_transaction_data(data)
    except BcsError:
        return Refusal("sui/tx-malformed")
    if parsed["$kind"] != "V1":
        return Refusal("sui/not-programmable")
    v1 = parsed["V1"]
    if v1["kind"]["$kind"] != "ProgrammableTransaction":
        return Refusal("sui/not-programmable")
    ptb = v1["kind"]["ProgrammableTransaction"]

    used: set[int] = set()
    for command in ptb["commands"]:
        for arg in command_arguments(command):
            if arg["$kind"] == "Input":
                used.add(arg["Input"])
    unused = tuple(
        i["Pure"]["bytes"] for n, i in enumerate(ptb["inputs"]) if i["$kind"] == "Pure" and n not in used
    )

    exp = v1["expiration"]
    until: int | None = None
    if exp["$kind"] == "Epoch":
        until = int(exp["Epoch"])
    elif exp["$kind"] == "ValidDuring" and exp["ValidDuring"]["maxEpoch"] is not None:
        until = int(exp["ValidDuring"]["maxEpoch"])
    elif exp["$kind"] == "Validity" and exp["Validity"]["maxEpoch"] is not None:
        until = int(exp["Validity"]["maxEpoch"])
    return SuiTx(data=data, digest=sui_digest(data), unused_pure=unused, until_epoch=until)


def sui_carrier(tx: SuiTx) -> AtrHash | Refusal:
    """The hash carried by exactly one unused Pure input of exactly 32 bytes."""
    if len(tx.unused_pure) == 0:
        return Refusal("sui/hash-not-carried")
    if len(tx.unused_pure) > 1:
        return Refusal("sui/ambiguous")
    carried = tx.unused_pure[0]
    return "0x" + carried.hex() if len(carried) == 32 else Refusal("sui/hash-not-carried")


def _is_station(value: object) -> bool:
    """An https URL of at most 2048 characters, as the gas station's endpoint."""
    if not isinstance(value, str) or js_length(value) > 2048:
        return False
    u = read_url(value)
    return u is not None and u.scheme == "https"


def sui_option_check(option: object) -> Refusal | None:
    """None for an option this pairing can pay, or the refusal naming why not. The option fixes the gas path: sponsored
    by the gas station extra.gasStation names, an https URL; gasless where extra.gasless is true; else the buyer pays;
    never both. The amount may be "0" except on the gasless path, whose floor is the coin type's smallest transfer."""
    if not is_object(option) or option.get("scheme") != "exact":
        return Refusal("x402/option-not-this-pairing")
    network = option.get("network")
    if not isinstance(network, str) or not network.startswith("sui:"):
        return Refusal("x402/option-not-this-pairing")
    if network not in NETWORKS:
        return Refusal("sui/network-malformed")
    if "extra" in option and not is_object(option["extra"]):
        return Refusal("x402/option-not-this-pairing")
    extra = option.get("extra")
    if is_object(extra) and "assetTransferMethod" in extra:
        return Refusal("x402/option-not-this-pairing")
    if is_object(extra) and "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return Refusal("x402/option-not-this-pairing")
    gas: Mapping[str, Any] = extra if is_object(extra) else {}
    station = "gasStation" in gas
    gasless = "gasless" in gas
    if station and not _is_station(gas["gasStation"]):
        return Refusal("x402/option-not-this-pairing")
    if gasless and (gas["gasless"] is not True or station):
        return Refusal("x402/option-not-this-pairing")
    pay_to, asset = option.get("payTo"), option.get("asset")
    if not isinstance(pay_to, str) or _PAY_TO.fullmatch(pay_to) is None:
        return Refusal("x402/option-not-this-pairing")
    if not isinstance(asset, str) or _COIN_TYPE.fullmatch(asset) is None:
        return Refusal("x402/option-not-this-pairing")
    amount = option.get("amount")
    zero = amount == "0" and not gasless
    if not (is_amount(amount) or zero) or decimal_below(amount, U64_LIMIT) is None:
        return Refusal("x402/option-not-this-pairing")
    if timeout_seconds(option.get("maxTimeoutSeconds")) is None:
        return Refusal("x402/option-not-this-pairing")
    return None


def _check(option: Mapping[str, Any]) -> Literal[True] | Refusal | None:
    refused = sui_option_check(option)
    return True if refused is None else refused


def _presented_tx(presented: object) -> SuiTx | Refusal:
    parts = presented_with(presented, _check)
    if isinstance(parts, Refusal):
        return parts
    _, payload, _ = parts
    signature, transaction = payload.get("signature"), payload.get("transaction")
    if not isinstance(signature, str) or signature == "":
        return Refusal("x402/signature-malformed")
    if not isinstance(transaction, str):
        return Refusal("x402/payload-malformed")
    return decode_sui_tx(transaction)


def _bound(presented: object) -> AtrHash | Refusal:
    tx = _presented_tx(presented)
    return tx if isinstance(tx, Refusal) else sui_carrier(tx)


@dataclass(frozen=True, slots=True)
class SuiUnsigned:
    """What the payer's wallet is handed, and the payment the wallet's signed transaction completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _expected: AtrHash

    def complete(self, signed: Mapping[str, str], sent: str | None = None) -> dict[str, Any] | Refusal:
        """The payment, when the signed transaction carries the built hash, with or without an epoch bound. sent is the
        transaction the client sent to the option's gas station (extra.gasStation), base64 of its TransactionData: on
        the sponsored path it is required, and the signed transaction must equal it in everything but the gas data,
        else sui/not-as-sent, since a gas station that changed the sender, an input, a command or the expiration could
        raise the amount or remove the lapse under a valid H."""
        payment = payment_with(self._required, self._accepted, signed)
        got = _bound(payment)
        if isinstance(got, Refusal) or got != self._expected:
            return Refusal("x402/signed-not-bound")
        extra = self._accepted.get("extra")
        if (is_object(extra) and "gasStation" in extra) or sent is not None:
            same = _same_but_gas(signed.get("transaction") if is_object(signed) else None, sent)
            if same is not True:
                return same
        return payment


def _same_but_gas(signed: object, sent: object) -> Literal[True] | Refusal:
    """True where signed equals sent in everything but the gas data: the sender, the transaction kind (its inputs and
    commands) and the expiration, compared as their BCS bytes. sui/not-as-sent where they differ, or where sent is
    absent or does not decode."""

    def v1(text: object) -> Any:
        data = base64_bytes(text, MAX_TX_BYTES)
        if not isinstance(data, bytes):
            return None
        try:
            parsed = TRANSACTION_DATA.parse(data)
        except Exception:
            return None
        return parsed["V1"] if parsed["$kind"] == "V1" else None

    a, b = v1(signed), v1(sent)
    if a is None or b is None:
        return Refusal("sui/not-as-sent")
    try:
        same = (
            a["sender"] == b["sender"]
            and TRANSACTION_KIND.serialize(a["kind"]) == TRANSACTION_KIND.serialize(b["kind"])
            and TRANSACTION_EXPIRATION.serialize(a["expiration"]) == TRANSACTION_EXPIRATION.serialize(b["expiration"])
        )
    except Exception:
        return Refusal("sui/not-as-sent")
    return True if same else Refusal("sui/not-as-sent")


@dataclass(frozen=True, slots=True)
class X402ExactSui:
    id: str = ID
    coverage: Coverage = "full"
    agreement: AgreementData | None = AgreementData(floor="rule")

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(_check)(doc)

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> SuiUnsigned | Refusal:
        """The wallet request: the scheme's payment plus one unused Pure input holding the hash, bounded by epoch. H is
        checked first, then the choice's document and option."""
        expected = normal_hash(h)
        if expected is None:
            return Refusal("x402/payload-malformed")
        c = choice if is_object(choice) else {}
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _check)
        if ok is not True:
            return ok
        assert is_object(required) and is_object(accepted)
        request = {
            "kind": "sui-transaction",
            "accepted": accepted,
            "pureInput": bytes.fromhex(expected[2:]),
            "expiration": "epoch-bounded",
        }
        return SuiUnsigned(request=request, _required=required, _accepted=accepted, _expected=expected)

    def bound(self, presented: Any, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """The hash inside the transaction the payer signed. The signature is not verified here."""
        return _bound(presented)

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payee broadcasts: the seller's facilitator executes the transaction the payer signed. The payment is held
        to x402_shape's gate, the one bound applies first; any other gets its refusal."""
        return x402_broadcaster(presented, "payee")
