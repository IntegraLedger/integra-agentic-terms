"""The buyer half of the pairing x402/exact/sui: read, build with complete, and bound.

The ATR hash rides as the one Pure input of the payer's programmable transaction that no command uses. Nothing here
fetches, hashes the ATR or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._bcs import BcsError
from ._lcp import is_object, normal_hash
from ._rail_bytes import U64_LIMIT, base64_bytes, decimal_below
from ._sui_tx import command_arguments, parse_transaction_data, sui_digest
from ._x402 import chosen, payment_with, presented_with, read_for

ID = "x402/exact/sui"

MAX_TX_BYTES = 128 * 1024
MAX_SIGNATURE = 8192
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
    """A base64 TransactionData V1 with a programmable kind."""
    data = base64_bytes(transaction, MAX_TX_BYTES)
    if data == "too-large":
        return Refusal("sui/tx-too-large")
    if data == "malformed":
        return Refusal("sui/tx-malformed")
    assert isinstance(data, bytes)
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


def sui_option_check(option: object) -> Refusal | None:
    """None for an option this pairing can pay, or the refusal naming why not."""
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
    pay_to, asset = option.get("payTo"), option.get("asset")
    if not isinstance(pay_to, str) or _PAY_TO.fullmatch(pay_to) is None:
        return Refusal("x402/option-not-this-pairing")
    if not isinstance(asset, str) or _COIN_TYPE.fullmatch(asset) is None:
        return Refusal("x402/option-not-this-pairing")
    if decimal_below(option.get("amount"), U64_LIMIT) is None:
        return Refusal("x402/option-not-this-pairing")
    return None


def _check(option: Mapping[str, Any]) -> bool | Refusal | None:
    refused = sui_option_check(option)
    return True if refused is None else refused


def _presented_tx(presented: object) -> SuiTx | Refusal:
    parts = presented_with(presented, _check)
    if isinstance(parts, Refusal):
        return parts
    _, payload, _ = parts
    signature, transaction = payload.get("signature"), payload.get("transaction")
    if not isinstance(signature, str) or not 0 < len(signature.encode("utf-16-le", "surrogatepass")) // 2 <= MAX_SIGNATURE:
        return Refusal("x402/signature-malformed")
    if not isinstance(transaction, str):
        return Refusal("x402/payload-malformed")
    return decode_sui_tx(transaction)


def _bound(presented: object) -> AtrHash | Refusal:
    tx = _presented_tx(presented)
    return tx if isinstance(tx, Refusal) else sui_carrier(tx)


def _reference_refuses(presented: object) -> bool:
    """Whether reference refuses the payment: its transaction does not decode, or has no epoch bound."""
    tx = _presented_tx(presented)
    return isinstance(tx, Refusal) or tx.until_epoch is None


@dataclass(frozen=True, slots=True)
class SuiUnsigned:
    """What the payer's wallet is handed, and the payment the wallet's signed transaction completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _expected: AtrHash

    def complete(self, signed: Mapping[str, str]) -> dict[str, Any] | Refusal:
        """The payment, when the signed transaction carries the built hash and is bounded by epoch."""
        payment = payment_with(self._required, self._accepted, signed)
        got = _bound(payment)
        if isinstance(got, Refusal) or got != self._expected or _reference_refuses(payment):
            return Refusal("x402/signed-not-bound")
        return payment


@dataclass(frozen=True, slots=True)
class X402ExactSui:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(_check)(doc)

    def build(self, choice: Json, h: AtrHash) -> SuiUnsigned | Refusal:
        """The wallet request: the scheme's payment plus one unused Pure input holding the hash, bounded by epoch."""
        c = choice if is_object(choice) else {}
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _check)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        expected = normal_hash(h)
        if expected is None:
            return Refusal("x402/payload-malformed")
        request = {
            "kind": "sui-transaction",
            "accepted": accepted,
            "pureInput": bytes.fromhex(expected[2:]),
            "expiration": "epoch-bounded",
        }
        return SuiUnsigned(request=request, _required=required, _accepted=accepted, _expected=expected)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """The hash inside the transaction the payer signed. The signature is not verified here."""
        return _bound(presented)
