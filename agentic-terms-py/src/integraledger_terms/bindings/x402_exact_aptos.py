"""The buyer half of the pairing x402/exact/aptos: read, build with complete, and bound.

No field of a standard Aptos transfer carries the ATR hash: the hash is advertised in the challenge and read back from
the echoed extension, and complete accepts only a transaction whose RawTransaction prefix is a framework
fungible-asset transfer on the option's chain. Nothing here fetches, hashes or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._lcp import is_object, normal_hash
from ._rail_bytes import U64_LIMIT, base64_bytes, decimal_below, parse_json
from ._x402 import chosen, legal_context_of, payment_with, presented_with, read_for

ID = "x402/exact/aptos"

MAX_TX_BYTES = 64 * 1024
_NETWORK = re.compile(r"aptos:([1-9][0-9]{0,2})")
_ADDRESS_64 = re.compile(r"0x[0-9a-fA-F]{64}")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,254}")
_ENTRY_FUNCTION = 2
_TYPE_TAG_STRUCT = 7
_FRAMEWORK = "0x" + "0" * 63 + "1"
TRANSFERS = (f"{_FRAMEWORK}::primary_fungible_store::transfer", f"{_FRAMEWORK}::fungible_asset::transfer")


class _Short(Exception):
    """A read past the end, a ULEB128 out of bounds, or an identifier that is not one."""


class _Reader:
    """A bounded BCS reader; every read past the end raises."""

    def __init__(self, data: bytes) -> None:
        self._b = data
        self._at = 0

    def bytes(self, n: int) -> bytes:
        if n < 0 or self._at + n > len(self._b):
            raise _Short("short")
        out = self._b[self._at : self._at + n]
        self._at += n
        return out

    def u8(self) -> int:
        return self.bytes(1)[0]

    def u64(self) -> int:
        return int.from_bytes(self.bytes(8), "little")

    def uleb(self) -> int:
        """ULEB128 up to 2^32 - 1, in its shortest form."""
        v = 0
        for i in range(5):
            byte = self.u8()
            v += (byte & 0x7F) << (7 * i)
            if byte & 0x80 == 0:
                if i > 0 and byte == 0:
                    raise _Short("non-canonical")
                if v > 0xFFFFFFFF:
                    raise _Short("too large")
                return v
        raise _Short("too long")

    def ident(self) -> str:
        try:
            s = self.bytes(self.uleb()).decode("utf-8-sig")
        except UnicodeDecodeError as e:
            raise _Short("identifier") from e
        if _IDENT.fullmatch(s) is None:
            raise _Short("identifier")
        return s


def _reference_form(data: bytes) -> bytes | None:
    """The transaction byte array of x402's reference wire form, or None when the bytes are not that JSON."""
    if not data or data[0] != 0x7B:
        return None
    try:
        o = parse_json(data)
    except ValueError:
        return None
    if not is_object(o):
        return None
    t = o.get("transaction")
    if not isinstance(t, list):
        return None
    for x in t:
        if isinstance(x, bool) or not isinstance(x, (int, float)) or not 0 <= x <= 255 or x != int(x):
            return None
    return bytes(int(x) for x in t)


def decode_aptos_tx(transaction: str) -> dict[str, Any] | Refusal:
    """The transfer the payer signed, read from the RawTransaction prefix of a base64 transaction in either wire form:
    the scheme's BCS bytes, or x402's reference form. Only an entry function call to a framework fungible-asset
    transfer is accepted."""
    decoded = base64_bytes(transaction, MAX_TX_BYTES)
    if decoded == "too-large":
        return Refusal("aptos/tx-too-large")
    if decoded == "malformed":
        return Refusal("aptos/tx-malformed")
    assert isinstance(decoded, bytes)
    data = _reference_form(decoded)
    r = _Reader(data if data is not None else decoded)
    try:
        sender = "0x" + r.bytes(32).hex()
        sequence_number = r.u64()
        if r.uleb() != _ENTRY_FUNCTION:
            return Refusal("aptos/not-entry-function")
        module_address = "0x" + r.bytes(32).hex()
        module = r.ident()
        name = r.ident()
        fn = f"{module_address}::{module}::{name}"
        type_arg_count = r.uleb()
        if fn not in TRANSFERS or type_arg_count != 1:
            return Refusal("aptos/not-an-x402-transfer")
        if r.uleb() != _TYPE_TAG_STRUCT:
            return Refusal("aptos/not-an-x402-transfer")
        type_address = "0x" + r.bytes(32).hex()
        type_module = r.ident()
        type_argument = f"{type_address}::{type_module}::{r.ident()}"
        if r.uleb() != 0:
            return Refusal("aptos/not-an-x402-transfer")
        if r.uleb() != 3:
            return Refusal("aptos/not-an-x402-transfer")
        first = r.bytes(r.uleb())
        second = r.bytes(r.uleb())
        amount = r.bytes(r.uleb())
        if len(first) != 32 or len(second) != 32 or len(amount) != 8:
            return Refusal("aptos/not-an-x402-transfer")
        r.u64()
        r.u64()
        expires_at = r.u64()
        chain_id = r.u8()
    except _Short:
        return Refusal("aptos/tx-malformed")
    return {
        "sender": sender,
        "sequenceNumber": sequence_number,
        "expiresAt": expires_at,
        "chainId": chain_id,
        "function": fn,
        "typeArguments": [type_argument],
        "arguments": ["0x" + first.hex(), "0x" + second.hex(), str(int.from_bytes(amount, "little"))],
    }


def chain_of(network: str) -> int | None:
    m = _NETWORK.fullmatch(network)
    if m is None:
        return None
    n = int(m.group(1))
    return n if 1 <= n <= 255 else None


def aptos_option_check(option: object) -> Refusal | None:
    """None for an option this pairing can pay, or the refusal naming why not."""
    if not is_object(option) or option.get("scheme") != "exact":
        return Refusal("x402/option-not-this-pairing")
    network = option.get("network")
    if not isinstance(network, str) or not network.startswith("aptos:"):
        return Refusal("x402/option-not-this-pairing")
    if chain_of(network) is None:
        return Refusal("aptos/network-malformed")
    if "extra" in option and not is_object(option["extra"]):
        return Refusal("x402/option-not-this-pairing")
    extra = option.get("extra")
    if is_object(extra) and "assetTransferMethod" in extra:
        return Refusal("x402/option-not-this-pairing")
    if is_object(extra) and "paymentFlow" in extra and extra["paymentFlow"] != "authorization":
        return Refusal("x402/option-not-this-pairing")
    asset, pay_to = option.get("asset"), option.get("payTo")
    if not isinstance(asset, str) or _ADDRESS_64.fullmatch(asset) is None:
        return Refusal("x402/option-not-this-pairing")
    if not isinstance(pay_to, str) or _ADDRESS_64.fullmatch(pay_to) is None:
        return Refusal("x402/option-not-this-pairing")
    if decimal_below(option.get("amount"), U64_LIMIT) is None:
        return Refusal("x402/option-not-this-pairing")
    return None


def _check(option: Mapping[str, Any]) -> bool | Refusal | None:
    refused = aptos_option_check(option)
    return True if refused is None else refused


def _instrument_of(presented: object) -> dict[str, Any] | Refusal:
    parts = presented_with(presented, _check)
    if isinstance(parts, Refusal):
        return parts
    accepted, payload, _ = parts
    transaction = payload.get("transaction")
    if not isinstance(transaction, str):
        return Refusal("x402/payload-malformed")
    instrument = decode_aptos_tx(transaction)
    if isinstance(instrument, Refusal):
        return instrument
    if instrument["chainId"] != chain_of(accepted["network"]):
        return Refusal("aptos/chain-mismatch")
    return instrument


@dataclass(frozen=True, slots=True)
class AptosUnsigned:
    """The wallet request, the scheme's own payment, and the payment the wallet's signed transaction completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, signed: Mapping[str, str]) -> dict[str, Any] | Refusal:
        """The payment, when the transaction's prefix is a transfer this pairing reads on the option's chain."""
        payment = payment_with(self._required, self._accepted, signed)
        return Refusal("x402/signed-not-bound") if isinstance(_instrument_of(payment), Refusal) else payment


@dataclass(frozen=True, slots=True)
class X402ExactAptos:
    id: str = ID
    public_proof: bool = False

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(_check)(doc)

    def build(self, choice: Json, h: AtrHash) -> AptosUnsigned | Refusal:
        """The wallet request: the scheme's own payment, which carries no hash."""
        c = choice if is_object(choice) else {}
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, _check)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        if normal_hash(h) is None:
            return Refusal("x402/payload-malformed")
        return AptosUnsigned(
            request={"kind": "aptos-transaction", "accepted": accepted}, _required=required, _accepted=accepted
        )

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """The hash in the echoed, unsigned extensions.legalContext."""
        parts = presented_with(presented, _check)
        if isinstance(parts, Refusal):
            return parts
        _, payload, extensions = parts
        if not isinstance(payload.get("transaction"), str):
            return Refusal("x402/payload-malformed")
        lc = legal_context_of(extensions)
        return Refusal("x402/no-legal-context") if isinstance(lc, Refusal) else lc[0]
