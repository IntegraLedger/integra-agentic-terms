"""What the buyer pieces share: the CAIP-10 account, the first x402 option on the account's network, the payment
identifier the x402 client writes, and the buyer's named inputs."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import unquote

from .._types import Advertised, Chosen, Inputs, Refusal

_CAIP10 = re.compile(r"([-a-z0-9]{3,8}):([-_a-zA-Z0-9]{1,32}):([-.%a-zA-Z0-9]{1,128})")
_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")
_DECIMAL = re.compile(r"[0-9]{1,78}")
_MAX_SAFE_INTEGER = 2**53 - 1
PAYMENT_IDENTIFIER = "payment-identifier"


@dataclass(frozen=True, slots=True)
class Account:
    namespace: str
    network: str
    address: str


def account_of(account: object) -> Account | None:
    """A CAIP-10 account's namespace, its CAIP-2 network and its address, percent-decoded (CAIP-10's escape). An
    eip155 address is taken as written: the gate's account form for EVM is ^eip155:([0-9]+):(0x[0-9a-fA-F]{40})$, which
    has no escape."""
    match = _CAIP10.fullmatch(account) if isinstance(account, str) else None
    if match is None:
        return None
    if match.group(1) == "eip155":
        return Account(match.group(1), f"{match.group(1)}:{match.group(2)}", match.group(3))
    if _PERCENT.search(match.group(3)) is not None:
        return None
    try:
        address = unquote(match.group(3), errors="strict")
    except UnicodeDecodeError:
        return None
    return Account(match.group(1), f"{match.group(1)}:{match.group(2)}", address)


def broadcasts(request: object) -> bool:
    """True when the request tells the signer to broadcast what it signs."""
    return isinstance(request, Mapping) and request.get("broadcast") is True


def x402_offer_of(read: Advertised) -> tuple[Mapping[str, Any], Sequence[Any]] | None:
    offer = read.offer
    required, options = offer.get("required"), offer.get("options")
    if not isinstance(required, Mapping) or not isinstance(options, Sequence) or isinstance(options, str):
        return None
    return required, options


@dataclass(frozen=True, slots=True)
class FirstOption:
    required: Mapping[str, Any]
    accepted: Mapping[str, Any]
    address: str


def first_option(
    read: Advertised, account: str, namespace: str, pairing: str, address: re.Pattern[str] | None = None
) -> FirstOption | Refusal:
    """The first of the offer's options, in document order, whose network is the account's, with the account parsed.
    The buyer chooses among options by removing the others from accepts first."""
    a = account_of(account)
    offer = x402_offer_of(read)
    if a is None or a.namespace != namespace or (address is not None and address.fullmatch(a.address) is None):
        return Refusal(pairing.split("/")[0] + "/no-payable-option")
    if offer is None:
        return Refusal("x402/no-payable-option")
    required, options = offer
    for option in options:
        if isinstance(option, Mapping) and option.get("network") == a.network:
            return FirstOption(required, option, a.address)
    return Refusal("x402/no-payable-option")


def with_payment_identifier(signed: dict[str, Any], required: object, ref: str) -> dict[str, Any] | Refusal:
    """The completed payment with id = ref appended to the echoed payment-identifier info, where the challenge
    advertises that extension. An info that is not an object, or that already holds id, is refused."""
    advertised = required.get("extensions") if isinstance(required, Mapping) else None
    if not isinstance(advertised, Mapping) or PAYMENT_IDENTIFIER not in advertised:
        return signed
    extensions = signed.get("extensions")
    extension = extensions.get(PAYMENT_IDENTIFIER) if isinstance(extensions, Mapping) else None
    info = extension.get("info") if isinstance(extension, Mapping) else None
    if not isinstance(extensions, Mapping) or not isinstance(extension, Mapping):
        return Refusal("x402/payment-identifier-unwritable")
    if not isinstance(info, Mapping) or "id" in info:
        return Refusal("x402/payment-identifier-unwritable")
    return {**signed, "extensions": {**extensions, PAYMENT_IDENTIFIER: {**extension, "info": {**info, "id": ref}}}}


def bytes_of(value: object, length: int | None = None) -> bytes | None:
    """The bytes of 0x hex, of the given length when one is named, or None."""
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        return None
    out = bytes.fromhex(value[2:])
    return out if length is None or len(out) == length else None


def bigint_of(value: object) -> int | None:
    """A decimal string of at most 78 digits as an int, or None."""
    return int(value) if isinstance(value, str) and _DECIMAL.fullmatch(value) is not None else None


def uint_of(value: object) -> int | None:
    """A non-negative safe integer, or None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    number = int(value)
    return number if 0 <= number <= _MAX_SAFE_INTEGER else None


InputKind = Literal[
    "string", "decimal", "uint", "hex", "object",
    "optional-string", "optional-uint", "optional-decimal", "optional-hex", "optional-object",
]  # fmt: skip


def inputs_of(inputs: Inputs, pairing: str, spec: Mapping[str, InputKind]) -> dict[str, Any] | Refusal:
    """The named inputs, present and of the given kinds; or the refusal naming the first missing one."""
    out: dict[str, Any] = {}
    for key, kind in spec.items():
        value = inputs.get(key)
        optional = kind.startswith("optional-")
        if value is None and key not in inputs and optional:
            continue
        base = kind[len("optional-") :] if optional else kind
        ok = (
            (base == "string" and isinstance(value, str) and value != "")
            or (base == "decimal" and bigint_of(value) is not None)
            or (base == "uint" and uint_of(value) is not None)
            or (base == "hex" and isinstance(value, str) and _HEX.fullmatch(value) is not None)
            or (base == "object" and isinstance(value, Mapping))
        )
        if not ok:
            return Refusal(pairing.split("/")[0] + "/input-missing")
        out[key] = value
    return out


def choice_of(chosen: Chosen) -> dict[str, Any] | None:
    return chosen.choice if isinstance(chosen, Chosen) and isinstance(chosen.choice, dict) else None
