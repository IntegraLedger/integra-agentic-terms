"""BOLT11 invoices: the Bech32 checksum (BIP 173), the human-readable prefix's currency and amount, and the tagged
fields, read without BOLT11's length limit up to 8 KiB. The signature is not verified."""

import re
from dataclasses import dataclass
from typing import Literal

from .._core import AtrHash
from .._types import Refusal
from ._jose import js_length

Currency = Literal["bc", "tb", "tbs", "bcrt"]

MAX_INVOICE = 8192
MAX_FIELDS = 64
SIGNATURE_WORDS = 104
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_INDEX = {c: i for i, c in enumerate(CHARSET)}
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_CURRENCIES: tuple[Currency, ...] = ("bcrt", "tbs", "tb", "bc")
_AMOUNT = re.compile(r"([0-9]+)([munp]?)")
# Tagged field types, as the Bech32 value of their letter.
FIELD = {"p": 1, "s": 16, "h": 23, "m": 27, "x": 6, "d": 13}


@dataclass(frozen=True, slots=True)
class Bolt11:
    currency: Currency
    amount_msat: int | None
    timestamp: int
    expiry: int
    payment_hash: bytes
    description_hash: bytes | None
    description: str | None
    metadata: bytes | None
    # Every tagged field's type, in invoice order.
    tags: tuple[int, ...]


def _polymod(values: list[int]) -> int:
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GENERATOR[i]
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _uint(words: list[int]) -> int:
    """5-bit words as a big-endian integer."""
    v = 0
    for w in words:
        v = v * 32 + w
    return v


def _to_bytes(words: list[int]) -> bytes:
    """5-bit words as bytes; trailing bits short of a byte are dropped."""
    out = bytearray()
    size = len(words) * 5 // 8
    acc = 0
    bits = 0
    for w in words:
        acc = ((acc << 5) | w) & 0xFFF
        bits += 5
        if bits >= 8:
            bits -= 8
            if len(out) < size:
                out.append((acc >> bits) & 0xFF)
    return bytes(out)


def _currency_and_amount(hrp: str) -> tuple[Currency, int | None] | None:
    """The currency and the amount in millisatoshi from the human-readable part, ln + currency + [amount]."""
    if not hrp.startswith("ln"):
        return None
    rest = hrp[2:]
    for currency in _CURRENCIES:
        if not rest.startswith(currency):
            continue
        amount = rest[len(currency) :]
        if amount == "":
            return currency, None
        a = _AMOUNT.fullmatch(amount)
        if a is None:
            continue
        n = int(a.group(1))
        unit = a.group(2)
        if unit == "":
            return currency, n * 100_000_000_000
        if unit == "m":
            return currency, n * 100_000_000
        if unit == "u":
            return currency, n * 100_000
        if unit == "n":
            return currency, n * 100
        return (currency, n // 10) if n % 10 == 0 else None
    return None


def _fixed_length_wrong(body: list[int]) -> bool:
    """True when any p, h or s field is not 52 words long."""
    i = 7
    while i + 3 <= len(body):
        field_type = body[i]
        length = body[i + 1] * 32 + body[i + 2]
        if field_type in (FIELD["p"], FIELD["h"], FIELD["s"]) and length != 52:
            return True
        i += 3 + length
    return False


def decode(invoice: object) -> Bolt11 | Refusal:
    """Decodes a BOLT11 invoice of at most 8 KiB. The signature is not verified."""
    if not isinstance(invoice, str):
        return Refusal("ln/invoice-malformed")
    if js_length(invoice) > MAX_INVOICE:
        return Refusal("ln/invoice-too-large")
    lower = invoice.lower()
    if lower != invoice and invoice.upper() != invoice:
        return Refusal("ln/invoice-malformed")
    sep = lower.rfind("1")
    if sep < 3:
        return Refusal("ln/invoice-malformed")
    hrp = lower[:sep]
    words: list[int] = []
    for c in lower[sep + 1 :]:
        w = _CHARSET_INDEX.get(c)
        if w is None:
            return Refusal("ln/invoice-malformed")
        words.append(w)
    if len(words) < 6 or _polymod(_hrp_expand(hrp) + words) != 1:
        return Refusal("ln/invoice-malformed")
    data = words[:-6]
    if len(data) < 7 + SIGNATURE_WORDS:
        return Refusal("ln/invoice-malformed")

    prefix = _currency_and_amount(hrp)
    if prefix is None:
        return Refusal("ln/invoice-malformed")

    body = data[: len(data) - SIGNATURE_WORDS]
    timestamp = _uint(body[:7])
    tags: list[int] = []
    first: dict[int, list[int]] = {}
    i = 7
    while i < len(body):
        if i + 3 > len(body):
            return Refusal("ln/invoice-malformed")
        field_type = body[i]
        length = body[i + 1] * 32 + body[i + 2]
        if i + 3 + length > len(body):
            return Refusal("ln/invoice-malformed")
        if len(tags) == MAX_FIELDS:
            return Refusal("ln/invoice-too-large")
        tags.append(field_type)
        if field_type not in first:
            first[field_type] = body[i + 3 : i + 3 + length]
        i += 3 + length

    if _fixed_length_wrong(body):
        return Refusal("ln/invoice-malformed")
    p = first.get(FIELD["p"])
    if p is None or tags.count(FIELD["p"]) != 1:
        return Refusal("ln/invoice-malformed")
    h = first.get(FIELD["h"])
    m = first.get(FIELD["m"])
    x = first.get(FIELD["x"])
    d = first.get(FIELD["d"])
    if x is not None and len(x) > 10:
        return Refusal("ln/invoice-malformed")
    description = None
    if d is not None:
        try:
            description = _to_bytes(d).decode("utf-8").removeprefix("\ufeff")
        except UnicodeDecodeError:
            return Refusal("ln/invoice-malformed")
    return Bolt11(
        currency=prefix[0],
        amount_msat=prefix[1],
        timestamp=timestamp,
        expiry=3600 if x is None else _uint(x),
        payment_hash=_to_bytes(p),
        description_hash=None if h is None else _to_bytes(h),
        description=description,
        metadata=None if m is None else _to_bytes(m),
        tags=tuple(tags),
    )


def invoice_h(b: Bolt11, field: Literal["h", "m"]) -> AtrHash | Refusal:
    """The one 32-byte h or m field of an invoice, as the hash it carries."""
    field_type = FIELD[field]
    count = b.tags.count(field_type)
    if count == 0:
        return Refusal("ln/no-description-hash" if field == "h" else "ln/no-metadata")
    if count > 1:
        return Refusal("ln/field-repeated")
    data = b.description_hash if field == "h" else b.metadata
    if data is None or len(data) != 32:
        return Refusal("ln/field-length")
    return "0x" + data.hex()
