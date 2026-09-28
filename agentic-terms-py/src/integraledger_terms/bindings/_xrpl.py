"""XRP Ledger rail pieces the buyer half reads: the signed blob decoded with its transaction hash, InvoiceID in each
scheme's form, and XRPL networks."""

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Refusal
from . import _xrpl_codec
from ._lcp import to_lcp_string

MAX_BLOB_HEX = 4096
_NETWORK = re.compile(r"xrpl:(0|[1-9][0-9]{0,9})")
_HEX = re.compile(r"(?:[0-9A-Fa-f]{2})+")
_HASH256 = re.compile(r"[0-9A-Fa-f]{64}")
_TXN_PREFIX = bytes.fromhex("54584E00")


def is_xrpl_network(value: object) -> bool:
    """xrpl: and a NetworkID from 0 to 4294967295."""
    match = _NETWORK.fullmatch(value) if isinstance(value, str) else None
    return match is not None and int(match.group(1)) <= 0xFFFFFFFF


def network_id(network: str) -> int:
    return int(network[len("xrpl:") :])


def is_blob_hex(value: object) -> bool:
    """A non-empty even number of hex digits in either case, without a prefix."""
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def same_invoice(a: object, b: object) -> bool:
    """True when two 256-bit hex values are the same bytes, ignoring case."""
    return (
        isinstance(a, str)
        and isinstance(b, str)
        and _HASH256.fullmatch(a) is not None
        and _HASH256.fullmatch(b) is not None
        and a.upper() == b.upper()
    )


def x402_invoice_id(h: AtrHash) -> str:
    """Upper-case hex of SHA-256 over the UTF-8 bytes of the hash's LCP string."""
    return hashlib.sha256(to_lcp_string(h).encode("utf-8")).hexdigest().upper()


def mpp_invoice_id(h: AtrHash) -> str:
    """The hash's 64 hex digits in upper case, without 0x."""
    return h[2:].upper()


@dataclass(frozen=True, slots=True)
class Blob:
    tx: dict[str, Any]
    hash: str


def decode_blob(text: object) -> Blob | Refusal:
    """A signed blob of at most 4096 hex digits decoded, with its transaction hash as the ledger computes it:
    SHA-512Half over 54584E00 and the blob, in upper case. The blob must be the canonical serialization of what it
    decodes to."""
    if not is_blob_hex(text):
        return Refusal("xrpl/blob-malformed")
    assert isinstance(text, str)
    if len(text) > MAX_BLOB_HEX:
        return Refusal("xrpl/blob-too-large")
    data = bytes.fromhex(text)
    try:
        tx = _xrpl_codec.decode(data)
    except _xrpl_codec.Malformed:
        return Refusal("xrpl/blob-malformed")
    if not isinstance(tx.get("TransactionType"), str) or not isinstance(tx.get("Account"), str):
        return Refusal("xrpl/blob-malformed")
    digest = hashlib.sha512(_TXN_PREFIX + data).digest()
    return Blob(tx=tx, hash=digest[:32].hex().upper())


def decode_presented(text: object) -> Blob | Refusal:
    """The signed blob a presented payment holds, decoded as decode_blob decodes it. A blob that carries Signers is
    xrpl/multisigned: the payer signs with a single key, so the transaction hash computed from the blob is the one that
    can land."""
    blob = decode_blob(text)
    if isinstance(blob, Refusal):
        return blob
    return Refusal("xrpl/multisigned") if "Signers" in blob.tx else blob


_PAY_CHANNEL_SPACE = bytes.fromhex("0078")
_CLAIM_PREFIX = bytes.fromhex("434C4D00")
_HASH256_TEXT = re.compile(r"[0-9A-Fa-f]{64}")


def channel_id(account: object, destination: object, sequence: object) -> str | Refusal:
    """The PayChannel id: SHA-512Half of 0x0078, the source's AccountID, the destination's AccountID and the creating
    transaction's sequence, big-endian; upper-case hex."""
    a = _xrpl_codec.account_id_of(account)
    d = _xrpl_codec.account_id_of(destination)
    if (
        a is None
        or d is None
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or not 0 <= sequence <= 0xFFFFFFFF
    ):
        return Refusal("xrpl/not-channel-create")
    digest = hashlib.sha512(_PAY_CHANNEL_SPACE + a + d + sequence.to_bytes(4, "big")).digest()
    return digest[:32].hex().upper()


def claim_bytes(channel: object, drops: object) -> bytes | Refusal:
    """The bytes a channel claim signs: CLM\\0, the channel id and the drops as a big-endian u64."""
    if (
        not isinstance(channel, str)
        or _HASH256_TEXT.fullmatch(channel) is None
        or isinstance(drops, bool)
        or not isinstance(drops, int)
        or not 0 <= drops < 1 << 64
    ):
        return Refusal("xrpl/not-channel-create")
    return _CLAIM_PREFIX + bytes.fromhex(channel) + drops.to_bytes(8, "big")
