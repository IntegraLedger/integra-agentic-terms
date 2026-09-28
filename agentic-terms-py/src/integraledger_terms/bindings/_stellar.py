"""Stellar rail pieces the buyer half reads and writes: strkeys (base32 with a CRC16-XModem checksum), the muxed id
that carries the ATR hash's first 8 bytes, a payer-signed Soroban transfer decoded from its envelope, and the
authorization preimage the payer signs with the envelope that its signature completes.
"""

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass

from .._core import AtrHash
from .._types import Refusal
from . import _stellar_xdr as xdr
from ._codec import b64_decode, b64_encode

PASSPHRASE = {
    "stellar:pubnet": "Public Global Stellar Network ; September 2015",
    "stellar:testnet": "Test SDF Network ; September 2015",
}
MAX_XDR = 8192

_ACCOUNT, _MUXED, _CONTRACT = 6 << 3, 12 << 3, 2 << 3
_LENGTHS = {_ACCOUNT: 56, _MUXED: 69, _CONTRACT: 56}
_PAYLOAD = {_ACCOUNT: 32, _MUXED: 40, _CONTRACT: 32}
_BASE32 = re.compile(r"[A-Z2-7]*")


def is_stellar_network(value: object) -> bool:
    """Whether value is a string naming a Stellar network the rail's passphrase table holds."""
    return isinstance(value, str) and value in PASSPHRASE


# ── strkeys ──────────────────────────────────────────────────────────────────────────────────────────────────────


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode_strkey(version: int, payload: bytes) -> str:
    body = bytes([version]) + payload
    return base64.b32encode(body + crc16_xmodem(body).to_bytes(2, "little")).decode("ascii").rstrip("=")


def decode_strkey(version: int, text: object) -> bytes | None:
    """The payload of a canonical strkey of this version with a valid checksum, or None."""
    if not isinstance(text, str) or len(text) != _LENGTHS[version] or _BASE32.fullmatch(text) is None:
        return None
    try:
        raw = base64.b32decode(text + "=" * (-len(text) % 8))
    except binascii.Error:
        return None
    if base64.b32encode(raw).decode("ascii").rstrip("=") != text or raw[0] != version or len(raw) != _PAYLOAD[version] + 3:
        return None
    return raw[1:-2] if crc16_xmodem(raw[:-2]).to_bytes(2, "little") == raw[-2:] else None


def account(key: bytes) -> str:
    return encode_strkey(_ACCOUNT, key)


def contract(key: bytes) -> str:
    return encode_strkey(_CONTRACT, key)


def muxed(key: bytes, muxed_id: int) -> str:
    return encode_strkey(_MUXED, key + muxed_id.to_bytes(8, "big"))


def is_account(value: object) -> bool:
    return decode_strkey(_ACCOUNT, value) is not None


def is_contract(value: object) -> bool:
    return decode_strkey(_CONTRACT, value) is not None


@dataclass(frozen=True, slots=True)
class Unmuxed:
    base: str
    id: int


def unmux(value: object) -> Unmuxed | None:
    """The G base and the id of an M strkey, or None."""
    raw = decode_strkey(_MUXED, value)
    return None if raw is None else Unmuxed(account(raw[:32]), int.from_bytes(raw[32:], "big"))


def is_muxed(value: object) -> bool:
    return unmux(value) is not None


def muxed_id(h: AtrHash) -> int:
    """The hash's first 8 bytes, big-endian, as a u64."""
    return int.from_bytes(bytes.fromhex(h[2:18]), "big")


def muxed_for(base: str, h: AtrHash) -> str:
    """The M strkey of a G account and muxed_id(h). Raises ValueError when base is not a G strkey."""
    key = decode_strkey(_ACCOUNT, base)
    if key is None:
        raise ValueError("not a G account strkey")
    return muxed(key, muxed_id(h))


# ── envelopes ────────────────────────────────────────────────────────────────────────────────────────────────────


def strict_base64(text: str) -> bytes | None:
    """Strict RFC 4648 base64: the standard alphabet, padded to a multiple of 4, with zero padding bits (the bytes
    encode back to the same text). None for anything else."""
    data = b64_decode(text)
    return data if data is not None and b64_encode(data) == text else None


def _strkey_of(address: xdr.Address) -> tuple[str, str, int | None] | None:
    """An SCAddress as a strkey, its non-muxed base, and its muxed id; None for kinds without a strkey here."""
    if address.kind == 0:
        g = account(address.key)
        return g, g, None
    if address.kind == 1:
        c = contract(address.key)
        return c, c, None
    if address.kind == 2:
        assert address.id is not None
        return muxed(address.key, address.id), account(address.key), address.id
    return None


@dataclass(frozen=True, slots=True)
class Auth:
    address: str
    nonce: int
    expiration: int
    v2: bool
    preimage_hash: str


@dataclass(frozen=True, slots=True)
class Payment:
    asset: str
    source: str
    to: str
    to_base: str
    to_id: int | None
    amount: int
    auth: Auth


@dataclass(frozen=True, slots=True)
class _Parsed:
    payment: Payment
    agrees: bool
    envelope: xdr.Envelope
    entry: xdr.Entry
    credentials: xdr.Credentials


@dataclass(frozen=True, slots=True)
class _Transfer:
    asset: str
    source: tuple[str, str, int | None]
    to: tuple[str, str, int | None]
    amount: int


def _transfer_of(call: xdr.Call) -> _Transfer | None:
    """A contract call's transfer(from, to, amount): the contract, both addresses and the amount, or None."""
    if call.function != b"transfer" or len(call.args) != 3 or call.contract.kind != 1:
        return None
    asset = _strkey_of(call.contract)
    a0, a1, a2 = call.args
    if asset is None or a0.kind != 18 or a1.kind != 18:
        return None
    assert a0.address is not None and a1.address is not None
    source, to = _strkey_of(a0.address), _strkey_of(a1.address)
    if source is None or to is None or a2.i128 is None:
        return None
    return _Transfer(asset[0], source, to, a2.i128)


def preimage_of(network: str, entry: xdr.Entry, c: xdr.Credentials, expiration: int | None = None) -> bytes:
    """The HashIDPreimage bytes an address credential's signature commits to: type 9, or type 10 with the address."""
    network_id = hashlib.sha256(PASSPHRASE[network].encode("utf-8")).digest()
    ledger = c.expiration if expiration is None else expiration
    head = (10 if c.v2 else 9).to_bytes(4, "big") + network_id + c.nonce.to_bytes(8, "big", signed=True)
    head += ledger.to_bytes(4, "big")
    return head + (c.address.raw if c.v2 else b"") + entry.invocation


def _parse(data: bytes, network: str) -> _Parsed | Refusal:
    """The envelope's one transfer operation and the one address-credential entry whose address is its from. The
    payment's contract, to and amount are read from the entry's root invocation, the invocation the payer signs, which
    must itself be one transfer(from, to, amount) with no sub-invocations."""
    try:
        env = xdr.envelope(data)
    except xdr.NotOneTransfer:
        return Refusal("stellar/not-one-transfer")
    except (xdr.Malformed, RecursionError):
        return Refusal("stellar/tx-malformed")
    call = env.invoke.call
    operation = _transfer_of(call)
    if operation is None:
        return Refusal("stellar/not-one-transfer")
    source = operation.source
    matches = [
        (e, e.credentials)
        for e in env.invoke.entries
        if e.credentials is not None
        and (who := _strkey_of(e.credentials.address)) is not None
        and who[0] == source[0]
    ]
    if len(matches) != 1:
        return Refusal("stellar/no-address-auth")
    entry, c = matches[0]
    assert c is not None
    root = entry.root
    if root.call is None or root.subs != 0:
        return Refusal("stellar/not-one-transfer")
    signed = _transfer_of(root.call)
    if signed is None:
        return Refusal("stellar/not-one-transfer")
    agrees = call.raw == root.call.raw
    digest = hashlib.sha256(preimage_of(network, entry, c)).hexdigest()
    auth = Auth(address=source[0], nonce=c.nonce, expiration=c.expiration, v2=c.v2, preimage_hash="0x" + digest)
    payment = Payment(signed.asset, source[0], signed.to[0], signed.to[1], signed.to[2], signed.amount, auth)
    return _Parsed(payment, agrees, env, entry, c)


def _bytes_of(text: object, network: object) -> bytes | Refusal:
    if not is_stellar_network(network):
        return Refusal("stellar/network-malformed")
    if not isinstance(text, str) or text == "":
        return Refusal("stellar/tx-malformed")
    if len(text) > MAX_XDR:
        return Refusal("stellar/tx-too-large")
    data = strict_base64(text)
    return Refusal("stellar/tx-malformed") if data is None else data


@dataclass(frozen=True, slots=True)
class SignedTransfer:
    payment: Payment
    agrees: bool


def read_signed_transfer(text: object, network: object) -> SignedTransfer | Refusal:
    """The payment the payer's entry signs, and whether the operation invokes exactly that: decode_stellar_tx's input
    checks, without refusing an operation that differs from the signed invocation."""
    data = _bytes_of(text, network)
    if isinstance(data, Refusal):
        return data
    assert isinstance(network, str)
    parsed = _parse(data, network)
    return parsed if isinstance(parsed, Refusal) else SignedTransfer(parsed.payment, parsed.agrees)


def decode_stellar_tx(text: object, network: object) -> Payment | Refusal:
    """The one transfer of a strict base64 envelope of at most 8 KiB, read whole, with the one address authorization
    entry whose address is from and the SHA-256 of that entry's preimage. The entry's root invocation must be that same
    transfer, byte for byte, with no sub-invocations; the payment's contract, to and amount are the signed
    invocation's."""
    p = read_signed_transfer(text, network)
    if isinstance(p, Refusal):
        return p
    return p.payment if p.agrees else Refusal("stellar/not-one-transfer")


def _signature_val(key: bytes, signature: bytes) -> bytes:
    """ScVal vec [map {public_key: bytes key, signature: bytes signature}]."""

    def u32(n: int) -> bytes:
        return n.to_bytes(4, "big")

    def symbol(text: bytes) -> bytes:
        return u32(15) + u32(len(text)) + text + b"\0" * (-len(text) % 4)

    def blob(data: bytes) -> bytes:
        return u32(13) + u32(len(data)) + data + b"\0" * (-len(data) % 4)

    entries = symbol(b"public_key") + blob(key) + symbol(b"signature") + blob(signature)
    return u32(16) + u32(1) + u32(1) + u32(17) + u32(1) + u32(2) + entries


@dataclass(frozen=True, slots=True)
class StellarUnsigned:
    """What the payer signs (the signer signs SHA-256 of the preimage), and how the signature completes the
    envelope."""

    request: dict[str, object]
    _data: bytes
    _parsed: _Parsed
    _expiration: int
    _zero_source: bool
    _key: bytes

    def complete(self, signature: object) -> str | Refusal:
        """The base64 envelope with the entry's expiration set and its signature written as an account's."""
        if not isinstance(signature, bytes) or len(signature) != 64:
            return Refusal("stellar/tx-malformed")
        env, c = self._parsed.envelope, self._parsed.credentials
        data = self._data
        out = (
            data[: c.expiration_at]
            + self._expiration.to_bytes(4, "big")
            + data[c.expiration_at + 4 : c.signature_start]
            + _signature_val(self._key, signature)
            + data[c.signature_end :]
        )
        if self._zero_source:
            out = out[: env.source_start] + bytes(36) + out[env.source_end :]
        return base64.b64encode(out).decode("ascii")


@dataclass(frozen=True, slots=True)
class Signing:
    payment: Payment
    agrees: bool
    unsigned: StellarUnsigned


def signing_for(text: object, network: object, expiration: object, zero_source: bool) -> Signing | Refusal:
    """The from entry's preimage with its expiration ledger set, the payment that entry signs, whether the operation
    invokes exactly that, and the completion that writes the payer's signature."""
    data = _bytes_of(text, network)
    if isinstance(data, Refusal):
        return data
    assert isinstance(network, str)
    parsed = _parse(data, network)
    if isinstance(parsed, Refusal):
        return parsed
    if isinstance(expiration, bool) or not isinstance(expiration, int) or not 0 <= expiration <= 0xFFFFFFFF:
        return Refusal("stellar/tx-malformed")
    key = decode_strkey(_ACCOUNT, parsed.payment.source)
    if key is None:
        return Refusal("stellar/no-address-auth")
    if parsed.envelope.fee_bump:
        return Refusal("stellar/tx-malformed")
    preimage = preimage_of(network, parsed.entry, parsed.credentials, expiration)
    unsigned = StellarUnsigned(
        request={"kind": "stellar-auth", "preimage": preimage},
        _data=data,
        _parsed=parsed,
        _expiration=expiration,
        _zero_source=zero_source,
        _key=key,
    )
    return Signing(parsed.payment, parsed.agrees, unsigned)
