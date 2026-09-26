"""The buyer half of the pairing x402/exact/polkadot/lcp-assets-remark: read, build with complete, and bound.

The payer signs one Polkadot Asset Hub extrinsic whose call is utility.batch_all([assets.transfer_keep_alive,
system.remark_with_event]) with the ATR hash's LCP string as the remark. Nothing here fetches, hashes or signs.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._lcp import from_lcp_string, is_object, normal_hash, safe_int, to_lcp_string
from ._scale import compact, compact_at
from ._ss58 import ss58_decode
from ._x402 import chosen, payment_with, presented_with, read_for

ID = "x402/exact/polkadot/lcp-assets-remark"

POLKADOT_NETWORKS = ("polkadot:68d56f15f85d3136970ec16946040bc1", "polkadot:67f9723393ef76214df0118c34bbbd3d")
LCP_ASSETS_REMARK = "lcp-assets-remark"
# Pallet and call indices, the same on both networks.
BATCH_ALL = bytes([40, 2])
TRANSFER_KEEP_ALIVE = bytes([50, 9])
REMARK_WITH_EVENT = bytes([0, 7])

MAX_EXTRINSIC = 4096
REMARK_LENGTH = 77
_U32_LIMIT = 1 << 32
_U128_LIMIT = 1 << 128
_DECIMAL = re.compile(r"0|[1-9][0-9]*")
_LOWER_HEX = re.compile(r"0x(?:[0-9a-f]{2})*")


def _decimal_below(value: object, limit: int) -> int | None:
    """A decimal string with no leading zero below limit, or None."""
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None or len(value) > len(str(limit)):
        return None
    n = int(value)
    return n if n < limit else None


def encode_profile_call(asset_id: int, dest: bytes, amount: int, remark: bytes) -> bytes:
    """batch_all([transfer_keep_alive(assetId, Id(dest), amount), remark_with_event(remark)])"""
    return (
        BATCH_ALL + b"\x08" + TRANSFER_KEEP_ALIVE + compact(asset_id) + b"\x00" + dest + compact(amount)
        + REMARK_WITH_EVENT + compact(len(remark)) + remark
    )  # fmt: skip


def decode_profile_call(call: bytes) -> tuple[int, bytes, int, bytes] | Refusal:
    """The profile's call, exactly, with canonical compacts and no trailing byte: asset id, dest, amount, remark."""
    no = Refusal("polkadot/call-not-profile")
    head = BATCH_ALL + b"\x08" + TRANSFER_KEEP_ALIVE
    if call[: len(head)] != head:
        return no
    asset = compact_at(call, len(head))
    if asset is None or asset[0] >= _U32_LIMIT or asset[1] >= len(call) or call[asset[1]] != 0x00:
        return no
    dest_at = asset[1] + 1
    dest = call[dest_at : dest_at + 32]
    if len(dest) != 32:
        return no
    amount = compact_at(call, dest_at + 32)
    if amount is None or amount[0] >= _U128_LIMIT:
        return no
    r = amount[1]
    if call[r : r + 2] != REMARK_WITH_EVENT:
        return no
    length = compact_at(call, r + 2)
    if length is None or length[0] != REMARK_LENGTH or length[1] + REMARK_LENGTH != len(call):
        return no
    return asset[0], dest, amount[0], call[length[1] :]


def split_signed(xt: bytes) -> tuple[bytes, int] | Refusal:
    """The preamble of a signed v4 extrinsic: the length prefix, 0x84, MultiAddress::Id and a MultiSignature. Gives
    the signer and the index after the signature; the extension bytes that follow are not decoded."""
    if len(xt) > MAX_EXTRINSIC:
        return Refusal("polkadot/extrinsic-too-large")
    length = compact_at(xt, 0)
    if length is None or length[0] != len(xt) - length[1]:
        return Refusal("polkadot/extrinsic-malformed")
    at = length[1]
    if at >= len(xt) or xt[at] != 0x84:
        return Refusal("polkadot/not-signed-v4")
    at += 1
    if at >= len(xt) or xt[at] != 0x00 or at + 33 > len(xt):
        return Refusal("polkadot/address-not-id")
    signer = xt[at + 1 : at + 33]
    at += 33
    variant = xt[at] if at < len(xt) else None
    size = 64 if variant in (0, 1) else 65 if variant in (2, 3) else -1
    if size < 0 or at + 1 + size > len(xt):
        return Refusal("polkadot/signature-malformed")
    return signer, at + 1 + size


def _with_suffix(xt: bytes, call: bytes) -> bool | Refusal:
    """The extrinsic ends with the call, which starts at or after the signature's end."""
    split = split_signed(xt)
    if isinstance(split, Refusal):
        return split
    start = len(xt) - len(call)
    if start < split[1] or xt[start:] != call:
        return Refusal("polkadot/call-not-suffix")
    return True


def _check(option: Mapping[str, Any]) -> bool | Refusal | None:
    """The pairing's filter: exact on a supported Polkadot network, the profile's transfer method, a u32 asset id, a
    non-zero u128 amount, a timeout of 1 to 3600 seconds and an SS58 payee."""
    network = option.get("network") if is_object(option) else None
    if not isinstance(network, str) or not network.startswith("polkadot:"):
        return None
    if option.get("scheme") != "exact":
        return None
    if network not in POLKADOT_NETWORKS:
        return Refusal("polkadot/network-unsupported")
    extra = option.get("extra")
    if not is_object(extra) or extra.get("assetTransferMethod") != LCP_ASSETS_REMARK:
        return Refusal("polkadot/option-malformed")
    if "paymentFlow" in extra and extra["paymentFlow"] not in ("authorization", "upfront"):
        return Refusal("polkadot/option-malformed")
    if _decimal_below(option.get("asset"), _U32_LIMIT) is None:
        return Refusal("polkadot/option-malformed")
    if _decimal_below(option.get("amount"), _U128_LIMIT) in (None, 0):
        return Refusal("polkadot/option-malformed")
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    if timeout is None or timeout < 1 or timeout > 3600:
        return Refusal("polkadot/option-malformed")
    return True if ss58_decode(option.get("payTo")) is not None else Refusal("polkadot/address-malformed")


@dataclass(frozen=True, slots=True)
class PolkadotUnsigned:
    """The call the payer's signer wraps in an extrinsic, and the payment that extrinsic completes."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]
    _call: bytes

    def complete(self, extrinsic: bytes) -> dict[str, Any] | Refusal:
        """The payment, for a signed v4 extrinsic that ends with the call."""
        if not isinstance(extrinsic, bytes):
            return Refusal("polkadot/extrinsic-malformed")
        ok = _with_suffix(extrinsic, self._call)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("polkadot/call-not-suffix")
        payload = {"extrinsic": "0x" + extrinsic.hex(), "call": "0x" + self._call.hex()}
        return payment_with(self._required, self._accepted, payload)


@dataclass(frozen=True, slots=True)
class X402ExactPolkadotLcpAssetsRemark:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        """H, the link, and the options this pairing can pay, in document order."""
        return read_for(_check)(doc)

    def build(self, choice: Json, h: AtrHash) -> PolkadotUnsigned | Refusal:
        """The profile call for the chosen option, the hash's LCP string as its remark."""
        if not is_object(choice):
            return Refusal("polkadot/option-malformed")
        required, accepted = choice.get("required"), choice.get("accepted")
        ok = chosen(required, accepted, _check)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        assert is_object(required) and is_object(accepted)
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        dest = ss58_decode(accepted["payTo"])
        assert dest is not None
        call = encode_profile_call(int(accepted["asset"]), dest, int(accepted["amount"]), to_lcp_string(nh).encode())
        request = {"kind": "substrate-call", "network": accepted["network"], "call": call}
        return PolkadotUnsigned(request=request, _required=required, _accepted=accepted, _call=call)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """The hash inside what the payer signed: the remark of the profile call the extrinsic ends with. No signature
        is verified here."""
        p = presented_with(presented, _check)
        if isinstance(p, Refusal):
            return p
        _, payload, _ = p
        extrinsic, call = payload.get("extrinsic"), payload.get("call")
        if (
            not isinstance(extrinsic, str)
            or len(extrinsic) > 2 * MAX_EXTRINSIC + 2
            or _LOWER_HEX.fullmatch(extrinsic) is None
        ):
            return Refusal("polkadot/extrinsic-malformed")
        if not isinstance(call, str) or _LOWER_HEX.fullmatch(call) is None:
            return Refusal("polkadot/call-not-profile")
        xt, call_bytes = bytes.fromhex(extrinsic[2:]), bytes.fromhex(call[2:])
        ok = _with_suffix(xt, call_bytes)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("polkadot/call-not-suffix")
        decoded = decode_profile_call(call_bytes)
        if isinstance(decoded, Refusal):
            return decoded
        try:
            remark = decoded[3].decode("utf-8")
        except UnicodeDecodeError:
            return Refusal("polkadot/remark-not-lcp")
        h = from_lcp_string(remark)
        return Refusal("polkadot/remark-not-lcp") if h is None else h
