"""The in-channel payment of MPP's sessions: the checks build_within makes on its input, the one EIP-712 voucher
request whose complete returns the within or close credential, and what the Hedera, Solana and XRPL sessions' channel
members read from a payment: its kind, and a within or close payment's echoed methodDetails."""

from collections.abc import Callable, Mapping, Sequence
from typing import Any, TypeVar

from .._core import AtrHash, hash_equals
from .._types import Refusal
from ._channel import BatchUnsigned, ChannelKind
from ._lcp import is_object, normal_hash
from ._mpp import credential_of, is_challenge_shape, is_hex_bytes
from ._mpp_checks import decode_object

U128 = 1 << 128
U96 = 1 << 96
MAX_SIGNATURE = 8192
# The actions build_within does not build: topUp (a new deposit), Solana's operator use and Lightning's bearer.
WITHIN_NOT_BUILT = ("topUp", "use", "bearer")

O = TypeVar("O")


def within_checks(
    w: object, h: object, intent_and_method: str, opened: Callable[[Mapping[str, Any]], O | Refusal], limit: int
) -> O | Refusal:
    """The checks build_within makes on its input before any channel value is read, in the input's member order: the
    within challenge's shape and its intent and method; the opening, by opened, bound to h; the cumulative amount below
    limit; and the action, voucher or close."""
    if not is_object(w):
        return Refusal("mpp/input-malformed")
    c = w.get("challenge")
    if not is_challenge_shape(c) or not isinstance(c.get("id"), str):  # type: ignore[union-attr]
        return Refusal("mpp/input-malformed")
    assert isinstance(c, Mapping)
    if f"{c['intent']}/{c['method']}" != intent_and_method:
        return Refusal("mpp/not-this-pairing")
    opening = credential_of(w.get("opening"))
    if isinstance(opening, Refusal):
        return opening
    o = opened(opening)
    if isinstance(o, Refusal):
        return o
    if not isinstance(h, str) or normal_hash(h) is None or not hash_equals(getattr(o, "h"), h):
        return Refusal("mpp/id-not-ours")
    amount = w.get("cumulativeAmount")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0 or amount >= limit:
        return Refusal("mpp/input-malformed")
    action = w.get("action")
    if action in WITHIN_NOT_BUILT:
        return Refusal("mpp/within-action-not-built")
    if action not in ("voucher", "close"):
        return Refusal("mpp/session-action")
    return o


def within_unsigned(w: Mapping[str, Any], typed_data: dict[str, Any], channel_id: str, descriptor: Any = None) -> BatchUnsigned:
    """The one eip712 voucher request, and the credential of the drafts' members: action, channel, amount, signature,
    and the opening's descriptor where it has one."""
    challenge = dict(w["challenge"])
    action = w["action"]
    amount = str(w["cumulativeAmount"])

    def complete(signatures: Sequence[str]) -> dict[str, Any] | Refusal:
        if not isinstance(signatures, (list, tuple)) or len(signatures) != 1:
            return Refusal("mpp/credential-malformed")
        signature = signatures[0]
        if not is_hex_bytes(signature, 65, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        payload: dict[str, Any] = {"action": action, "channelId": channel_id, "cumulativeAmount": amount, "signature": signature}
        if descriptor is not None:
            payload["descriptor"] = descriptor
        return {"challenge": challenge, "payload": payload}

    return BatchUnsigned(requests=[{"kind": "eip712", "typedData": typed_data}], complete=complete)


def action_kind(presented: object, within: Sequence[str]) -> ChannelKind | Refusal:
    """open, close, or within for an action named in within."""
    if not is_object(presented) or not is_object(presented.get("payload")):
        return Refusal("mpp/credential-malformed")
    action = presented["payload"].get("action")
    if action == "open":
        return "open"
    if action == "close":
        return "close"
    if isinstance(action, str) and action in within:
        return "within"
    return Refusal("mpp/session-action")


def echoed_details(presented: object, method: str) -> Mapping[str, Any] | Refusal:
    """The methodDetails of a within or close payment's echoed session challenge of method, read from its request
    without the opening's checks: the seller issues those challenges itself, with its own id and the channel named."""
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    challenge = c["challenge"]
    if challenge.get("intent") != "session" or challenge.get("method") != method:
        return Refusal("mpp/not-this-pairing")
    request = decode_object(challenge.get("request"))
    if request is None:
        return Refusal("mpp/request-malformed")
    if "methodDetails" not in request:
        return {}
    md = request["methodDetails"]
    return md if is_object(md) else Refusal("mpp/request-malformed")
