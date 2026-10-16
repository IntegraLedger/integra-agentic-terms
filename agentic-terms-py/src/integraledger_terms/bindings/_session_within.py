"""The in-channel payment of MPP's sessions: the checks build_within makes on its input, the one EIP-712 voucher
request whose complete returns the within or close credential, and what the Hedera, Solana and XRPL sessions' channel
members read from a payment: its kind, a within or close payment's echoed methodDetails, and the network those
methodDetails name."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from .._core import AtrHash, hash_equals
from .._types import Refusal
from ._channel import BatchUnsigned, ChannelKind
from ._lcp import is_object, normal_hash
from ._mpp import challenge_snapshot, credential_of, is_challenge_shape, is_hex_bytes, measured
from ._mpp_checks import decode_object, hedera_session_network_of, solana_network_of, xrpl_network_of

U128 = 1 << 128
U96 = 1 << 96
MAX_SIGNATURE = 8192

O = TypeVar("O")
R = TypeVar("R")


@dataclass(frozen=True, slots=True)
class WithinHeld(Generic[O, R]):
    """What within_checks holds: the opening, read and bound to H; the within challenge's read; and the within
    challenge, the snapshot the in-channel credential carries."""

    opening: O
    within: R
    challenge: dict[str, Any]


def within_checks(
    w: object,
    h: object,
    intent_and_method: str,
    read: Callable[[dict[str, Any]], R | Refusal],
    opened: Callable[[Mapping[str, Any]], O | Refusal],
    limit: int,
    not_built: Sequence[str],
) -> WithinHeld[O, R] | Refusal:
    """The checks build_within makes on its input before any channel value is read, in this order (@integraledger/lcp
    0.4.1's withinChecks). First the within challenge, read as the pairing's channel_kind, channel_ref and bound_within
    read the payment that carries it, with their code for each fault: the snapshot challenge_snapshot takes of it, its
    own members only, which is the challenge the credential carries; a value that is not an object, a snapshot that is
    not challenge-shaped or has no string id, and one whose least credential, {challenge, payload: {}}, is over the
    credential size bound, mpp/credential-malformed; another intent or method, mpp/not-this-pairing; then read, the
    readers' read of its request, with their codes. The seller issues the within challenge with its own id and the
    channel named, so it is not held to the pairing's filter, which refuses a challenge naming a channel, and its id is
    not read. Then h, a valid ATR hash (else mpp/id-not-ours); the cumulative amount below limit; the action, voucher or
    close; and last the opening, by opened, bound to h. Every check before the opening reads only the input and h.
    not_built lists the actions the pairing's draft defines within a channel that build_within does not build: each is
    mpp/within-action-not-built, and an action neither built nor listed is mpp/session-action, as the pairing's
    channel_kind answers an action its draft does not define."""
    if not is_object(w):
        return Refusal("mpp/input-malformed")
    c = challenge_snapshot(w.get("challenge"))
    if c is None or not is_challenge_shape(c) or not isinstance(c.get("id"), str):
        return Refusal("mpp/credential-malformed")
    least = measured({"challenge": c, "payload": {}})
    if isinstance(least, Refusal):
        return least
    if f"{c['intent']}/{c['method']}" != intent_and_method:
        return Refusal("mpp/not-this-pairing")
    within = read(c)
    if isinstance(within, Refusal):
        return within
    if not isinstance(h, str) or normal_hash(h) is None:
        return Refusal("mpp/id-not-ours")
    amount = w.get("cumulativeAmount")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0 or amount >= limit:
        return Refusal("mpp/input-malformed")
    action = w.get("action")
    if action in not_built:
        return Refusal("mpp/within-action-not-built")
    if action not in ("voucher", "close"):
        return Refusal("mpp/session-action")
    opening = credential_of(w.get("opening"))
    if isinstance(opening, Refusal):
        return opening
    o = opened(opening)
    if isinstance(o, Refusal):
        return o
    if not hash_equals(getattr(o, "h"), h):
        return Refusal("mpp/id-not-ours")
    return WithinHeld(o, within, c)


@dataclass(frozen=True, slots=True)
class WithinDetails:
    """A Hedera, Solana or XRPL session's within challenge as the channel members read it: its methodDetails and the
    network they name."""

    details: Mapping[str, Any]
    network: str


def within_details(challenge: dict[str, Any], method: str) -> WithinDetails | Refusal:
    """The Hedera, Solana or XRPL session's read of a within challenge, as channel_kind, channel_ref and bound_within
    read the payment that carries it: its methodDetails (echoed_details, on {challenge, payload: {}}), then the network
    they name: Hedera's chainId, Solana's network (localnet, which has no CAIP-2 network, svm/network-undeclared) or
    XRPL's network, with each reader's code."""
    details = echoed_details({"challenge": challenge, "payload": {}}, method)
    if isinstance(details, Refusal):
        return details
    network: str | None | Refusal
    if method == "hedera":
        network = hedera_session_network_of(details)
    elif method == "solana":
        network = solana_network_of(details, True)
        if network is None:
            network = Refusal("svm/network-undeclared")
    else:
        network = xrpl_network_of(details)
    return network if isinstance(network, Refusal) else WithinDetails(details, network)


def within_unsigned(
    challenge: dict[str, Any], w: Mapping[str, Any], typed_data: dict[str, Any], channel_id: str, descriptor: Any = None
) -> BatchUnsigned:
    """The one eip712 voucher request, and the credential of the drafts' members: action, channel, amount, signature,
    and the opening's descriptor where it has one. Its challenge is the snapshot within_checks holds."""
    action = w["action"]
    amount = str(w["cumulativeAmount"])

    def complete(signatures: Sequence[str]) -> dict[str, Any] | Refusal:
        if not isinstance(signatures, (list, tuple)) or len(signatures) != 1:
            return Refusal("mpp/credential-malformed")
        signature = signatures[0]
        if not is_hex_bytes(signature, 1, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        payload: dict[str, Any] = {"action": action, "channelId": channel_id, "cumulativeAmount": amount, "signature": signature}
        if descriptor is not None:
            payload["descriptor"] = descriptor
        return measured({"challenge": challenge, "payload": payload})

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
