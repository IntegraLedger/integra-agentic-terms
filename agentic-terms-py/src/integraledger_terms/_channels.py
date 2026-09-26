"""The buyer's channel steps. One ATR covers a whole channel: the gate compares it once, at the opening, and the caller
keeps the result as a channel hold, the ATR's bytes together with the signed opening and the channel it names.
within signs a later voucher only for a channel held this way, re-deriving everything from the hold and never from the
new challenge, and only when that challenge advertises the held ATR's hash. It serves x402's batch channels and MPP's
sessions through the binding's build_within. record_charge records the server's cumulative charge, bounded by what was
signed.

The channel members come from the pairing's binding (build_within, channel_kind, channel_ref, bound_within)."""

import base64
import binascii
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

from . import _gate
from ._core import MAX_ATR_BYTES, atr_hash, hash_equals
from ._types import Advertised, Declined, DeclineCode, Json, Refusal, Signer
from .bindings._channel import BatchUnsigned, ChannelRef
from .bindings._jose import parse_json
from .bindings._lcp import from_lcp_string
from .bindings._mpp import network as mpp_network
from .bindings.mpp_session import session_resume
from .pieces._common import with_payment_identifier
from .pieces._mpp import pairings_of_placed, request_of

# A channel the buyer opened for an ATR it compared, as JSON the caller keeps and hands back: pairing, network,
# channel, h, atr (base64 of the ATR bytes the opening compared), opening (the signed opening, exactly as the gate
# returned it), charged (the server's cumulative charge last recorded, decimal, "0" at the opening) and signedMax (the
# largest maxClaimableAmount signed in the channel, decimal).
ChannelHold = dict[str, Any]

_DECIMAL = re.compile(r"[0-9]{1,78}")
_NOT_BOUND_WITHIN = re.compile(r".*/not-bound-within")
_HOLD_KEYS = ("pairing", "network", "channel", "h", "atr", "charged", "signedMax")
_REF_BYTES = 24
_MEMBERS = ("channel_kind", "channel_ref", "bound_within")
# At most this many challenges of a within document are looked at, as the MPP entry point reads a document.
_MAX_CHALLENGES = 32
# An opaque of at most this many base64url characters, 8 KiB decoded, is read.
_MAX_OPAQUE = 10_924
_B64URL = re.compile(r"[A-Za-z0-9_-]*")

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class Within:
    """A later payment signed in a held channel, and the hold with its largest signed amount updated."""

    signed: dict[str, Any]
    hold: ChannelHold


def _declined(code: DeclineCode, detail: str) -> Declined:
    return Declined(code, detail)


def _guarded(run: Callable[[], T]) -> T | Refusal:
    """Calls a binding member, reading a raise as a refusal."""
    try:
        return run()
    except Exception:
        return Refusal("member-failed")


def _has_channel(binding: Any) -> bool:
    return isinstance(getattr(binding, "id", None), str) and all(callable(getattr(binding, m, None)) for m in _MEMBERS)


def _as_json(value: object) -> Any:
    """The value as plain JSON, or None when it holds anything JSON does not carry."""
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError):
        return None


def _is_hold(value: object) -> bool:
    return (
        isinstance(value, Mapping)
        and all(isinstance(value.get(k), str) for k in _HOLD_KEYS)
        and _DECIMAL.fullmatch(value["charged"]) is not None
        and _DECIMAL.fullmatch(value["signedMax"]) is not None
        and isinstance(value.get("opening"), Mapping)
    )


def _opening_max(signed: object) -> str:
    """The opening voucher's maxClaimableAmount, where the payment carries one, else "0"."""
    payload = signed.get("payload") if isinstance(signed, Mapping) else None
    voucher = payload.get("voucher") if isinstance(payload, Mapping) else None
    most = voucher.get("maxClaimableAmount") if isinstance(voucher, Mapping) else None
    return most if isinstance(most, str) and _DECIMAL.fullmatch(most) is not None else "0"


def _atr_of(hold: Mapping[str, Any]) -> bytes | None:
    try:
        return base64.b64decode(hold["atr"], validate=True)
    except (binascii.Error, ValueError):
        return None


def open_channel(atr_bytes: bytes, opened: Json, binding: Any, landed: Json | None = None) -> ChannelHold | Declined:
    """Takes a channel pairing's signed opening and the ATR bytes the gate compared for it, with the landed receipt
    transact returned beside the opening, where it returned one. The opening, with that receipt, must be of kind open,
    carry the hash of these bytes, and name its channel; the hold keeps all three together."""
    if not _has_channel(binding):
        return _declined("pairing-not-supported", "The pairing has no channel.")
    if landed is not None and (not isinstance(landed, Mapping) or not isinstance(opened, Mapping)):
        return _declined("signed-not-bound", "The landed receipt is not a JSON object beside the opening.")
    signed = opened if landed is None else {**opened, "landed": landed}
    if not isinstance(atr_bytes, bytes):
        return _declined("signed-not-bound", "The ATR bytes are missing.")
    if len(atr_bytes) > MAX_ATR_BYTES:
        return _declined("atr-too-large", f"The ATR is larger than {MAX_ATR_BYTES} bytes.")
    if _guarded(lambda: binding.channel_kind(signed)) != "open":
        return _declined("signed-not-bound", "The payment does not open a channel.")
    h = atr_hash(atr_bytes)
    inside = _guarded(lambda: binding.bound(signed))
    if not isinstance(inside, str) or not hash_equals(inside, h):
        return _declined("signed-not-bound", "The opening does not carry the hash of these bytes.")
    ref = _guarded(lambda: binding.channel_ref(signed))
    if isinstance(ref, Refusal):
        return _declined("signed-not-bound", ref.code)
    if not isinstance(ref, ChannelRef):
        return _declined("signed-not-bound", "The opening names no channel.")
    opening = _as_json(signed)
    if not isinstance(opening, dict):
        return _declined("signed-not-bound", "The opening is not plain JSON.")
    return {
        "pairing": binding.id,
        "network": ref.network,
        "channel": ref.channel,
        "h": h,
        "atr": base64.b64encode(atr_bytes).decode("ascii"),
        "opening": opening,
        "charged": "0",
        "signedMax": _opening_max(signed),
    }


def _refund_inputs(inputs: Mapping[str, Any]) -> dict[str, Any]:
    """The buyer's own chain values a refund's build takes: a Solana request_close needs a recent blockhash when the
    option names none, and may take the Compute Budget values."""
    out: dict[str, Any] = {}
    blockhash, limit, price = inputs.get("recentBlockhash"), inputs.get("computeUnitLimit"), inputs.get("computeUnitPrice")
    if isinstance(blockhash, str):
        out["recentBlockhash"] = blockhash
    if isinstance(limit, int) and not isinstance(limit, bool) and 0 <= limit <= 2**53 - 1:
        out["computeUnitLimit"] = limit
    if isinstance(price, str) and _DECIMAL.fullmatch(price) is not None:
        out["computeUnitPrice"] = int(price)
    return out


def _same_channel(ref: object, hold: Mapping[str, Any]) -> bool:
    return isinstance(ref, ChannelRef) and ref.network == hold["network"] and ref.channel == hold["channel"]


async def within(
    doc: object,
    hold: ChannelHold,
    binding: Any,
    signer: Signer,
    refund: Mapping[str, Any] | None = None,
    inputs: Mapping[str, Any] | None = None,
) -> Within | Declined:
    """Signs one later voucher, or a refund, in a held channel. doc is the seller's document as given: an x402
    document, or MPP's list of challenges. The ATR bytes, the opening's hash and the opening's channel are re-derived
    from the hold, and the challenge must advertise the held hash. A voucher's
    maxClaimableAmount is the recorded charge plus the option's amount; a refund's is the recorded charge. inputs are
    the buyer's own chain values a refund's build takes. What was signed must be of the expected kind and belong to the
    held channel, or it is dropped."""
    if not _has_channel(binding):
        return _declined("pairing-not-supported", "The pairing has no channel.")
    ns = binding.id.split("/")[0]
    if not callable(getattr(binding, "build_within", None)):
        return _declined("pairing-not-supported", f"The pairing {binding.id} has no in-channel payment.")
    if not _is_hold(hold):
        return _declined("signed-not-bound", "The channel hold is malformed.")
    if hold["pairing"] != binding.id:
        return _declined("pairing-not-supported", f"The hold is not for the pairing {binding.id}.")
    refund_amount: int | None = None
    if refund is not None:
        amount = refund.get("amount") if isinstance(refund, Mapping) else None
        if not isinstance(refund, Mapping) or (
            "amount" in refund and (not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None)
        ):
            return _declined("no-payable-option", f"{ns}/input-missing")
        refund_amount = int(amount) if isinstance(amount, str) else None

    atr = _atr_of(hold)
    if atr is None or len(atr) > MAX_ATR_BYTES:
        return _declined("signed-not-bound", "The held ATR is unreadable.")
    h = atr_hash(atr)
    if not hash_equals(hold["h"], h):
        return _declined("hash-mismatch", "The held ATR does not hash to the held hash.")
    opened = _guarded(lambda: binding.bound(hold["opening"]))
    if not isinstance(opened, str) or not hash_equals(opened, h):
        return _declined("signed-not-bound", "The held opening does not carry the held ATR's hash.")
    if not _same_channel(_guarded(lambda: binding.channel_ref(hold["opening"])), hold):
        return _declined("signed-not-bound", "The held opening does not name the held channel.")

    if ns == "mpp":
        return await _session_within(binding, doc, hold, h, signer, refund)
    read = _guarded(lambda: binding.read(doc))
    if isinstance(read, Refusal):
        return _declined("offer-unreadable", read.code)
    if not isinstance(read, Advertised):
        return _declined("offer-unreadable", f"{ns}/offer-unreadable")
    if not hash_equals(read.h, h):
        return _declined(
            "hash-mismatch", "The challenge advertises another ATR's hash than the one this channel opened for."
        )
    offer = read.offer
    options = offer.get("options") if isinstance(offer, Mapping) else None
    accepted = next(
        (o for o in (options if isinstance(options, list) else []) if isinstance(o, Mapping) and o.get("network") == hold["network"]),
        None,
    )  # fmt: skip
    if accepted is None:
        return _declined("no-payable-option", f"{ns}/no-payable-option")
    price = accepted.get("amount")
    if not isinstance(price, str) or _DECIMAL.fullmatch(price) is None:
        return _declined("offer-unreadable", f"{ns}/option-malformed")
    charged = int(hold["charged"])
    max_claimable = charged if refund is not None else charged + int(price)
    payload = hold["opening"].get("payload")
    channel_config = payload.get("channelConfig") if isinstance(payload, Mapping) else None
    required = offer.get("required") if isinstance(offer, Mapping) else None

    w: dict[str, Any] = {
        "required": required,
        "accepted": accepted,
        "channelConfig": channel_config,
        "maxClaimableAmount": max_claimable,
    }
    if refund is not None:
        w["refund"] = {} if refund_amount is None else {"amount": refund_amount}
        w.update(_refund_inputs(inputs if isinstance(inputs, Mapping) else {}))
    unsigned = _guarded(lambda: binding.build_within(w, h))
    if isinstance(unsigned, Refusal):
        return _declined("offer-unreadable", unsigned.code)
    if not isinstance(unsigned, BatchUnsigned):
        return _declined("offer-unreadable", f"{ns}/build-failed")
    request = _gate.json_form({"kind": "batch", "requests": list(unsigned.requests)})

    try:
        answer = await signer.sign(request)
    except Exception:
        return _declined("signer-failed", "The signer did not sign.")
    if not isinstance(answer, list) or len(answer) != len(unsigned.requests) or not all(isinstance(s, str) for s in answer):
        return _declined("signed-not-bound", "The signer's answer did not complete the payment.")
    completed = _guarded(lambda: unsigned.complete(answer))
    if isinstance(completed, Refusal):
        return _declined("signed-not-bound", completed.code)
    if not isinstance(completed, dict):
        return _declined("signed-not-bound", "The signer's answer did not complete the payment.")
    signed = with_payment_identifier(completed, required, secrets.token_urlsafe(_REF_BYTES))
    if isinstance(signed, Refusal):
        return _declined("signed-not-bound", signed.code)

    expected = "close" if refund is not None and refund_amount is None else "within"
    if _guarded(lambda: binding.channel_kind(signed)) != expected:
        return _declined("signed-not-bound", f"The signed payment is not a {expected} payment.")
    inside = _guarded(lambda: binding.bound_within(signed))
    if isinstance(inside, Refusal):
        unbound = _NOT_BOUND_WITHIN.fullmatch(inside.code) is None
    else:
        unbound = not isinstance(inside, str) or not hash_equals(inside, h)
    if unbound:
        return _declined("signed-not-bound", "The signed voucher does not commit to the held ATR's hash.")
    if not _same_channel(_guarded(lambda: binding.channel_ref(signed)), hold):
        return _declined("signed-not-bound", "The signed voucher does not name the held channel.")
    signed_max = hold["signedMax"] if int(hold["signedMax"]) > max_claimable else str(max_claimable)
    return Within(signed=signed, hold={**hold, "signedMax": signed_max})


async def _session_within(
    binding: Any, doc: object, hold: ChannelHold, h: str, signer: Signer, refund: Mapping[str, Any] | None
) -> Within | Declined:
    """One voucher, or the close, in a held MPP session. The within challenge is the first of the document that either
    offers the pairing on the held network, or names a channel of the pairing on the held network, as session_resume
    reads it for the pairing's method. A named channel must be the held one, and a legal context in
    the challenge's opaque must name the held hash; either is checked before the signer is called. The voucher's
    cumulative amount is the recorded charge plus the challenge's amount, and the close's is the recorded charge. Every
    channel value comes from the held opening, through the binding's build_within."""
    if refund is not None and "amount" in refund:
        return _declined("pairing-not-supported", "mpp/within-action-not-built")
    challenge: Any = None
    candidates: list[Any] = doc[:_MAX_CHALLENGES] if isinstance(doc, list) else []
    for c in candidates:
        if not isinstance(c, Mapping):
            continue
        named = _named_channel(c, binding.id)
        if named is _NONE:
            if binding.id in pairings_of_placed(c) and mpp_network(c) == hold["network"]:
                challenge = c
                break
            continue
        if named is None or named.network != hold["network"]:
            continue
        if named.channel != hold["channel"]:
            return _declined("no-payable-option", "The challenge names a channel this hold did not open.")
        challenge = c
        break
    if challenge is None:
        return _declined("no-payable-option", "mpp/no-payable-option")
    named_h = _legal_context_of(challenge)
    if named_h == "malformed":
        return _declined("offer-unreadable", "mpp/legal-context-malformed")
    if named_h is not None and not hash_equals(named_h, h):
        return _declined("hash-mismatch", "The challenge names another ATR's hash than the one this channel opened for.")
    request_body = request_of(challenge)
    amount = request_body.get("amount") if request_body is not None else None
    if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None:
        return _declined("offer-unreadable", "mpp/request-malformed")
    action = "close" if refund is not None else "voucher"
    cumulative = int(hold["charged"]) if action == "close" else int(hold["charged"]) + int(amount)

    w = {"challenge": challenge, "opening": hold["opening"], "cumulativeAmount": cumulative, "action": action}
    unsigned = _guarded(lambda: binding.build_within(w, h))
    if isinstance(unsigned, Refusal):
        code: DeclineCode = "pairing-not-supported" if unsigned.code.endswith("/within-action-not-built") else "offer-unreadable"
        return _declined(code, unsigned.code)
    if not isinstance(unsigned, BatchUnsigned):
        return _declined("offer-unreadable", "mpp/build-failed")
    try:
        answer = await signer.sign(_gate.json_form({"kind": "batch", "requests": list(unsigned.requests)}))
    except Exception:
        return _declined("signer-failed", "The signer did not sign.")
    if not isinstance(answer, list) or len(answer) != len(unsigned.requests) or not all(isinstance(s, str) for s in answer):
        return _declined("signed-not-bound", "The signer's answer did not complete the payment.")
    signed = _guarded(lambda: unsigned.complete(answer))
    if isinstance(signed, Refusal):
        return _declined("signed-not-bound", signed.code)
    if not isinstance(signed, dict):
        return _declined("signed-not-bound", "The signer's answer did not complete the payment.")

    expected = "close" if action == "close" else "within"
    if _guarded(lambda: binding.channel_kind(signed)) != expected:
        return _declined("signed-not-bound", f"The signed payment is not a {expected} payment.")
    inside = _guarded(lambda: binding.bound_within(signed))
    if isinstance(inside, Refusal):
        unbound = _NOT_BOUND_WITHIN.fullmatch(inside.code) is None
    else:
        unbound = not isinstance(inside, str) or not hash_equals(inside, h)
    if unbound:
        return _declined("signed-not-bound", "The signed voucher does not commit to the held ATR's hash.")
    if not _same_channel(_guarded(lambda: binding.channel_ref(signed)), hold):
        return _declined("signed-not-bound", "The signed voucher does not name the held channel.")
    signed_max = hold["signedMax"] if int(hold["signedMax"]) > cumulative else str(cumulative)
    return Within(signed=signed, hold={**hold, "signedMax": signed_max})


_NONE = ChannelRef("", "")


def _named_channel(c: Mapping[str, Any], pairing: str) -> ChannelRef | None:
    """The channel a challenge of the pairing names for the client to resume: _NONE when it names none, None when the
    challenge is not of the pairing, and otherwise session_resume's network and channel, spelled as the pairing's
    channel_ref spells a held channel. A named channel that session_resume cannot read names a channel no hold
    opened."""
    ref = session_resume(c)
    if ref is None:
        return _NONE
    if f"mpp/{c.get('intent')}/{c.get('method')}" != pairing:
        return None
    return ChannelRef("unread", "unread") if isinstance(ref, Refusal) else ref


def _legal_context_of(c: Mapping[str, Any]) -> str | None:
    """The hash a challenge's opaque names as its legal context: None when there is no opaque or it has no
    legalContext member, "malformed" when either cannot be read."""
    opaque = c.get("opaque")
    if opaque is None:
        return None
    if not isinstance(opaque, str) or len(opaque) > _MAX_OPAQUE or _B64URL.fullmatch(opaque) is None:
        return "malformed"
    try:
        value = parse_json(base64.urlsafe_b64decode(opaque + "=" * (-len(opaque) % 4)).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return "malformed"
    if not isinstance(value, dict):
        return "malformed"
    lc = value.get("legalContext")
    if lc is None:
        return None
    named = from_lcp_string(lc) if isinstance(lc, str) else None
    return "malformed" if named is None else named


def record_charge(hold: ChannelHold, charged_cumulative_amount: str) -> ChannelHold | Declined:
    """Records the server's cumulative charge for the channel. It must be a decimal no lower than the charge last
    recorded and no higher than the largest amount signed in the channel."""
    if not _is_hold(hold):
        return _declined("signed-not-bound", "The channel hold is malformed.")
    if not isinstance(charged_cumulative_amount, str) or _DECIMAL.fullmatch(charged_cumulative_amount) is None:
        return _declined("offer-unreadable", "The charged amount is not a decimal.")
    charged = int(charged_cumulative_amount)
    if charged < int(hold["charged"]):
        return _declined("offer-unreadable", "The charged amount is below the charge already recorded.")
    if charged > int(hold["signedMax"]):
        return _declined("offer-unreadable", "The charged amount is above the largest amount signed in the channel.")
    return {**hold, "charged": str(charged)}
