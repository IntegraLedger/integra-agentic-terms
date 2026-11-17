"""The deadline of a payment whose wallet builds the transaction and picks its expiry itself (terms' profile
buyer-gate.md, rule 8): aptos-transaction, cardano-transaction, sui-transaction and substrate-call. Before anything is
signed, the gate hands the wallet the pairing's ceiling as the latest deadline it may sign, in the form's own unit;
after the wallet signs, and before the payment is returned, the gate reads the deadline the transaction signs with the
bindings' decoders, as the protocol package's reference reads it, and holds it to that latest deadline. A payment signed
past it, or with no deadline, is declined and discarded: the decline carries no part of it."""

import re
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Literal

from ._checks import ceiling_of, given_start, pace_of, start_input
from ._types import Binding, Ceilings, Chosen, Declined, Inputs
from .bindings.x402_exact_aptos import decode_aptos_tx
from .bindings.x402_exact_cardano import decode_cardano_tx
from .bindings.x402_exact_polkadot_lcp_assets_remark import era_of
from .bindings.x402_exact_sui import decode_sui_tx

# Each wallet-built kind: the request member that carries the latest deadline, and the unit it is counted in.
_MEMBERS: Mapping[str, tuple[str, str]] = {
    "aptos-transaction": ("maxExpirationTimestampSecs", "seconds"),
    "cardano-transaction": ("maxTtl", "slot"),
    "sui-transaction": ("maxEpoch", "epoch"),
    "substrate-call": ("maxEraPeriod", "block"),
}

# A mortal era's period on a Substrate chain: a power of two from 4 to 65,536 blocks.
_MIN_ERA = 4
_MAX_ERA = 65_536
_DECIMAL = re.compile(r"[0-9]{1,78}")
_HEX = re.compile(r"0x(?:[0-9a-fA-F]{2})*")


def _wallet_kind(request: object) -> str | None:
    """The request's kind where it is one whose wallet picks the expiry; else None."""
    kind = request.get("kind") if isinstance(request, Mapping) else None
    return kind if isinstance(kind, str) and kind in _MEMBERS else None


def _network_of(request: Mapping[str, Any]) -> str | None:
    """The network the request names: accepted.network for an x402 option the wallet builds from, else network."""
    accepted = request.get("accepted")
    n = accepted.get("network") if isinstance(accepted, Mapping) else request.get("network")
    return n if isinstance(n, str) else None


def _floor_power_of_two(n: int) -> int:
    """The largest power of two at most n, or 0 for none."""
    return 1 << (n.bit_length() - 1) if n >= 1 else 0


def _latest(kind: str, network: str, ceiling: int, inputs: Inputs, now: int, pairing: str) -> str | Declined:
    """The latest deadline the wallet may sign, in the form's unit, for a ceiling of ceiling seconds at the gate's clock
    now: Aptos's expiration_timestamp_secs at now plus the ceiling; Cardano's TTL slot and Sui's epoch counted from the
    slot or epoch the caller gives, at the chain's pace, an epoch admitting the whole of itself; the longest mortal era
    a Substrate signer may write, a power of two. A form whose finest deadline is longer than the ceiling (a Sui epoch
    against less than a day) is past-ceiling; a start the caller does not give is no-payable-option."""
    if kind == "aptos-transaction":
        return str(now + ceiling)
    pace = pace_of(network)
    if pace is None:
        return Declined("past-ceiling", f"The gate holds no pace for {network}.")
    units = int(ceiling // pace)
    if kind == "substrate-call":
        era = _floor_power_of_two(min(units, _MAX_ERA))
        if era < _MIN_ERA:
            return Declined("past-ceiling", f"The shortest era a payment through {pairing} signs is past its ceiling of {ceiling} s.")
        return str(era)
    start = given_start(network, inputs)
    if start_input(network) is None or start is None:
        return Declined("no-payable-option", f"{network.split(':', 1)[0]}/input-missing")
    if kind == "sui-transaction":
        if units < 1:
            return Declined(
                "past-ceiling", f"An epoch, the shortest deadline a payment through {pairing} signs, is past its ceiling of {ceiling} s."
            )
        return str(start + units - 1)
    return str(start + units)


def with_deadline(
    binding: Binding, request: dict[str, Any] | None, chosen: Chosen, inputs: Inputs, ceilings: Ceilings | None, now: int
) -> tuple[dict[str, Any] | None, Chosen] | Declined:
    """The request handed to the wallet with the latest deadline it may sign, and chosen keeping it, where the request
    is of a kind whose wallet picks the expiry: the deadline chosen already keeps, else the pairing's ceiling in the
    form's unit. Where ceilings lifts the pairing's ceiling ("no-end") the request is handed as built. Any other request
    is returned as it is."""
    kind = _wallet_kind(request)
    if kind is None or request is None:
        return request, chosen
    member = _MEMBERS[kind][0]
    deadline = chosen.deadline
    if deadline is None:
        pairing = str(binding.id)
        ceiling = ceiling_of(pairing, inputs, ceilings)
        if ceiling == "no-end":
            return request, chosen
        if isinstance(ceiling, Declined):
            return ceiling
        network = _network_of(request)
        if network is None:
            return Declined("offer-unreadable", f"{pairing.split('/', 1)[0]}/option-malformed")
        found = _latest(kind, network, ceiling, inputs, now, pairing)
        if isinstance(found, Declined):
            return found
        deadline = found
    return {**request, member: deadline}, replace(chosen, deadline=deadline)


def _signed_deadline(kind: str, signed: object) -> int | Literal["none"] | None:
    """The deadline the signed payment signs, in the form's unit, read as the protocol package's reference reads it:
    Aptos's expiresAt, Cardano's ttlSlot, Sui's untilEpoch and a Substrate era's period; "none" where it signs none (no
    TTL, no expiration epoch, an immortal era); None where it cannot be read."""
    payload = signed.get("payload") if isinstance(signed, Mapping) else None
    if not isinstance(payload, Mapping):
        return None
    if kind == "substrate-call":
        xt = payload.get("extrinsic")
        if not isinstance(xt, str) or _HEX.fullmatch(xt) is None:
            return None
        era = era_of(bytes.fromhex(xt[2:]))
        if era == "immortal":
            return "none"
        return era[0] if isinstance(era, tuple) else None
    transaction = payload.get("transaction")
    if not isinstance(transaction, str):
        return None
    if kind == "aptos-transaction":
        aptos = decode_aptos_tx(transaction)
        at = aptos.get("expiresAt") if isinstance(aptos, dict) else None
        return at if isinstance(at, int) and not isinstance(at, bool) else None
    if kind == "cardano-transaction":
        cardano = decode_cardano_tx(transaction)
        ttl = getattr(cardano, "ttl_slot", "unread")
        return "none" if ttl is None else ttl if isinstance(ttl, int) and not isinstance(ttl, bool) else None
    sui = decode_sui_tx(transaction)
    until = getattr(sui, "until_epoch", "unread")
    return "none" if until is None else until if isinstance(until, int) and not isinstance(until, bool) else None


def held_to_deadline(binding: Binding, request: object, signed: object, chosen: Chosen) -> Declined | None:
    """After the wallet signs and before the payment is returned: where chosen keeps the latest deadline the request
    carried, the deadline the signed payment signs is held to it: a payment that signs none is no-end, one past it, or
    one whose deadline cannot be read, past-ceiling. The decline names no part of the payment, which the gate
    discards."""
    kind = _wallet_kind(request)
    kept: object = chosen.deadline
    if kind is None or kept is None:
        return None
    pairing = str(binding.id)
    if not isinstance(kept, str) or _DECIMAL.fullmatch(kept) is None:
        return Declined("past-ceiling", f"The latest deadline kept for {pairing} is not a decimal.")
    try:
        signed_at = _signed_deadline(kind, signed)
    except Exception:
        signed_at = None
    if signed_at == "none":
        return Declined("no-end", f"The payment through {pairing} the wallet signed signs no end; it was discarded.")
    if signed_at is None:
        return Declined("past-ceiling", f"The gate cannot read the deadline the payment through {pairing} signs; it was discarded.")
    unit = _MEMBERS[kind][1]
    if signed_at > int(kept):
        return Declined(
            "past-ceiling", f"The payment through {pairing} the wallet signed ends past the latest {unit} it may sign, {kept}; it was discarded."
        )
    return None
