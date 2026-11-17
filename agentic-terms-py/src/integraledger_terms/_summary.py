"""The approval summary (terms' profile buyer-gate.md, rule 13): for each pairing whose row the profile's table fills, the
function that reads every authority the signature grants from the request handed to the signer, never from the option
or the build's inputs. A pairing with no entry here, or whose entry cannot read the request it is given, has no summary,
and the gate declines its request summary-missing: nothing is signed unshown."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from ._types import Inputs, Payee, Summary, Validity
from ._summary_checkout import acp_allowance, ap2_checkout_mandate, ucp_checkout, ucp_legal_context

_DECIMAL = re.compile(r"[0-9]{1,78}")


@dataclass(frozen=True, slots=True)
class Opened:
    """The step that opened a payment signed in steps, such as a session's or a channel's opening before its voucher:
    the request the signer was handed, its summary, whose payees, asset and network are the channel's, and the signer's
    answer to it."""

    request: Mapping[str, Any]
    summary: Summary
    signature: Any


@dataclass(frozen=True, slots=True)
class SummaryEntry:
    """One pairing's summary. show reads the request handed to the signer, with the signing account's CAIP-2 network
    where the gate knows the account, and answers None for a request it cannot read; its atr is filled by the gate. A
    kind whose signed bytes name no network (a Solana message, an XRPL transaction without NetworkID, a Hedera body)
    shows that network; a kind whose bytes name one shows its own, so a mismatch is visible. opened, for a later step of
    a payment signed in steps, which names only the channel, is the step that opened that channel: the later step is
    shown with its payees, asset and network, and one whose channel is not the one it opened has no summary. start, for
    a deadline signed as a height where the request signs no start, reads the height the caller gave the build from its
    inputs."""

    show: Callable[[Mapping[str, Any], str | None, Opened | None], Summary | None]
    start: Callable[[Inputs], int | None] | None = None


def _decimal(v: object) -> str | None:
    """A non-negative integer as a decimal string: an int (a bool is none) or a decimal string; else None."""
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v) if v >= 0 else None
    return v if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


def _transfer_with_authorization(request: Mapping[str, Any], network: str | None = None, opened: Opened | None = None) -> Summary | None:
    """eip712, TransferWithAuthorization (EIP-3009): the amount and the one payee's part are m.value, the payee m.to,
    the asset d.verifyingContract, the network eip155: and d.chainId, and the validity m.validAfter to m.validBefore, in
    seconds."""
    typed = request.get("typedData")
    if request.get("kind") != "eip712" or not isinstance(typed, Mapping):
        return None
    if typed.get("primaryType") != "TransferWithAuthorization":
        return None
    m, d = typed.get("message"), typed.get("domain")
    if not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    value, after, before, chain = (_decimal(x) for x in (m.get("value"), m.get("validAfter"), m.get("validBefore"), d.get("chainId")))
    to, asset = m.get("to"), d.get("verifyingContract")
    if value is None or after is None or before is None or chain is None:
        return None
    if not isinstance(to, str) or not isinstance(asset, str):
        return None
    return Summary(
        amount=value,
        payees=(Payee(account=to, amount=value),),
        asset=asset,
        network=f"eip155:{chain}",
        validity=Validity(not_before=after, not_after=before, unit="seconds"),
        atr=b"",
    )


def _erc7710(request: Mapping[str, Any], network: str | None = None, opened: Opened | None = None) -> Summary | None:
    """erc7710: the amount and the one payee's part are amount, the payee payTo, the asset token, the network eip155:
    and chainId; a delegation signs no end, and its grant is {token, payTo, amount}."""
    if request.get("kind") != "erc7710":
        return None
    amount, chain = _decimal(request.get("amount")), _decimal(request.get("chainId"))
    token, pay_to = request.get("token"), request.get("payTo")
    if amount is None or chain is None or not isinstance(token, str) or not isinstance(pay_to, str):
        return None
    return Summary(
        amount=amount,
        payees=(Payee(account=pay_to, amount=amount),),
        asset=token,
        network=f"eip155:{chain}",
        validity=Validity(not_before=None, not_after=None, unit="seconds"),
        grant={"token": token, "payTo": pay_to, "amount": amount},
        atr=b"",
    )


# Each pairing's summary, by pairing id, as the profile's table fills its row.
SUMMARIES: dict[str, SummaryEntry] = {
    "x402/exact/eip155/eip3009": SummaryEntry(show=_transfer_with_authorization),
    "x402/exact/eip155/erc7710": SummaryEntry(show=_erc7710),
    "x402/exact/eip155/erc7710-salt": SummaryEntry(show=_erc7710),
    "ap2/checkout-mandate": SummaryEntry(show=ap2_checkout_mandate),
    "ap2/checkout-mandate/x402": SummaryEntry(show=ap2_checkout_mandate),
    "ucp/checkout/ap2-mandate": SummaryEntry(show=ucp_checkout),
    "ucp/booking/ap2-mandate": SummaryEntry(show=ucp_checkout),
    "ucp/checkout/agent-signed": SummaryEntry(show=ucp_legal_context),
    "acp/checkout/delegated": SummaryEntry(show=acp_allowance),
}


def summary_of(
    pairing: str, request: Mapping[str, Any], atr: bytes, network: str | None = None, opened: Opened | None = None
) -> Summary | None:
    """The summary of request, a request of pairing handed to the signer, with atr, the ATR's bytes, network, the
    signing account's CAIP-2 network where the gate knows it, and opened, for a later step, the step that opened its
    channel, each given to the entry as it is given here; or None where the pairing has no summary or its entry cannot
    read the request. An entry that raises gives none."""
    entry = SUMMARIES.get(pairing)
    if entry is None:
        return None
    try:
        shown = entry.show(request, network, opened)
    except Exception:
        return None
    return None if shown is None else replace(shown, atr=bytes(atr))


def start_of(pairing: str, inputs: Inputs) -> int | None:
    """The height the caller gave the build of pairing's request, where its entry reads one."""
    entry = SUMMARIES.get(pairing)
    if entry is None or entry.start is None:
        return None
    try:
        return entry.start(inputs)
    except Exception:
        return None
