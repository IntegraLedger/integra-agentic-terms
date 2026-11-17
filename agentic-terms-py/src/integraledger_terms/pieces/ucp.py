"""The buyer pieces of the UCP pairings. The build input is the offer read gives, {"checkout": ...}. Under the AP2
Mandates extension the checkout goes, unchanged, to the buyer's mandate issuer, which answers the checkout mandate as
issued, an SD-JWT string, or AP2's chained presentation of the open and closed mandates joined by ~~. Where the
platform signs its requests, its signer is handed the legal_context member the build gives, beside the checkout its
request completes: it writes the member at the top level of the JSON body of the request that completes the checkout,
signs the request with HTTP Message Signatures (RFC 9421) covering content-digest, as UCP has a platform sign its
requests, and answers {"body", "contentDigest"}, the body as sent, as text, and its Content-Digest value. Otherwise
the gate confirms only."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Binding, Chosen, Inputs, Json, Refusal, Signature
from ..bindings.ucp import (
    BOOKING_AP2_MANDATE,
    BOOKING_UNSIGNED,
    CHECKOUT_AGENT_SIGNED,
    CHECKOUT_AP2_MANDATE,
    CHECKOUT_UNSIGNED,
)
from ._base import BasePiece
from .protocol_groups import ConfirmOnlyPiece, object_choice, unnamed_buyer


def choose_checkout(read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> dict[str, Any] | Refusal:
    unnamed = unnamed_buyer(account, "ucp")
    if unnamed is not None:
        return unnamed
    if not isinstance(read.offer, Mapping):
        return Refusal("ucp/no-payable-option")
    return dict(read.offer)


class UcpMandatePiece(BasePiece):
    """The piece of a UCP pairing under the AP2 Mandates extension."""

    def __init__(self, pairing: str) -> None:
        self.pairing = pairing

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        choice = choose_checkout(read, account, inputs, now, ref, doc)
        if isinstance(choice, Refusal):
            return choice
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return object_choice(chosen, "ucp")

    def request(self, unsigned: Any) -> dict[str, Any]:
        return {"kind": "ucp-checkout", "checkout": unsigned.checkout}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, str) or signature == "":
            return Refusal("ucp/signature-malformed")
        signed: dict[str, Any] | Refusal = unsigned.complete(signature)
        return signed


@dataclass(frozen=True, slots=True)
class _Built:
    """The member the build gives, with the checkout the platform's request completes."""

    checkout: Mapping[str, Any]
    member: Mapping[str, Any]


class UcpAgentSignedPiece(BasePiece):
    """The piece of ucp/checkout/agent-signed."""

    pairing = CHECKOUT_AGENT_SIGNED

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        choice = choose_checkout(read, account, inputs, now, ref, doc)
        if isinstance(choice, Refusal):
            return choice
        return Chosen(pairing=self.pairing, choice=choice, ref=ref)

    def choice(self, chosen: Chosen, atr_bytes: bytes) -> Any:
        return object_choice(chosen, "ucp")

    def build(self, binding: Binding, choice: Any, h: AtrHash) -> Any:
        member = binding.build(choice, h)
        if isinstance(member, Refusal):
            return member
        return _Built(choice["checkout"], member)

    def request(self, unsigned: Any) -> dict[str, Any]:
        member = unsigned.member["legal_context"]
        return {"kind": "ucp-legal-context", "checkout": unsigned.checkout, "legal_context": member}

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Refusal:
        if not isinstance(signature, Mapping) or len(signature) != 2:
            return Refusal("ucp/signature-malformed")
        body = signature.get("body")
        content_digest = signature.get("contentDigest")
        if not isinstance(body, str) or not isinstance(content_digest, str):
            return Refusal("ucp/signature-malformed")
        return {"body": body, "contentDigest": content_digest}


CHECKOUT_AP2_MANDATE_PIECE = UcpMandatePiece(CHECKOUT_AP2_MANDATE)
CHECKOUT_AGENT_SIGNED_PIECE = UcpAgentSignedPiece()
BOOKING_AP2_MANDATE_PIECE = UcpMandatePiece(BOOKING_AP2_MANDATE)
CHECKOUT_UNSIGNED_PIECE = ConfirmOnlyPiece(CHECKOUT_UNSIGNED, choose_checkout)
BOOKING_UNSIGNED_PIECE = ConfirmOnlyPiece(BOOKING_UNSIGNED, choose_checkout)
