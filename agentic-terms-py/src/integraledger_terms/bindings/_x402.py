"""What every x402 pairing's buyer half shares: reading the legal context and the options a pairing's filter serves,
checking the chosen option is one the document offers, the payment for it, and reading a presented payment."""

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Refusal
from ._codec import canonical_or_none
from ._lcp import (
    AgreementFault,
    MAX_LINK_CHARS,
    agreement_in,
    is_hash_with_non_https_link,
    is_list,
    is_object,
    legal_context_info,
    safe_int,
)

LEGAL_CONTEXT = "legalContext"
MAX_OPTIONS = 32
MAX_SIGNATURE_BYTES = 8192

# A pairing's option filter: True for an option the pairing serves, a refusal naming why an option of this pairing
# cannot be served, and None for an option that is not this pairing's.
OptionFilter = Callable[[Mapping[str, Any]], "bool | Refusal | None"]


def filter_of(
    pairs: Callable[[Mapping[str, Any]], bool], payable: Callable[[Mapping[str, Any]], bool] | None = None
) -> OptionFilter:
    """The filter for the options pairs accepts: those payable also accepts (every one, without it) are served, and
    the rest are refused x402/option-malformed."""

    def check(option: Mapping[str, Any]) -> bool | Refusal | None:
        if not pairs(option):
            return None
        return True if payable is None or payable(option) else Refusal("x402/option-malformed")

    return check


def is_v2(doc: object) -> bool:
    return is_object(doc) and safe_int(doc.get("x402Version")) == 2 and not isinstance(doc.get("x402Version"), bool)


def same_json(a: object, b: object) -> bool:
    """Equal RFC 8785 forms; False when either has none."""
    if a is None or b is None:
        return False
    x = canonical_or_none(a)
    return x is not None and x == canonical_or_none(b)


def is_offered(accepts: Sequence[Any], offer: object) -> bool:
    return any(a is offer or same_json(a, offer) for a in accepts)


def legal_context_of(extensions: object) -> tuple[AtrHash, str] | Refusal:
    """The hash and link in a document's extensions.legalContext, or the refusal that names what is wrong."""
    lc = extensions.get(LEGAL_CONTEXT) if is_object(extensions) else None
    if lc is None:
        return Refusal("x402/no-legal-context")
    info = lc.get("info") if is_object(lc) else None
    decoded = legal_context_info(info)
    if decoded is None:
        return Refusal("x402/link-not-https" if is_hash_with_non_https_link(info) else "x402/legal-context-malformed")
    if len(decoded[1]) > MAX_LINK_CHARS:
        return Refusal("x402/legal-context-malformed")
    return decoded


def read_for(check: OptionFilter) -> Callable[[object], Advertised | Refusal]:
    """The hash, the link, the agreement URL when extensions.legalContext carries one, and the options the filter
    serves, in document order, as offer {"required", "options"}."""

    def read(doc: object) -> Advertised | Refusal:
        if not is_v2(doc):
            return Refusal("x402/not-v2")
        assert is_object(doc)
        accepts = doc.get("accepts")
        if not is_list(accepts) or len(accepts) > MAX_OPTIONS:
            return Refusal("x402/option-malformed")
        extensions = doc.get("extensions")
        lc = legal_context_of(extensions)
        if isinstance(lc, Refusal):
            return lc
        present = extensions.get(LEGAL_CONTEXT) if is_object(extensions) else None
        agreement = agreement_in(present.get("info") if is_object(present) else None)
        if isinstance(agreement, AgreementFault):
            return Refusal(f"x402/{agreement.fault}")
        options = [o for o in accepts if is_object(o) and check(o) is True]
        if not options:
            return Refusal("x402/no-payable-option")
        offer = {"required": doc, "options": options}
        return Advertised(h=lc[0], link=lc[1], offer=offer, agreement=agreement if isinstance(agreement, str) else None)

    return read


def chosen(required: object, accepted: object, check: OptionFilter) -> bool | Refusal:
    """The checks build makes on the buyer's choice before anything pairing-specific: the document is x402 v2 with
    at most 32 options, the chosen option is one it offers, and the filter serves it."""
    if not is_v2(required):
        return Refusal("x402/not-v2")
    assert is_object(required)
    accepts = required.get("accepts")
    if not is_list(accepts) or len(accepts) > MAX_OPTIONS:
        return Refusal("x402/option-malformed")
    if not is_offered(accepts, accepted):
        return Refusal("x402/option-not-in-document")
    served = check(accepted) if is_object(accepted) else None
    return Refusal("x402/option-not-this-pairing") if served is None else served


def payment_with(required: Mapping[str, Any], accepted: Mapping[str, Any], payload: Any) -> dict[str, Any]:
    """The payment for the chosen option: the challenge's resource and extensions unchanged, omitted when absent."""
    payment: dict[str, Any] = {"x402Version": 2}
    if "resource" in required:
        payment["resource"] = required["resource"]
    payment["accepted"] = accepted
    payment["payload"] = payload
    if "extensions" in required:
        payment["extensions"] = required["extensions"]
    return payment


def presented_with(presented: object, check: OptionFilter) -> tuple[Mapping[str, Any], Mapping[str, Any], Any] | Refusal:
    """A presented payment's accepted (served by the filter), its payload object and its extensions."""
    if not is_v2(presented):
        return Refusal("x402/not-v2")
    assert is_object(presented)
    accepted = presented.get("accepted")
    if not is_object(accepted):
        return Refusal("x402/payload-malformed")
    served = check(accepted)
    if served is None:
        return Refusal("x402/option-not-this-pairing")
    if served is not True:
        return served if isinstance(served, Refusal) else Refusal("x402/option-not-this-pairing")
    payload = presented.get("payload")
    if not is_object(payload):
        return Refusal("x402/payload-malformed")
    return accepted, payload, presented.get("extensions")
