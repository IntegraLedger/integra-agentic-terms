"""The shape checks and legal-context forms every binding's buyer half reads: hashes in their three written forms,
https links, the agreement URL, JSON objects and lists, safe integers and uint256 decimals, EVM addresses and
networks."""

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeGuard
from urllib.parse import urlsplit

from .._core import AtrHash, is_hash
from ._url import url_scheme

MAX_LINK_CHARS = 2048
MAX_SAFE_INTEGER = 2**53 - 1
UINT256_LIMIT = 2**256

AGREEMENT_URL = "legalContextAgreementUrl"
AGREEMENT_URL_SNAKE = "legal_context_agreement_url"

_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_EIP155 = re.compile(r"eip155:([1-9][0-9]{0,15})")
_DECIMAL = re.compile(r"[0-9]{1,78}")
# Code points a WHATWG URL host may not hold.
_FORBIDDEN_HOST = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")


def is_object(value: object) -> TypeGuard[Mapping[str, Any]]:
    return isinstance(value, Mapping)


def is_list(value: object) -> TypeGuard[Sequence[Any]]:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def safe_int(value: object) -> int | None:
    """The value as an int when it is a JSON number holding a safe integer; None otherwise."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    else:
        return None
    return number if -MAX_SAFE_INTEGER <= number <= MAX_SAFE_INTEGER else None


def uint256_of(value: object) -> int | None:
    """A string of decimal digits below 2^256 as an int, or None."""
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        return None
    number = int(value)
    return number if number < UINT256_LIMIT else None


def is_address(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _ADDRESS.fullmatch(value) is not None


def chain_id_of(network: object) -> int | None:
    """The decimal chain id of an eip155:<decimal> network, or None."""
    match = _EIP155.fullmatch(network) if isinstance(network, str) else None
    if match is None:
        return None
    chain_id = int(match.group(1))
    return chain_id if chain_id <= MAX_SAFE_INTEGER else None


def normal_hash(value: object) -> AtrHash | None:
    """The lower-case form of 0x and 64 hex digits in either case, or None."""
    return value.lower() if isinstance(value, str) and is_hash(value) else None


def to_lcp_string(h: AtrHash) -> str:
    return "lcp:sha256:" + h.lower()


def from_lcp_string(value: object) -> AtrHash | None:
    """The lower-case hash of lcp:sha256:0x..., or None for anything else."""
    if not isinstance(value, str) or not value.startswith("lcp:sha256:"):
        return None
    return normal_hash(value[len("lcp:sha256:") :])


def is_url(value: object) -> TypeGuard[str]:
    """Whether value parses as an absolute URL with a host, as a WHATWG URL parser would accept it."""
    if not isinstance(value, str) or value != value.strip() or any(c in value for c in "\t\n\r"):
        return False
    try:
        parts = urlsplit(value)
        parts.port
    except ValueError:
        return False
    if parts.scheme == "" or parts.netloc == "":
        return False
    host = parts.hostname or ""
    if host == "" or (not host.startswith("[") and _FORBIDDEN_HOST.search(host) is not None):
        return False
    return True


# Unicode White_Space, every Unicode Cc control character, and the backslash.
_LINK_FORBIDDEN = re.compile("[\u0000-\u0020\u007f-\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\\\\]")
# The scheme https in either case, then // and the authority up to the path, query or fragment.
_HTTPS_AUTHORITY = re.compile(r"https://([^/?#]*)", re.IGNORECASE | re.ASCII)
_DNS_LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
# An IP literal in brackets, or a DNS name of RFC 1123 labels (which includes dotted IPv4), then an optional port.
_HOST_PORT = re.compile(rf"(?:\[[0-9A-Fa-f:.]+\]|{_DNS_LABEL}(?:\.{_DNS_LABEL})*\.?)(?::([0-9]{{0,5}}))?")
_MAX_DNS_NAME = 253
_IPV4_NUMBER = re.compile(r"(?:0[xX][0-9A-Fa-f]*|[0-9]+)")


def _whatwg_ipv4(host: str) -> bool | None:
    """For a host whose last label is a number, whether the WHATWG URL parser reads it as a valid IPv4 address; None
    for a host the parser reads as a domain."""
    labels = host.split(".")
    if labels[-1] == "" and len(labels) > 1:
        labels = labels[:-1]
    if _IPV4_NUMBER.fullmatch(labels[-1]) is None:
        return None
    if len(labels) > 4:
        return False
    numbers: list[int] = []
    for label in labels:
        if _IPV4_NUMBER.fullmatch(label) is None:
            return False
        if label[:2] in ("0x", "0X"):
            numbers.append(int(label[2:], 16) if label[2:] != "" else 0)
        elif len(label) > 1 and label[0] == "0":
            if any(c not in "01234567" for c in label):
                return False
            numbers.append(int(label, 8))
        else:
            numbers.append(int(label))
    if any(n > 255 for n in numbers[:-1]):
        return False
    return numbers[-1] < 1 << (8 * (5 - len(numbers)))


def is_https_link(value: object) -> TypeGuard[str]:
    """The one https-link rule. The raw string holds no whitespace, control character or backslash; it parses as an
    absolute URL; its scheme is https, compared case-insensitively (RFC 3986 section 3.1); its authority has a host, a
    DNS name or an IP literal, and no userinfo."""
    if not isinstance(value, str) or _LINK_FORBIDDEN.search(value) is not None:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    m = _HTTPS_AUTHORITY.match(value)
    if m is None or "@" in m.group(1):
        return False
    authority = m.group(1)
    hp = _HOST_PORT.fullmatch(authority)
    if hp is None:
        return False
    port = hp.group(1)
    host = authority if port is None else authority[: len(authority) - len(port) - 1]
    if not host.startswith("[") and len(host.rstrip(".")) > _MAX_DNS_NAME:
        return False
    if port is not None and port != "" and int(port) > 65_535:
        return False
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return False
        return True
    return _whatwg_ipv4(host) is not False


def from_legal_context(holder: object) -> tuple[AtrHash, str] | None:
    """H and the link of holder["legalContext"]: type sha256, a 32-byte hash, and an https link in either spelling.
    None for anything else, including two spellings that disagree."""
    if not is_object(holder):
        return None
    lc = holder.get("legalContext")
    return legal_context_info(lc)


def legal_context_info(lc: object) -> tuple[AtrHash, str] | None:
    """H and the link of a legal context's inner object, as from_legal_context reads it."""
    if not is_object(lc) or lc.get("type") != "sha256":
        return None
    h = normal_hash(lc.get("value"))
    if h is None:
        return None
    camel, snake = lc.get("legalContextUrl"), lc.get("legal_context_url")
    if "legalContextUrl" in lc and "legal_context_url" in lc and camel != snake:
        return None
    link = camel if camel is not None else snake
    if not is_https_link(link):
        return None
    return h, link


def is_other_scheme_link(value: object) -> TypeGuard[str]:
    """True for a string of at most 2048 characters that parses as an absolute URL whose scheme is not https: the one
    failing link refused as link-not-https. Every other failing link is legal-context-malformed."""
    return isinstance(value, str) and len(value) <= MAX_LINK_CHARS and url_scheme(value) not in (None, "https")


def is_hash_with_non_https_link(info: object) -> bool:
    """True for a legal context's inner object that legal_context_info would decode except that its one link, in
    either spelling, is a link of another scheme (is_other_scheme_link)."""
    if not is_object(info) or info.get("type") != "sha256" or normal_hash(info.get("value")) is None:
        return False
    camel, snake = info.get("legalContextUrl"), info.get("legal_context_url")
    if "legalContextUrl" in info and "legal_context_url" in info and camel != snake:
        return False
    return is_other_scheme_link(camel if camel is not None else snake)


def is_agreement_url(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and len(value) <= MAX_LINK_CHARS and is_https_link(value)


@dataclass(frozen=True, slots=True)
class AgreementFault:
    """Why a value in the agreement URL's place is refused, as the suffix of the pairing's refusal code."""

    fault: str


def agreement_fault(url: object) -> AgreementFault:
    """The fault of a value that is not an agreement URL: a string of at most 2048 characters that parses as an
    absolute URL whose scheme is not https is link-not-https; every other value (not a string, empty, unparseable,
    longer than 2048 characters, or an https URL the link rule refuses) is legal-context-malformed."""
    return AgreementFault("link-not-https" if is_other_scheme_link(url) else "legal-context-malformed")


def agreement_in(lc: object) -> str | None | AgreementFault:
    """The agreement URL in a legal context object, in either spelling: None when neither is present; the fault when
    the two spellings disagree (legal-context-malformed) or the value is not an agreement URL (agreement_fault)."""
    if not is_object(lc):
        return None
    camel, snake = lc.get(AGREEMENT_URL), lc.get(AGREEMENT_URL_SNAKE)
    if AGREEMENT_URL not in lc and AGREEMENT_URL_SNAKE not in lc:
        return None
    if AGREEMENT_URL in lc and AGREEMENT_URL_SNAKE in lc and camel != snake:
        return AgreementFault("legal-context-malformed")
    url = camel if camel is not None else snake
    return url if is_agreement_url(url) else agreement_fault(url)
