"""x402 lnbtc's request binding, computed by the buyer from its own request: the option's profile and parameters are
validated, the binding object is built from the request the buyer gives, and requestHash is SHA-256 over the UTF-8 of
its RFC 8785 form. The option's extra.requestHash and the invoice's description hash must both equal it.

The buyer's request, the request input:
- http:1: {method, url, body?, headers?}, body the content bytes as 0x hex (absent is empty), headers the value of each
  present header by lower-case name, each field line's values joined as RFC 9421 section 2.1 joins them.
- mcp:1: {server, name, arguments?, meta?}, server the MCP server's URI as the buyer's own configuration spells it,
  name and arguments the tools/call params, meta its params._meta."""

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from .._types import Refusal
from ..bindings._bolt11 import decode, invoice_h
from ..bindings._codec import canonical_json
from ._common import bytes_of

_HTTP_DOMAIN = "x402:exact:lnbtc:bolt11:http:1"
_MCP_DOMAIN = "x402:exact:lnbtc:bolt11:mcp:1"
_REQUEST_HASH = re.compile(r"[0-9a-f]{64}")
_FIELD_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9a-z-]+")
_METHOD = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_FIELD_VALUE = re.compile(r"[\t\x20-\x7e]*")
_ASCII_URI = re.compile(r"[\x21-\x7e]+")
# http or https, //, an authority with no user information, then a path or query and no fragment.
_HTTP_TARGET = re.compile(r"https?://[^/?#@]+(?:[/?][^#]*)?", re.IGNORECASE | re.ASCII)
# A scheme, then no fragment; where there is an authority, no user information in it.
_ABSOLUTE_URI = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:[^#]*")
_USERINFO = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*@")
_EXCLUDED_META = ("x402/payment", "progressToken")


def _malformed() -> Refusal:
    return Refusal("ln/request-binding-malformed")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _value_hash(data: bytes | None) -> str:
    """SHA-256 of 0x01 || data for a present value, of the single byte 0x00 for an absent one."""
    return _sha256_hex(b"\x00" if data is None else b"\x01" + data)


def _is_target_uri(url: object) -> bool:
    return isinstance(url, str) and _ASCII_URI.fullmatch(url) is not None and _HTTP_TARGET.fullmatch(url) is not None


def _is_absolute_uri(value: object) -> bool:
    return (
        isinstance(value, str)
        and _ASCII_URI.fullmatch(value) is not None
        and _ABSOLUTE_URI.fullmatch(value) is not None
        and _USERINFO.match(value) is None
    )


def _ascending(names: list[str]) -> bool:
    """Strictly ascending and without duplicates, by UTF-16 code units, which is RFC 8785's member order."""
    keys = [n.encode("utf-16-be") for n in names]
    return all(keys[i - 1] < keys[i] for i in range(1, len(keys)))


def _exact_keys(o: Mapping[str, Any], keys: tuple[str, ...]) -> bool:
    return len(o) == len(keys) and all(k in o for k in keys)


def _http_binding(params: Mapping[str, Any], request: Mapping[str, Any], resource_url: object) -> dict[str, Any] | Refusal:
    names = params.get("headers")
    if not _exact_keys(params, ("headers",)) or not isinstance(names, list):
        return _malformed()
    if not all(isinstance(n, str) and _FIELD_NAME.fullmatch(n) and n != "payment-signature" for n in names):
        return _malformed()
    if not _ascending(names):
        return _malformed()
    method, url, body, headers = request.get("method"), request.get("url"), request.get("body"), request.get("headers")
    if not isinstance(method, str) or _METHOD.fullmatch(method) is None or not _is_target_uri(url):
        return _malformed()
    if resource_url != url:
        return Refusal("ln/request-resource-mismatch")
    content = b"" if body is None else bytes_of(body)
    if content is None:
        return _malformed()
    if headers is not None and not isinstance(headers, Mapping):
        return _malformed()
    given = headers if headers is not None else {}
    bound: list[dict[str, str]] = []
    for name in names:
        v = given.get(name)
        if v is not None and (not isinstance(v, str) or _FIELD_VALUE.fullmatch(v) is None):
            return _malformed()
        value = None if v is None else v.strip(" \t").encode("ascii")
        bound.append({"name": name, "valueHash": _value_hash(value)})
    return {"domain": _HTTP_DOMAIN, "method": method, "url": url, "bodyHash": _sha256_hex(content), "headers": bound}


def _mcp_binding(params: Mapping[str, Any], request: Mapping[str, Any]) -> dict[str, Any] | Refusal:
    names = params.get("metadata")
    if not _exact_keys(params, ("server", "metadata")) or not isinstance(names, list):
        return _malformed()
    if not all(isinstance(n, str) and n != "" and n not in _EXCLUDED_META for n in names):
        return _malformed()
    if not _ascending(names):
        return _malformed()
    server, name, meta = request.get("server"), request.get("name"), request.get("meta")
    if not _is_absolute_uri(server):
        return _malformed()
    if params.get("server") != server:
        return Refusal("ln/request-server-mismatch")
    if not isinstance(name, str) or name == "":
        return _malformed()
    arguments = request["arguments"] if "arguments" in request else {}
    if not isinstance(arguments, Mapping):
        return _malformed()
    if meta is not None and not isinstance(meta, Mapping):
        return _malformed()
    given = meta if meta is not None else {}
    bound: list[dict[str, str]] = []
    for n in names:
        if n not in given:
            bound.append({"name": n, "valueHash": _value_hash(None)})
            continue
        try:
            text = canonical_json(given[n])
        except (TypeError, ValueError):
            return _malformed()
        bound.append({"name": n, "valueHash": _value_hash(text.encode("utf-8"))})
    return {"domain": _MCP_DOMAIN, "server": server, "method": "tools/call", "name": name, "arguments": dict(arguments), "metadata": bound}


def binding_of(profile: object, params: object, request: object, resource_url: object) -> dict[str, Any] | Refusal:
    """The binding object of the buyer's own request under a profile and its parameters, the profile being the one
    the request's transport uses: http:1 for an HTTP request, mcp:1 for a tools/call."""
    if not isinstance(params, Mapping) or not isinstance(request, Mapping):
        return _malformed()
    is_mcp = "server" in request
    if profile == "http:1" and not is_mcp:
        return _http_binding(params, request, resource_url)
    if profile == "mcp:1" and is_mcp:
        return _mcp_binding(params, request)
    return Refusal("ln/request-profile-mismatch")


def request_hash_of(profile: object, params: object, request: object, resource_url: object) -> str | Refusal:
    """requestHash: lower-case hex of SHA-256 over the UTF-8 of the binding object's RFC 8785 form."""
    binding = binding_of(profile, params, request, resource_url)
    if isinstance(binding, Refusal):
        return binding
    try:
        text = canonical_json(binding)
    except (TypeError, ValueError):
        return _malformed()
    return _sha256_hex(text.encode("utf-8"))


def check_request_hash(option: object, resource_url: object, request: object) -> str | Refusal:
    """The request hash of the buyer's own request under the option's profile, when the option's extra.requestHash
    and the invoice's description hash both equal it; otherwise the refusal naming what differs."""
    extra = option.get("extra") if isinstance(option, Mapping) else None
    if not isinstance(extra, Mapping):
        return _malformed()
    request_hash = extra.get("requestHash")
    if not isinstance(request_hash, str) or _REQUEST_HASH.fullmatch(request_hash) is None:
        return _malformed()
    computed = request_hash_of(extra.get("requestBindingProfile"), extra.get("requestBindingParams"), request, resource_url)
    if isinstance(computed, Refusal):
        return computed
    if computed != request_hash:
        return Refusal("ln/request-hash-mismatch")
    invoice = extra.get("invoice")
    if not isinstance(invoice, str):
        return Refusal("ln/invoice-malformed")
    b = decode(invoice)
    if isinstance(b, Refusal):
        return b
    d = invoice_h(b, "h")
    if isinstance(d, Refusal):
        return d
    if d != "0x" + computed:
        return Refusal("ln/request-hash-mismatch")
    return computed
