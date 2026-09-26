"""The scheme of a string that parses as an absolute URL, read as the WHATWG URL Standard's basic URL parser reads a
string with no base.

Leading and trailing C0 controls and spaces are stripped and ASCII tabs and newlines removed. The scheme is an ASCII
letter, then letters, digits, "+", "-" or ".", then ":", lower-cased. For http, ws, wss and ftp the slashes and
backslashes after the scheme are skipped and the authority runs to the next "/", "\\", "?" or "#"; its host, after any
userinfo, must be non-empty. A bracketed host is an IPv6 address with no zone. Any other host is percent-decoded as UTF-8 and must
hold no forbidden domain code point; an ASCII label is lower-cased, a non-ASCII label is converted as IDNA 2003 does;
a host whose last label is a number must be an IPv4 address in the parser's forms (decimal, 0x hex or 0-led octal
parts, at most four). A port is digits up to 65535. For file, a host may be empty. For any other scheme, an authority
after "//" holds an opaque host with no forbidden host code point, and without "//" the rest is an opaque path that
always parses.
"""

import ipaddress
import re
from urllib.parse import unquote

_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*):")
_SPECIAL = frozenset({"http", "https", "ws", "wss", "ftp", "file"})
_FORBIDDEN_HOST = frozenset("\x00\t\n\r #/:<>?@[\\]^|")
_FORBIDDEN_DOMAIN = _FORBIDDEN_HOST | frozenset(chr(c) for c in range(0x20)) | frozenset("%\x7f")
_IPV4_PART = re.compile(r"0[xX][0-9a-fA-F]*|0[0-7]*|[1-9][0-9]*")


def _ipv4_number(part: str) -> int | None:
    if _IPV4_PART.fullmatch(part) is None:
        return None
    if part[:2] in ("0x", "0X"):
        return int(part[2:] or "0", 16)
    if len(part) > 1 and part[0] == "0":
        return int(part, 8)
    return int(part)


def _ends_in_a_number(host: str) -> bool:
    labels = host.split(".")
    if labels[-1] == "" and len(labels) > 1:
        labels.pop()
    last = labels[-1]
    return last != "" and (last.isascii() and last.isdigit() or _ipv4_number(last) is not None)


def _is_ipv4(host: str) -> bool:
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        return False
    numbers = [_ipv4_number(p) for p in parts]
    if any(n is None for n in numbers):
        return False
    values = [n for n in numbers if n is not None]
    if any(n > 255 for n in values[:-1]):
        return False
    limit: int = 256 ** (5 - len(values))
    return values[-1] < limit


def _is_domain(host: str) -> bool:
    decoded = unquote(host, encoding="utf-8", errors="replace")
    labels = []
    for label in decoded.split("."):
        if label.isascii():
            labels.append(label.lower())
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            return False
    ascii_host = ".".join(labels)
    if ascii_host == "" or any(c in _FORBIDDEN_DOMAIN for c in ascii_host):
        return False
    return not _ends_in_a_number(ascii_host) or _is_ipv4(ascii_host)


def _authority_parses(authority: str, special: bool, file: bool) -> bool:
    host_port = authority.rpartition("@")[2]
    if host_port.startswith("["):
        end = host_port.find("]")
        if end < 0 or "%" in host_port[:end]:
            return False
        try:
            ipaddress.IPv6Address(host_port[1:end])
        except ValueError:
            return False
        host, rest = host_port[: end + 1], host_port[end + 1 :]
        if rest and not rest.startswith(":"):
            return False
        port = rest[1:]
    else:
        host, _, port = host_port.partition(":")
    if port and (not (port.isascii() and port.isdigit()) or int(port) > 65_535):
        return False
    if host.startswith("["):
        return True
    if not special:
        return not any(c in _FORBIDDEN_HOST for c in host)
    if host == "":
        return file
    return _is_domain(host)


def url_scheme(value: str) -> str | None:
    """The lower-cased scheme of a string that parses as an absolute URL, or None."""
    text = value.strip("".join(chr(c) for c in range(0x21)))
    text = text.replace("\t", "").replace("\n", "").replace("\r", "")
    m = _SCHEME.match(text)
    if m is None:
        return None
    scheme = m.group(1).lower()
    rest = text[m.end() :]
    special = scheme in _SPECIAL
    if special and scheme != "file":
        rest = rest.lstrip("/\\")
        authority = re.split(r"[/\\?#]", rest, maxsplit=1)[0]
        return scheme if _authority_parses(authority, True, False) else None
    if scheme == "file":
        if rest[:2] not in ("//", "\\\\", "/\\", "\\/"):
            return scheme
        authority = re.split(r"[/\\?#]", rest[2:], maxsplit=1)[0]
        return scheme if _authority_parses(authority, True, True) else None
    if rest.startswith("//"):
        authority = re.split(r"[/?#]", rest[2:], maxsplit=1)[0]
        return scheme if _authority_parses(authority, False, False) else None
    return scheme
