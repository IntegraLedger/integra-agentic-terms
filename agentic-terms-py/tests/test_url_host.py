"""The URL Standard's host parser and domain parser as this package carries them (bindings/_url.py), and the readers
that take a URL through them. Expected values come from the URL Standard (url.spec.whatwg.org): the table of host
parser results in section 3 and the registrable-domain table in section 3.2, which shows إختبار as the host
xn--kgbechtv; RFC 3492's own encoder (rfc3492.py) for a long label; web-platform-tests' url/resources/toascii.json at
42cbc75a for the hosts that IDNA 2003 reads otherwise; and Node.js 26.11.1's URL for the lnbtc request URLs and hosts,
each of which it reads as the Standard does. The conformance file is run in test_url_conformance.py."""

from typing import Any
from urllib.parse import quote

import pytest

from rfc3492 import rfc3492_encode

from integraledger_terms import Refusal
from integraledger_terms.bindings._url import UrlAuthority, domain_to_ascii, parse_host, read_url
from integraledger_terms.pieces._lnbtc_request import request_hash_of

# [input, the host with is_opaque false, with is_opaque true], None for failure.
HOST_PARSER_RESULTS = [
    ("EXAMPLE.COM", "example.com", "EXAMPLE.COM"),
    ("example%2Ecom", "example.com", "example%2Ecom"),
    ("faß.example", "xn--fa-hia.example", "fa%C3%9F.example"),
    ("0", "0.0.0.0", "0"),
    ("%30", "0.0.0.0", "%30"),
    ("0x", "0.0.0.0", "0x"),
    ("0xffffffff", "255.255.255.255", "0xffffffff"),
    ("[0:0::1]", "[::1]", "[::1]"),
    ("[0:0::1%5D", None, None),
    ("[0:0::%31]", None, None),
    ("09", None, "09"),
    ("example.255", None, "example.255"),
    ("example^example", None, None),
]


@pytest.mark.parametrize(("text", "domain", "opaque"), HOST_PARSER_RESULTS, ids=[r[0] for r in HOST_PARSER_RESULTS])
def test_parse_host_gives_the_standards_table_of_host_parser_results(text: str, domain: str | None, opaque: str | None) -> None:
    assert (parse_host(text), parse_host(text, False), parse_host(text, True)) == (domain, domain, opaque)


def test_the_arabic_test_label_is_the_host_xn__kgbechtv() -> None:
    assert parse_host("إختبار") == "xn--kgbechtv"
    assert parse_host("example.إختبار") == "example.xn--kgbechtv"


def test_the_empty_string_is_an_opaque_host_and_a_failure_otherwise() -> None:
    assert parse_host("", True) == ""
    assert parse_host("") is None


def test_percent_encoded_bytes_that_are_not_utf8_decode_to_u_fffd_which_the_mapping_disallows() -> None:
    # fa%C3%9F.example is the table's faß.example, percent-encoded: its bytes are UTF-8 and decode to it.
    assert parse_host("fa%C3%9F.example") == "xn--fa-hia.example"
    assert parse_host("%EF%BF%BD.example") is None
    assert parse_host("%FF.example") is None
    assert parse_host("fa%C3.example") is None
    assert parse_host("%FF.example", True) == "%FF.example"


def test_domain_to_ascii_lowercases_an_ascii_domain_whatever_toascii_gives_when_not_strict() -> None:
    # Section 3.3's note: xn--8i7caa decodes to ｗｗｗ, whose code points are mapped, so ToASCII fails on it.
    assert domain_to_ascii("XN--8I7CAA.Example") == "xn--8i7caa.example"
    assert domain_to_ascii("xn--8i7caa", True) is None


def test_domain_to_ascii_reads_a_coffee_cup_as_uts_46_does() -> None:
    # Section 3.3's note: xn--53h.example, not failure.
    assert domain_to_ascii("☕.example") == "xn--53h.example"
    assert domain_to_ascii("☕.example", True) == "xn--53h.example"


def test_domain_to_ascii_fails_on_an_empty_result_or_a_forbidden_code_point_and_strict_gives_toascii() -> None:
    assert domain_to_ascii("") is None
    assert domain_to_ascii("a%b") is None
    assert domain_to_ascii("a b") is None
    # U+00AD SOFT HYPHEN is ignored by the mapping: the result is empty.
    assert domain_to_ascii("\u00ad") is None
    # UseSTD3ASCIIRules refuses "_"; CheckHyphens refuses a hyphen at the label's start; VerifyDnsLength the root label.
    assert (domain_to_ascii("a_b.example"), domain_to_ascii("a_b.example", True)) == ("a_b.example", None)
    assert (domain_to_ascii("-a.example"), domain_to_ascii("-a.example", True)) == ("-a.example", None)
    assert (domain_to_ascii("a.example."), domain_to_ascii("a.example.", True)) == ("a.example.", None)


def test_a_lone_surrogate_reads_as_u_fffd_which_no_domain_parse_accepts() -> None:
    assert domain_to_ascii("a\ud800.example") is None
    assert parse_host("a\ud800.example", True) == "a%EF%BF%BD.example"
    # A surrogate pair held as two code points is the one code point it forms.
    assert parse_host("\ud83d\ude00.example") == parse_host("\U0001f600.example") == f"xn--{rfc3492_encode([0x1F600])}.example"


def test_a_label_of_any_length_a_letter_and_30000_combining_acute_accents() -> None:
    # UAX #15: a and the first U+0301 compose to U+00E1, and each later U+0301 is blocked by the one before it, of the
    # same combining class (230). The label is valid in UTS #46, and RFC 3492 encodes it. A label that begins with a
    # combining mark is refused (UTS #46 section 4.1).
    marks = "\u0301" * 30_000
    label = f"xn--{rfc3492_encode([0xE1] + [0x301] * 29_999)}"
    assert domain_to_ascii(f"a{marks}") == label
    assert parse_host(f"a{marks}.example") == f"{label}.example"
    assert domain_to_ascii(marks) is None


def test_read_url_reads_the_scheme_host_port_and_credentials() -> None:
    assert read_url("HTTPS://User:Pw@EXAMPLE.com:0444/p?q#f") == UrlAuthority("https", "example.com", True, 444)
    assert read_url("https://:@example.com/") == UrlAuthority("https", "example.com", False, None)
    assert read_url("http://[::FFFF:192.0.2.1]:/") == UrlAuthority("http", "[::ffff:c000:201]", False, None)
    assert read_url("foo://ex%41mple:7/") == UrlAuthority("foo", "ex%41mple", False, 7)
    assert read_url("mailto:a b@c") == UrlAuthority("mailto", None, False, None)
    assert read_url("file://localhost/x") == UrlAuthority("file", "", False, None)
    # Leading and trailing C0 controls and spaces are removed, then every tab and newline.
    assert read_url(" \u0000\u001fhttp://\th\n/x \u001f") == UrlAuthority("http", "h", False, None)


def test_read_url_gives_no_port_for_the_schemes_default_port() -> None:
    # Section 4.2's special schemes and their default ports: the URL record holds none for the default.
    ports = [
        ("http://h:80/", None),
        ("http://h:0080/", None),
        ("http://h:443/", 443),
        ("HTTPS://h:443/", None),
        ("https://h:80/", 80),
        ("ws://h:80/", None),
        ("wss://h:443/", None),
        ("ftp://h:21/", None),
        ("ftp://h:22/", 22),
        ("foo://h:80/", 80),
        ("https://h:/", None),
    ]
    assert [(url, u.port if (u := read_url(url)) else "failure") for url, _ in ports] == ports


def test_read_url_fails_where_the_authority_fails_and_never_on_a_path_query_or_fragment() -> None:
    for s in ("https://", "https://u@/x", "https://h:65536/", "https://h:1x/", "foo://a b/", "foo://:1/", "1http://x/", "http://a^b/"):
        assert read_url(s) is None, s
    for s in ("http://h/ %zz^`{}|\\", "http://h?\u0000 \ud800", "http://h#\U0001f600 ", "foo:/%zz ^", "foo: x"):
        assert read_url(s) is not None, s


def test_ipv4_numbers_and_ports_at_around_and_far_past_their_caps() -> None:
    # An IPv4 part or a port of any length is read without converting a number past every bound it is compared with, so
    # no input reaches the interpreter's limit of 4,300 decimal digits. Each answer is @integraledger/lcp's parseHost or
    # readUrl: 2^32 - 1 is eleven 0-led octal digits, and leading zeros of any count are read.
    z = "0" * 5_000
    hosts = [
        ("037777777777", "255.255.255.255"),
        ("040000000000", None),
        ("0" + z + "37777777777", "255.255.255.255"),
        ("0x" + z + "ffffffff", "255.255.255.255"),
        ("4294967295", "255.255.255.255"),
        ("4294967296", None),
        ("9" * 4_301, None),
        ("1." + "9" * 5_000, None),
        ("0x" + "f" * 17, None),
        ("0" + "7" * 17, None),
    ]
    assert [parse_host(h) for h, _ in hosts] == [want for _, want in hosts]
    ports: list[tuple[str, int | str | None]] = [
        ("65535", 65_535),
        (z + "65535", 65_535),
        ("65536", "failure"),
        ("9" * 4_301, "failure"),
        (z, 0),
        (z[1:] + "80", None),
        (z[700:] + "65536", "failure"),
    ]
    assert [(u.port if (u := read_url(f"http://h:{p}/")) else "failure") for p, _ in ports] == [w for _, w in ports]


# toascii.json's rows that IDNA 2003 reads otherwise than UTS #46: each through https://<input>/x, as its harness reads
# it. The first three parse under IDNA 2003 and fail here; the last three fail under IDNA 2003 and parse here.
IDNA_2003_ROWS = [
    ("xn--a.ß", None),
    ("www\u2025lookout.net", None),
    ("\u0378.net", None),
    ("look\u180eout.net", "lookout.net"),
    ("look\u206bout.net", "lookout.net"),
    (
        "x01234567890123456789012345678901234567890123456789012345678901\u2020",
        "xn--x01234567890123456789012345678901234567890123456789012345678901-6963b",
    ),
]


@pytest.mark.parametrize(("text", "host"), IDNA_2003_ROWS, ids=[f"toascii {r[0][:12]!r}" for r in IDNA_2003_ROWS])
def test_the_toascii_rows_that_idna_2003_reads_otherwise(text: str, host: str | None) -> None:
    u = read_url(f"https://{text}/x")
    assert (None if u is None else u.host) == host


# URLs whose host Node.js 26.11.1's URL reads as the Standard does, with the host it gives (None: it fails).
NODE_HOSTS = [
    ("http://xn--a.\U0001f600com/", None),
    ("http://xn--a.com/", "xn--a.com"),
    ("http://\U0001f600com/", "xn--com-qh33b"),
    ("http://xn--a.bücher.de/", None),
    ("http://xn--zz.bücher.de/", None),
    ("http://bücher.de/", "xn--bcher-kva.de"),
    ("http://ß.com/", "xn--zca.com"),
    ("http://a\u200db.com/", None),
    ("http://\u06611.com/", None),
    ("http://xn--.bücher.de/", None),
    ("http://a.bücher.xn--a/", None),
    ("http://\u2488.com/", None),
    ("http://\uff21.com/", "a.com"),
    ("http://-a.bücher.de/", "-a.xn--bcher-kva.de"),
    ("http://\u0300a.com/", None),
]


@pytest.mark.parametrize(("url", "host"), NODE_HOSTS, ids=[r[0] for r in NODE_HOSTS])
def test_each_host_reads_as_the_standard_reads_it(url: str, host: str | None) -> None:
    u = read_url(url)
    assert (None if u is None else u.host) == host


# lnbtc request URLs, percent-encoded: the first two are refused as Node.js's URL refuses them (an xn-- label that is
# not Punycode, and a ZWJ, U+200D, that ContextJ refuses), and the third is hashed.
LNBTC_URLS = [
    ("https://xn--a.b%C3%BCcher.de/x", "ln/request-binding-malformed"),
    (f"https://a{quote(chr(0x200D))}b.com/x", "ln/request-binding-malformed"),
    ("https://b%C3%BCcher.de/x", None),
]


@pytest.mark.parametrize(("url", "refusal"), LNBTC_URLS, ids=[r[0] for r in LNBTC_URLS])
def test_an_lnbtc_request_url_is_hashed_only_where_the_standard_reads_it(url: str, refusal: str | None) -> None:
    out: Any = request_hash_of("http:1", {"headers": []}, {"method": "GET", "url": url}, url)
    assert (out.code if isinstance(out, Refusal) else None) == refusal
