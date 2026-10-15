"""The host parser this package carries, against the conformance files of the standards it implements, as the protocol
package's conformance test reads them. Each file is in data/, byte-equal to the file at its address and held to that
file's SHA-256, the address and hash the protocol package's test pins:
- IdnaTestV2.txt, Unicode's UTS #46 conformance file, https://www.unicode.org/Public/17.0.0/idna/IdnaTestV2.txt,
  beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf;
- NormalizationTest.txt, Unicode's normalization conformance file,
  https://www.unicode.org/Public/17.0.0/ucd/NormalizationTest.txt,
  5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db;
- DerivedAge.txt, the Unicode version that assigns each code point,
  https://www.unicode.org/Public/17.0.0/ucd/DerivedAge.txt,
  f8ecdf768bdc210f201abd271d9bc587825618a86a7046a8146cc816393f1998;
- toascii.json, IdnaTestV2.json and urltestdata.json, web-platform-tests' URL Standard tests at
  https://raw.githubusercontent.com/web-platform-tests/wpt/42cbc75a89c64ce896ad20736f2393dba7ba2e91/url/resources/,
  644eba9d5b593df8095cfa307222f3014542ff9cc02d555f8e5660059d80470f,
  84de621e5239676e59e5a3e68ef3e2b1acde9da5480a633d2ef446ef03238b76 and
  81e85fd3c199c08ef9c34cf651b3580eeedd080316493bfaf277a6b5ff8cf652;
- wpt-LICENSE.txt, the 3-Clause BSD License of those three files, web-platform-tests' LICENSE.md at the same commit,
  5fac07febb0e2a97fb0d7b0def149ec08b642e1ba4b9c345283ab1cbd2af6570.
The Unicode files carry Unicode's own notice and terms of use.

The sets:
- IdnaTestV2.txt, every row: UTS #46 ToASCII with the file's own flags (domain_to_ascii strict); the URL Standard's
  domain parser (domain_to_ascii), where the file's status codes for the flags the Standard sets false (A4_1 and A4_2
  for VerifyDnsLength, U1 for UseSTD3ASCIIRules, V2 and V3 for CheckHyphens) are not failures; and the Punycode encoder
  and decoder against RFC 3492's own procedures (rfc3492.py) on every label of every row;
- NormalizationTest.txt: normalization form C on every row, and on every code point that part 1 does not list;
- toascii.json, IdnaTestV2.json and urltestdata.json's rows with no base, each as web-platform-tests' harness reads it,
  through the URL https://<input>/x or the input itself; IdnaTestV2.json leaves the rows that read a later Unicode
  version, by DerivedAge.txt.
Each set asserts its row count and no difference. No test reads the network."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from rfc3492 import rfc3492_decode, rfc3492_encode

from integraledger_terms.bindings._url import (
    _nfc,
    _punycode_decode,
    _punycode_encode,
    domain_to_ascii,
    parse_host,
    read_url,
)

UCD = "https://www.unicode.org/Public/17.0.0"
WPT = "https://raw.githubusercontent.com/web-platform-tests/wpt/42cbc75a89c64ce896ad20736f2393dba7ba2e91"
# Each file of data/: its address and its SHA-256.
FILES = {
    "IdnaTestV2.txt": (
        f"{UCD}/idna/IdnaTestV2.txt",
        "beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf",
    ),
    "NormalizationTest.txt": (
        f"{UCD}/ucd/NormalizationTest.txt",
        "5019ffd530751a741900c849c0e010332f142a3612234639bd200b82138a87db",
    ),
    "DerivedAge.txt": (f"{UCD}/ucd/DerivedAge.txt", "f8ecdf768bdc210f201abd271d9bc587825618a86a7046a8146cc816393f1998"),
    "toascii.json": (
        f"{WPT}/url/resources/toascii.json",
        "644eba9d5b593df8095cfa307222f3014542ff9cc02d555f8e5660059d80470f",
    ),
    "IdnaTestV2.json": (
        f"{WPT}/url/resources/IdnaTestV2.json",
        "84de621e5239676e59e5a3e68ef3e2b1acde9da5480a633d2ef446ef03238b76",
    ),
    "urltestdata.json": (
        f"{WPT}/url/resources/urltestdata.json",
        "81e85fd3c199c08ef9c34cf651b3580eeedd080316493bfaf277a6b5ff8cf652",
    ),
    "wpt-LICENSE.txt": (f"{WPT}/LICENSE.md", "5fac07febb0e2a97fb0d7b0def149ec08b642e1ba4b9c345283ab1cbd2af6570"),
}
DATA = Path(__file__).parent / "data"
_ESCAPE = re.compile(r"\\x\{([0-9A-Fa-f]+)\}|\\u([0-9A-Fa-f]{4})")


def read(name: str) -> str:
    """A file of data/, read only when it is the file its address holds."""
    url, sha256 = FILES[name]
    data = (DATA / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == sha256, f"data/{name} is not {url}"
    return data.decode("utf-8")


@pytest.mark.parametrize("name", list(FILES))
def test_each_file_is_the_one_its_address_holds(name: str) -> None:
    assert hashlib.sha256((DATA / name).read_bytes()).hexdigest() == FILES[name][1]


def data_lines(text: str) -> list[tuple[int, list[str]]]:
    """The data lines of a Unicode text file, comments dropped, with their line numbers."""
    lines: list[tuple[int, list[str]]] = []
    for i, line in enumerate(text.split("\n")):
        body = line.split("#")[0].strip()
        if body != "" and not body.startswith("@"):
            lines.append((i + 1, [column.strip() for column in body.split(";")]))
    return lines


def unescape(s: str) -> str:
    """IdnaTestV2.txt's escapes, \\uXXXX and \\x{X...}, read as a JavaScript string reads them: a \\u escape is one
    UTF-16 code unit, so two that form a surrogate pair are the one code point, and a lone one stays a surrogate."""
    units = _ESCAPE.sub(lambda m: chr(int(m.group(1) or m.group(2), 16)), s)
    return units.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


class IdnaRow(NamedTuple):
    line: int
    source: str
    to_unicode: str
    to_ascii_n: str
    statuses: list[str]


def idna_rows() -> list[IdnaRow]:
    rows: list[IdnaRow] = []
    for line, c in data_lines(read("IdnaTestV2.txt")):
        source = "" if c[0] == '""' else unescape(c[0])
        to_unicode = source if c[1] == "" else "" if c[1] == '""' else unescape(c[1])
        to_ascii_n = to_unicode if c[3] == "" else "" if c[3] == '""' else unescape(c[3])
        status = c[4] or c[2] or "[]"
        statuses = [s.strip() for s in status[1:-1].split(",") if s.strip()]
        rows.append(IdnaRow(line, source, to_unicode, to_ascii_n, statuses))
    assert len(rows) == 6391, "IdnaTestV2.txt 17.0.0: 6,391 rows"
    return rows


# The status codes of the flags the URL Standard's domain parser sets false.
OFF_IN_URLS = frozenset({"A4_1", "A4_2", "U1", "V2", "V3"})
FORBIDDEN_DOMAIN = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")


def test_every_row_strict_is_uts_46_toascii_with_the_files_flags() -> None:
    def expected(r: IdnaRow) -> str | None:
        return None if r.statuses else r.to_ascii_n

    assert [r.line for r in idna_rows() if domain_to_ascii(r.source, True) != expected(r)] == []


def test_every_row_is_the_url_standards_domain_parser() -> None:
    def expected(r: IdnaRow) -> str | None:
        failed = any(s not in OFF_IN_URLS for s in r.statuses)
        result = r.source.lower() if r.source.isascii() else None if failed else r.to_ascii_n
        return None if result is None or result == "" or FORBIDDEN_DOMAIN.search(result) else result

    assert [r.line for r in idna_rows() if domain_to_ascii(r.source) != expected(r)] == []


def test_every_label_of_its_three_columns_encodes_and_decodes_as_rfc_3492() -> None:
    # Each label of source, toUnicode and toAsciiN is encoded as code points, and each ASCII label is decoded, after
    # xn-- where it begins with that prefix in any case.
    labels = [label for r in idna_rows() for s in (r.source, r.to_unicode, r.to_ascii_n) for label in s.split(".")]
    ascii_labels = [label[4:] if label[:4].lower() == "xn--" else label for label in labels if label.isascii()]
    code_points = [[ord(c) for c in label] for label in labels]
    encode_differ = [cps for cps in code_points if _punycode_encode(cps) != rfc3492_encode(cps)]
    decode_differ = [label for label in ascii_labels if _punycode_decode(label) != rfc3492_decode(label)]
    assert (encode_differ, decode_differ) == ([], [])
    # The file's counts: 37,680 labels, 20,400 of them ASCII, of which 16,496 decode to a code point past U+007F.
    decoded = [label for label in ascii_labels if any(c >= 0x80 for c in rfc3492_decode(label) or [])]
    assert (len(labels), len(ascii_labels), len(decoded)) == (37_680, 20_400, 16_496)


def code_points(column: str) -> list[int]:
    return [int(h, 16) for h in column.split(" ")]


def test_normalization_form_c_on_every_row() -> None:
    # c2 = NFC(c1) = NFC(c2) = NFC(c3), and c4 = NFC(c4) = NFC(c5).
    rows = data_lines(read("NormalizationTest.txt"))
    assert len(rows) == 20_034, "NormalizationTest.txt 17.0.0: 20,034 rows"
    differ = []
    for line, c in rows:
        c1, c2, c3, c4, c5 = (code_points(column) for column in c[:5])
        if any(_nfc(x) != c2 for x in (c1, c2, c3)) or any(_nfc(x) != c4 for x in (c4, c5)):
            differ.append(line)
    assert differ == []


def test_every_code_point_that_part_1_does_not_list_is_its_own_normalization_form_c() -> None:
    text = read("NormalizationTest.txt")
    part1 = text[text.index("@Part1") : text.index("@Part2")]
    listed = {code_points(c[0])[0] for _, c in data_lines(part1)}
    assert len(listed) > 0
    checked = 0
    differ = []
    for cp in range(0x110000):
        if cp in listed or 0xD800 <= cp < 0xE000:
            continue
        checked += 1
        if _nfc([cp]) != [cp]:
            differ.append(cp)
    assert checked == 0x110000 - 0x800 - len(listed)
    assert differ == []


def wpt_rows(name: str) -> list[dict[str, Any]]:
    """The rows of a web-platform-tests JSON file: its objects, the strings between them being comments."""
    return [r for r in json.loads(read(name)) if isinstance(r, dict)]


def harness(text: str) -> str | None:
    """The host of https://<text>/x, as web-platform-tests' harness reads it."""
    u = read_url(f"https://{text}/x")
    return None if u is None else u.host


def test_toascii_json_every_row_through_a_url_and_through_parse_host_where_it_is_a_whole_host() -> None:
    rows = wpt_rows("toascii.json")
    assert len(rows) == 87, "toascii.json: 87 rows"
    assert [r["input"] for r in rows if harness(r["input"]) != r["output"]] == []
    whole = [r for r in rows if not re.search(r"[\t\n\r/\\?#@:]|^[\x00-\x20]|[\x00-\x20]\Z", r["input"])]
    assert len(whole) > 0
    assert [r["input"] for r in whole if parse_host(r["input"]) != r["output"]] == []


def test_idnatestv2_json_every_row_but_the_empty_input_and_those_of_a_later_unicode() -> None:
    # IdnaTestV2.json is generated from Unicode's latest IdnaTestV2.txt. A row that expects a host while it holds a code
    # point Unicode 17.0.0 leaves unassigned, which every 17.0.0 domain parse refuses, reads a later version's data. The
    # harness skips the empty input.
    ranges = (c[0].partition("..") for _, c in data_lines(read("DerivedAge.txt")))
    assigned = [(int(a, 16), int(z or a, 16)) for a, _, z in ranges]

    def later(r: dict[str, Any]) -> bool:
        return r["output"] is not None and any(not any(a <= ord(ch) <= z for a, z in assigned) for ch in r["input"])

    rows = wpt_rows("IdnaTestV2.json")
    assert len(rows) == 2676, "IdnaTestV2.json: 2,676 rows"
    kept = [r for r in rows if r["input"] != "" and not later(r)]
    assert len(kept) == 2668, "IdnaTestV2.json: 2,668 rows of a non-empty input that read Unicode 17.0.0"
    assert [r["input"] for r in kept if harness(r["input"]) != r["output"]] == []


def test_urltestdata_json_each_row_with_no_base_parses_or_fails_as_the_file_says() -> None:
    # Its scheme, host, port and whether it has a username or password, from read_url; a row with a base resolves a
    # relative reference against it, which read_url does not read.
    rows = wpt_rows("urltestdata.json")
    assert len(rows) == 896, "urltestdata.json: 896 rows"
    no_base = [r for r in rows if r.get("base") is None]
    assert len(no_base) == 560, "urltestdata.json: 560 rows with no base"
    assert len([r for r in no_base if r.get("failure")]) == 207

    def want(r: dict[str, Any]) -> list[object] | None:
        userinfo = (r.get("username") or "") + (r.get("password") or "") != ""
        return None if r.get("failure") else [r["protocol"], r["hostname"], r["port"], userinfo]

    def ours(r: dict[str, Any]) -> list[object] | None:
        u = read_url(r["input"])
        if u is None:
            return None
        return [f"{u.scheme}:", u.host or "", "" if u.port is None else str(u.port), u.credentials]

    assert [r["input"] for r in no_base if ours(r) != want(r)] == []
