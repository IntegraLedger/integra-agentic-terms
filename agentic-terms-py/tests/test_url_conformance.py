"""The host parser this package carries, against Unicode's IdnaTestV2.txt 17.0.0, every row, as the protocol package's
conformance test reads it. The file is data/IdnaTestV2.txt, fetched from
https://www.unicode.org/Public/17.0.0/idna/IdnaTestV2.txt and held to its SHA-256:
- UTS #46 ToASCII with the file's own flags (domain_to_ascii strict);
- the URL Standard's domain parser (domain_to_ascii), where the file's status codes for the flags the Standard sets
  false (A4_1 and A4_2 for VerifyDnsLength, U1 for UseSTD3ASCIIRules, V2 and V3 for CheckHyphens) are not failures;
- the Punycode encoder and decoder against RFC 3492's own procedures (rfc3492.py) on every label of every row.
Each asserts the file's row count and no difference."""

import hashlib
import re
from pathlib import Path
from typing import NamedTuple

from rfc3492 import rfc3492_decode, rfc3492_encode

from integraledger_terms.bindings._url import _punycode_decode, _punycode_encode, domain_to_ascii

IDNA_TEST = Path(__file__).parent / "data" / "IdnaTestV2.txt"
IDNA_TEST_SHA256 = "beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf"
DATA = IDNA_TEST.read_bytes()
_ESCAPE = re.compile(r"\\x\{([0-9A-Fa-f]+)\}|\\u([0-9A-Fa-f]{4})")


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
    """The data lines, comments dropped, with their line numbers."""
    rows: list[IdnaRow] = []
    for i, line in enumerate(DATA.decode("utf-8").split("\n")):
        body = line.split("#")[0].strip()
        if body == "" or body.startswith("@"):
            continue
        c = [column.strip() for column in body.split(";")]
        source = "" if c[0] == '""' else unescape(c[0])
        to_unicode = source if c[1] == "" else "" if c[1] == '""' else unescape(c[1])
        to_ascii_n = to_unicode if c[3] == "" else "" if c[3] == '""' else unescape(c[3])
        status = c[4] or c[2] or "[]"
        statuses = [s.strip() for s in status[1:-1].split(",") if s.strip()]
        rows.append(IdnaRow(i + 1, source, to_unicode, to_ascii_n, statuses))
    assert len(rows) == 6391, "IdnaTestV2.txt 17.0.0: 6,391 rows"
    return rows


# The status codes of the flags the URL Standard's domain parser sets false.
OFF_IN_URLS = frozenset({"A4_1", "A4_2", "U1", "V2", "V3"})
FORBIDDEN_DOMAIN = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")


def test_the_file_is_unicodes_idnatestv2_17() -> None:
    assert hashlib.sha256(DATA).hexdigest() == IDNA_TEST_SHA256


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
