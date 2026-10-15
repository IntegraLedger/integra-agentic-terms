"""The package's Punycode encoder and decoder (bindings/_url.py), which take O(n log n) time, against RFC 3492's own
procedures (rfc3492.py), which scan or insert once per code point: the same answer, a string or None, for each label
below. The labels are drawn by the seeded generator mulberry32 with the seed, the draws and the counts of the protocol
package's Punycode test, so both compare the same labels. IdnaTestV2.txt's labels are compared in
test_url_conformance.py.

The work each takes is counted, never timed: every line the interpreter runs, and for each call of a list method that
moves or scans the list (insert, index, count, remove, sort), the length of the list. Making a label four times as long
multiplies an O(n log n) count by about four and a half, where the RFC's procedures, which scan or move the whole label
or output once per code point, multiply it by sixteen."""

import ast
import math
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from types import FrameType
from typing import Any

from rfc3492 import rfc3492_decode, rfc3492_encode

from integraledger_terms.bindings import _url
from integraledger_terms.bindings._url import _punycode_decode, _punycode_encode, domain_to_ascii


def generator(seed: int) -> Callable[[], float]:
    """mulberry32: a seeded generator of numbers in [0, 1), in 32-bit unsigned arithmetic."""
    state = seed & 0xFFFFFFFF

    def imul(a: int, b: int) -> int:
        return (a * b) & 0xFFFFFFFF

    def next_value() -> float:
        nonlocal state
        state = (state + 0x6D2B79F5) & 0xFFFFFFFF
        t = imul(state ^ (state >> 15), state | 1)
        t ^= (t + imul(t ^ (t >> 7), t | 61)) & 0xFFFFFFFF
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296

    return next_value


random = generator(20261015)


def below(n: int) -> int:
    return math.floor(random() * n)


def between(lo: int, hi: int) -> int:
    return lo + below(hi - lo + 1)


def code_point(kind: int) -> int:
    """A code point of one kind: 0 basic (below U+0080), 1 past U+007F in the BMP, 2 astral. Never a surrogate."""
    if kind == 0:
        return below(0x80)
    if kind == 2:
        return between(0x10000, 0x10FFFF)
    c = between(0x80, 0xFFFF - 0x800)
    return c if c < 0xD800 else c + 0x800


def label(size: int) -> list[int]:
    """A label of size code points drawn from a pool of distinct ones: one, a few, many, or as many as the label is
    long, so some code points repeat and some do not. Each label draws its own proportions of the three kinds."""
    sizes = [1, between(2, 8), between(9, 300), max(1, size)]
    pool_size = sizes[below(4)]
    weights = [random(), random(), random()]
    total = weights[0] + weights[1] + weights[2]

    def kind() -> int:
        x = random() * total
        return 0 if x < weights[0] else 1 if x < weights[0] + weights[1] else 2

    pool = [code_point(kind()) for _ in range(pool_size)]
    return [pool[below(pool_size)] for _ in range(size)]


def near_the_bound() -> list[int]:
    """A label of 1,900 to 2,500 basic code points with one or two code points from U+C0000 to U+10FFFF among them, so
    the encoder's first step past the basic code points, (m - 0x80) * (h + 1), falls on either side of 2^31 - 1."""
    cps = [below(0x80) for _ in range(between(1900, 2500))]
    for _ in range(between(1, 2)):
        position = below(len(cps) + 1)
        cps.insert(position, between(0xC0000, 0x10FFFF))
    return cps


# [labels, least size, greatest size]
SIZES = ((400, 0, 16), (250, 17, 300), (80, 301, 4000))
LABELS = [label(between(lo, hi)) for count, lo, hi in SIZES for _ in range(count)] + [near_the_bound() for _ in range(60)]
assert len(LABELS) == 790, "the seeded labels: 790"
RFC_ENCODED = [rfc3492_encode(cps) for cps in LABELS]

ALPHABETS = ("a", "ab", "abc-", "aAbB9-", "abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz-0123ABCXYZ")


def text(alphabet: str, size: int) -> str:
    return "".join(alphabet[below(len(alphabet))] for _ in range(size))


STRINGS = [text(ALPHABETS[i % len(ALPHABETS)], between(0, 3000 if i % 10 == 0 else 40)) for i in range(600)]
assert len(STRINGS) == 600, "the seeded ASCII strings: 600"


def differences(inputs: Sequence[Any], ours: Callable[[Any], object], rfc: Callable[[Any, int], object]) -> list[str]:
    """The inputs where the package's answer differs from the RFC's: their index, and both answers."""
    answers = [(i, ours(x), rfc(x, i)) for i, x in enumerate(inputs)]
    return [f"{i}: {a!r:.80} where RFC 3492 gives {b!r:.80}" for i, a, b in answers if a != b]


def test_the_encoder_gives_rfc_3492s_answer_for_each_seeded_label() -> None:
    assert differences(LABELS, _punycode_encode, lambda _x, i: RFC_ENCODED[i]) == []
    # The seeded set's counts: RFC 3492 refuses 12 labels, and gives 121 encodings longer than 1,000 characters.
    refused = sum(1 for a in RFC_ENCODED if a is None)
    long = sum(1 for a in RFC_ENCODED if a is not None and len(a) > 1000)
    assert (refused, long) == (12, 121)


def test_the_encoder_at_the_integer_bound_before_the_first_insertion() -> None:
    # RFC 3492 section 6.4: (0x10FFFF - 0x80) * (h + 1) is 2,146,645,241 for h = 1926, and 2,147,759,224 for h = 1927,
    # past 2^31 - 1.
    def at(h: int) -> list[int]:
        return [0x61] * h + [0x10FFFF]

    assert _punycode_encode(at(1926)) == rfc3492_encode(at(1926)) is not None
    assert rfc3492_encode(at(1927)) is None
    assert _punycode_encode(at(1927)) is None


def test_the_encoder_at_the_integer_bound_within_the_scan() -> None:
    # (0x10FF70 - 0x80) * 1928 is 2,147,483,520, 127 below 2^31 - 1, and the scan adds one for each basic code point
    # before U+10FF70.
    def at(before: int) -> list[int]:
        cps = [0x61] * 1928
        cps[before] = 0x10FF70
        return cps

    assert _punycode_encode(at(127)) == rfc3492_encode(at(127)) is not None
    assert rfc3492_encode(at(128)) is None
    assert _punycode_encode(at(128)) is None


def test_the_decoder_gives_rfc_3492s_answer_for_each_seeded_labels_encoding() -> None:
    encoded = [e for e in RFC_ENCODED if e is not None]
    assert len(encoded) == 778
    assert differences(encoded, _punycode_decode, lambda x, _i: rfc3492_decode(x)) == []
    assert [_punycode_decode(e) for e in encoded] == [cps for cps, e in zip(LABELS, RFC_ENCODED) if e is not None]


def test_the_decoder_gives_rfc_3492s_answer_for_each_seeded_ascii_string() -> None:
    assert differences(STRINGS, _punycode_decode, lambda x, _i: rfc3492_decode(x)) == []
    answers = [rfc3492_decode(s) for s in STRINGS]
    # The seeded set's counts: RFC 3492 refuses 123 strings, and decodes 37 to more than 100 code points.
    refused = sum(1 for a in answers if a is None)
    long = sum(1 for a in answers if a is not None and len(a) > 100)
    assert (refused, long) == (123, 37)


def test_the_decoder_for_basic_code_points_a_delimiter_and_digits_that_insert_one_code_point_each() -> None:
    for b, d in ((0, 3000), (1500, 1500), (3000, 1), (1, 3000)):
        s = "a" * b + "-" + "a" * d
        assert _punycode_decode(s) == rfc3492_decode(s), (b, d)


SCANS = frozenset({"insert", "index", "count", "remove", "sort"})


def work(f: Callable[[], object]) -> int:
    """The work f takes: each line the interpreter runs, and for each call of a list method that moves or scans the
    list, the length of the list. Work done inside one statement or builtin call is not seen: a slice assignment, an
    item deletion, and min, max or bisect's insort over a list, which
    test_the_host_step_holds_no_work_the_count_cannot_see keeps out of _url.py."""
    count = 0

    def line(frame: FrameType, event: str, _arg: object) -> Any:
        nonlocal count
        if event == "line":
            count += 1
        return line

    def call(_frame: FrameType, event: str, arg: object) -> None:
        nonlocal count
        held = getattr(arg, "__self__", None)
        if event == "c_call" and isinstance(held, list) and getattr(arg, "__name__", "") in SCANS:
            count += len(held)

    saved_trace, saved_profile = sys.gettrace(), sys.getprofile()
    sys.settrace(line)
    sys.setprofile(call)
    try:
        f()
    finally:
        sys.settrace(saved_trace)
        sys.setprofile(saved_profile)
    return count


def growth(f: Callable[[int], object], n: int) -> float:
    """How many times the work grows when the input grows from n to 4n."""
    return work(lambda: f(4 * n)) / work(lambda: f(n))


def test_the_encoders_work_grows_as_n_log_n_with_the_labels_length() -> None:
    # Labels of n distinct CJK ideographs: the RFC's encoder scans the whole label once for each of them.
    def encode(n: int) -> object:
        return _punycode_encode(list(range(0x4E00, 0x4E00 + n)))

    # n log n from 500 to 2,000 code points is 4.9 times the work, and n squared 16 times.
    assert growth(encode, 500) < 8


def test_the_decoders_work_grows_as_n_log_n_with_the_strings_length() -> None:
    # n basic code points, a delimiter and n digits "a", each of which inserts a code point at the start: the RFC's
    # decoder moves the whole output once for each.
    def decode(n: int) -> object:
        return _punycode_decode("a" * n + "-" + "a" * n)

    assert growth(decode, 500) < 8


def test_the_domain_parsers_work_grows_as_n_log_n_with_the_domains_length() -> None:
    def parse(n: int) -> object:
        return domain_to_ascii("".join(chr(0x4E00 + i) for i in range(n)))

    assert growth(parse, 500) < 8


UNSEEN_CALLS = frozenset({"min", "max", "insort", "insort_left", "insort_right"})


def test_the_host_step_holds_no_work_the_count_cannot_see() -> None:
    # A slice assignment, an item deletion, and min, max or bisect's insort over a list each move or scan the list
    # inside one statement or builtin call, which work does not count, so _url.py holds none of them.
    def unseen(node: ast.AST) -> bool:
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            return any(isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Slice) for t in targets)
        if isinstance(node, ast.Delete):
            return any(isinstance(t, ast.Subscript) for t in node.targets)
        if isinstance(node, ast.Call):
            f = node.func
            return (f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else "") in UNSEEN_CALLS
        return False

    tree = ast.parse(Path(_url.__file__).read_text(encoding="utf-8"))
    assert [ast.unparse(node) for node in ast.walk(tree) if unseen(node)] == []
