"""The WHATWG URL Standard's host parser (section 3.5), its domain parser (section 3.3, UTS #46 ToASCII with the flags
the Standard sets, over the Unicode 17.0.0 data in _idna_data), and the part of its basic URL parser (section 4.4) that
reads an absolute URL's scheme and authority. Each reads a string as the Standard reads a scalar value string, taking
the string as a JavaScript string of its UTF-16 code units: a surrogate pair is the one code point it forms, held as one
code point or as two, and a lone surrogate is U+FFFD, as Web IDL's USVString conversion gives it.

Unicode normalization form C is UAX #15 over the tables, Punycode is RFC 3492 with its integers bounded at 2^31 - 1,
ContextJ is RFC 5892 appendix A.1 and A.2, and the bidi rule is RFC 5893 section 2. No answer depends on the
interpreter's own URL parser, codecs, normalization or Unicode version.
"""

import re
from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import cache

from . import _idna_data as _data
from ._codec import to_well_formed

# The special schemes, each with its default port (section 4.2).
_SPECIAL: dict[str, int | None] = {"ftp": 21, "file": None, "http": 80, "https": 443, "ws": 80, "wss": 443}
# The forbidden host code points (section 3.5).
_FORBIDDEN_HOST = re.compile(r"[\x00\t\n\r #/:<>?@\[\\\]^|]")
# The forbidden domain code points: the forbidden host code points, the C0 controls, "%" and U+007F.
_FORBIDDEN_DOMAIN = re.compile(r"[\x00-\x20#%/:<>?@\[\\\]^|\x7f]")


def _range_of(starts: Sequence[int], cp: int) -> int:
    """The index of the range holding cp, in a table of sorted range starts."""
    return bisect_right(starts, cp) - 1


def _code_points(s: str) -> list[int]:
    return [ord(c) for c in s]


def _from_code_points(cps: Sequence[int]) -> str:
    return "".join(map(chr, cps))


def _ccc(cp: int) -> int:
    return _data.CCC[_range_of(_data.CCC_STARTS, cp)]


def _mapping_of(cp: int) -> int | str | None:
    return _data.MAPPING[_range_of(_data.MAPPING_STARTS, cp)]


def _bidi_of(cp: int) -> str:
    return _data.BIDI[_range_of(_data.BIDI_STARTS, cp)]


def _joining_of(cp: int) -> str:
    return _data.JOINING[_range_of(_data.JOINING_STARTS, cp)]


def _is_mark(cp: int) -> bool:
    """General_Category Mark: the runs of MARK_STARTS alternate, starting with a run of non-marks at U+0000."""
    return _range_of(_data.MARK_STARTS, cp) % 2 == 1


# Unicode normalization form C (UAX #15).
_S_BASE = 0xAC00
_L_BASE = 0x1100
_V_BASE = 0x1161
_T_BASE = 0x11A7
_L_COUNT = 19
_V_COUNT = 21
_T_COUNT = 28
_N_COUNT = _V_COUNT * _T_COUNT
_S_COUNT = _L_COUNT * _N_COUNT


@cache
def _tables_for_nfc() -> tuple[dict[int, list[int]], dict[int, int]]:
    """Each code point's full canonical decomposition, and each primary composite by its pair, built at first use."""
    one = {cp: _code_points(d) for cp, d in _data.DECOMPOSITIONS.items()}

    def full(cp: int) -> list[int]:
        d = one.get(cp)
        return [cp] if d is None else [x for c in d for x in full(c)]

    decomposed: dict[int, list[int]] = {}
    composed: dict[int, int] = {}
    for cp, d in one.items():
        decomposed[cp] = full(cp)
        if len(d) == 2 and cp not in _data.COMPOSITION_EXCLUSIONS:
            composed[d[0] * 0x110000 + d[1]] = cp
    return decomposed, composed


def _composite(a: int, b: int, composed: dict[int, int]) -> int | None:
    if _L_BASE <= a < _L_BASE + _L_COUNT and _V_BASE <= b < _V_BASE + _V_COUNT:
        return _S_BASE + ((a - _L_BASE) * _V_COUNT + b - _V_BASE) * _T_COUNT
    s = a - _S_BASE
    if 0 <= s < _S_COUNT and s % _T_COUNT == 0 and _T_BASE < b < _T_BASE + _T_COUNT:
        return a + b - _T_BASE
    return composed.get(a * 0x110000 + b)


def _nfc(cps: Sequence[int]) -> list[int]:
    """Normalization form C of code points: canonical decomposition, the canonical ordering, then canonical
    composition."""
    if all(c < 0x80 for c in cps):
        return list(cps)
    decomposed, composed = _tables_for_nfc()
    flat: list[int] = []
    for cp in cps:
        s = cp - _S_BASE
        if 0 <= s < _S_COUNT:
            flat += (_L_BASE + s // _N_COUNT, _V_BASE + s % _N_COUNT // _T_COUNT)
            if s % _T_COUNT != 0:
                flat.append(_T_BASE + s % _T_COUNT)
        else:
            flat += decomposed.get(cp, (cp,))
    ordered: list[int] = []
    marks: list[int] = []
    for cp in flat:
        if _ccc(cp) == 0:
            ordered += sorted(marks, key=_ccc)
            marks = []
            ordered.append(cp)
        else:
            marks.append(cp)
    ordered += sorted(marks, key=_ccc)
    out: list[int] = []
    starter = -1
    for cp in ordered:
        c = _ccc(cp)
        # After the canonical ordering, the last code point kept since the starter has the highest class among those
        # between.
        blocked = len(out) - 1 > starter and (_ccc(out[-1]) == 0 or _ccc(out[-1]) >= c)
        if starter >= 0 and not blocked:
            p = _composite(out[starter], cp, composed)
            if p is not None:
                out[starter] = p
                continue
        if c == 0:
            starter = len(out)
        out.append(cp)
    return out


# Punycode (RFC 3492), its integers bounded at 2^31 - 1.
_BASE = 36
_TMIN = 1
_TMAX = 26
_SKEW = 38
_DAMP = 700
_MAXINT = 0x7FFFFFFF
_DIGITS = "abcdefghijklmnopqrstuvwxyz0123456789"


def _adapt(delta: int, points: int, first: bool) -> int:
    d = delta // _DAMP if first else delta // 2
    d += d // points
    k = 0
    while d > ((_BASE - _TMIN) * _TMAX) >> 1:
        d //= _BASE - _TMIN
        k += _BASE
    return k + ((_BASE - _TMIN + 1) * d) // (d + _SKEW)


def _threshold(k: int, bias: int) -> int:
    return _TMIN if k <= bias else _TMAX if k >= bias + _TMAX else k - bias


def _digit_of(c: int | None) -> int | None:
    """An ASCII character's value as a Punycode digit, or None."""
    if c is None:
        return None
    if 0x61 <= c <= 0x7A:
        return c - 0x61
    if 0x41 <= c <= 0x5A:
        return c - 0x41
    if 0x30 <= c <= 0x39:
        return c - 0x30 + 26
    return None


class _Ones:
    """A Fenwick tree over the positions 0 to size - 1, each holding 0 or 1: it changes a position, counts the ones
    before a position, and finds the position of the k-th one, each in O(log size) time."""

    def __init__(self, size: int, full: bool) -> None:
        """All positions hold 0, or all hold 1 when full is true."""
        self._tree = [0] * (size + 1)
        if full:
            for i in range(1, size + 1):
                self._tree[i] = i & -i

    def add(self, p: int, d: int) -> None:
        """Adds d to position p."""
        i = p + 1
        while i < len(self._tree):
            self._tree[i] += d
            i += i & -i

    def before(self, p: int) -> int:
        """The number of ones at the positions before p."""
        total = 0
        i = p
        while i > 0:
            total += self._tree[i]
            i -= i & -i
        return total

    def nth(self, k: int) -> int:
        """The position of the k-th one, counting from 1, where at least k positions hold one."""
        p = 0
        step = 1
        while step * 2 < len(self._tree):
            step *= 2
        while step > 0:
            if p + step < len(self._tree) and self._tree[p + step] < k:
                p += step
                k -= self._tree[p]
            step >>= 1
        return p


def _punycode_decode(text: str) -> list[int] | None:
    """The code points an ASCII Punycode string encodes, or None where RFC 3492's decoder fails. The RFC's decoder
    inserts each code point it reads into the output at the position it reads. Here each insertion is recorded, then
    placed from the last to the first: the output slots that no later insertion takes hold the earlier code points in
    order, so an insertion at position i takes the (i + 1)-th of those slots, which a Fenwick tree finds. A string of n
    characters takes O(n log n) time."""
    delimiter = text.rfind("-")
    basic = _code_points(text[:delimiter]) if delimiter > 0 else []
    pos = delimiter + 1 if delimiter > 0 else 0
    n = 0x80
    i = 0
    bias = 72
    length = len(basic)
    inserted: list[int] = []
    at: list[int] = []
    while pos < len(text):
        old_i = i
        w = 1
        k = _BASE
        while True:
            digit = _digit_of(ord(text[pos]) if pos < len(text) else None)
            pos += 1
            if digit is None or digit > (_MAXINT - i) // w:
                return None
            i += digit * w
            t = _threshold(k, bias)
            if digit < t:
                break
            if w > _MAXINT // (_BASE - t):
                return None
            w *= _BASE - t
            k += _BASE
        bias = _adapt(i - old_i, length + 1, old_i == 0)
        if i // (length + 1) > _MAXINT - n:
            return None
        n += i // (length + 1)
        i %= length + 1
        if n > 0x10FFFF:
            return None
        inserted.append(n)
        at.append(i)
        length += 1
        i += 1
    out = [-1] * length
    open_slots = _Ones(length, True)
    for j in range(len(inserted) - 1, -1, -1):
        slot = open_slots.nth(at[j] + 1)
        out[slot] = inserted[j]
        open_slots.add(slot, -1)
    following = 0
    for slot in range(length):
        if out[slot] == -1:
            out[slot] = basic[following]
            following += 1
    return out


def _punycode_encode(cps: Sequence[int]) -> str | None:
    """RFC 3492's encoding of a label, or None where the encoder fails. The RFC's main loop takes each distinct code
    point past U+007F, from the least, and scans the whole label for it, adding one to delta for each code point less
    than it and writing delta at each of its occurrences. Here the positions of those code points are sorted once, by
    code point and then by position, and a Fenwick tree over the label counts the code points less than the current one
    between two positions, so each stretch of the scan is one count, checked against the same bound of 2^31 - 1. A
    label of n code points takes O(n log n) time."""
    out = [chr(c) for c in cps if c < 0x80]
    b = len(out)
    h = b
    if b > 0:
        out.append("-")
    order: list[int] = []
    handled = _Ones(len(cps), False)
    for p, c in enumerate(cps):
        if c < 0x80:
            handled.add(p, 1)
        else:
            order.append(p)
    order.sort(key=lambda p: (cps[p], p))
    n = 0x80
    delta = 0
    bias = 72
    first = 0
    while first < len(order):
        m = cps[order[first]]
        end = first + 1
        while end < len(order) and cps[order[end]] == m:
            end += 1
        if m - n > (_MAXINT - delta) // (h + 1):
            return None
        delta += (m - n) * (h + 1)
        n = m
        # The scan: from position start up to each position of m, then to the end of the label.
        start = 0
        for j in range(first, end):
            p = order[j]
            delta += handled.before(p) - handled.before(start)
            if delta > _MAXINT:
                return None
            q = delta
            k = _BASE
            while True:
                t = _threshold(k, bias)
                if q < t:
                    break
                out.append(_DIGITS[t + (q - t) % (_BASE - t)])
                q = (q - t) // (_BASE - t)
                k += _BASE
            out.append(_DIGITS[q])
            bias = _adapt(delta, h + 1, h == b)
            delta = 0
            h += 1
            start = p + 1
        delta += handled.before(len(cps)) - handled.before(start)
        if delta > _MAXINT:
            return None
        for j in range(first, end):
            handled.add(order[j], 1)
        delta += 1
        n += 1
        first = end
    return "".join(out)


# UTS #46 processing and ToASCII.
_FULL_STOP = 0x2E
_HYPHEN = 0x2D
_ZWNJ = 0x200C
_ZWJ = 0x200D
_VIRAMA = 9
_STD3_ASCII = re.compile(r"[a-z0-9-]")


def _mapped(cps: Sequence[int]) -> list[int]:
    """The Map step: a disallowed code point is kept, and the validity criteria refuse it."""
    out: list[int] = []
    for cp in cps:
        m = _mapping_of(cp)
        if m is None:
            out.append(cp)
        elif isinstance(m, int):
            out.append(cp + m)
        else:
            out += _code_points(m)
    return out


def _joiner_allowed(label: Sequence[int], i: int) -> bool:
    """RFC 5892 appendix A.1 and A.2: a joiner after a virama, or a ZWNJ between a left- or dual-joining letter and a
    right- or dual-joining one, with only transparent letters between."""
    if i > 0 and _ccc(label[i - 1]) == _VIRAMA:
        return True
    if label[i] == _ZWJ:
        return False
    before = i - 1
    while before >= 0 and _joining_of(label[before]) == "T":
        before -= 1
    after = i + 1
    while after < len(label) and _joining_of(label[after]) == "T":
        after += 1
    if before < 0 or after >= len(label):
        return False
    return _joining_of(label[before]) in ("L", "D") and _joining_of(label[after]) in ("R", "D")


def _meets_bidi_rule(label: Sequence[int]) -> bool:
    """RFC 5893 section 2's six conditions, for a label of a domain name that holds an R, AL or AN code point."""
    classes = [_bidi_of(cp) for cp in label]
    last = len(classes) - 1
    while last >= 0 and classes[last] == "M":
        last -= 1
    end = classes[last] if last >= 0 else ""
    if classes[0] in ("R", "A"):
        numbers = "E" in classes and "N" in classes
        return all(x in "RANESCTOBM" for x in classes) and end != "" and end in "RAEN" and not numbers
    return classes[0] == "L" and all(x in "LESCTOBM" for x in classes) and end != "" and end in "LE"


def _meets_validity_criteria(label: Sequence[int], from_punycode: bool, strict: bool) -> bool:
    """UTS #46 section 4.1 for a non-empty label, under nontransitional processing with CheckJoiners, and CheckHyphens
    and UseSTD3ASCIIRules as strict sets them. A label from Punycode must also be in NFC and hold no full stop; every
    other label is in NFC by the Normalize step, and holds no full stop since the domain is split at each one."""
    if from_punycode:
        if _nfc(label) != list(label):
            return False
        if _FULL_STOP in label:
            return False
    if strict:
        if list(label[2:4]) == [_HYPHEN, _HYPHEN]:
            return False
        if label[0] == _HYPHEN or label[-1] == _HYPHEN:
            return False
    elif _from_code_points(label[:4]) == "xn--":
        return False
    if _is_mark(label[0]):
        return False
    for cp in label:
        if _mapping_of(cp) != 0:
            return False
        if strict and cp < 0x80 and _STD3_ASCII.fullmatch(chr(cp)) is None:
            return False
    return all((cp != _ZWNJ and cp != _ZWJ) or _joiner_allowed(label, i) for i, cp in enumerate(label))


def _to_ascii(domain: str, strict: bool) -> str | None:
    """UTS #46 ToASCII with nontransitional processing, CheckBidi, CheckJoiners and IgnoreInvalidPunycode false, and
    with CheckHyphens, UseSTD3ASCIIRules and VerifyDnsLength each strict: the URL Standard's domain parser ToASCII. None
    where it records an error."""
    labels: list[list[int]] = []
    split: list[list[int]] = [[]]
    for cp in _nfc(_mapped(_code_points(domain))):
        if cp == _FULL_STOP:
            split.append([])
        else:
            split[-1].append(cp)
    for raw in split:
        label = raw
        if _from_code_points(label[:4]) == "xn--":
            decoded = _punycode_decode(_from_code_points(label[4:])) if all(c < 0x80 for c in label) else None
            if decoded is None or all(c < 0x80 for c in decoded):
                return None
            if not _meets_validity_criteria(decoded, True, strict):
                return None
            label = decoded
        elif len(label) > 0 and not _meets_validity_criteria(label, False, strict):
            return None
        labels.append(label)
    rtl = any(_bidi_of(cp) in ("R", "A", "N") for label in labels for cp in label)
    if rtl and not all(len(label) == 0 or _meets_bidi_rule(label) for label in labels):
        return None
    out: list[str] = []
    for label in labels:
        if all(c < 0x80 for c in label):
            out.append(_from_code_points(label))
            continue
        encoded = _punycode_encode(label)
        if encoded is None:
            return None
        out.append(f"xn--{encoded}")
    if strict:
        total = sum(len(part) for part in out) + len(out) - 1
        if total < 1 or total > 253 or any(len(part) < 1 or len(part) > 63 for part in out):
            return None
    return ".".join(out)


def domain_to_ascii(domain: str, be_strict: bool = False) -> str | None:
    """The URL Standard's domain parser (section 3.3, "IDNA"): the ASCII form of a domain, or None for failure.

    With be_strict false, the URL parser's call: an ASCII domain is lowercased, and any other is read by UTS #46 ToASCII
    (Unicode 17.0.0) with CheckBidi and CheckJoiners, nontransitional processing, and CheckHyphens, UseSTD3ASCIIRules
    and VerifyDnsLength false; the result fails when it is empty or holds a forbidden domain code point. With be_strict
    true, every domain is read by ToASCII with CheckHyphens, UseSTD3ASCIIRules and VerifyDnsLength true as well, and its
    result is the answer. A lone surrogate is read as U+FFFD, which every domain parse refuses.

    A domain of length n takes O(n log n) time. The Standard sets no bound on the length when be_strict is false."""
    d = to_well_formed(domain)
    if be_strict:
        return _to_ascii(d, True)
    result = d.lower() if d.isascii() else _to_ascii(d, False)
    if result is None or result == "" or _FORBIDDEN_DOMAIN.search(result) is not None:
        return None
    return result


_HEX_DIGITS = re.compile(r"[0-9A-Fa-f]+")
_OCTAL_DIGITS = re.compile(r"[0-7]+")
_DECIMAL_DIGITS = re.compile(r"[0-9]+")
_HEX_PREFIX = re.compile(r"0[xX]")
# Every bound the IPv4 parser compares a number with is at most 2^32, which has ten decimal digits.
_PAST_EVERY_BOUND = 1 << 64


def _ipv4_number(part: str) -> int | None:
    """The URL Standard's IPv4 number parser: the number a part writes, in decimal, 0x hex or 0-led octal, or None."""
    if part == "":
        return None
    digits = part
    radix = 10
    if _HEX_PREFIX.match(part) is not None:
        digits = part[2:]
        radix = 16
    elif len(part) > 1 and part[0] == "0":
        digits = part[1:]
        radix = 8
    if digits == "":
        return 0
    valid = _HEX_DIGITS if radix == 16 else _OCTAL_DIGITS if radix == 8 else _DECIMAL_DIGITS
    if valid.fullmatch(digits) is None:
        return None
    # A number of more than 16 digits after its leading zeros is past every bound the IPv4 parser compares it with, and
    # is not converted: the interpreter bounds the digits a decimal conversion reads.
    significant = digits.lstrip("0")
    return _PAST_EVERY_BOUND if len(significant) > 16 else int(significant or "0", radix)


def _dotted_parts(host: str) -> list[str]:
    """The parts of a dotted host, without one empty last part."""
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    return parts


def _ends_in_a_number(host: str) -> bool:
    """The URL Standard's ends-in-a-number checker."""
    last = _dotted_parts(host)[-1]
    return last != "" and (_DECIMAL_DIGITS.fullmatch(last) is not None or _ipv4_number(last) is not None)


def _ipv4(host: str) -> str | None:
    """The URL Standard's IPv4 parser, serialized: four decimal numbers joined by dots, or None for failure."""
    parts = _dotted_parts(host)
    if len(parts) > 4:
        return None
    numbers: list[int] = []
    for part in parts:
        n = _ipv4_number(part)
        if n is None:
            return None
        numbers.append(n)
    if any(n > 255 for n in numbers[:-1]):
        return None
    last = numbers[-1]
    if last >= 256 ** (5 - len(numbers)):
        return None
    address = last
    for i, n in enumerate(numbers[:-1]):
        address += n * 256 ** (3 - i)
    return ".".join(str(address // 2**s % 256) for s in (24, 16, 8, 0))


def _is_hex(c: str) -> bool:
    return c != "" and c in "0123456789ABCDEFabcdef"


def _is_digit(c: str) -> bool:
    return c != "" and "0" <= c <= "9"


def _ipv6(text: str) -> list[int] | None:
    """The URL Standard's IPv6 parser: the eight pieces, or None for failure. text[p : p + 1] is the code point at p,
    or the empty string past the end."""
    address = [0, 0, 0, 0, 0, 0, 0, 0]
    s = text
    piece_index = 0
    compress: int | None = None
    p = 0
    if s[p : p + 1] == ":":
        if s[p + 1 : p + 2] != ":":
            return None
        p += 2
        piece_index += 1
        compress = piece_index
    while p < len(s):
        if piece_index == 8:
            return None
        if s[p] == ":":
            if compress is not None:
                return None
            p += 1
            piece_index += 1
            compress = piece_index
            continue
        value = 0
        length = 0
        while length < 4 and _is_hex(s[p : p + 1]):
            value = value * 0x10 + int(s[p], 16)
            p += 1
            length += 1
        if s[p : p + 1] == ".":
            if length == 0:
                return None
            p -= length
            if piece_index > 6:
                return None
            numbers_seen = 0
            while p < len(s):
                piece: int | None = None
                if numbers_seen > 0:
                    if s[p] == "." and numbers_seen < 4:
                        p += 1
                    else:
                        return None
                if not _is_digit(s[p : p + 1]):
                    return None
                while _is_digit(s[p : p + 1]):
                    number = int(s[p])
                    if piece is None:
                        piece = number
                    elif piece == 0:
                        return None
                    else:
                        piece = piece * 10 + number
                    if piece > 255:
                        return None
                    p += 1
                # The digit check above read at least one digit, so piece holds a number.
                address[piece_index] = address[piece_index] * 0x100 + (piece or 0)
                numbers_seen += 1
                if numbers_seen == 2 or numbers_seen == 4:
                    piece_index += 1
            if numbers_seen != 4:
                return None
            break
        elif s[p : p + 1] == ":":
            p += 1
            if p >= len(s):
                return None
        elif p < len(s):
            return None
        address[piece_index] = value
        piece_index += 1
    if compress is not None:
        swaps = piece_index - compress
        piece_index = 7
        while piece_index != 0 and swaps > 0:
            other = compress + swaps - 1
            address[piece_index], address[other] = address[other], address[piece_index]
            piece_index -= 1
            swaps -= 1
    elif piece_index != 8:
        return None
    return address


def _serialize_ipv6(address: Sequence[int]) -> str:
    """The URL Standard's IPv6 serializer: lowercase hex pieces, the first longest run of two or more zeros as ::."""
    best = -1
    best_length = 1
    i = 0
    while i < 8:
        j = i
        while j < 8 and address[j] == 0:
            j += 1
        if j - i > best_length:
            best = i
            best_length = j - i
        i = i + 1 if j == i else j
    out = ""
    ignore0 = False
    for i in range(8):
        if ignore0 and address[i] == 0:
            continue
        ignore0 = False
        if i == best:
            out += "::" if i == 0 else ":"
            ignore0 = True
            continue
        out += format(address[i], "x")
        if i != 7:
            out += ":"
    return out


def _percent_encode_c0(s: str) -> str:
    """UTF-8 percent-encoding with the C0 control percent-encode set: each C0 control and each code point past
    U+007E."""
    out: list[str] = []
    for c in s:
        if 0x1F < ord(c) < 0x7F:
            out.append(c)
        else:
            out += [f"%{b:02X}" for b in c.encode("utf-8")]
    return "".join(out)


_HEX_BYTES = frozenset(b"0123456789ABCDEFabcdef")


def _percent_decode(s: str) -> str | None:
    """UTF-8 decode without BOM of the percent-decoding of a string, or None where the bytes are not UTF-8. For those
    bytes the Standard's decode gives U+FFFD, which the IDNA Mapping Table disallows, so the domain parser fails on its
    result: None is the host parser's answer for every such input."""
    if "%" not in s:
        return s
    data = s.encode("utf-8")
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x25 and i + 2 < len(data) and data[i + 1] in _HEX_BYTES and data[i + 2] in _HEX_BYTES:
            out.append(int(data[i + 1 : i + 3], 16))
            i += 3
        else:
            out.append(data[i])
            i += 1
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return None


def parse_host(text: str, is_opaque: bool = False) -> str | None:
    """The URL Standard's host parser (section 3.5), with the host serializer (section 3.6): the serialized host, or
    None for failure.

    [...] is read by the IPv6 parser and serialized in brackets, compressed. With is_opaque true (the host of a URL
    whose scheme is not special) any other input is an opaque host: it fails on a forbidden host code point, and is
    otherwise UTF-8 percent-encoded with the C0 control percent-encode set. Otherwise the input is percent-decoded,
    decoded as UTF-8, and read by the domain parser (domain_to_ascii with be_strict false); a domain whose last label,
    after one trailing dot, is a number is read by the IPv4 parser, in decimal, 0x hex or 0-led octal parts, and
    serialized as four decimal numbers. The empty string is an opaque host, and a failure otherwise. A lone surrogate is
    read as U+FFFD, and so are percent-encoded bytes that are not UTF-8, which the domain parser fails on.

    An input of length n takes O(n log n) time. The Standard sets no bound on the length."""
    s = to_well_formed(text)
    if s.startswith("["):
        if not s.endswith("]"):
            return None
        address = _ipv6(s[1:-1])
        return None if address is None else f"[{_serialize_ipv6(address)}]"
    if is_opaque:
        return None if _FORBIDDEN_HOST.search(s) is not None else _percent_encode_c0(s)
    decoded = _percent_decode(s)
    if decoded is None:
        return None
    ascii_domain = domain_to_ascii(decoded)
    if ascii_domain is None:
        return None
    return _ipv4(ascii_domain) if _ends_in_a_number(ascii_domain) else ascii_domain


@dataclass(frozen=True)
class UrlAuthority:
    """What the basic URL parser gives for an absolute URL's scheme and authority."""

    scheme: str
    """The scheme, lowercased."""
    host: str | None
    """The serialized host, or None for a URL with no authority."""
    credentials: bool
    """Whether the URL has a username or a password that is not empty."""
    port: int | None
    """The port, or None where the URL names none or names its scheme's default port, as the URL record holds it."""


_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_TAB_OR_NEWLINE = re.compile(r"[\t\n\r]")
_TWO_SLASHES = re.compile(r"[/\\]{2}")
_FILE_HOST = re.compile(r"[^/\\?#]*")
_WINDOWS_DRIVE_LETTER = re.compile(r"[A-Za-z][:|]")
_SPECIAL_AUTHORITY = re.compile(r"[/\\]*([^/\\?#]*)")
_AUTHORITY = re.compile(r"[^/?#]*")
_PORT = re.compile(r"[0-9]*")


def read_url(value: str) -> UrlAuthority | None:
    """The scheme and authority of a string that the URL Standard's basic URL parser (section 4.4) reads, with no base,
    as an absolute URL, or None where it returns failure. Only the scheme and the authority can fail: the parser's
    path, query and fragment states accept every input, so they are not read."""
    # Leading and trailing C0 controls and spaces are removed, then every tab and newline.
    w = to_well_formed(value)
    start = 0
    end = len(w)
    while start < end and ord(w[start]) <= 0x20:
        start += 1
    while end > start and ord(w[end - 1]) <= 0x20:
        end -= 1
    s = _TAB_OR_NEWLINE.sub("", w[start:end])
    m = _SCHEME.match(s)
    if m is None:
        return None
    scheme = m.group(0)[:-1].lower()
    rest = s[m.end() :]
    special = scheme in _SPECIAL
    none = UrlAuthority(scheme=scheme, host=None, credentials=False, port=None)
    if scheme == "file":
        # The file state, then the file slash state: two slashes or backslashes start the file host state.
        if _TWO_SLASHES.match(rest) is None:
            return replace(none, host="")
        buffer = _FILE_HOST.match(rest, 2)
        file_host = "" if buffer is None else buffer.group(0)
        if file_host == "" or _WINDOWS_DRIVE_LETTER.fullmatch(file_host) is not None:
            return replace(none, host="")
        host = parse_host(file_host)
        if host is None:
            return None
        return replace(none, host="" if host == "localhost" else host)
    if special:
        # The special authority slashes and ignore slashes states skip every slash and backslash.
        found = _SPECIAL_AUTHORITY.match(rest)
        authority = "" if found is None else found.group(1)
    elif rest.startswith("//"):
        found = _AUTHORITY.match(rest, 2)
        authority = "" if found is None else found.group(0)
    else:
        return none
    # The authority state: everything before the last "@" is the userinfo, split into username and password at its
    # first ":".
    at = authority.rfind("@")
    userinfo = "" if at < 0 else authority[:at]
    host_port = authority[at + 1 :]
    if at >= 0 and host_port == "":
        return None
    # The host state: a ":" outside brackets ends the host and starts the port.
    inside = False
    colon = -1
    for i, c in enumerate(host_port):
        if c == "[":
            inside = True
        elif c == "]":
            inside = False
        elif c == ":" and not inside:
            colon = i
            break
    host_text = host_port if colon < 0 else host_port[:colon]
    if host_text == "" and (colon >= 0 or special):
        return None
    host = parse_host(host_text, not special)
    if host is None:
        return None
    port: int | None = None
    if colon >= 0:
        digits = host_port[colon + 1 :]
        if _PORT.fullmatch(digits) is None:
            return None
        if digits != "":
            # A port of more than five digits after its leading zeros is past 65,535, and is not converted: the
            # interpreter bounds the digits a decimal conversion reads.
            significant = digits.lstrip("0")
            if len(significant) > 5:
                return None
            port = int(significant or "0")
            if port > 65_535:
                return None
            if port == _SPECIAL.get(scheme):
                port = None
    return UrlAuthority(scheme=scheme, host=host, credentials=userinfo != "" and userinfo != ":", port=port)
