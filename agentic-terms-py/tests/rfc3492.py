"""RFC 3492's Punycode decoder and encoder as section 6.2 and section 6.3 write them, with the overflow checks of
section 6.4 for integers bounded at 2^31 - 1, and a decoded code point past U+10FFFF a failure, since Unicode has none.
The decoder inserts each code point into its output as it reads it, and the encoder scans the whole input once for each
distinct code point it encodes. The tests compare the package's encoder and decoder with these two."""

from collections.abc import Sequence

BASE = 36
TMIN = 1
TMAX = 26
SKEW = 38
DAMP = 700
INITIAL_BIAS = 72
INITIAL_N = 0x80
MAXINT = 2**31 - 1


def adapt(delta: int, numpoints: int, firsttime: bool) -> int:
    """Section 6.1, bias adaptation."""
    delta = delta // DAMP if firsttime else delta // 2
    delta += delta // numpoints
    k = 0
    while delta > ((BASE - TMIN) * TMAX) // 2:
        delta //= BASE - TMIN
        k += BASE
    return k + ((BASE - TMIN + 1) * delta) // (delta + SKEW)


def threshold(k: int, bias: int) -> int:
    return TMIN if k <= bias else TMAX if k >= bias + TMAX else k - bias


def digit_value(c: int) -> int | None:
    """Section 5: a to z and A to Z are 0 to 25, 0 to 9 are 26 to 35; any other code point has no digit value."""
    if 0x61 <= c <= 0x7A:
        return c - 0x61
    if 0x41 <= c <= 0x5A:
        return c - 0x41
    if 0x30 <= c <= 0x39:
        return c - 0x30 + 26
    return None


def digit_char(d: int) -> str:
    return chr(0x61 + d if d < 26 else 0x30 + d - 26)


def rfc3492_decode(text: str) -> list[int] | None:
    """Section 6.2: the code points the ASCII string text encodes, or None where the procedure fails."""
    n = INITIAL_N
    i = 0
    bias = INITIAL_BIAS
    delimiter = text.rfind("-")
    output: list[int] = []
    pos = 0
    if delimiter > 0:
        while pos < delimiter:
            c = ord(text[pos])
            if c >= 0x80:
                return None
            output.append(c)
            pos += 1
        pos += 1
    while pos < len(text):
        oldi = i
        w = 1
        k = BASE
        while True:
            if pos >= len(text):
                return None
            digit = digit_value(ord(text[pos]))
            pos += 1
            if digit is None:
                return None
            if digit > (MAXINT - i) // w:
                return None
            i += digit * w
            t = threshold(k, bias)
            if digit < t:
                break
            if w > MAXINT // (BASE - t):
                return None
            w *= BASE - t
            k += BASE
        bias = adapt(i - oldi, len(output) + 1, oldi == 0)
        if i // (len(output) + 1) > MAXINT - n:
            return None
        n += i // (len(output) + 1)
        i %= len(output) + 1
        if n > 0x10FFFF:
            return None
        output.insert(i, n)
        i += 1
    return output


def rfc3492_encode(cps: Sequence[int]) -> str | None:
    """Section 6.3: the ASCII string that encodes the code points cps, or None where the procedure fails."""
    n = INITIAL_N
    delta = 0
    bias = INITIAL_BIAS
    output = [chr(c) for c in cps if c < 0x80]
    b = len(output)
    h = b
    if b > 0:
        output.append("-")
    while h < len(cps):
        m = min(c for c in cps if c >= n)
        if m - n > (MAXINT - delta) // (h + 1):
            return None
        delta += (m - n) * (h + 1)
        n = m
        for c in cps:
            if c < n:
                if delta == MAXINT:
                    return None
                delta += 1
            if c == n:
                q = delta
                k = BASE
                while True:
                    t = threshold(k, bias)
                    if q < t:
                        break
                    output.append(digit_char(t + (q - t) % (BASE - t)))
                    q = (q - t) // (BASE - t)
                    k += BASE
                output.append(digit_char(q))
                bias = adapt(delta, h + 1, h == b)
                delta = 0
                h += 1
        delta += 1
        n += 1
    return "".join(output)
