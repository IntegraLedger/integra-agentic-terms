"""The secp256k1 curve (SEC 2, 2.4.1) as the bindings read it: its field prime and group order, the point a compressed
key's x and parity name (SEC 1, 2.3.4), and the public key an ECDSA signature recovers to (SEC 1, 4.1.6)."""

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = tuple[int, int] | None


def point_of(x: int, odd: bool) -> Point:
    """The point whose x is x and whose y has the parity odd; None when x is not below the field prime or no point
    has it."""
    if not 0 <= x < P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    return (x, y if y % 2 == odd else P - y)


def _add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        m = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x = (m * m - x1 - x2) % P
    return (x, (m * (x1 - x) - y1) % P)


def _mul(k: int, a: Point) -> Point:
    out: Point = None
    while k:
        if k & 1:
            out = _add(out, a)
        a = _add(a, a)
        k >>= 1
    return out


def recover(digest: bytes, r: int, s: int, odd: bool) -> bytes | None:
    """The 64 bytes x || y of the public key the signature (r, s) over the 32-byte digest recovers to, R's y of parity
    odd: r^-1 (sR - eG), e the digest read as an integer modulo the group order. None when r or s is not from 1 to the
    group order less one, when no point has x r, or when the key is the point at infinity."""
    if not (0 < r < N and 0 < s < N):
        return None
    big_r = point_of(r, odd)
    if big_r is None:
        return None
    inverse = pow(r, -1, N)
    e = int.from_bytes(digest, "big") % N
    q = _add(_mul(-e * inverse % N, _G), _mul(s * inverse % N, big_r))
    if q is None:
        return None
    return q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
