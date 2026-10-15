"""The Ed25519 curve, edwards25519 (RFC 8032, 5.1), as the bindings read it: its field prime p, curve constant d and
group order L, the x a y names (RFC 8032, 5.1.3, steps 2 and 3), the point 32 bytes encode (RFC 8032, 5.1.3), and the
sum of two points (RFC 8032, section 3)."""

P = 2**255 - 19
D = -121665 * pow(121666, -1, P) % P
L = 2**252 + 27742317777372353535851937790883648493
# 2^((p-1)/4), a square root of -1 modulo p (RFC 8032, 5.1.3, step 3).
_SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int]


def x_of(y: int) -> int | None:
    """A square root x of (y^2 - 1) / (d y^2 + 1) modulo p, y taken modulo p; None when it has none (RFC 8032, 5.1.3).
    Step 2: with u = y^2 - 1 and v = d y^2 + 1, the candidate x = u v^3 (u v^7)^((p-5)/8). Step 3: x when v x^2 = u,
    x 2^((p-1)/4) when v x^2 = -u, and None otherwise."""
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    vx2 = v * x * x % P
    if vx2 == u:
        return x
    if vx2 == (-u) % P:
        return x * _SQRT_M1 % P
    return None


def decode(data: bytes) -> Point | None:
    """The point (x, y) 32 bytes encode (RFC 8032, 5.1.3). Step 1: y is the little-endian integer with bit 255, x_0,
    cleared, and must be below p. Steps 2 and 3: x is x_of(y), and must exist. Step 4: x = 0 with x_0 = 1 is no point;
    otherwise x is p - x when its parity is not x_0. None for any bytes that fail a step, or that are not 32 bytes."""
    if len(data) != 32:
        return None
    n = int.from_bytes(data, "little")
    y, x_0 = n & (2**255 - 1), n >> 255
    if y >= P:
        return None
    x = x_of(y)
    if x is None or (x == 0 and x_0 == 1):
        return None
    return (x if x & 1 == x_0 else P - x, y)


def add(a: Point, b: Point) -> Point:
    """The sum of two points in affine coordinates, by the twisted Edwards addition law with a = -1 (RFC 8032,
    section 3): x3 = (x1 y2 + x2 y1) / (1 + d x1 x2 y1 y2), y3 = (y1 y2 + x1 x2) / (1 - d x1 x2 y1 y2). The neutral
    element is (0, 1)."""
    (x1, y1), (x2, y2) = a, b
    t = D * x1 * x2 * y1 * y2 % P
    x = (x1 * y2 + y1 * x2) * pow(1 + t, -1, P) % P
    y = (y1 * y2 + x1 * x2) * pow(1 - t, -1, P) % P
    return x, y
