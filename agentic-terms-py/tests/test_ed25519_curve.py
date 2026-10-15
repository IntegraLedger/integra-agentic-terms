"""The Ed25519 curve arithmetic the Solana and Stacks readers share, against RFC 8032: its parameters (5.1, Table 1),
the points of its Ed25519 test vectors (7.1: TEST 1, TEST 2, TEST 3 and TEST SHA(abc)) decoded (5.1.3) and encoded back
(5.1.2), each public key the multiple of B its secret scalar names (5.1.5), each signature meeting the group equation
(5.1.7, step 3), and decoding failing at each step 5.1.3 fails it."""

import hashlib

import pytest

from integraledger_terms.bindings import _ed25519
from integraledger_terms.bindings._ed25519 import Point, add, decode, x_of

# RFC 8032, 5.1, Table 1.
TABLE_1_P = 2**255 - 19
TABLE_1_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555
TABLE_1_L = 2**252 + 27742317777372353535851937790883648493
TABLE_1_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)

# RFC 8032, 7.1: (secret key, public key, message, signature).
VECTORS = {
    "TEST 1": (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    "TEST 2": (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    "TEST 3": (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    "TEST SHA(abc)": (
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
        "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
}


def encode(point: Point) -> bytes:
    """RFC 8032, 5.1.2: y in 32 little-endian bytes, the final byte's top bit the least significant bit of x."""
    x, y = point
    return (y | (x & 1) << 255).to_bytes(32, "little")


def times(k: int, point: Point) -> Point:
    """[k]point, by doubling and adding from the neutral element (0, 1)."""
    out = (0, 1)
    while k:
        if k & 1:
            out = add(out, point)
        point = add(point, point)
        k >>= 1
    return out


def test_the_parameters_are_rfc_8032_table_1s() -> None:
    assert (_ed25519.P, _ed25519.D, _ed25519.L) == (TABLE_1_P, TABLE_1_D, TABLE_1_L)


@pytest.mark.parametrize("name", list(VECTORS))
def test_each_vector_point_decodes_to_the_point_it_encodes(name: str) -> None:
    """The public key and the signature's R decode to points that encode back to the same 32 bytes; B's encoding, y
    = 4/5 with x even, decodes to Table 1's B, whose x is a root x_of answers for its y."""
    _, public, _, signature = VECTORS[name]
    for encoded in (bytes.fromhex(public), bytes.fromhex(signature)[:32]):
        point = decode(encoded)
        assert point is not None and encode(point) == encoded, encoded.hex()
    b_encoded = (4 * pow(5, -1, TABLE_1_P) % TABLE_1_P).to_bytes(32, "little")
    assert decode(b_encoded) == TABLE_1_B
    assert x_of(TABLE_1_B[1]) in (TABLE_1_B[0], TABLE_1_P - TABLE_1_B[0])


@pytest.mark.parametrize("name", list(VECTORS))
def test_each_public_key_is_its_secret_scalars_multiple_of_b(name: str) -> None:
    """RFC 8032, 5.1.5: the secret key's SHA-512, its lower 32 bytes pruned, is the scalar s, and the public key is
    the encoding of [s]B."""
    secret, public, _, _ = VECTORS[name]
    h = hashlib.sha512(bytes.fromhex(secret)).digest()
    s = int.from_bytes(h[:32], "little") & ~7 & ~(1 << 255) | 1 << 254
    assert encode(times(s, TABLE_1_B)).hex() == public


@pytest.mark.parametrize("name", list(VECTORS))
def test_each_signature_meets_the_group_equation(name: str) -> None:
    """RFC 8032, 5.1.7, step 3: [S]B = R + [k]A, R and A decoded from the signature and the public key, and k the
    SHA-512 of R, A and the message, read little-endian."""
    _, public, message, signature = VECTORS[name]
    sig, key = bytes.fromhex(signature), bytes.fromhex(public)
    r, a = decode(sig[:32]), decode(key)
    assert r is not None and a is not None
    k = int.from_bytes(hashlib.sha512(sig[:32] + key + bytes.fromhex(message)).digest(), "little")
    assert times(int.from_bytes(sig[32:], "little"), TABLE_1_B) == add(r, times(k, a))


# RFC 8032, 5.1.3: the step at which decoding each fails.
FAILURES = [
    ((TABLE_1_P + 1).to_bytes(32, "little"), "step 1, y = p + 1 not below p"),
    ((2**255 - 1).to_bytes(32, "little"), "step 1, y = 2^255 - 1 not below p"),
    ((2).to_bytes(32, "little"), "step 3, y = 2 with no square root"),
    ((1 | 1 << 255).to_bytes(32, "little"), "step 4, y = 1 with x = 0 and x_0 = 1"),
    ((TABLE_1_P - 1 | 1 << 255).to_bytes(32, "little"), "step 4, y = p - 1 with x = 0 and x_0 = 1"),
    (bytes(31), "31 bytes, not a 32-octet string"),
]


@pytest.mark.parametrize("encoded", [e for e, _ in FAILURES], ids=[step for _, step in FAILURES])
def test_decoding_fails_where_rfc_8032_fails_it(encoded: bytes) -> None:
    assert decode(encoded) is None
