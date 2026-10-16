"""Fixed inputs, stubs and signers shared by the tests."""

import copy
import hashlib
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import Advertised, AtrHash, Json, Refusal, Unsigned
from integraledger_terms._types import Broadcaster

# The shared vectors as @integraledger/lcp ships them, where the TypeScript gate beside this package installs it.
VECTORS = Path(__file__).resolve().parents[2] / "agentic-terms" / "node_modules" / "@integraledger" / "lcp" / "vectors"


def load(name: str) -> dict[str, Any]:
    with (VECTORS / name).open("rb") as handle:
        loaded: dict[str, Any] = json.load(handle)
    return loaded


BUYER = load("buyer.json")
PAIRING = load("x402-exact-eip155-eip3009.json")

A = bytes.fromhex(BUYER["fixed"]["A"])
C = bytes.fromhex(BUYER["fixed"]["C"])
HASH_C: str = BUYER["fixed"]["hashC"]
D: dict[str, Any] = BUYER["fixed"]["D"]
HASH_A: str = D["extensions"]["legalContext"]["info"]["value"]
LINK_A: str = D["extensions"]["legalContext"]["info"]["legalContextUrl"]
KEY: str = BUYER["fixed"]["payerKey"]
ACCOUNT: str = BUYER["fixed"]["account"]
NOW: int = BUYER["fixed"]["now"]
O: dict[str, Any] = D["accepts"][0]


def hexb(value: Any) -> bytes:
    """A byte field of a signing request as the gate hands it to the signer: 0x and lowercase hex."""
    assert isinstance(value, str) and value.startswith("0x") and value == value.lower(), value
    return bytes.fromhex(value[2:])


def row(name: str) -> dict[str, Any]:
    """One of the buyer rows, by name."""
    for candidate in BUYER["rows"]:
        if candidate["name"] == name:
            found: dict[str, Any] = candidate
            return found
    raise KeyError(name)


def document(h: str = HASH_A, link: str = LINK_A, extensions: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """D, with extensions.legalContext naming h and link, and any other extensions added."""
    doc = copy.deepcopy(D)
    info = doc["extensions"]["legalContext"]["info"]
    info["value"] = h
    info["legalContextUrl"] = link
    doc["extensions"] = {**(extensions or {}), **doc["extensions"]}
    return doc


def core_vectors() -> dict[str, Any]:
    return load("core-vectors.json")


def core_vector(name: str) -> dict[str, Any]:
    for vector in core_vectors()["vectors"]:
        if vector["name"] == name:
            found: dict[str, Any] = vector
            return found
    raise KeyError(name)


Handler = Callable[[httpx.Request], httpx.Response | Awaitable[httpx.Response]]


@dataclass
class Link:
    """An httpx client whose transport is a stub, counting the requests it receives."""

    handler: Handler
    calls: int = 0

    def client(self, follow_redirects: bool = False) -> httpx.AsyncClient:
        async def counted(request: httpx.Request) -> httpx.Response:
            self.calls += 1
            answer = self.handler(request)
            if isinstance(answer, httpx.Response):
                return answer
            return await answer

        return httpx.AsyncClient(transport=httpx.MockTransport(counted), follow_redirects=follow_redirects)


AGREEMENT_BASE = "https://api.seller.example/agreement/"


def receipt_for(h: str) -> dict[str, Any]:
    """The agreement resource's receipt for h (its four members)."""
    return {"atrHash": h, "agreed": True, "network": "eip155:84532", "transaction": "0x" + "cd" * 32}


def serving(body: bytes) -> Link:
    """A stub serving the bytes at every link; an agreement URL answers 200 with the receipt for the served bytes'
    hash, as the agreement resource answers once the agreement is recorded."""

    def handle(request: httpx.Request) -> httpx.Response:
        if str(request.url).startswith(AGREEMENT_BASE):
            return httpx.Response(200, json=receipt_for("0x" + hashlib.sha256(body).hexdigest()))
        return httpx.Response(200, content=body)

    return Link(handle)


class Chunks(httpx.AsyncByteStream):
    """A response body streamed in chunks with no content-length, recording how much was read and whether it was
    closed."""

    def __init__(self, total: int, size: int = 65536) -> None:
        self.total = total
        self.size = size
        self.sent = 0
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        while self.sent < self.total:
            chunk = b"x" * min(self.size, self.total - self.sent)
            self.sent += len(chunk)
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


@dataclass
class CountingSigner:
    """A signer that records each request and answers with a fixed signature, or raises."""

    account: str = ACCOUNT
    signature: str = "0x" + "11" * 65
    fail: bool = False
    requests: list[Json] = field(default_factory=list)

    async def sign(self, request: Json) -> str:
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("the wallet refused")
        return self.signature


@dataclass
class EthAccountSigner:
    """A test signer backed by eth-account and the published Anvil key."""

    account: str = ACCOUNT
    calls: int = 0

    async def sign(self, request: Json) -> str:
        self.calls += 1
        return sign_typed(request["typedData"])


def sign_typed(typed_data: Mapping[str, Any]) -> str:
    """The Anvil key's signature over typed data, from eth-account."""
    signed = Account.sign_message(encode_typed_data(full_message=dict(typed_data)), KEY)
    return "0x" + bytes(signed.signature).hex()


def recover(typed_data: Mapping[str, Any], signature: str) -> str:
    recovered: str = Account.recover_message(
        encode_typed_data(full_message=dict(typed_data)), signature=bytes.fromhex(signature[2:])
    )
    return recovered


def digest(typed_data: Mapping[str, Any]) -> str:
    """The EIP-712 digest of typed data, from eth-account."""
    signed = Account.sign_message(encode_typed_data(full_message=dict(typed_data)), KEY)
    return "0x" + bytes(signed.message_hash).hex()


@dataclass(frozen=True, slots=True)
class StubBinding:
    """A binding that delegates to a real one, with read, build or bound replaced."""

    inner: Any
    id: str = "x402/exact/eip155/eip3009"
    public_proof: bool = True
    read_answer: Advertised | Refusal | None = None
    bound_answer: str | None = None
    built: list[str] = field(default_factory=list)

    def read(self, doc: Json) -> Advertised | Refusal:
        if self.read_answer is not None:
            return self.read_answer
        answer: Advertised | Refusal = self.inner.read(doc)
        return answer

    def build(self, choice: Json, h: AtrHash) -> Any:
        self.built.append(h)
        answer: Any = self.inner.build(choice, h)
        return answer

    def bound(self, presented: Json) -> AtrHash | Refusal:
        if self.bound_answer is not None:
            return self.bound_answer
        answer: AtrHash | Refusal = self.inner.bound(presented)
        return answer

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        answer: Broadcaster | Refusal = self.inner.broadcaster(presented)
        return answer


# msgpack formats by their first byte (the msgpack specification): str and bin, a length and then its bytes; values of
# a fixed size after it; ext, a length, a type byte and the bytes; array 16/32 and map 16/32, a count.
_MSGPACK_STR = {0xD9: 1, 0xDA: 2, 0xDB: 4}
_MSGPACK_BIN = {0xC4: 1, 0xC5: 2, 0xC6: 4}
_MSGPACK_UINT = {0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8}
_MSGPACK_INT = {0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8}
_MSGPACK_FIXED = {0xCA: 4, 0xCB: 8, 0xD4: 2, 0xD5: 3, 0xD6: 5, 0xD7: 9, 0xD8: 17}
_MSGPACK_EXT = {0xC7: 1, 0xC8: 2, 0xC9: 4}
_MSGPACK_ARRAY = {0xDC: 2, 0xDD: 4}
_MSGPACK_MAP = {0xDE: 2, 0xDF: 4}
# Each str, bin, array and map format, with the length or count below which a shorter format holds it.
_MSGPACK_LONGER = {0xD9: 32, 0xDA: 256, 0xDB: 65536, 0xC5: 256, 0xC6: 65536, 0xDC: 16, 0xDD: 65536, 0xDE: 16,
                   0xDF: 65536}  # fmt: skip


@dataclass(frozen=True)
class Msgpack:
    """One msgpack value read from the specification's formats: head is its first byte, size a str's or bin's length
    or an array's or map's count, text a str's or bin's bytes, number an integer's value, items an array's elements,
    and pairs a map's keys and values in the order written."""

    head: int
    size: int = 0
    text: bytes | None = None
    number: int | None = None
    items: tuple["Msgpack", ...] = ()
    pairs: tuple[tuple["Msgpack", "Msgpack"], ...] = ()

    @property
    def is_str(self) -> bool:
        return 0xA0 <= self.head <= 0xBF or self.head in _MSGPACK_STR


def msgpack_value(data: bytes) -> Msgpack | None:
    """data read as one msgpack value from the specification's formats, without the package's reader; None unless data
    is exactly one value whose every declared length and count fits in its bytes."""
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if n > len(data) - at:
            raise ValueError("past the end")
        at += n
        return data[at - n : at]

    def number(width: int, signed: bool = False) -> int:
        return int.from_bytes(take(width), "big", signed=signed)

    def value() -> Msgpack:
        b = take(1)[0]
        if b <= 0x7F or b >= 0xE0:
            return Msgpack(b, number=b if b <= 0x7F else b - 0x100)
        if b <= 0x8F or b in _MSGPACK_MAP:
            count = b & 0x0F if b <= 0x8F else number(_MSGPACK_MAP[b])
            if 2 * count > len(data) - at:
                raise ValueError("past the end")
            return Msgpack(b, count, pairs=tuple((value(), value()) for _ in range(count)))
        if b <= 0x9F or b in _MSGPACK_ARRAY:
            count = b & 0x0F if b <= 0x9F else number(_MSGPACK_ARRAY[b])
            if count > len(data) - at:
                raise ValueError("past the end")
            return Msgpack(b, count, items=tuple(value() for _ in range(count)))
        if b <= 0xBF or b in _MSGPACK_STR or b in _MSGPACK_BIN:
            length = b & 0x1F if b <= 0xBF else number({**_MSGPACK_STR, **_MSGPACK_BIN}[b])
            return Msgpack(b, length, text=take(length))
        if b in _MSGPACK_UINT or b in _MSGPACK_INT:
            return Msgpack(b, number=number({**_MSGPACK_UINT, **_MSGPACK_INT}[b], b in _MSGPACK_INT))
        if b in _MSGPACK_FIXED:
            take(_MSGPACK_FIXED[b])
        elif b in _MSGPACK_EXT:
            take(number(_MSGPACK_EXT[b]) + 1)
        elif b not in (0xC0, 0xC2, 0xC3):
            raise ValueError("no such format")
        return Msgpack(b)

    try:
        read = value()
    except (ValueError, RecursionError):
        return None
    return read if at == len(data) else None


def msgpack_strings(value: Msgpack) -> list[tuple[bytes, bytes | None]]:
    """Every str in value, at any depth, each with the key it is the value of: that key's bytes when the key is a str or
    a bin, None for a str that is itself a map key, and b"" for any other place (an array's element, the value itself,
    or the value of a key of another format)."""
    out: list[tuple[bytes, bytes | None]] = []

    def walk(v: Msgpack, under: bytes | None) -> None:
        if v.is_str and v.text is not None:
            out.append((v.text, under))
        for item in v.items:
            walk(item, b"")
        for key, inner in v.pairs:
            walk(key, None)
            walk(inner, key.text if key.text is not None else b"")

    walk(value, b"")
    return out


def _msgpack_int_head(n: int) -> int:
    """The first byte of the shortest format that holds the integer n."""
    if -32 <= n < 0x80:
        return n & 0xFF
    for width, heads in zip((1, 2, 4), ((0xCC, 0xD0), (0xCD, 0xD1), (0xCE, 0xD2))):
        if -(1 << (8 * width - 1)) <= n < 1 << (8 * width):
            return heads[0] if n >= 0 else heads[1]
    return 0xCF if n >= 0 else 0xD3


def msgpack_longer_forms(value: Msgpack) -> list[str]:
    """Each place where value is written otherwise than in its shortest form with distinct str keys: a length, count or
    integer in a longer format than it needs, a map key written twice in one map, and a map key that is not a str."""
    out: list[str] = []

    def walk(v: Msgpack) -> None:
        if v.head in _MSGPACK_LONGER and v.size < _MSGPACK_LONGER[v.head]:
            out.append(f"a length or count of {v.size} in format {v.head:02x}")
        if v.number is not None and v.head != _msgpack_int_head(v.number):
            out.append(f"the integer {v.number} in format {v.head:02x}")
        keys = [(k.head, k.text, k.number) for k, _ in v.pairs]
        if len(set(keys)) < len(keys):
            out.append("a map key written twice")
        out.extend(f"a map key in format {k.head:02x}" for k, _ in v.pairs if not k.is_str)
        for item in (*v.items, *(x for pair in v.pairs for x in pair)):
            walk(item)

    walk(value)
    return out
