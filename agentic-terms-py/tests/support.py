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


# msgpack formats by their first byte (the msgpack specification): values of a fixed size after it; bin and str, a
# length and then its bytes; ext, a length, a type byte and the bytes; array 16/32 and map 16/32, a count of elements or
# of key-value pairs.
_MSGPACK_FIXED = {0xCA: 4, 0xCB: 8, 0xCC: 1, 0xCD: 2, 0xCE: 4, 0xCF: 8, 0xD0: 1, 0xD1: 2, 0xD2: 4, 0xD3: 8,
                  0xD4: 2, 0xD5: 3, 0xD6: 5, 0xD7: 9, 0xD8: 17}  # fmt: skip
_MSGPACK_SIZED = {0xC4: 1, 0xC5: 2, 0xC6: 4, 0xD9: 1, 0xDA: 2, 0xDB: 4, 0xC7: 1, 0xC8: 2, 0xC9: 4}
_MSGPACK_COUNTED = {0xDC: (2, 1), 0xDD: (4, 1), 0xDE: (2, 2), 0xDF: (4, 2)}
_MSGPACK_STR = (0xD9, 0xDA, 0xDB)


def msgpack_strings(data: bytes) -> list[bytes] | None:
    """The bytes of every string in data (fixstr, str 8, str 16 or str 32; a map key or a value, at any depth), read
    from the msgpack specification's formats; None unless data is exactly one msgpack value whose every declared length
    and count fits in its bytes."""
    strings: list[bytes] = []
    at, values = 0, 1
    while values:
        if at >= len(data):
            return None
        b, at, values = data[at], at + 1, values - 1
        if b <= 0x7F or b >= 0xE0 or b in (0xC0, 0xC2, 0xC3):
            continue
        if b <= 0x9F:
            values += (b & 0x0F) * (2 if b <= 0x8F else 1)
            continue
        if b <= 0xBF:
            length = b & 0x1F
        elif b in _MSGPACK_FIXED:
            length = _MSGPACK_FIXED[b]
        elif b in _MSGPACK_SIZED or b in _MSGPACK_COUNTED:
            width, per = _MSGPACK_COUNTED.get(b, (_MSGPACK_SIZED.get(b, 0), 0))
            if at + width > len(data):
                return None
            length, at = int.from_bytes(data[at : at + width], "big"), at + width
            if per:
                values += per * length
                if values > len(data) - at:
                    return None
                continue
            length += 1 if b in (0xC7, 0xC8, 0xC9) else 0
        else:
            return None
        if at + length > len(data):
            return None
        if b <= 0xBF or b in _MSGPACK_STR:
            strings.append(data[at : at + length])
        at += length
    return strings if at == len(data) else None
