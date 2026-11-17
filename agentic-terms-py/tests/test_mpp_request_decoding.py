"""An MPP challenge's request is read as the protocol package reads it: base64url without padding (RFC 4648 section 5),
whose final character's unused bits are zero (RFC 4648 section 3.5), at most 8 KiB decoded; UTF-8 whose leading byte
order mark is kept as a character, so no JSON text follows one (RFC 8259 section 8.1); one JSON object nested at most 16
levels deep, with an RFC 8785 form. Each case's expected answer is the protocol package's own pairingsOf on the same
challenge, which the TypeScript twin of this test asks: mpp/request-malformed for each refused form, and the pairing for
each control. The request is the protocol package's EVM charge request (mpp-challenge.json R_E), which it reads as
offering mpp/charge/evm/permit2 and mpp/charge/evm/authorization. finish for mpp/charge/evm/authorization builds the
chosen challenge again, and the protocol package's build refuses a request it does not read, mpp/request-malformed, so
nothing is built: offer-unreadable. The same cases run through the TypeScript gate in mpp-request-decoding.test.ts."""

import base64
import dataclasses
import json
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_EVM_AUTHORIZATION as BINDING
from integraledger_terms import Chosen, Confirmed, Declined, Finished, Refusal, confirm, finish
from integraledger_terms.bindings._codec import b64u_encode, js_json
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.pieces._mpp import request_of

from breadth import ABC, H, LINK, run
from mpp_docs import placed_doc
from support import load, serving, sign_typed

F: dict[str, Any] = load("mpp-challenge.json")["fixed"]
AUTH: dict[str, Any] = load("mpp-charge-evm-authorization.json")["fixed"]
PAIRINGS = ("mpp/charge/evm/permit2", "mpp/charge/evm/authorization")
BOM = b"\xef\xbb\xbf"
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
TEXT: str = F["R_E"]
assert TEXT == js_json(json.loads(TEXT))


def utf8(text: str) -> bytes:
    return text.encode("utf-8")


def with_member(name: str, value_json: str) -> str:
    """The vector's request text with one more member."""
    return TEXT[:-1] + "," + json.dumps(name) + ":" + value_json + "}"


def of_bytes(n: int) -> str:
    """The vector's request text, with a string member that makes it exactly n UTF-8 bytes."""
    short = len(utf8(with_member("pad", '""')))
    return with_member("pad", json.dumps("x" * (n - short)))


def nested(depth: int) -> str:
    """The vector's request text with a member whose innermost object sits depth levels down, the request the first."""
    return with_member("deep", '{"a":' * (depth - 2) + "{}" + "}" * (depth - 2))


# A request text whose UTF-8 length is not a multiple of three, so its base64url ends in unused bits.
ODD = with_member("x", '"y"') if len(utf8(TEXT)) % 3 == 0 else TEXT
PADDED = b64u_encode(utf8(ODD)) + "=" * ((4 - len(b64u_encode(utf8(ODD))) % 4) % 4)


def bent(text: str) -> str:
    """The base64url of text with its final character's lowest unused bit set: the same bytes, written another way."""
    o = b64u_encode(utf8(text))
    return o[:-1] + _ALPHABET[_ALPHABET.index(o[-1]) | 1]


REFUSED = [
    ("a byte order mark before its JSON text", b64u_encode(BOM + utf8(TEXT))),
    ("the padded form", PADDED),
    ("a final character with a non-zero unused bit", bent(ODD)),
    ("8,193 bytes decoded", b64u_encode(utf8(of_bytes(8193)))),
    ("a member nested 17 levels deep", b64u_encode(utf8(nested(17)))),
    ("an escaped lone surrogate, which has no RFC 8785 form", b64u_encode(utf8(with_member("s", '"\\ud800"')))),
]
READ = [
    ("the vector's request", b64u_encode(utf8(TEXT))),
    ("8,192 bytes decoded", b64u_encode(utf8(of_bytes(8192)))),
    ("a member nested 16 levels deep", b64u_encode(utf8(nested(16)))),
]


def issued(request: str) -> dict[str, Any]:
    return {"realm": F["realm"], "method": "evm", "intent": "charge", "request": request, "expires": F["expires"]}


def test_each_refused_form_differs_from_the_canonical_encoding_and_the_padded_and_bent_forms_hold_the_same_bytes() -> None:
    canonical = b64u_encode(utf8(ODD))
    assert PADDED != canonical and bent(ODD) != canonical
    assert base64.urlsafe_b64decode(PADDED) == utf8(ODD)
    assert base64.urlsafe_b64decode(bent(ODD) + "=" * (-len(bent(ODD)) % 4)) == utf8(ODD)
    assert len(utf8(of_bytes(8193))) == 8193


@pytest.mark.parametrize(("name", "encoded"), READ, ids=[n for n, _ in READ])
def test_a_request_is_read_as_the_protocol_package_reads_it(name: str, encoded: str) -> None:
    assert pairings_of(issued(encoded)) == PAIRINGS
    assert request_of(issued(encoded)) == json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


@pytest.mark.parametrize(("name", "encoded"), REFUSED, ids=[n for n, _ in REFUSED])
def test_a_request_the_protocol_package_answers_request_malformed_is_not_read(name: str, encoded: str) -> None:
    assert pairings_of(issued(encoded)) == Refusal("mpp/request-malformed")
    assert request_of(issued(encoded)) is None


INPUTS = {"tokenDomain": AUTH["tokenDomain"]}
ACCOUNT = f"eip155:84532:{AUTH['payer']}"


def confirmed() -> Confirmed:
    canonical = issued(b64u_encode(utf8(TEXT)))
    out = run(lambda c: confirm(placed_doc(canonical, H, LINK), BINDING, ACCOUNT, c, INPUTS), serving(ABC))
    assert isinstance(out, Confirmed), out
    return out


def chosen() -> Chosen:
    return confirmed().chosen


def signature() -> str:
    request = confirmed().request
    assert request is not None and request["kind"] == "eip712", request
    return sign_typed(request["typedData"])


def edited(c: Chosen, request: str) -> Chosen:
    return dataclasses.replace(c, choice={**c.choice, "challenge": {**c.choice["challenge"], "request": request}})


def test_finish_with_the_chosen_payment_as_confirmed_is_signed() -> None:
    assert isinstance(finish(ABC, chosen(), signature(), BINDING), Finished)


@pytest.mark.parametrize(("name", "encoded"), REFUSED, ids=[n for n, _ in REFUSED])
def test_finish_with_a_chosen_request_that_is_not_read_is_offer_unreadable_and_nothing_is_built(name: str, encoded: str) -> None:
    out = finish(ABC, edited(chosen(), encoded), signature(), BINDING)
    assert out == Declined("offer-unreadable", "mpp/request-malformed")
