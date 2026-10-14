"""The SD-JWT reader over sd-jwt.json, base64url, and the JSON reads and measures. Each expected value is the
file's, or, as each test names, what JSON.parse and JSON.stringify or @integraledger/lcp's reader give for the same
input."""

import base64
import json
import math
from typing import Any

from support import load

from integraledger_terms import Refusal
from integraledger_terms.bindings._jose import (
    SdJwt,
    SdJwtCodes,
    b64u_decode,
    b64u_encode,
    disclosure_digest,
    js_length,
    json_bytes,
    member_names,
    parse_json,
    read_sd_jwt,
)
from integraledger_terms.bindings.ap2_checkout_mandate import read_mandate

V = load("sd-jwt.json")
CODES = SdJwtCodes(malformed="malformed", sd_alg_unsupported="sd-alg-unsupported", unreferenced="unreferenced", too_large="too-large")


def read(presentation: str) -> SdJwt:
    r = read_sd_jwt(presentation, CODES)
    assert isinstance(r, SdJwt), r
    return r


def vcts(dp: Any) -> list[Any] | None:
    return [x.get("vct") for x in dp] if isinstance(dp, list) else None


def test_sd_jwt_c4_published_disclosure_digests() -> None:
    for row in V["C4"]:
        assert disclosure_digest(row["disclosure"]) == row["expectDigest"]


def test_sd_jwt_c6_resolves_both_delegate_payload_entries() -> None:
    r = read(V["C6"]["presentation"])
    dp = r.resolved["delegate_payload"]
    assert vcts(dp) == V["C6"]["expectDelegatePayloadVcts"]
    assert dp[0] == V["C6"]["expectCheckoutMandate"]
    assert "_sd" not in r.resolved
    assert r.key_binding is None


def test_sd_jwt_c6_plant_unreferenced_disclosure_is_refused() -> None:
    r = read_sd_jwt(V["C6plant"]["presentation"], CODES)
    assert r == Refusal(V["C6plant"]["expect"])
    assert V["C6plant"]["E"][2:] not in repr(r)


def test_sd_jwt_c7_undisclosed_mandate_l3b_and_l1() -> None:
    for row in V["C7"]:
        r = read(row["presentation"])
        assert vcts(r.resolved.get("delegate_payload")) == row["expectDelegatePayloadVcts"]
        if "expectCheckoutMandate" in row:
            assert r.resolved["delegate_payload"][0] == row["expectCheckoutMandate"]


def test_sd_jwt_c8_a_digest_that_names_no_disclosure_is_listed_once() -> None:
    rows = V["C8"]["rows"]
    assert rows
    for row in rows:
        r = read_sd_jwt(row["presentation"], CODES)
        if "expect" in row:
            assert r == Refusal(row["expect"]), row["case"]
        else:
            assert isinstance(r, SdJwt) and r.resolved == row["expectResolved"], row["case"]


def test_sd_jwt_a_resolved_payload_nested_past_64_levels_is_too_large() -> None:
    """The payload nests 42 levels and its disclosure 1 + n, each within 64; the disclosed value takes the place of
    the reference at level 42, so the resolved payload nests 41 + n levels. @integraledger/lcp's SD-JWT reader
    resolves 64 levels and refuses 65 as too large, as its AP2 mandate reader does with ap2/too-large."""

    def b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def compact(value: Any) -> bytes:
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    def presentation(n: int) -> str:
        value: list[Any] = []
        for _ in range(n - 1):
            value = [value]
        d = b64u(compact(["c2FsdA", value]))
        inner: list[Any] = [{"...": disclosure_digest(d)}]
        for _ in range(39):
            inner = [inner]
        payload = {"x": inner, "_sd_alg": "sha-256"}
        return f"{b64u(compact({'alg': 'ES256'}))}.{b64u(compact(payload))}.{'A' * 86}~{d}~"

    assert isinstance(read_sd_jwt(presentation(23), CODES), SdJwt)
    assert read_sd_jwt(presentation(24), CODES) == Refusal("too-large")
    assert read_sd_jwt(presentation(60), CODES) == Refusal("too-large")
    assert read_mandate(presentation(24)) == Refusal("ap2/too-large")


def test_base64url_round_trip_over_every_byte_value() -> None:
    every = bytes(range(256))
    text = b64u_encode(every)
    assert text == base64.urlsafe_b64encode(every).rstrip(b"=").decode("ascii")
    assert b64u_decode(text) == every
    assert b64u_decode("A") is None
    assert b64u_decode("AA==") is None
    assert b64u_decode("A+") is None


def test_json_forms() -> None:
    assert list(parse_json('{"b":1,"2":2,"a":3,"1":4}')) == ["1", "2", "b", "a"]
    assert parse_json('{"a":1,"a":2}') == {"a": 2}
    assert not isinstance(parse_json("NaN"), float)
    assert js_length("a\U0001f600") == 3
    assert json_bytes({"a": "é\U0001f600\ud800"}) == len('{"a":"') + 2 + 4 + 6 + 2
    assert json_bytes([1.5, 1e21, None, True]) == len("[1.5,1e+21,null,true]")


def test_an_integer_literal_reads_as_json_parse_reads_it() -> None:
    """JSON.parse on Node 26.10.0 reads an integer literal of 4,301 or 400 digits as Infinity, and one of 309 digits,
    inside the double range, as a number."""
    for digits in (4301, 400):
        text = '{"n":1' + "0" * (digits - 1) + "}"
        assert parse_json(text) == {"n": math.inf}, digits
        assert member_names(text) == ["n"], digits
    assert parse_json('{"n":-1' + "0" * 399 + "}") == {"n": -math.inf}
    assert parse_json('{"n":1' + "0" * 308 + "}") == {"n": 10**308}


def test_json_bytes_measures_as_json_stringify_writes() -> None:
    """JSON.stringify writes a number that is not finite as null (ECMA-262 SerializeJSONProperty), so an integer past
    the double range, or a float such as 1e400, which JSON.parse reads as Infinity, measures 4; a value nested past 64
    levels, the value being level 1, measures infinity, as @integraledger/lcp's jsonBytes measures it; a cycle cannot be
    written."""

    def arrays(count: int) -> list[Any]:
        value: list[Any] = []
        for _ in range(count - 1):
            value = [value]
        return value

    # JSON.stringify(JSON.parse(text)) on Node 26.10.0: "1" followed by 400 zeros is written null, as are 1e400 and
    # -1e400, and 2**1024 - 2**970, the first integer that rounds past the largest double.
    assert json_bytes([10**400, -(10**400), 2**1024 - 2**970, 2**1024 - 2**970 - 1]) == len(
        "[null,null,null,1.7976931348623157e+308]"
    )
    assert json_bytes(parse_json("[1e400,-1e400]")) == len("[null,null]")
    # JSON.stringify(JSON.parse(text)) on Node 26.10.0: an integer past 2**53 is written as the double it reads as.
    assert json_bytes([10**308, 2**53 + 1, 123456789012345678901234567890, 10**21 - 1, 2**63]) == len(
        "[1e+308,9007199254740992,1.2345678901234568e+29,1e+21,9223372036854776000]"
    )
    assert json_bytes(arrays(64)) == 128
    assert json_bytes({"a": arrays(63)}) == len('{"a":}') + 126
    assert json_bytes(arrays(65)) == math.inf
    assert json_bytes({"a": arrays(64)}) == math.inf
    assert json_bytes(arrays(100_000)) == math.inf
    cycle: list[Any] = []
    cycle.append(cycle)
    assert json_bytes(cycle) is None
    shared: list[Any] = []
    assert json_bytes([shared, shared]) == len("[[],[]]")
    assert json_bytes({1: "a"}) is None
