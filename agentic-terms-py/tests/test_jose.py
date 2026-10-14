"""The SD-JWT reader over sd-jwt.json, base64url, and the JSON reads and measures. Each expected value is the
file's, or what JSON.parse and JSON.stringify give for the same input."""

import base64
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
    parse_json,
    read_sd_jwt,
)

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


def test_json_bytes_measures_as_json_stringify_writes() -> None:
    """JSON.stringify writes an infinity as null (ECMA-262 SerializeJSONProperty), so an integer past the double
    range, which JSON.parse reads as Infinity, measures 4; a value nested past 64 levels, the value being level 1,
    measures infinity, as @integraledger/lcp's jsonBytes measures it; a cycle cannot be written."""

    def arrays(count: int) -> list[Any]:
        value: list[Any] = []
        for _ in range(count - 1):
            value = [value]
        return value

    assert json_bytes([10**400, -(10**400), 2**1024 - 2**970, 2**1024 - 2**970 - 1]) == len(
        "[null,null,null,1.7976931348623157e+308]"
    )
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
