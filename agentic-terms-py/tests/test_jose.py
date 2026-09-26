"""The SD-JWT reader and base64url over sd-jwt.json. Every expected value is the file's."""

import base64
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
