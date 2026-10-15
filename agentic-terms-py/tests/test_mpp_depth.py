"""MPP's 16-level bound, as @integraledger/lcp's MPP reads hold it: a decoded request object and an echoed challenge's
credential each nest at most 16 arrays and objects, the outermost counting 1, so a 17th level is refused whatever the
innermost holds, an empty array included (lcp's mpp-challenge agreedRefusals case of a credential deeper than 16
levels)."""

import json
from typing import Any

import pytest
from breadth import H, LINK
from mpp_docs import MC, issued, placed_doc

from integraledger_terms import Refusal
from integraledger_terms.bindings._codec import b64u_encode
from integraledger_terms.bindings._mpp import challenge_bound
from integraledger_terms.bindings._mpp_checks import MAX_JSON_DEPTH, decode_object


def nest(levels: int, inner: Any) -> Any:
    """An array nesting `levels` levels, its innermost empty when inner is None, else holding inner."""
    value: Any = [] if inner is None else [inner]
    for _ in range(levels - 1):
        value = [value]
    return value


def test_the_bound_is_sixteen_levels() -> None:
    assert MAX_JSON_DEPTH == 16


@pytest.mark.parametrize(("levels", "inner"), [(16, 0), (16, None), (17, 0), (17, None), (18, None)])
def test_a_request_object_nests_at_most_16_levels(levels: int, inner: Any) -> None:
    value = {"a": nest(levels - 1, inner)}
    decoded = decode_object(b64u_encode(json.dumps(value).encode("utf-8")))
    assert (decoded == value) is (levels <= 16)
    assert (decoded is None) is (levels > 16)


@pytest.mark.parametrize(
    ("levels", "inner", "within"),
    [(16, 0, True), (16, None, True), (17, None, False), (17, 0, False), (18, None, False)],
)
def test_a_credential_nests_as_the_challenge_bound_reads_it(levels: int, inner: Any, within: bool) -> None:
    # The credential is level 1, its payload 2, and the array from 3.
    challenge = placed_doc(issued("tempo", "charge", MC["fixed"]["R_T"]), H, LINK)[0]
    payload = {"type": "hash", "hash": "0x" + "ab" * 32, "deep": nest(levels - 2, inner)}
    out = challenge_bound({"challenge": challenge, "payload": payload})
    if within:
        assert not isinstance(out, Refusal), out
    else:
        assert out == Refusal("mpp/credential-malformed")
