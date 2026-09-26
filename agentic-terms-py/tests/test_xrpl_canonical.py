"""The XRPL blob decoder takes only the canonical serialization of what it decodes to. Expected values are
xrpl_canonical.json's, which ripple-binary-codec 2.11.0 gave for each blob, and x402-exact-xrpl.json's."""

import json
from pathlib import Path
from typing import Any

from integraledger_terms import X402_EXACT_XRPL, Refusal
from integraledger_terms.bindings import _xrpl

from support import load

CASES: dict[str, Any] = json.loads((Path(__file__).parent / "xrpl_canonical.json").read_text())
X = load("x402-exact-xrpl.json")


def outcome(blob: str) -> str:
    decoded = _xrpl.decode_blob(blob)
    return "decoded" if isinstance(decoded, _xrpl.Blob) else decoded.code


def test_xrpl_canonical_rows() -> None:
    assert len(CASES["rows"]) == 62
    for row in CASES["rows"]:
        assert outcome(row["blob"]) == row["expect"], row["case"]


def test_xrpl_canonical_rows_through_x402_bound() -> None:
    for row in CASES["rows"]:
        if row["expect"] == "decoded":
            continue
        presented = {
            "x402Version": 2,
            "resource": X["fixed"]["resource"],
            "accepted": X["V2"]["accepted"],
            "payload": {"signedTxBlob": row["blob"]},
        }
        assert X402_EXACT_XRPL.bound(presented) == Refusal(row["expect"]), row["case"]


def test_xrpl_blob_holding_a_number_field_takes_the_codecs_outcome() -> None:
    # A Number-typed field is read as ripple-binary-codec reads it: a blob whose Number is the codec's encoding of its
    # own decoding is decoded, and any other is blob-malformed.
    assert len(CASES["numbers"]) >= 3
    for row in CASES["numbers"]:
        assert outcome(row["blob"]) == row["codec"], row["case"]
