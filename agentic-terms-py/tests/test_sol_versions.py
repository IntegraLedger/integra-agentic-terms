"""The transactionVersions sections of @integraledger/lcp's x402-exact-solana.json, x402-upto-solana.json and
x402-batch-settlement.json: each Solana build under an option whose extra.transactionVersions is each row's value. A
row that admits version 0 is built as the file's version-0 message; any other is refused svm/version-not-built before
anything is signed. Every expected value is the file's."""

import copy
import hashlib
from collections.abc import Callable
from typing import Any

import pytest

from breadth import H, LINK, x402_doc
from integraledger_terms import X402_BATCH_SETTLEMENT_SOLANA, X402_EXACT_SOLANA, X402_UPTO_SOLANA, Refusal
from support import load

E = load("x402-exact-solana.json")
U = load("x402-upto-solana.json")
B = load("x402-batch-settlement.json")
L = "lcp:sha256:" + H


def offered(option: dict[str, Any], versions: Any) -> dict[str, Any]:
    """The option with extra.memo L and extra.transactionVersions set to versions, and a document that offers it
    alone, as build's required and accepted."""
    accepted = {**option, "extra": {**option["extra"], "memo": L, "transactionVersions": copy.deepcopy(versions)}}
    doc = x402_doc(accepted, E["fixed"]["resource"], H, LINK)
    return {"required": doc, "accepted": doc["accepts"][0]}


def shown(out: Any) -> dict[str, Any]:
    """What a build answered, as the rows write it: the refusal, or the first byte and SHA-256 of its Solana message."""
    if isinstance(out, Refusal):
        return {"refused": True, "code": out.code}
    if hasattr(out, "request"):
        message = out.request["message"]
    else:
        message = next(r["message"] for r in out.requests if r["kind"] == "solana-message")
    assert isinstance(message, bytes)
    return {"messageFirstByte": message[0], "buildMessageSha256": hashlib.sha256(message).hexdigest()}


def exact(versions: Any) -> Any:
    f = E["fixed"]
    choice = {
        **offered(f["option"], versions),
        "payer": f["payer"],
        "decimals": f["decimals"],
        "tokenProgram": f["tokenProgram"],
        "recentBlockhash": f["blockhash"],
        "computeUnitLimit": f["computeUnitLimit"],
        "computeUnitPrice": int(f["computeUnitPrice"]),
    }
    return X402_EXACT_SOLANA.build(choice, H)


def upto(versions: Any) -> Any:
    f = U["fixed"]
    choice = {
        **offered(f["option"], versions),
        "payer": f["payer"],
        "nonce": int(f["nonce"]),
        "openSlot": int(f["openSlot"]),
        "now": f["now"],
        "tokenProgram": f["tokenProgram"],
        "recentBlockhash": f["blockhash"],
    }
    return X402_UPTO_SOLANA.build(choice, H)


def batch(versions: Any) -> Any:
    s = B["fixed"]["svm"]
    choice = {
        **offered(s["option"], versions),
        "payer": s["payer"],
        "payerAuthorizer": s["payer"],
        "deposit": int(s["deposit"]),
        "salt": int(s["salt"]),
        "openSlot": int(s["openSlot"]),
        "tokenProgram": s["tokenProgram"],
        "recentBlockhash": s["blockhash"],
    }
    return X402_BATCH_SETTLEMENT_SOLANA.build(choice, H)


def refund(versions: Any, blockhash: bool = True) -> Any:
    s = B["fixed"]["svm"]
    w = {
        **offered(s["option"], versions),
        "channelConfig": copy.deepcopy(B["ES4"]["config"]),
        "maxClaimableAmount": 1000,
        "refund": {},
        **({"recentBlockhash": s["blockhash"]} if blockhash else {}),
    }
    return X402_BATCH_SETTLEMENT_SOLANA.build_within(w, H)  # type: ignore[attr-defined]


CASES: list[tuple[str, list[dict[str, Any]], Callable[[Any], Any]]] = [
    ("x402-exact-solana.json rows", E["transactionVersions"]["rows"], exact),
    ("x402-upto-solana.json rows", U["transactionVersions"]["rows"], upto),
    ("x402-batch-settlement.json rows", B["transactionVersions"]["rows"], batch),
    ("x402-batch-settlement.json refundRows", B["transactionVersions"]["refundRows"], refund),
]


@pytest.mark.parametrize(("name", "rows", "build"), CASES, ids=[c[0] for c in CASES])
def test_each_row_is_built_as_version_0_or_refused(name: str, rows: list[dict[str, Any]], build: Callable[[Any], Any]) -> None:
    assert len(rows) == 10
    for row in rows:
        assert shown(build(row["transactionVersions"])) == row["expect"], row["transactionVersions"]


def test_a_refund_without_recent_blockhash_builds_no_transaction_under_any_field() -> None:
    for row in B["transactionVersions"]["refundRows"]:
        out = refund(row["transactionVersions"], blockhash=False)
        assert not isinstance(out, Refusal), out
        assert [r["kind"] for r in out.requests] == ["ed25519-raw"]
