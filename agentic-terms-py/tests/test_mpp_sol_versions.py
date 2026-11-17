"""The transactionVersions sections of @integraledger/lcp's mpp-charge-solana.json and mpp-charge-usdc-solana.json:
each Solana charge build on a challenge whose Solana details hold transactionVersions as each row's value, or none for
the row without the member. A row whose list holds 1 is built as version 1, the message the stock client writes; one
whose list holds 0 alone, or that has none, as mpp-charge-solana.json's build message; any other is refused
svm/input-malformed before anything is signed. Every expected value is the files'."""

import copy
import hashlib
import json
from collections.abc import Callable
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_SOLANA, MPP_CHARGE_USDC_SOLANA, Refusal
from integraledger_terms.bindings._codec import b64u_decode, canonical_json
from mpp_docs import b64u, place_carrier
from support import load

MS = load("mpp-charge-solana.json")
MU = load("mpp-charge-usdc-solana.json")


def with_versions(details: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """details with transactionVersions set to the row's value, or without it for a row without the member."""
    out = {k: v for k, v in details.items() if k != "transactionVersions"}
    if "transactionVersions" in row:
        out["transactionVersions"] = copy.deepcopy(row["transactionVersions"])
    return out


def placed(base: dict[str, Any], request: dict[str, Any], f: dict[str, Any]) -> dict[str, Any]:
    """The challenge of request, placed under the file's H and link with externalId its LCP string."""
    c = {**base, "request": b64u(json.dumps(request, separators=(",", ":"), sort_keys=True))}
    out = place_carrier([c], f["H"], f["link"], c, lambda v: f["L"] if v is None or v == f["L"] else Refusal("occupied"))
    assert not isinstance(out, Refusal), out
    return out[0]


def with_row(challenge: dict[str, Any], details: Callable[[dict[str, Any]], dict[str, Any]], row: dict[str, Any]) -> dict[str, Any]:
    """The placed challenge with its Solana details' transactionVersions set to the row's value, or left without it:
    a list the filter refuses cannot be placed, so the row's list is written into the placed request."""
    raw = b64u_decode(challenge["request"], 8192)
    assert raw is not None
    request = json.loads(raw)
    if "transactionVersions" in row:
        details(request)["transactionVersions"] = copy.deepcopy(row["transactionVersions"])
    return {**challenge, "request": b64u(canonical_json(request))}


def shown(out: Any) -> dict[str, Any]:
    """What a build answered, as the rows write it: the refusal, or the first byte and SHA-256 of its message."""
    if isinstance(out, Refusal):
        return {"refused": True, "code": out.code}
    message = out.request["message"]
    assert isinstance(message, bytes)
    return {"messageFirstByte": message[0], "buildMessageSha256": hashlib.sha256(message).hexdigest()}


CHOICE = {
    "payer": MS["fixed"]["payer"],
    "computeUnitLimit": MS["build"]["computeUnitLimit"],
    "computeUnitPrice": int(MS["build"]["computeUnitPrice"]),
}


def solana(row: dict[str, Any]) -> Any:
    f = MS["fixed"]
    request = {**f["request"], "methodDetails": with_versions(f["request"]["methodDetails"], {})}
    c = with_row(placed(MS["challenge"], request, f), lambda r: r["methodDetails"], row)
    return MPP_CHARGE_SOLANA.build({**CHOICE, "challenge": c}, f["H"])


def usdc(row: dict[str, Any]) -> Any:
    f = MU["fixed"]
    md = f["request"]["methodDetails"]
    request = {**f["request"], "methodDetails": {**md, "solana": with_versions(md["solana"], {})}}
    base = {"realm": f["realm"], "method": "usdc", "intent": "charge", "request": "", "expires": f["expires"]}
    c = with_row(placed(base, request, f), lambda r: r["methodDetails"]["solana"], row)
    return MPP_CHARGE_USDC_SOLANA.build({**CHOICE, "challenge": c}, f["H"])


CASES: list[tuple[str, list[dict[str, Any]], Callable[[dict[str, Any]], Any]]] = [
    ("mpp-charge-solana.json", MS["transactionVersions"]["rows"], solana),
    ("mpp-charge-usdc-solana.json", MU["transactionVersions"]["rows"], usdc),
]


@pytest.mark.parametrize(("name", "rows", "build"), CASES, ids=[c[0] for c in CASES])
def test_each_row_is_built_as_its_version_or_refused(
    name: str, rows: list[dict[str, Any]], build: Callable[[dict[str, Any]], Any]
) -> None:
    for row in rows:
        assert shown(build(row)) == row["expect"], row.get("transactionVersions", "absent")
