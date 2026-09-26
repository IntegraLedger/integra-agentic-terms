"""mpp/charge/usdc/stacks: the TypeScript gate's B2 and B6 rows (pairings-b7.test.ts), and the buyer half's M4 rows.
Expected values are the vector file's (M4); the wallet stub answers with M4's signed transaction, as the TypeScript
gate's test does."""

import base64
import json
from pathlib import Path
from typing import Any

from integraledger_terms import MPP_CHARGE_USDC_STACKS, Refusal

from breadth import H, LINK, Pairing, build_and_sign, plant
from mpp_docs import issued, placed_doc
from support import load

V = load("mpp-charge-usdc-stacks.json")
F: dict[str, Any] = V["fixed"]
M4: dict[str, Any] = V["M4"]
WIRE = bytes.fromhex(M4["wireHex"][2:])


def request_json() -> str:
    return json.dumps(F["request"], separators=(",", ":"))


def answer(request: Any) -> Any:
    assert request["kind"] == "stacks-contract-call", request["kind"]
    return M4["wireHex"]


STACKS = Pairing(
    binding=MPP_CHARGE_USDC_STACKS,
    doc=placed_doc(issued("usdc", "charge", request_json(), F["realm"], F["expires"]), H, LINK),
    account=f"{F['network']}:{F['sender']}",
    answer=answer,
)

def test_mpp_charge_usdc_stacks_b6_wallet_is_handed_m4_transfer_and_signed_transaction_is_bound() -> None:
    def inspect(request: Any) -> None:
        assert request == {
            "kind": "stacks-contract-call",
            "contract": F["contract"],
            "functionName": "transfer",
            "args": {"amount": F["amount"], "sender": F["sender"], "recipient": F["recipient"], "memo": H},
            "postCondition": "SentEq",
            "postConditionMode": "deny",
            "anchorMode": "onChainOnly",
        }

    signed, _ = build_and_sign(STACKS, inspect)
    assert signed["source"] == STACKS.account
    assert base64.b64decode(signed["payload"]["transaction"]) == WIRE


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def credential(wire: bytes, form: str | None = "stacks_transaction_v1") -> dict[str, Any]:
    payload: dict[str, Any] = {"type": "transaction", "transaction": base64.b64encode(wire).decode("ascii")}
    if form is not None:
        payload["transactionFormat"] = form
    return {"challenge": STACKS.doc[0], "source": STACKS.account, "payload": payload}


def test_mpp_charge_usdc_stacks_m4_bound_memo_none_and_other_format() -> None:
    assert len(WIRE) == M4["expectLength"]
    assert M4["wireHex"].startswith(M4["expectPrefix"]) and M4["wireHex"].endswith(M4["expectSuffix"][2:])
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE)) == M4["expectBound"]
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE, None)) == M4["expectBound"]
    # The same transfer with the memo argument none: the 38 bytes of (some H) become the one byte of none.
    memo_none = WIRE[: -len(bytes.fromhex(M4["expectSuffix"][2:]))] + b"\x09"
    assert len(memo_none) == M4["memoNoneLength"]
    assert MPP_CHARGE_USDC_STACKS.bound(credential(memo_none)) == Refusal(M4["expectMemoNone"]["code"])
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE, M4["otherFormat"])) == Refusal(M4["expectOtherFormat"]["code"])


def test_mpp_charge_usdc_stacks_malformed_and_type() -> None:
    assert MPP_CHARGE_USDC_STACKS.bound(credential(WIRE[:40])) == Refusal("mpp/stacks-tx-malformed")
    assert MPP_CHARGE_USDC_STACKS.bound(credential(b"")) == Refusal("mpp/stacks-tx-malformed")
    hashed = {**credential(WIRE), "payload": {"type": "hash", "hash": "0x" + "00" * 32}}
    assert MPP_CHARGE_USDC_STACKS.bound(hashed) == Refusal("mpp/credential-type")


def test_mpp_charge_usdc_stacks_truncated_or_extended_transaction_is_malformed() -> None:
    # SIP-005: a transaction is exactly its encoding, so bytes read short, or bytes after the encoding, are not one.
    for wire in (WIRE[:-1], WIRE + b"\x00"):
        assert MPP_CHARGE_USDC_STACKS.bound(credential(wire)) == Refusal("mpp/stacks-tx-malformed")


def test_mpp_charge_usdc_stacks_canonical_rows() -> None:
    rows = json.loads((Path(__file__).parent / "stacks_canonical.json").read_text())["rows"]
    assert len(rows) == 48
    for row in rows:
        out = MPP_CHARGE_USDC_STACKS.bound(credential(bytes.fromhex(row["wire"])))
        assert (out if isinstance(out, str) else out.code) == row["expect"], row["case"]
