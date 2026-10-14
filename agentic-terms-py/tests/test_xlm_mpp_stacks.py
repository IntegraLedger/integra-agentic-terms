"""mpp/charge/usdc/stacks: the TypeScript gate's B2 and B6 rows (pairings-b7.test.ts), and the buyer half's M4 rows.
Expected values are the vector file's (M4); the wallet stub answers with M4's signed transaction, as the TypeScript
gate's test does."""

import base64
import json
from pathlib import Path
from typing import Any

from integraledger_terms import MPP_CHARGE_USDC_STACKS, AtrHash, Refusal

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


# ── Clarity values and a Stacks node's depth bound ───────────────────────────────────────────────────────────────
# A Stacks node reads a transaction's Clarity values to 16 levels, the outermost counting 1 (stacks-core's
# UNSANITIZED_DEPTH_CHECK). The transactions below are M4's with one value replaced, left with M4's signature, which
# bound does not verify. Each expected answer is @integraledger/lcp's chargeUsdcStacks.bound over the same bytes with
# @stacks/transactions 7.6.0.

PREFIX, FT_CONDITION, CALL = WIRE[:111], WIRE[115:186], WIRE[186:]
ARGUMENTS_AT = 41  # the call's type, contract address, contract name, function name and argument count
UINT = b"\x01" + (0xA1A2A3A4A5A6A7A8).to_bytes(16, "big")
CONTAINERS = {
    "some": b"\x0a",
    "ok": b"\x07",
    "err": b"\x08",
    "list": b"\x0b\x00\x00\x00\x01",
    "tuple": b"\x0c\x00\x00\x00\x01\x01a",
}
MALFORMED = Refusal("mpp/stacks-tx-malformed")


def levels(n: int, container: bytes, inner: bytes = UINT) -> bytes:
    """inner as the one value of n - 1 nested containers, so that it sits at level n."""
    return container * (n - 1) + inner


def transaction(conditions: list[bytes], payload: bytes) -> bytes:
    return PREFIX + len(conditions).to_bytes(4, "big") + b"".join(conditions) + payload


def first_argument(value: bytes) -> bytes:
    """M4's transfer with value as its first argument in place of the uint amount."""
    assert CALL[ARGUMENTS_AT : ARGUMENTS_AT + 17] == b"\x01" + int(F["amount"]).to_bytes(16, "big")
    return transaction([FT_CONDITION], CALL[:ARGUMENTS_AT] + value + CALL[ARGUMENTS_AT + 17 :])


def nft_asset_value(value: bytes) -> bytes:
    """M4's transfer under one non-fungible post-condition (the sender does not send the token's nft) on value."""
    condition = b"\x02\x02" + FT_CONDITION[2:44] + b"\x05usdcx\x03nft" + value + b"\x11"
    return transaction([condition], CALL)


def bind(wire: bytes) -> AtrHash | Refusal:
    return MPP_CHARGE_USDC_STACKS.bound(credential(wire))


def test_mpp_charge_usdc_stacks_clarity_value_past_16_levels_is_malformed() -> None:
    assert bind(first_argument(UINT)) == bind(nft_asset_value(UINT)) == M4["expectBound"]
    for name, container in CONTAINERS.items():
        for build in (first_argument, nft_asset_value):
            assert (name, bind(build(levels(16, container)))) == (name, M4["expectBound"])
            assert (name, bind(build(levels(17, container)))) == (name, MALFORMED)
    mixed = b"".join(CONTAINERS.values()) * 3
    assert bind(first_argument(mixed + UINT)) == M4["expectBound"]
    assert bind(first_argument(mixed + CONTAINERS["some"] + UINT)) == MALFORMED
    assert bind(first_argument(levels(1000, CONTAINERS["some"]))) == MALFORMED


def test_mpp_charge_usdc_stacks_depth_reads_every_element_and_member() -> None:
    lists, empty = CONTAINERS["list"], b"\x0b\x00\x00\x00\x00"
    assert bind(first_argument(levels(16, lists, empty))) == M4["expectBound"]
    assert bind(first_argument(levels(17, lists, empty))) == MALFORMED
    three = b"\x0b\x00\x00\x00\x03" + UINT * 3
    assert bind(first_argument(levels(15, lists, three))) == M4["expectBound"]
    assert bind(first_argument(levels(16, lists, three))) == MALFORMED

    def pair(a: bytes) -> bytes:
        """A tuple of two members: a, then a uint."""
        return b"\x0c\x00\x00\x00\x02\x01a" + a + b"\x01b" + UINT

    assert bind(first_argument(pair(levels(15, CONTAINERS["some"])))) == M4["expectBound"]
    assert bind(first_argument(pair(levels(16, CONTAINERS["some"])))) == MALFORMED


def test_mpp_charge_usdc_stacks_canonical_rows() -> None:
    rows = json.loads((Path(__file__).parent / "stacks_canonical.json").read_text())["rows"]
    assert len(rows) == 48
    for row in rows:
        out = MPP_CHARGE_USDC_STACKS.bound(credential(bytes.fromhex(row["wire"])))
        assert (out if isinstance(out, str) else out.code) == row["expect"], row["case"]


def test_mpp_charge_usdc_stacks_multisig_key_fields() -> None:
    # SIP-005: a multisig key field holds a compressed secp256k1 point, marked compressed (0x00) or uncompressed (0x01).
    # A key off the curve, a 65-byte body, or an uncompressed key under P2WSH is not a transaction that decodes and
    # re-serializes to the same bytes.
    rows = json.loads((Path(__file__).parent / "stacks_key_fields.json").read_text())["rows"]
    assert len(rows) == 11
    for row in rows:
        out = MPP_CHARGE_USDC_STACKS.bound(credential(bytes.fromhex(row["wire"])))
        assert (out if isinstance(out, str) else out.code) == row["expect"], row["case"]


def test_mpp_charge_usdc_stacks_agreed_refusals() -> None:
    # Each agreedRefusals row is M4's signed transaction with its payload replaced, presented as the credential's
    # transaction; bound refuses it with the row's code, the outcome @stacks/transactions 7.6.0 gives. The rows are
    # selected by their input, and the file holds at least one.
    rows = [r for r in V.get("agreedRefusals", {}).get("rows", []) if isinstance(r.get("wireHex"), str)]
    assert rows, "mpp-charge-usdc-stacks.json holds no agreedRefusals row with a wireHex"
    for row in rows:
        out = MPP_CHARGE_USDC_STACKS.bound(credential(bytes.fromhex(row["wireHex"][2:])))
        assert (row["case"], out) == (row["case"], Refusal(row["expect"]))
