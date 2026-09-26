"""B2, B6, B10, B16, the payment identifier and the inputs rows for x402/exact/tvm (a deployed wallet and an undeployed
one), and the buyer half's vector rows. Expected values are x402-exact-tvm.json's and RFC 3720's."""

import base64
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_TVM as BINDING
from integraledger_terms import Refusal, _gate
from integraledger_terms.bindings._ton_cell import Builder, Cell, crc32c, parse_boc
from integraledger_terms.bindings.x402_exact_tvm import boc_of, lcp_comment, root_of

import ed25519
from breadth import Pairing, build_and_sign, plant, x402_doc
from hbar_support import EVM_ACCOUNT, b10, b16, identifier_row, inputs_row
from support import hexb, load

V = load("x402-exact-tvm.json")
F: dict[str, Any] = V["fixed"]
W: dict[str, Any] = V["V2b"]
SEED = bytes.fromhex(F["seedHex"])


def tvm_answer(request: Any) -> Any:
    if request["kind"] != "ton-w5":
        raise AssertionError(request["kind"])
    return "0x" + ed25519.sign(SEED, hexb(request["hash"])).hex()


def caip10(raw: str) -> str:
    """CAIP-10 writes the raw address's colon as %3A."""
    return raw.replace(":", "%3A")


TVM = Pairing(
    binding=BINDING,
    doc=x402_doc(F["placed"], F["resource"]),
    account=f"{F['O']['network']}:{caip10(F['wallet'])}",
    answer=tvm_answer,
    inputs={"walletId": F["walletId"], "seqno": F["seqno"], "jettonWallet": F["jettonWallet"], "attachNanotons": F["attachNanotons"]},
)
UNDEPLOYED = replace(
    TVM,
    account=f"{F['O']['network']}:{caip10(W['wallet'])}",
    inputs={**(TVM.inputs or {}), "seqno": W["seqno"], "stateInit": W["stateInit"]},
)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: F["now"])


def settlement_root(signed: Any) -> Cell:
    roots = parse_boc(base64.b64decode(signed["payload"]["settlementBoc"]))
    assert len(roots) == 1
    return roots[0]


def test_x402_exact_tvm_the_document_places_v1_as_forward_payload() -> None:
    comment = lcp_comment(F["H"])
    assert isinstance(comment, Cell)
    assert F["placed"]["extra"]["forwardPayload"] == boc_of(comment) == V["V1"]["expectBoc"]

def test_x402_exact_tvm_b6_request_is_the_vectors_and_signature_completes() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "ton-w5"
        assert hexb(request["hash"]).hex() == V["V2"]["expectRequestHash"]
        sig = ed25519.sign(SEED, hexb(request["hash"])).hex()
        assert sig.startswith(V["V2"]["expectSignature"]["prefix"]) and sig.endswith(V["V2"]["expectSignature"]["suffix"])

    signed, _ = build_and_sign(TVM, inspect)
    assert settlement_root(signed).hash.hex() == V["V2"]["expectSettlementRootHash"]


def test_x402_exact_tvm_b6_payment_identifier() -> None:
    identifier_row(TVM)


def test_x402_exact_tvm_b10_http_link() -> None:
    b10(TVM)


def test_x402_exact_tvm_b16_other_accounts() -> None:
    b16(TVM, [EVM_ACCOUNT, f"tvm:-3:{caip10(F['wallet'])}"])


def test_x402_exact_tvm_undeployed_b2_plant() -> None:
    plant(UNDEPLOYED)


def test_x402_exact_tvm_undeployed_b6_request_signature_and_state_init() -> None:
    def inspect(request: Any) -> None:
        assert hexb(request["hash"]).hex() == W["expectRequestHash"]
        assert ed25519.sign(SEED, hexb(request["hash"])).hex() == W["expectSignature"]

    signed, _ = build_and_sign(UNDEPLOYED, inspect)
    assert settlement_root(signed).hash.hex() == W["expectSettlementRootHash"]
    # The message carries the state init: its code cell's 32 bits, 0xdeadbeef, are in the bag of cells.
    assert bytes.fromhex("deadbeef") in base64.b64decode(signed["payload"]["settlementBoc"])


def test_x402_exact_tvm_undeployed_b6_payment_identifier() -> None:
    identifier_row(UNDEPLOYED)


def test_x402_exact_tvm_undeployed_b10_http_link() -> None:
    b10(UNDEPLOYED)


def test_x402_exact_tvm_undeployed_b16_other_accounts() -> None:
    b16(UNDEPLOYED, [EVM_ACCOUNT, f"tvm:-3:{caip10(W['wallet'])}"])


def test_x402_exact_tvm_inputs() -> None:
    inputs_row(TVM, {"walletId": 2147483409, "seqno": 5, "jettonWallet": F["jettonWallet"]}, "x402/input-missing")


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def tvm_choice(option: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    offered = option if option is not None else F["placed"]
    value: dict[str, Any] = {
        "required": {"x402Version": 2, "resource": F["resource"], "accepts": [offered]},
        "accepted": offered,
        "wallet": F["wallet"],
        "walletId": F["walletId"],
        "seqno": F["seqno"],
        "jettonWallet": F["jettonWallet"],
        "attachNanotons": int(F["attachNanotons"]),
        "now": F["now"],
    }
    value.update(changes)
    return value


def presented(boc: Any, accepted: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "x402Version": 2,
        "resource": F["resource"],
        "accepted": accepted if accepted is not None else F["placed"],
        "payload": {"settlementBoc": boc, "asset": F["O"]["asset"]},
    }


def test_crc32c_rfc3720_b4() -> None:
    assert crc32c(bytes(32)) == bytes.fromhex("aa36918a")
    assert crc32c(b"\xff" * 32) == bytes.fromhex("43aba862")
    assert crc32c(bytes(range(32))) == bytes.fromhex("4e79dd46")


def test_x402_exact_tvm_v1_comment() -> None:
    comment = lcp_comment(F["H"])
    assert isinstance(comment, Cell)
    assert comment.length == V["V1"]["expectCommentBits"]
    assert comment.hash.hex() == V["V1"]["expectCommentHash"]
    root = root_of(V["V1"]["expectBoc"])
    assert isinstance(root, Cell) and root.equals(comment)


def test_x402_exact_tvm_v2_cells_and_v3_bound() -> None:
    unsigned = BINDING.build(tvm_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert unsigned.request["hash"].hex() == V["V2"]["expectRequestHash"]
    signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
    assert not isinstance(signed, Refusal)
    root = settlement_root(signed)
    assert root.hash.hex() == V["V2"]["expectSettlementRootHash"]
    request = root.refs[0]
    actions = request.refs[0]
    out = actions.refs[1]
    body = out.refs[0]
    assert actions.hash.hex().startswith(V["V2"]["expectActionsHash"]["prefix"])
    assert actions.hash.hex().endswith(V["V2"]["expectActionsHash"]["suffix"])
    assert out.hash.hex().startswith(V["V2"]["expectOutMessageHash"]["prefix"])
    assert out.hash.hex().endswith(V["V2"]["expectOutMessageHash"]["suffix"])
    assert body.length == V["V2"]["expectTransferBodyBits"]
    assert body.hash.hex() == V["V2"]["expectTransferBodyHash"]
    assert signed["payload"]["asset"] == F["O"]["asset"]
    assert BINDING.bound(signed) == V["V3"]["expectBound"]
    for row in V["V3"]["refusals"]:
        assert BINDING.bound(presented(row["settlementBoc"], row["accepted"])) == Refusal(row["expect"]), row["case"]


def test_x402_exact_tvm_v2b_undeployed_wallet() -> None:
    choice = tvm_choice(wallet=W["wallet"], seqno=W["seqno"], stateInit=W["stateInit"])
    unsigned = BINDING.build(choice, F["H"])
    assert not isinstance(unsigned, Refusal)
    assert unsigned.request["hash"].hex() == W["expectRequestHash"]
    signed = unsigned.complete(bytes.fromhex(W["expectSignature"]))
    assert not isinstance(signed, Refusal)
    root = settlement_root(signed)
    assert root.hash.hex() == W["expectSettlementRootHash"]
    assert root.refs[0].hash.hex() == W["expectStateInitHash"]
    assert root.refs[1].refs[0].refs[1].refs[0].hash.hex() == W["expectTransferBodyHash"]
    assert BINDING.bound(signed) == F["H"]
    for row in W["refusals"]:
        assert BINDING.build(tvm_choice(stateInit=row["stateInit"]), F["H"]) == Refusal(row["expect"]), row["case"]


def test_x402_exact_tvm_agreed_refusals() -> None:
    seen = 0
    for row in V["agreedRefusals"]["rows"]:
        expect = Refusal(row["expect"])
        if "option" in row:
            assert BINDING.build(tvm_choice(row["option"]), F["H"]) == expect, row["case"]
        elif "attachNanotons" in row:
            assert BINDING.build(tvm_choice(attachNanotons=int(row["attachNanotons"])), F["H"]) == expect
        elif "wallet" in row:
            assert BINDING.build(tvm_choice(wallet=row["wallet"]), F["H"]) == expect
            assert BINDING.build(tvm_choice(jettonWallet=row["wallet"]), F["H"]) == expect
            assert BINDING.build(tvm_choice(walletId=-1), F["H"]) == expect
            assert BINDING.build(tvm_choice(seqno=2**32), F["H"]) == expect
            assert BINDING.build(tvm_choice(now=-1), F["H"]) == expect
        elif "signatureBytes" in row:
            unsigned = BINDING.build(tvm_choice(), F["H"])
            assert not isinstance(unsigned, Refusal)
            assert unsigned.complete(bytes(row["signatureBytes"])) == expect
        elif "settlementBoc" in row:
            assert BINDING.bound(presented(row["settlementBoc"])) == expect, row["case"]
        else:
            continue
        seen += 1
    assert seen >= 12


# The TON BoC bounds: at most 512 distinct cells and a depth of at most 32, so a settlement carrying an undeployed W5
# wallet's state init is read (x402's TON scheme supports payers in the uninit and nonexist states).
def _tree_of(n: int, counter: list[int]) -> Cell:
    """n distinct cells as a tree of at most four references per cell; each cell's 16 data bits are its own number."""
    b = Builder().uint(counter[0], 16)
    counter[0] += 1
    rest = n - 1
    for k in range(min(4, rest), 0, -1):
        share = -(-rest // k)
        b.ref(_tree_of(share, counter))
        rest -= share
    return b.end()


def _chain_of(d: int) -> Cell:
    """A chain of cells whose root has depth d."""
    c = Builder().uint(0, 8).end()
    for i in range(1, d + 1):
        c = Builder().uint(i, 8).ref(c).end()
    return c


def _count(root: Cell) -> int:
    seen: set[bytes] = set()
    stack = [root]
    while stack:
        c = stack.pop()
        if c.hash not in seen:
            seen.add(c.hash)
            stack.extend(c.refs)
    return len(seen)


def test_x402_exact_tvm_513_cells_is_too_large_and_512_is_within_the_bound() -> None:
    at, over = _tree_of(512, [0]), _tree_of(513, [0])
    assert (_count(at), _count(over)) == (512, 513)
    assert root_of(boc_of(over)) == Refusal("tvm/boc-too-large")
    assert isinstance(root_of(boc_of(at)), Cell)


def test_x402_exact_tvm_depth_33_is_too_large_and_depth_32_is_within_the_bound() -> None:
    assert (_chain_of(32).depth, _chain_of(33).depth) == (32, 33)
    assert root_of(boc_of(_chain_of(33))) == Refusal("tvm/boc-too-large")
    assert isinstance(root_of(boc_of(_chain_of(32))), Cell)


def test_x402_exact_tvm_an_exotic_cell_in_the_settlement_is_boc_malformed() -> None:
    rows = json.loads((Path(__file__).parent / "tvm_exotic.json").read_text())["rows"]
    assert [r["expect"] for r in rows[1:]] == ["tvm/boc-malformed"] * 3
    for row in rows:
        out = BINDING.bound(presented(row["settlementBoc"]))
        assert (out if isinstance(out, str) else out.code) == row["expect"], row["case"]
