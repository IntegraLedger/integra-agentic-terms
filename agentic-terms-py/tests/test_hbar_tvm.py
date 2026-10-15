"""B2, B6, B10, B16, the payment identifier and the inputs rows for x402/exact/tvm (a deployed wallet and an undeployed
one), and the buyer half's vector rows. Expected values are x402-exact-tvm.json's and RFC 3720's."""

import base64
import json
import math
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_TVM as BINDING
from integraledger_terms import Declined, Refusal, _gate
from integraledger_terms.bindings._ton_cell import Builder, Cell, Malformed, crc32c, parse_boc
from integraledger_terms.bindings._ton_tlb import raw_address
from integraledger_terms.bindings.x402_exact_tvm import OP_SEND_MSG, boc_of, lcp_comment, root_of, tvm_carrier

import ed25519
from breadth import Pairing, build_and_sign, link_calls, plant, x402_doc
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
    return parse_boc(base64.b64decode(signed["payload"]["settlementBoc"]))


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


def test_x402_exact_tvm_v3_a_comment_that_begins_with_a_byte_order_mark_holds_no_lcp_string() -> None:
    # The V3 refusals whose comment, which the option's forwardPayload holds too, is the 32-bit zero op and then a
    # byte-order mark (EF BB BF). lcp reads a comment as strict UTF-8 with the mark kept as a character, so it holds no
    # LCP string. Expected values are the rows'.
    def led_by_the_mark(option: Any) -> bool:
        extra = option.get("extra") if isinstance(option, dict) else None
        cell = root_of(extra.get("forwardPayload")) if isinstance(extra, dict) else None
        return isinstance(cell, Cell) and cell.length >= 56 and cell.value >> (cell.length - 56) == 0xEFBBBF

    rows = [r for r in V["V3"]["refusals"] if led_by_the_mark(r.get("accepted"))]
    assert len(rows) >= 1
    for row in rows:
        assert BINDING.bound(presented(row["settlementBoc"], row["accepted"])) == Refusal(row["expect"]), row["case"]


def test_x402_exact_tvm_bound_reads_no_amount_or_timeout_from_the_echoed_option() -> None:
    # As lcp's exactTvm does: bound reads the echoed option's scheme, network, asset, payTo and extra, and neither its
    # amount nor its maxTimeoutSeconds, which read and build require. Expected values are V3's and lcp's codes.
    unsigned = BINDING.build(tvm_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
    assert not isinstance(signed, Refusal)
    placed = F["placed"]
    untimed = {k: v for k, v in placed.items() if k != "maxTimeoutSeconds"}
    unpriced = {k: v for k, v in placed.items() if k != "amount"}
    echoed = [{**placed, "amount": "abc"}, {**placed, "amount": "1e3"}, unpriced, {**placed, "maxTimeoutSeconds": 0}, untimed]
    for accepted in echoed:
        assert BINDING.bound({**signed, "accepted": accepted}) == V["V3"]["expectBound"], accepted
        assert BINDING.read({**TVM.doc, "accepts": [accepted]}) == Refusal("x402/no-payable-option"), accepted
        choice = tvm_choice(accepted, required={"x402Version": 2, "resource": F["resource"], "accepts": [accepted]})
        assert BINDING.build(choice, F["H"]) == Refusal("tvm/option-malformed"), accepted
    unsponsored = {**placed, "extra": {**placed["extra"], "areFeesSponsored": False}}
    assert BINDING.bound({**signed, "accepted": unsponsored}) == Refusal("tvm/option-malformed")


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


def test_x402_exact_tvm_v2b_build_refuses_a_state_init_that_holds_libraries_and_bound_reads_one() -> None:
    # V2b.nonCanonicalLibraries's state init holds a libraries dictionary: from global version 15 TON deploys no wallet
    # from it, so build answers the row's expect, while a settlement message carrying it binds, since whether the
    # wallet deploys is chain state. The settlement is V2b's, rewritten with the row's state init and wallet; written
    # with V2b's own, it is V2b's settlement (expectSettlementRootHash).
    r = W["nonCanonicalLibraries"]
    assert BINDING.build(tvm_choice(wallet=r["wallet"], seqno=W["seqno"], stateInit=r["stateInit"]), F["H"]) == Refusal(r["expect"])
    unsigned = BINDING.build(tvm_choice(wallet=W["wallet"], seqno=W["seqno"], stateInit=W["stateInit"]), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete(bytes.fromhex(W["expectSignature"]))
    assert not isinstance(signed, Refusal)
    request = settlement_root(signed).refs[1]
    v2b, given = root_of(W["stateInit"]), root_of(r["stateInit"])
    assert isinstance(v2b, Cell) and isinstance(given, Cell)
    assert _message(W["wallet"], request, init=_init_by_ref(v2b)).hash.hex() == W["expectSettlementRootHash"]
    assert BINDING.bound(presented(boc_of(_message(r["wallet"], request, init=_init_by_ref(given))))) == F["H"]


def _width(n: int) -> int:
    return math.ceil(math.log2(n + 1))


def _v2b_code_and_data() -> tuple[Cell, Cell]:
    s = parse_boc(base64.b64decode(W["stateInit"])).slice()
    s.bit()
    s.bit()
    code, data = s.maybe_ref(), s.maybe_ref()
    assert code is not None and data is not None
    return code, data


def _state_init(libraries: Cell | None, edit: Callable[[Builder], Builder] = lambda b: b) -> Cell:
    """V2b's code and data with the libraries dictionary given: StateInitWithLibs, fixed_prefix_length and special
    absent."""
    code, data = _v2b_code_and_data()
    return edit(Builder().bit(0).bit(0).maybe_ref(code).maybe_ref(data).maybe_ref(libraries)).end()


def _simple_lib(b: Builder) -> Builder:
    """simple_lib public:Bool root:^Cell, private, whose root is V2b's code."""
    return b.bit(0).ref(_v2b_code_and_data()[0])


def _shared_libraries(forks: int) -> Cell:
    """V2b's code and data with a libraries dictionary of forks that each reference one child twice: 2^forks entries
    in forks + 1 cells, which TON's validation reads 2^(forks + 1) - 1 times."""
    code, _ = _v2b_code_and_data()
    node = Builder().uint(0b10, 2).bit(0).ref(code).end()
    for n in range(1, forks):
        node = Builder().uint(0b10, 2).uint(0, _width(n)).ref(node).ref(node).end()
    return _state_init(Builder().uint(0b11, 2).bit(0).uint(256 - forks, _width(256)).ref(node).ref(node).end())


def _carried(given: Cell) -> bool:
    unsigned = BINDING.build(tvm_choice(stateInit=boc_of(given)), F["H"])
    assert not isinstance(unsigned, Refusal), unsigned
    signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
    assert not isinstance(signed, Refusal)
    return settlement_root(signed).refs[0].equals(given)


# TON reads a message's ^StateInit as StateInitWithLibs (ton-blockchain/ton crypto/block/block.tlb; transaction.cpp,
# unpack_input_msg), and TLB::validate_ref_internal (crypto/tl/tlblib.cpp) takes a cell only when it is ordinary and
# read to its end, for the state init and for each cell of its library:(HashmapE 256 SimpleLib); from global version
# 15 it deploys no account from a state init that holds libraries (transaction.cpp, unpack_msg_state). lcp's build
# answers each case below so: V2b's state init rides as given, and each other one is x402/option-malformed.
def test_x402_exact_tvm_build_takes_only_a_state_init_ton_deploys_a_wallet_from() -> None:
    code, _ = _v2b_code_and_data()
    key = code.hash

    def leaf(n: int, edit: Callable[[Builder], Builder] = lambda b: b) -> Cell:
        return edit(_simple_lib(Builder().uint(0b10, 2).uint(n, 9).buf(key))).end()

    def fork(edit: Callable[[Builder], Builder] = lambda b: b) -> Cell:
        # A zero-length label at the root, then two edges whose 255-bit labels end the key past its first bit.
        half = _simple_lib(Builder().uint(0b10, 2).uint(255, 8).uint(key[0] & 0x7F, 7).buf(key[1:])).end()
        return edit(Builder().uint(0b10, 2).uint(0, 9).ref(half).ref(half)).end()

    library = Cell((2 << 256) | int.from_bytes(b"\x01" * 32, "big"), 8 + 256, (), True)
    v2b = root_of(W["stateInit"])
    assert isinstance(v2b, Cell)
    assert _carried(v2b)
    bad = {
        "a libraries dictionary of one leaf": _state_init(leaf(256)),
        "a libraries dictionary of one fork": _state_init(fork()),
        "a bit after the fields": _state_init(None, lambda b: b.bit(1)),
        "a reference after the fields": _state_init(None, lambda b: b.ref(Builder().end())),
        "fixed_prefix_length cut short": Builder().bit(1).uint(0, 3).end(),
        "a libraries leaf with a bit after its SimpleLib": _state_init(leaf(256, lambda b: b.bit(1))),
        "a libraries leaf with a reference after its SimpleLib": _state_init(leaf(256, lambda b: b.ref(Builder().end()))),
        "a libraries fork with a bit after its two edges": _state_init(fork(lambda b: b.bit(1))),
        "a libraries label longer than its key": _state_init(leaf(257)),
        "a libraries cell that is exotic": _state_init(library),
        "a state init cell that is exotic": library,
    }
    for name, given in bad.items():
        assert BINDING.build(tvm_choice(stateInit=boc_of(given)), F["H"]) == Refusal("x402/option-malformed"), name


# TON validates a message's state init reading at most 1,024 cells, the state init's first and each dictionary cell
# each time a path reaches it (ton-blockchain/ton crypto/tl/tlblib.hpp, default_validate_max_cells; tlblib.cpp,
# validate_ref_internal). A dictionary whose forks each reference one child twice holds 2^f entries in f + 1 cells,
# and TON reads 2^(f+1) - 1 of them: 9 levels are 1,024 reads with the state init's, 10 and 30 are past the bound. A
# dictionary of n entries has 2n - 1 cells on its paths: 512 entries are 1,024 reads, 513 are 1,026. Each holds
# libraries, from which TON deploys no account from global version 15, so lcp's build refuses each, within the bound
# and past it; the read side's bound is the message dictionaries test's.
def test_x402_exact_tvm_build_refuses_a_state_init_that_holds_libraries_within_ton_s_reads_and_past_them() -> None:
    shared = _shared_libraries

    def edge(keys: list[int], n: int) -> Cell:
        """keys (each n bits) as a Hashmap edge, every label written hml_long."""
        if len(keys) == 1:
            return _simple_lib(Builder().uint(0b10, 2).uint(n, _width(n)).uint(keys[0], n)).end()
        length = 0
        while len({k >> (n - 1 - length) for k in keys}) == 1:
            length += 1
        rest = n - length - 1
        sides = [[k & ((1 << rest) - 1) for k in keys if (k >> rest) & 1 == bit] for bit in (0, 1)]
        label = Builder().uint(0b10, 2).uint(length, _width(n)).uint(keys[0] >> (n - length), length)
        return label.ref(edge(sides[0], rest)).ref(edge(sides[1], rest)).end()

    def plain(entries: int) -> Cell:
        return _state_init(edge(list(range(entries)), 256))

    cases = {"9 levels": shared(9), "10 levels": shared(10), "30 levels": shared(30), "512 entries": plain(512), "513 entries": plain(513)}
    for name, given in cases.items():
        assert BINDING.build(tvm_choice(stateInit=boc_of(given)), F["H"]) == Refusal("x402/option-malformed"), name


# addr_std's workchain_id is an int8 (ton-blockchain/ton crypto/block/block.tlb): a raw address outside [-128, 127] is
# no address. The option filter answers tvm/option-malformed, build x402/option-malformed for its own inputs, and
# the piece pays no account there. build writes wallet and jettonWallet only on the workchains the configuration holds,
# -1 and 0, the masterchain and ConfigParam 12's one workchain: an account at -128 or 127 is chosen and its link
# fetched, then its build declines. lcp's filter and build answer the same.
def test_x402_exact_tvm_a_raw_address_whose_workchain_is_outside_int8_is_not_an_address() -> None:
    hex_hash = F["wallet"].split(":")[1]
    for workchain in (128, -129, 9999999999):
        address = f"{workchain}:{hex_hash}"
        placed = F["placed"]
        for option in (
            {**placed, "payTo": address},
            {**placed, "asset": address},
            {**placed, "extra": {**placed["extra"], "responseDestination": address}},
        ):
            required = {"x402Version": 2, "resource": F["resource"], "accepts": [option]}
            built = BINDING.build(tvm_choice(option, required=required), F["H"])
            assert built == Refusal("tvm/option-malformed"), option
        assert BINDING.build(tvm_choice(wallet=address), F["H"]) == Refusal("x402/option-malformed")
        assert BINDING.build(tvm_choice(jettonWallet=address), F["H"]) == Refusal("x402/option-malformed")
    for workchain in (-128, 127):
        address = f"{workchain}:{hex_hash}"
        assert BINDING.build(tvm_choice(wallet=address), F["H"]) == Refusal("x402/option-malformed")
        assert BINDING.build(tvm_choice(jettonWallet=address), F["H"]) == Refusal("x402/option-malformed")
        out, calls = link_calls(TVM, f"{F['O']['network']}:{caip10(address)}")
        assert isinstance(out, Declined) and (out.code, out.detail, calls) == ("offer-unreadable", "x402/option-malformed", 1)
    for workchain in (-1, 0):
        address = f"{workchain}:{hex_hash}"
        assert not isinstance(BINDING.build(tvm_choice(wallet=address), F["H"]), Refusal)
        assert not isinstance(BINDING.build(tvm_choice(jettonWallet=address), F["H"]), Refusal)
        out, calls = link_calls(TVM, f"{F['O']['network']}:{caip10(address)}")
        assert not isinstance(out, Declined) and calls == 1, (address, out)
    b16(TVM, [f"{F['O']['network']}:{caip10(f'{w}:{hex_hash}')}" for w in (128, -129)])


def test_x402_exact_tvm_agreed_refusals_with_a_state_init() -> None:
    # The agreedRefusals rows that give build a stateInit TON does not read as one StateInitWithLibs.
    rows = [r for r in V["agreedRefusals"]["rows"] if "stateInit" in r]
    assert len(rows) >= 1
    for row in rows:
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


def test_x402_exact_tvm_a_bag_not_in_canonical_base64_is_malformed_before_its_size_is_read() -> None:
    # 8,194 bytes, over the 8 KiB bound. The respelled text sets a bit past the last byte in the last character before
    # the padding (RFC 4648 §3.5). lcp's exactTvm.bound answers tvm/boc-too-large for the canonical text and
    # tvm/boc-malformed for the respelled one.
    canonical = base64.b64encode(bytes(8193) + b"\x01").decode()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    respelled = canonical[:-3] + alphabet[alphabet.index(canonical[-3]) | 1] + canonical[-2:]
    assert respelled != canonical and base64.b64decode(respelled) == base64.b64decode(canonical)
    assert root_of(canonical) == Refusal("tvm/boc-too-large")
    assert root_of(respelled) == Refusal("tvm/boc-malformed")
    assert BINDING.bound(presented(canonical)) == Refusal("tvm/boc-too-large")
    assert BINDING.bound(presented(respelled)) == Refusal("tvm/boc-malformed")
    assert root_of("") == Refusal("tvm/boc-malformed")


# An exotic cell is refused only where the read parses it, with the code of the check that reads it; one that no read
# parses, such as a state init's code, is carried as given. Expected values are tvm_exotic.json's, from lcp's
# exactTvm.bound over BoCs @ton/core 0.63.1 built.
def test_x402_exact_tvm_an_exotic_cell_is_refused_by_the_check_that_parses_it() -> None:
    rows = json.loads((Path(__file__).parent / "tvm_exotic.json").read_text())["rows"]
    read = [r for r in rows if "settlementBoc" in r]
    codes = {"tvm/boc-malformed", "tvm/actions", "tvm/not-jetton-transfer", "tvm/payload-not-lcp"}
    assert {r["expect"] for r in read} == codes | {F["H"]}
    for row in read:
        out = BINDING.bound(presented(row["settlementBoc"]))
        assert (out if isinstance(out, str) else out.code) == row["expect"], row["case"]
    carried = [r for r in read if "stateInit" in r and not r["expect"].startswith("tvm/")]
    assert len(carried) >= 2
    for row in carried:
        init = root_of(row["stateInit"])
        assert isinstance(init, Cell) and init.hash.hex() == row["stateInitHash"], row["case"]
        unsigned = BINDING.build(tvm_choice(stateInit=row["stateInit"]), F["H"])
        assert not isinstance(unsigned, Refusal), row["case"]
        signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
        assert not isinstance(signed, Refusal)
        assert signed["payload"]["settlementBoc"] == row["settlementBoc"], row["case"]
    refused = [r for r in rows if "stateInit" in r and r not in carried]
    assert len(refused) >= 1
    for row in refused:
        assert BINDING.build(tvm_choice(stateInit=row["stateInit"]), F["H"]) == Refusal(row["expect"]), row["case"]


# A pruned branch reads its level byte after its type byte (@ton/core 0.63.1 exoticPruned), so a cell marked exotic
# whose first byte is that type and which holds fewer than 16 bits is not read. Each bag is one such cell (d1 8: exotic,
# no references), with no index and a CRC-32C. lcp's exactTvm answers tvm/boc-malformed for the bag as a settlement and
# as a state init, and tvm/carrier-mismatch for an option whose forwardPayload is the bag, in build and in bound.
@pytest.mark.parametrize(
    "bag",
    [
        "b5ee9c724101010100030008020115dae68b",  # 8 bits: the type byte alone
        "b5ee9c724101010100040008030108e45088de",  # 12 bits
        "b5ee9c724101010100040008030101288b3aa6",  # 15 bits
    ],
)
def test_x402_exact_tvm_a_pruned_branch_cell_without_its_level_byte_is_malformed(bag: str) -> None:
    boc = base64.b64encode(bytes.fromhex(bag)).decode()
    with pytest.raises(Malformed):
        parse_boc(bytes.fromhex(bag))
    assert root_of(boc) == Refusal("tvm/boc-malformed")
    assert BINDING.bound(presented(boc)) == Refusal("tvm/boc-malformed")
    assert BINDING.build(tvm_choice(stateInit=boc), F["H"]) == Refusal("tvm/boc-malformed")
    option = {**F["placed"], "extra": {**F["placed"]["extra"], "forwardPayload": boc}}
    choice = tvm_choice(option, required={"x402Version": 2, "resource": F["resource"], "accepts": [option]})
    assert BINDING.build(choice, F["H"]) == Refusal("tvm/carrier-mismatch")
    unsigned = BINDING.build(tvm_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
    assert not isinstance(signed, Refusal)
    assert BINDING.bound({**signed, "accepted": option}) == Refusal("tvm/carrier-mismatch")


# A pruned branch holds a level mask from 1 to 7 and a stored hash and depth for each bit the mask sets, and the
# hashes of the cells over it at each level are TON's (ton-blockchain/ton crypto/vm/cells/DataCell.cpp, CellChecker).
# The settlement carries a pruned branch of level mask 2 under two Merkle proofs; the expected hashes are TON's HASHCU
# (tvm_pruned_branch.json).
def test_x402_exact_tvm_a_pruned_branch_of_level_mask_2_is_hashed_as_ton_hashes_it() -> None:
    f = json.loads((Path(__file__).parent / "tvm_pruned_branch.json").read_text())
    assert BINDING.bound(presented(f["settlementBoc"])) == F["H"]
    request = settlement_root({"payload": {"settlementBoc": f["settlementBoc"]}}).refs[1]
    transfer = request.refs[0].refs[1].refs[0]
    assert "0x" + request.hash.hex() == f["expectRequestBodyHash"]
    assert "0x" + transfer.hash.hex() == f["expectTransferBodyHash"]


def _pruned(mask: int, count: int, depth: int = 1, refs: tuple[Cell, ...] = ()) -> Cell:
    """An exotic cell of type 1 and the mask, then count stored hashes (the k-th 32 bytes of k + 1) and count stored
    depths."""
    data = bytes([1, mask]) + b"".join(bytes([k + 1]) * 32 for k in range(count)) + depth.to_bytes(2, "big") * count
    return Cell(int.from_bytes(data, "big"), 8 * len(data), refs, True)


# TON creates a cell as ton-blockchain/ton crypto/vm/cells/DataCell.cpp's CellChecker does: a pruned branch has no
# reference, a level mask from 1 to 7 and (2 + 34 for each bit the mask sets) bytes; its hash and depth at level i are
# the stored ones of the lowest bit of the mask at or above i, and above every bit its own; a library cell is 264 bits
# with no reference; no cell is deeper than 1,024 at any level (CellTraits.h, max_depth).
def test_x402_exact_tvm_a_cell_is_created_as_ton_creates_it() -> None:
    for mask in range(1, 8):
        count = bin(mask).count("1")
        c = _pruned(mask, count)
        assert c.level_mask == mask and c.depth == 0
        for level in range(4):
            above = [bit for bit in range(level, 3) if mask >> bit & 1]
            k = bin(mask & ((1 << above[0]) - 1)).count("1") if above else count
            assert c.hashes[level] == (bytes([k + 1]) * 32 if above else c.hash), (mask, level)
    library = Cell((2 << 256) | int.from_bytes(b"\x01" * 32, "big"), 8 + 256, (), True)
    assert library.level_mask == 0
    assert _pruned(1, 1, 1024).depths[0] == 1024
    refused: dict[str, Callable[[], Cell]] = {
        "a pruned branch of level mask 0": lambda: _pruned(0, 0),
        "a pruned branch of level mask 8": lambda: _pruned(8, 1),
        "a pruned branch of level mask 2 with a hash for each level up to its own": lambda: _pruned(2, 2),
        "a pruned branch of level mask 5 with one hash": lambda: _pruned(5, 1),
        "a pruned branch of 280 bits: its type, one hash and no depth": lambda: Cell((1 << 272) | 1, 280, (), True),
        "a pruned branch with a reference": lambda: _pruned(1, 1, refs=(Builder().end(),)),
        "a pruned branch storing depth 1,025": lambda: _pruned(1, 1, 1025),
        "a library cell with a reference": lambda: Cell(library.value, 264, (Builder().end(),), True),
        "an exotic cell of type 5": lambda: Cell(5 << 256, 264, (), True),
    }
    for name, make in refused.items():
        try:
            make()
        except Malformed:
            continue
        raise AssertionError(name)


# tvm_boc.json holds bags of cells with TON's own verdict on each, from TON's deserializer run as its transaction
# emulator: parse_boc reads exactly the bags TON reads, and root_of refuses the others as tvm/boc-malformed.
def test_x402_exact_tvm_a_bag_of_cells_is_read_as_ton_deserializes_it() -> None:
    rows = json.loads((Path(__file__).parent / "tvm_boc.json").read_text())["rows"]
    assert {r["ton"] for r in rows} == {True, False}
    for row in rows:
        try:
            root: Cell | None = parse_boc(base64.b64decode(row["boc"]))
        except Malformed:
            root = None
        assert (root is not None) == row["ton"], row["case"]
        within = root is not None and root.depth <= 32
        assert isinstance(root_of(row["boc"]), Cell) if within else root_of(row["boc"]) in (
            Refusal("tvm/boc-malformed") if root is None else Refusal("tvm/boc-too-large"),
        ), row["case"]


Write = Callable[[Builder], Builder]


def _v2_request() -> Cell:
    """V2's signed W5 request, from build and complete with the vector seed."""
    unsigned = BINDING.build(tvm_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
    assert not isinstance(signed, Refusal)
    return settlement_root(signed).refs[0]


def _message(to: str, body: Cell, /, **fields: Write) -> Cell:
    """An int_msg_info message to the raw address to, written field by field: IHR disabled, no source, a value of 0, no extra
    currency, zero fees and times, no init and the body by reference. Each keyword writes the field it names instead:
    flags (ihr_disabled, bounce, bounced), src, dest, value, extra, extra_flags, fwd_fee, times, init, body or tail,
    which writes nothing after the body."""
    address = raw_address(to)
    assert address is not None
    write: dict[str, Write] = {
        "flags": lambda b: b.bit(1).bit(0).bit(0),
        "src": lambda b: b.uint(0, 2),
        "dest": lambda b: b.uint(0b100, 3).sint(address.workchain, 8).buf(address.hash),
        "value": lambda b: b.coins(0),
        "extra": lambda b: b.bit(0),
        "extra_flags": lambda b: b.coins(0),
        "fwd_fee": lambda b: b.coins(0),
        "times": lambda b: b.uint(0, 64 + 32),
        "init": lambda b: b.bit(0),
        "body": lambda b: b.bit(1).ref(body),
        "tail": lambda b: b,
        **fields,
    }
    b = Builder().bit(0)
    for name in ("flags", "src", "dest", "value", "extra", "extra_flags", "fwd_fee", "times", "init", "body", "tail"):
        write[name](b)
    return b.end()


def _outgoing(**fields: Write) -> Cell:
    """V2's outgoing message to fixed.jettonWallet, bounceable, with V2's Jetton transfer body, written by _message."""
    transfer = _v2_request().refs[0].refs[1].refs[0]
    flags: Write = lambda b: b.bit(1).bit(1).bit(0)  # noqa: E731
    return _message(F["jettonWallet"], transfer, **{"flags": flags, **fields})


def _settlement(out: Cell | None = None, mode: int = 3, **fields: Write) -> str:
    """V2's settlement as a bag of cells: the W5 request with V2's fields and signature, whose one action sends out
    (V2's outgoing message when None) with the mode, in a message to fixed.wallet that _message writes with fields."""
    request = _v2_request()
    out = request.refs[0].refs[1] if out is None else out
    actions = Builder().ref(Builder().end()).uint(OP_SEND_MSG, 32).uint(mode, 8).ref(out).end()
    head, signature = request.value >> (request.length - 128), request.value & ((1 << 512) - 1)
    signed = Builder().uint(head, 128).bit(1).ref(actions).bit(0).uint(signature, 512).end()
    return boc_of(_message(F["wallet"], signed, **fields))


def _init_by_ref(init: Cell) -> Write:
    return lambda b: b.bit(1).bit(1).ref(init)


def _init_inline(init: Cell) -> Write:
    return lambda b: b.bit(1).bit(0).slice(init.slice())


def _extra(dictionary: Cell) -> Write:
    return lambda b: b.bit(1).ref(dictionary)


# TON validates the action that sends a message (ton-blockchain/ton crypto/block/transaction.cpp: the action list's
# t_OutListNode.validate_ref, and validate_message_relaxed_libs for its state init) as crypto/tl/tlblib.cpp's
# validate_ref_internal does: each cell ordinary and read to its end, each dictionary label at most as long as its key,
# and at most 1,024 cells read, each dictionary cell each time a path reaches it. A libraries dictionary of 9 shared
# forks is 1,023 reads with its state init, and 10 are 2,047: TON's emulator relays and sends the message with 9 and
# refuses 10, by reference or inline. lcp's exactTvm.bound answers each case below the same: H, tvm/boc-malformed for
# the settlement message and tvm/not-jetton-transfer for the outgoing one.
def test_x402_exact_tvm_a_message_s_dictionaries_are_validated_as_ton_validates_them() -> None:
    def bound(boc: str) -> Any:
        return BINDING.bound(presented(boc))

    for init in (_init_by_ref, _init_inline):
        assert bound(_settlement(init=init(_shared_libraries(9)))) == F["H"]
        assert bound(_settlement(init=init(_shared_libraries(10)))) == Refusal("tvm/boc-malformed")
    assert bound(_settlement(_outgoing(init=_init_by_ref(_shared_libraries(9))))) == F["H"]
    assert bound(_settlement(_outgoing(init=_init_by_ref(_shared_libraries(10))))) == Refusal("tvm/not-jetton-transfer")
    code, _ = _v2b_code_and_data()
    key = code.hash
    leaf = Builder().uint(0b10, 2).uint(256, 9).buf(key).bit(0).ref(code)
    library = Cell((2 << 256) | int.from_bytes(b"\x01" * 32, "big"), 8 + 256, (), True)
    refused = {
        "a libraries label of 257 bits": _state_init(Builder().uint(0b10, 2).uint(257, 9).buf(key).bit(0).bit(0).ref(code).end()),
        "a libraries label of hml_same 300": _state_init(Builder().uint(0b11, 2).bit(0).uint(300, 9).bit(0).ref(code).end()),
        "a libraries leaf with a bit after its SimpleLib": _state_init(Builder().slice(leaf.end().slice()).bit(1).end()),
        "a libraries cell that is exotic": _state_init(library),
    }
    for name, init_cell in refused.items():
        assert bound(_settlement(init=_init_by_ref(init_cell))) == Refusal("tvm/boc-malformed"), name
        assert bound(_settlement(_outgoing(init=_init_by_ref(init_cell)))) == Refusal("tvm/not-jetton-transfer"), name
    currencies = {
        "a label of 40 bits on 32-bit keys": Builder().uint(0b10, 2).uint(40, 6).uint(0, 40).uint(1, 5).uint(1, 8).end(),
        "a leaf with a bit after its amount": Builder().uint(0b10, 2).uint(32, 6).uint(7, 32).uint(1, 5).uint(1, 8).bit(1).end(),
        "an exotic dictionary cell": library,
    }
    for name, dictionary in currencies.items():
        assert bound(_settlement(extra=_extra(dictionary))) == Refusal("tvm/boc-malformed"), name
        assert bound(_settlement(_outgoing(extra=_extra(dictionary)))) == Refusal("tvm/not-jetton-transfer"), name


def _address(raw: str) -> tuple[int, int]:
    """A raw workchain:hex address's workchain, of any width, and its 256 bits."""
    workchain, hex_hash = raw.split(":")
    return int(workchain), int(hex_hash, 16)


def _anycast(b: Builder, anycast: bool) -> Builder:
    """Maybe Anycast: absent, or a rewrite prefix of depth 1."""
    return b.bit(1).uint(1, 5).bit(0) if anycast else b.bit(0)


def _std(raw: str, anycast: bool = False) -> Write:
    workchain, value = _address(raw)
    return lambda b: _anycast(b.uint(0b10, 2), anycast).sint(workchain, 8).uint(value, 256)


def _var(raw: str, length: int = 256, anycast: bool = False) -> Write:
    """addr_var of length bits: the address's bits, cut or followed by zeros."""
    workchain, value = _address(raw)
    bits = value >> (256 - length) if length <= 256 else value << (length - 256)
    return lambda b: _anycast(b.uint(0b11, 2), anycast).uint(length, 9).sint(workchain, 32).uint(bits, length)


def _on(workchain: int, raw: str) -> str:
    return f"{workchain}:{raw.split(':')[1]}"


# A library cell (exotic type 2 and a 256-bit hash), and a HashmapE 32 (VarUInteger 32) of one entry: key 1, value 5.
_LIBRARY = Cell((2 << 256) | int.from_bytes(b"\x01" * 32, "big"), 8 + 256, (), True)
_ONE_CURRENCY = Builder().uint(0b10, 2).uint(32, 6).uint(1, 32).uint(1, 5).uint(5, 8).end()


# A message is read as TON's action phase sends it (ton-blockchain/ton crypto/block/transaction.cpp,
# try_action_send_msg, at mainnet's configuration as @ton/sandbox 0.45.0 ships it): the relayer's sends the settlement
# message, and the W5 wallet's the outgoing one. Each case is V2's settlement with one field of one message written
# bit by bit. A form TON refuses to send is tvm/boc-malformed on the settlement message and tvm/not-jetton-transfer on
# the outgoing one, and a form TON sends binds H. TON's transaction emulator and lcp's exactTvm.bound give each case
# the same answer; the number after a case is the action phase's result code.
def test_x402_exact_tvm_a_message_is_read_as_ton_s_action_phase_sends_it() -> None:
    wallet, jetton, other = F["wallet"], F["jettonWallet"], f"0:{'12' * 32}"
    tail: Write = lambda b: b.bit(1)  # noqa: E731
    library: Write = lambda b: b.bit(1).ref(_LIBRARY)  # noqa: E731
    extra = _extra(_ONE_CURRENCY)
    flags_4: Write = lambda b: b.coins(4)  # noqa: E731
    flags_3: Write = lambda b: b.coins(3)  # noqa: E731
    sends = {
        "the settlement written field by field": _settlement(),
        "the settlement's src, another account's addr_std (TON sends it when that account relays it)": _settlement(src=_std(other)),
        "the settlement's dest, an addr_var of 256 bits on workchain 0": _settlement(dest=_var(wallet)),
        "the settlement's dest on the masterchain": _settlement(dest=_std(_on(-1, wallet))),
        "the settlement's extra_flags of 3": _settlement(extra_flags=flags_3),
        "the outgoing src, the W5 wallet's own addr_std": _settlement(_outgoing(src=_std(wallet))),
        "the outgoing dest, an addr_var of 256 bits on workchain 0": _settlement(_outgoing(dest=_var(jetton))),
    }
    for name, boc in sends.items():
        assert BINDING.bound(presented(boc)) == F["H"], name
    malformed, not_transfer = Refusal("tvm/boc-malformed"), Refusal("tvm/not-jetton-transfer")
    refused = {
        "the settlement's src, an addr_extern (35)": (_settlement(src=lambda b: b.uint(1, 2).uint(8, 9).uint(0xFF, 8)), malformed),
        "the settlement's src, an addr_var (35)": (_settlement(src=_var(other)), malformed),
        "the settlement's src, an addr_std with anycast (35)": (_settlement(src=_std(other, True)), malformed),
        "the settlement's src, an addr_std on workchain 1 (35)": (_settlement(src=_std(_on(1, other))), malformed),
        "the settlement's dest, an addr_var of 256 bits with anycast (36)": (_settlement(dest=_var(wallet, 256, True)), malformed),
        "the settlement's dest, an addr_var of 255 bits (36)": (_settlement(dest=_var(wallet, 255)), malformed),
        "the settlement's dest, an addr_var on workchain 128 (36)": (_settlement(dest=_var(_on(128, wallet))), malformed),
        "the settlement's dest, an addr_std on workchain 1 (36)": (_settlement(dest=_std(_on(1, wallet))), malformed),
        "the settlement's dest, an addr_std with anycast (36)": (_settlement(dest=_std(wallet, True)), malformed),
        "the settlement's extra currencies, one entry (44)": (_settlement(extra=extra), malformed),
        "the settlement's extra_flags of 4 (45)": (_settlement(extra_flags=flags_4), malformed),
        "the settlement's body reference, then one bit": (_settlement(tail=tail), malformed),
        "the settlement's body reference, a library cell (34)": (_settlement(body=library), malformed),
        "the outgoing src, another account's addr_std (35)": (_settlement(_outgoing(src=_std(other))), not_transfer),
        "the outgoing src, the W5 wallet's address as an addr_var (35)": (_settlement(_outgoing(src=_var(wallet))), not_transfer),
        "the outgoing dest, an addr_std with anycast (36)": (_settlement(_outgoing(dest=_std(jetton, True))), not_transfer),
        "the outgoing dest, an addr_std on workchain 1 (36)": (_settlement(_outgoing(dest=_std(_on(1, jetton)))), not_transfer),
        "the outgoing dest, an addr_var of 264 bits (36)": (_settlement(_outgoing(dest=_var(jetton, 264))), not_transfer),
        "the outgoing extra currencies, one entry (44)": (_settlement(_outgoing(extra=extra)), not_transfer),
        "the outgoing extra_flags of 4 (45)": (_settlement(_outgoing(extra_flags=flags_4)), not_transfer),
        "the outgoing body reference, then one bit": (_settlement(_outgoing(tail=tail)), not_transfer),
        "the outgoing body reference, a library cell (34)": (_settlement(_outgoing(body=library)), not_transfer),
    }
    for name, (boc, expect) in refused.items():
        assert BINDING.bound(presented(boc)) == expect, name


def _wide(value: int, length: int) -> Write:
    """A VarUInteger 16 whose value is written in length bytes, the leading ones zero."""
    return lambda b: b.uint(length, 4).uint(value, 8 * length)


# TON's action phase validates a sent message's value, and from global version 12 its extra_flags, each as a
# VarUInteger 16 in its shortest form: a length whose first byte is zero is refused (ton-blockchain/ton
# crypto/block/block-parse.cpp, VarUInteger::validate_skip; crypto/block/transaction.cpp, try_action_send_msg), while
# fwd_fee is not read from global version 8. TON's transaction emulator and lcp's exactTvm.bound give each case the
# same answer; the number after a case is the action phase's result code, and under the W5 action's mode 3 an outgoing
# message TON refuses is skipped.
def test_x402_exact_tvm_a_message_s_value_and_extra_flags_are_read_in_their_shortest_form() -> None:
    attach = int(F["attachNanotons"])
    assert BINDING.bound(presented(_settlement(fwd_fee=_wide(0, 1)))) == F["H"]
    assert BINDING.bound(presented(_settlement(_outgoing(fwd_fee=_wide(0, 1))))) == F["H"]
    assert BINDING.bound(presented(_settlement(_outgoing(value=_wide(attach, 4))))) == F["H"]
    malformed, not_transfer = Refusal("tvm/boc-malformed"), Refusal("tvm/not-jetton-transfer")
    refused = {
        "the settlement's value of 0 in one byte (34)": (_settlement(value=_wide(0, 1)), malformed),
        "the settlement's extra_flags of 0 in one byte (45)": (_settlement(extra_flags=_wide(0, 1)), malformed),
        "the settlement's extra_flags of 3 in two bytes (45)": (_settlement(extra_flags=_wide(3, 2)), malformed),
        "the outgoing value with a leading zero byte (34)": (_settlement(_outgoing(value=_wide(attach, 8))), not_transfer),
        "the outgoing extra_flags of 0 in one byte (45)": (_settlement(_outgoing(extra_flags=_wide(0, 1))), not_transfer),
    }
    for name, (boc, expect) in refused.items():
        assert BINDING.bound(presented(boc)) == expect, name


# The W5 action's send mode is read as TON's action phase takes it (ton-blockchain/ton crypto/block/transaction.cpp,
# try_action_send_msg): TON's transaction emulator sends V2's settlement's Jetton transfer with exactly these 48 of the
# 256 modes, refuses the others without +2 and skips those with it, so nothing is sent. lcp's exactTvm.bound binds H
# for the 48 and answers tvm/not-jetton-transfer for the 208.
_SENDS = {m + 16 * k for m in range(4) for k in range(12)}


def test_x402_exact_tvm_the_w5_action_s_send_mode_is_read_as_ton_takes_it() -> None:
    assert len(_SENDS) == 48 and max(_SENDS) == 179
    sent = refused = 0
    for mode in range(256):
        out = BINDING.bound(presented(_settlement(mode=mode)))
        if mode in _SENDS:
            assert out == F["H"], mode
            sent += 1
        else:
            assert out == Refusal("tvm/not-jetton-transfer"), mode
            refused += 1
    assert (sent, refused) == (48, 208)


def _signed() -> dict[str, Any]:
    """V2's payment, from build and complete with the vector seed."""
    unsigned = BINDING.build(tvm_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
    assert isinstance(signed, dict)
    return signed


def _offered(option: dict[str, Any]) -> dict[str, Any]:
    return tvm_choice(option, required={"x402Version": 2, "resource": F["resource"], "accepts": [option]})


# The pairing serves the two networks x402's TON scheme names, tvm:-239 (mainnet) and tvm:-3 (testnet), and reads
# each message at the configuration held for the network. lcp's exactTvm answers each case the same: any other tvm:
# network is tvm/network-malformed, so read finds no payable option, and a tvm:-3 option builds V2's request and binds
# H, with the carrier tvm:-239 gives.
def test_x402_exact_tvm_the_option_s_network_is_one_of_the_two_the_pairing_serves() -> None:
    signed = _signed()
    boc = signed["payload"]["settlementBoc"]
    for network in ("tvm:-1", "tvm:0", "tvm:698", "tvm:-2390"):
        option = {**F["placed"], "network": network}
        assert BINDING.build(_offered(option), F["H"]) == Refusal("tvm/network-malformed"), network
        assert BINDING.bound({**signed, "accepted": option}) == Refusal("tvm/network-malformed"), network
        assert BINDING.read({**TVM.doc, "accepts": [option]}) == Refusal("x402/no-payable-option"), network
    for given in ("tvm:-1", "tvm:0", "tvm:698", "tvm:-2390", "eip155:1", None):
        assert tvm_carrier(boc, given) == Refusal("tvm/network-malformed"), given
    testnet = {**F["placed"], "network": "tvm:-3"}
    unsigned = BINDING.build(_offered(testnet), F["H"])
    assert not isinstance(unsigned, Refusal) and unsigned.request["hash"].hex() == V["V2"]["expectRequestHash"]
    assert BINDING.bound({**signed, "accepted": testnet}) == F["H"]
    comment = lcp_comment(F["H"])
    assert isinstance(comment, Cell)
    for network in ("tvm:-239", "tvm:-3"):
        carried = tvm_carrier(boc, network)
        assert isinstance(carried, tuple) and carried[0] == F["H"] and carried[1].equals(comment), network


# The agreedRefusals option rows whose network is tvm: and a global id other than the two the pairing serves.
def test_x402_exact_tvm_agreed_refusals_of_networks_the_pairing_does_not_serve() -> None:
    def other(option: Any) -> bool:
        network = option.get("network") if isinstance(option, dict) else None
        return isinstance(network, str) and re.fullmatch(r"tvm:-?[0-9]+", network) is not None and network not in ("tvm:-239", "tvm:-3")

    rows = [r for r in V["agreedRefusals"]["rows"] if other(r.get("option"))]
    assert len(rows) >= 1
    signed = _signed()
    for row in rows:
        assert BINDING.build(_offered(row["option"]), F["H"]) == Refusal(row["expect"]), row["case"]
        assert BINDING.bound({**signed, "accepted": row["option"]}) == Refusal(row["expect"]), row["case"]


def _proofs(c: Cell, levels: int) -> Cell:
    """The cell under levels Merkle proofs (exotic type 3: the child's level-0 hash and depth)."""
    for _ in range(levels):
        c = Cell((3 << 272) | (int.from_bytes(c.hashes[0], "big") << 16) | c.depths[0], 280, (c,), True)
    return c


# TON refuses to send a message whose init and body nest Merkle proofs or updates three deep
# (ton-blockchain/ton crypto/block/transaction.h, max_allowed_merkle_depth; result 40), counted along every path from
# the settlement message, the outgoing message under its body included. TON's emulator and lcp's exactTvm.bound send
# and bind two levels, in the settlement's init and in the outgoing message's, and refuse three in either.
def test_x402_exact_tvm_a_message_nests_at_most_two_merkle_levels() -> None:
    code, data = _v2b_code_and_data()

    def init(levels: int) -> Cell:
        return Builder().bit(0).bit(0).maybe_ref(_proofs(code, levels)).maybe_ref(data).bit(0).end()

    def settlement(c: Cell) -> str:
        return _settlement(init=_init_by_ref(c))

    def outgoing(c: Cell) -> str:
        return _settlement(_outgoing(init=_init_by_ref(c)))

    for placed in (settlement, outgoing):
        assert BINDING.bound(presented(placed(init(2)))) == F["H"]
        assert BINDING.bound(presented(placed(init(3)))) == Refusal("tvm/boc-malformed")


def _with_code(code: Cell, prefix: int | None = None) -> Cell:
    """V2b's data under the given code, with no libraries, and a fixed_prefix_length when prefix is given."""
    _, data = _v2b_code_and_data()
    fixed = Builder().bit(0) if prefix is None else Builder().bit(1).uint(prefix, 5)
    return fixed.bit(0).maybe_ref(code).maybe_ref(data).bit(0).end()


# From global version 10, TON deploys no account whose state init's fixed_prefix_length is above ConfigParam 43's
# max_acc_fixed_prefix_length, 8 in the mainnet configuration @ton/sandbox 0.45.0 ships (ton-blockchain/ton
# crypto/block/transaction.cpp, prepare_compute_phase), and its action phase sends no message nesting three Merkle
# levels. TON's emulator deploys W5 from a fixed prefix of 8 and skips the compute phase at 9. lcp's build answers each
# case so, and its bound binds a settlement carrying the prefix of 9, since whether the wallet deploys is chain state.
def test_x402_exact_tvm_build_takes_a_fixed_prefix_of_at_most_8_and_two_merkle_levels() -> None:
    code, _ = _v2b_code_and_data()
    for prefix in (None, 1, 8):
        assert _carried(_with_code(code, prefix)), prefix
    for prefix in (9, 30, 31):
        built = BINDING.build(tvm_choice(stateInit=boc_of(_with_code(code, prefix))), F["H"])
        assert built == Refusal("x402/option-malformed"), prefix
    assert BINDING.bound(presented(_settlement(init=_init_by_ref(_with_code(code, 9))))) == F["H"]
    assert _carried(_with_code(_proofs(code, 2)))
    assert BINDING.build(tvm_choice(stateInit=boc_of(_with_code(_proofs(code, 3)))), F["H"]) == Refusal("x402/option-malformed")


def _canonical(boc: object) -> bool:
    try:
        return isinstance(boc, str) and base64.b64encode(base64.b64decode(boc, validate=True)).decode() == boc
    except ValueError:
        return False


# The agreedRefusals rows whose settlement bag TON reads and whose settlement message TON's action phase refuses to
# send, or whose bag TON's deserialization refuses: each row's bytes are TON's own emulator's verdict.
def test_x402_exact_tvm_agreed_refusals_of_settlements_ton_refuses() -> None:
    rows = [r for r in V["agreedRefusals"]["rows"] if _canonical(r.get("settlementBoc")) and r["expect"] == "tvm/boc-malformed"]
    assert len(rows) >= 1
    for row in rows:
        assert BINDING.bound(presented(row["settlementBoc"])) == Refusal(row["expect"]), row["case"]


# The agreedRefusals rows whose outgoing message, the W5 request's one action, TON's action phase does not send.
def test_x402_exact_tvm_agreed_refusals_of_outgoing_messages_ton_does_not_send() -> None:
    rows = [r for r in V["agreedRefusals"]["rows"] if "settlementBoc" in r and r["expect"] == "tvm/not-jetton-transfer"]
    assert len(rows) >= 1
    for row in rows:
        assert BINDING.bound(presented(row["settlementBoc"])) == Refusal(row["expect"]), row["case"]
