"""B2, B6, B10, B16, the payment identifier and the inputs rows for x402/exact/tvm (a deployed wallet and an undeployed
one), and the buyer half's vector rows. Expected values are x402-exact-tvm.json's and RFC 3720's."""

import base64
import json
import math
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_TVM as BINDING
from integraledger_terms import Declined, Refusal, _gate
from integraledger_terms.bindings._ton_cell import Builder, Cell, Malformed, crc32c, parse_boc
from integraledger_terms.bindings.x402_exact_tvm import boc_of, lcp_comment, root_of

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


def test_x402_exact_tvm_v2b_a_state_init_whose_libraries_label_is_not_its_shortest_form_rides_as_given() -> None:
    # Every expected value is V2b.nonCanonicalLibraries's: build carries the given cell, so the request and signature
    # are V2b's and the settlement message's init is that cell, whose hash is the wallet's address.
    r = W["nonCanonicalLibraries"]
    given = root_of(r["stateInit"])
    assert isinstance(given, Cell) and given.hash.hex() == r["expectStateInitHash"]
    unsigned = BINDING.build(tvm_choice(wallet=r["wallet"], seqno=W["seqno"], stateInit=r["stateInit"]), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert unsigned.request["hash"].hex() == W["expectRequestHash"]
    signature = ed25519.sign(SEED, unsigned.request["hash"])
    assert signature.hex() == W["expectSignature"]
    signed = unsigned.complete(signature)
    assert not isinstance(signed, Refusal)
    root = settlement_root(signed)
    assert root.hash.hex() == r["expectSettlementRootHash"]
    assert root.refs[0].hash.hex() == r["expectStateInitHash"] and f"0:{root.refs[0].hash.hex()}" == r["wallet"]
    assert BINDING.bound(signed) == F["H"]


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


def _carried(given: Cell) -> bool:
    unsigned = BINDING.build(tvm_choice(stateInit=boc_of(given)), F["H"])
    assert not isinstance(unsigned, Refusal), unsigned
    signed = unsigned.complete(ed25519.sign(SEED, unsigned.request["hash"]))
    assert not isinstance(signed, Refusal)
    return settlement_root(signed).refs[0].equals(given)


# TON reads a message's ^StateInit as StateInitWithLibs (ton-blockchain/ton crypto/block/block.tlb; transaction.cpp,
# unpack_input_msg), and TLB::validate_ref_internal (crypto/tl/tlblib.cpp) takes a cell only when it is ordinary and
# read to its end, for the state init and for each cell of its library:(HashmapE 256 SimpleLib). lcp's build answers
# each case below so: the well-formed state inits ride as given, and each change is x402/option-malformed.
def test_x402_exact_tvm_build_takes_only_a_state_init_ton_reads_as_one_state_init_with_libs() -> None:
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
    for given in [v2b, _state_init(leaf(256)), _state_init(fork())]:
        assert _carried(given)
    bad = {
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
# dictionary of n entries has 2n - 1 cells on its paths: 512 entries are 1,024 reads, 513 are 1,026. lcp's build
# answers each so, from TON's own transaction emulator.
def test_x402_exact_tvm_a_state_init_whose_validation_reads_more_than_1024_cells_is_refused() -> None:
    code, _ = _v2b_code_and_data()

    def shared(forks: int) -> Cell:
        node = Builder().uint(0b10, 2).bit(0).ref(code).end()
        for n in range(1, forks):
            node = Builder().uint(0b10, 2).uint(0, _width(n)).ref(node).ref(node).end()
        return _state_init(Builder().uint(0b11, 2).bit(0).uint(256 - forks, _width(256)).ref(node).ref(node).end())

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

    assert _carried(shared(9))
    assert _carried(plain(512))
    for name, given in {"10 levels": shared(10), "30 levels": shared(30), "513 entries": plain(513)}.items():
        assert BINDING.build(tvm_choice(stateInit=boc_of(given)), F["H"]) == Refusal("x402/option-malformed"), name


# addr_std's workchain_id is an int8 (ton-blockchain/ton crypto/block/block.tlb): a raw address outside [-128, 127] is
# no address. The option filter answers tvm/option-malformed, build x402/option-malformed for its own inputs, and
# the piece pays no account there. lcp's filter and build answer the same.
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
    codes = {"tvm/boc-malformed", "tvm/not-w5-signed", "tvm/actions", "tvm/not-jetton-transfer", "tvm/payload-not-lcp"}
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
