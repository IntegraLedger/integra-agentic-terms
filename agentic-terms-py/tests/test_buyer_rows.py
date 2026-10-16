"""Every vector file's buyer group, run through the gate. B2, the plant: transact with a counting signer over the row's
document, account, inputs and clock, the link serving the planted ATR, declines hash-mismatch and never calls the
signer; confirm declines the same. B6: check over the file's signed payment gives H for the ATR and declines
signed-not-bound for the planted ATR. Every expected value, and every input, is the row's.

buyer.json's rows that call one gate function (B19 to B22) and its within rows (BW1 to BW4), each found by its name: the
documents, holds and signers are those the rows name, and a row's cases share its input and expect except where a case
gives its own. A BW row's hold is what open_channel gives for the row's ATR and the opening it names."""

import base64
import copy
import json
from typing import Any

import httpx
import pytest
from breadth import Recording, run
from support import BUYER, VECTORS, Link

import integraledger_terms as terms
from integraledger_terms import Checked, Declined, _gate, check, confirm, finish, open_channel, transact, within

BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.isupper() and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}
ROWS: list[tuple[str, dict[str, Any]]] = [
    (path.name, row)
    for path in sorted(VECTORS.glob("*.json"))
    for row in (json.loads(path.read_bytes()).get("buyer") or {}).get("rows", [])
]


def serving(body: bytes) -> Link:
    return Link(lambda request: httpx.Response(200, content=body))


def test_the_files_hold_a_b2_for_every_pairing_the_gate_serves() -> None:
    b2 = sorted({row["pairing"] for _, row in ROWS if row["name"] == "B2"})
    assert b2 == sorted(BINDINGS)


B2 = [(f, r) for f, r in ROWS if r["name"] == "B2"]
B6 = [(f, r) for f, r in ROWS if r["name"] == "B6"]


@pytest.mark.parametrize(("file", "row"), B2, ids=[f"{f} {r['pairing']}" for f, r in B2])
def test_b2_the_plant(file: str, row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    given = row["input"]
    if "now" in given:
        monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    binding = BINDINGS[row["pairing"]]
    inputs = given.get("inputs", {})
    served = bytes.fromhex(given["servesHex"])

    def never(request: Any) -> Any:
        raise AssertionError("the signer is never called on a plant")

    signer = Recording(given["account"], never)
    out = run(lambda c: transact(copy.deepcopy(given["doc"]), binding, signer, c, inputs=inputs), serving(served))
    assert isinstance(out, Declined) and out.code == row["expect"]["decline"], out
    assert len(signer.requests) == row["expect"]["signCalls"]
    link = serving(served)
    confirmed = run(lambda c: confirm(copy.deepcopy(given["doc"]), binding, given["account"], c, inputs), link)
    assert isinstance(confirmed, Declined) and confirmed.code == row["expect"]["decline"], confirmed
    assert link.calls == 1


@pytest.mark.parametrize(("file", "row"), B6, ids=[f"{f} {r['pairing']}" for f, r in B6])
def test_b6_check(file: str, row: dict[str, Any]) -> None:
    """check of each B6 row's presented payment; an input that holds fetched, the read of a push payment, is checked
    with it as the landed receipt beside the payment, as the row's file says the seller holds it."""
    binding = BINDINGS[row["pairing"]]
    got: list[dict[str, str]] = []
    for c in row["input"]["check"]:
        out = check(bytes.fromhex(c["bytesHex"]), copy.deepcopy(row["input"]["presented"]), binding, row["input"].get("fetched"))
        got.append({"h": out.h} if isinstance(out, Checked) else {"decline": out.code})
    assert got == row["expect"]


def named(name: str) -> dict[str, Any]:
    found: list[dict[str, Any]] = [r for r in BUYER["rows"] if r["name"] == name]
    assert len(found) == 1, f"buyer.json holds one row {name}"
    return found[0]


def buyer_row(file: str, pairing: str, name: str) -> dict[str, Any]:
    """A file's buyer row of pairing, by its name."""
    found = [r for f, r in ROWS if f == file and r["pairing"] == pairing and r["name"] == name]
    assert len(found) == 1, f"{file} holds one buyer row {name} for {pairing}"
    return found[0]


def stand_in(request: Any) -> Any:
    """A stand-in of a signature's form: 65 bytes of hex for EIP-712, 64 zero bytes in base58 for any other request,
    and one for each request of a batch."""
    if request["kind"] == "batch":
        return [stand_in(r) for r in request["requests"]]
    return "0x" + "11" * 65 if request["kind"] == "eip712" else "1" * 64


def runs_of(r: dict[str, Any]) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Each run a row asks for: every case, or the row itself, with the case's members over the row's."""
    shared = {k: v for k, v in r["input"].items() if k != "cases"}
    out: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for c in r["input"].get("cases", [{"case": r["name"]}]):
        given = {k: v for k, v in c.items() if k not in ("case", "expect")}
        out.append((c["case"], {**shared, **given}, {**r["expect"], **c.get("expect", {})}))
    return out


def compare(where: str, e: dict[str, Any], out: Any, fetches: int, sign_calls: int) -> None:
    """The decline's code and detail, the fetches and the signer calls a row expects, against what the call did."""
    assert (out.code if isinstance(out, Declined) else None) == e.get("decline"), (where, out)
    if "detail" in e:
        assert out.detail == e["detail"], (where, out)
    if "fetches" in e:
        assert fetches == e["fetches"], where
    if "signCalls" in e:
        assert sign_calls == e["signCalls"], where


D: dict[str, Any] = BUYER["fixed"]["D"]
A = bytes.fromhex(BUYER["fixed"]["A"])
ACCOUNT: str = BUYER["fixed"]["account"]
EIP3009 = BINDINGS["x402/exact/eip155/eip3009"]


def test_b19_finish_compares_the_pairing_before_it_rebuilds_anything() -> None:
    r = named("B19")
    assert (r["input"]["entry"], r["input"]["binding"]) == ("finish", "x402/exact/eip155/permit2")
    confirmed = run(lambda c: confirm(copy.deepcopy(D), EIP3009, ACCOUNT, c), serving(A))
    assert not isinstance(confirmed, Declined), confirmed
    signer = Recording(ACCOUNT, stand_in)
    out = finish(A, confirmed.chosen, named("B6")["expect"]["signature"], BINDINGS[r["input"]["binding"]])
    compare("B19", r["expect"], out, 0, len(signer.requests))


def test_b20_confirm_declines_inputs_that_are_not_an_object_before_the_link_is_fetched() -> None:
    r = named("B20")
    assert r["input"]["entry"] == "confirm"
    runs = runs_of(r)
    assert runs
    for case, given, e in runs:
        link = serving(A)
        inputs = given["inputs"]
        out = run(lambda c: confirm(copy.deepcopy(D), EIP3009, ACCOUNT, c, inputs), link)
        compare(f"B20, {case}", e, out, link.calls, 0)


# B21's and B22's documents are D as each row describes it: its one option on eip155:0, and its link 2049 UTF-16 code
# units long, 2048 code points, ending in U+10000.
LINK_22 = "https://atr.seller.example/" + "a" * 2020 + "\U00010000"


def test_b22s_link_is_2049_utf16_code_units_and_2048_code_points() -> None:
    assert (len(LINK_22.encode("utf-16-le")) // 2, len(LINK_22)) == (2049, 2048)


def doc_of(name: str) -> dict[str, Any]:
    doc = copy.deepcopy(D)
    if name == "B21":
        doc["accepts"][0]["network"] = "eip155:0"
    else:
        doc["extensions"]["legalContext"]["info"]["legalContextUrl"] = LINK_22
    return doc


@pytest.mark.parametrize("name", ["B21", "B22"])
def test_transact_declines_the_offer_before_any_fetch_or_signer_call(name: str) -> None:
    r = named(name)
    link = serving(A)
    signer = Recording(ACCOUNT, stand_in)
    out = run(lambda c: transact(doc_of(name), EIP3009, signer, c), link)
    compare(name, r["expect"], out, link.calls, len(signer.requests))


def hold_of(r: dict[str, Any]) -> dict[str, Any]:
    """The hold a BW row names, with its network and channel as the row states them."""
    spec = r["input"]["hold"]
    if isinstance(spec, str):
        spec = named(spec.removeprefix("as "))["input"]["hold"]
    file, _, _, name = spec["opening"].split(" ")[:4]
    opening = buyer_row(file, r["input"]["pairing"], name.rstrip(","))["input"]["presented"]
    hold = open_channel(bytes.fromhex(spec["atrHex"]), copy.deepcopy(opening), BINDINGS[r["input"]["pairing"]])
    assert not isinstance(hold, Declined), hold
    assert (hold["network"], hold["channel"]) == (spec["network"], spec["channel"])
    return hold


def within_doc(r: dict[str, Any], given: dict[str, Any]) -> Any:
    """The document a BW row's run names: its own challenges, whose opaque is its opaqueText, or the x402 document of
    the buyer row it names."""
    if isinstance(given["doc"], list):
        opaque = given["doc"][0]["opaque"]
        assert base64.urlsafe_b64decode(opaque + "=" * (-len(opaque) % 4)).decode("utf-8") == given["opaqueText"]
        return copy.deepcopy(given["doc"])
    file, _, _, name = given["doc"].split(" ")[:4]
    return copy.deepcopy(buyer_row(file, r["input"]["pairing"], name)["input"]["doc"])


def play(r: dict[str, Any], where: str, given: dict[str, Any], e: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    hold = hold_of(r)
    if "now" in given:
        monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    signer = Recording(ACCOUNT, stand_in)
    binding = BINDINGS[r["input"]["pairing"]]
    doc = within_doc(r, given)
    out = run(lambda c: within(doc, hold, binding, signer, given.get("refund"), given.get("inputs")), serving(b""))
    compare(where, e, out, 0, len(signer.requests))
    if "signedPayload" in e:
        assert {k: out.signed["payload"][k] for k in e["signedPayload"]} == e["signedPayload"], where


@pytest.mark.parametrize("name", ["BW1", "BW2", "BW3", "BW4"])
def test_within_declines_before_the_build_and_the_signer_call(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    r = named(name)
    runs = runs_of(r)
    assert runs
    for case, given, e in runs:
        play(r, f"{name}, {case}", given, e, monkeypatch)


@pytest.mark.parametrize("name", ["BW1", "BW3"])
def test_the_control_within_signs_once(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    r = named(name)
    control = r["control"]
    given = {**{k: v for k, v in r["input"].items() if k != "cases"}, **control["input"]}
    play(r, f"{name} control", given, control["expect"], monkeypatch)
