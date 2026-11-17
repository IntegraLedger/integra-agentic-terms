"""x402/exact/lnbtc/payment-hash's buyer half and piece, and the summary of the bolt11-pay request the Lightning pairings
hand the buyer's node, over the protocol package's x402-exact-lnbtc.json, mpp-charge-lightning.json and
mpp-session-lightning.json. Every input and expected value is those files': x402's scheme text (the option, its invoice,
the buyer's request, the request binding test vectors, the preimage, the payment, the validation time and the client's
refusals) and invoices bolt11 1.4.1 wrote and signed and light-bolt11-decoder 3.2.0 read back, with the fields they were
written with and the key that signed them. The request is given as the piece's request input: the file's request, its
body as 0x hex."""

import copy
from typing import Any

import pytest
from breadth import ABC, H, Pairing, build_and_sign, x402_doc
from support import load

import integraledger_terms as terms
from integraledger_terms import Confirmed, Declined, Finished, Payee, Refusal, Summary, Validity, _gate
from integraledger_terms._summary import summary_of
from integraledger_terms.bindings.lightning import request_hash
from support import finish, piece_confirm

V = load("x402-exact-lnbtc.json")
L2 = load("mpp-charge-lightning.json")["L2"]
S1 = load("mpp-session-lightning.json")["S1"]
F = V["fixed"]
BINDING = terms.X402_EXACT_LNBTC_PAYMENT_HASH
MAINNET = "lnbtc:000000000019d6689c085ae165831e93"
ACCOUNT = f"{MAINNET}:{F['payee']}"


def as_input(request: dict[str, Any]) -> dict[str, Any]:
    """The file's request as the piece's request input: its bodyHex as body, 0x hex."""
    rest = {k: v for k, v in request.items() if k != "bodyHex"}
    return {"request": rest if "bodyHex" not in request else {**rest, "body": "0x" + request["bodyHex"]}}


def with_set(value: Any, path: str, to: Any) -> Any:
    """value with the member at the dotted path set to to."""
    head, _, rest = path.partition(".")
    return {**value, head: with_set(value[head], rest, to) if rest else to}


# ── The binding: lcp's rows for the request binding, the build, the payment presented and the options read offers.


@pytest.mark.parametrize("row", V["requestHashes"]["rows"], ids=[r["case"] for r in V["requestHashes"]["rows"]])
def test_request_hash_row(row: dict[str, Any]) -> None:
    """x402's Request Binding Test Vectors: each request's hash under its profile and parameters."""
    request = dict(row["request"])
    if "bodyHex" in request:
        request["body"] = bytes.fromhex(request.pop("bodyHex"))
    assert request_hash(row["profile"], row["params"], request, request.get("url")) == row["expect"]


@pytest.mark.parametrize("row", V["build"]["rows"], ids=[r["case"] for r in V["build"]["rows"]])
def test_build_row_through_the_piece(row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    """The client's checks before the node pays: the choice of fixed.required's option for the account, with the
    file's request, at the file's clock, each with the one change its row names; the invoice to pay, or the refusal."""
    given: dict[str, Any] = {"now": F["now"], "request": F["request"], "required": F["required"]}
    for path, to in row["set"].items():
        given = with_set(given, path, to)
    monkeypatch.setattr(_gate, "_now", lambda: given["now"])
    out = piece_confirm(copy.deepcopy(given["required"]), BINDING, ACCOUNT, as_input(given["request"]))
    if row["expect"] == "served":
        assert isinstance(out, Confirmed), out
        assert out.request == {"kind": "bolt11-pay", "invoice": F["x402Invoice"]}
    else:
        assert isinstance(out, Declined) and out.detail == row["expect"], out


def test_the_preimage_completes_fixed_p_and_each_complete_row_is_refused_as_moved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: F["now"])
    out = piece_confirm(copy.deepcopy(F["required"]), BINDING, ACCOUNT, as_input(F["request"]))
    assert isinstance(out, Confirmed), out
    assert finish(ABC, out.chosen, F["preimage"], BINDING) == Finished(signed=F["P"], h=F["H"])
    for row in V["build"]["complete"]:
        refused = finish(ABC, out.chosen, row["preimage"], BINDING)
        assert isinstance(refused, Declined), row["case"]
        assert (refused.code, refused.detail, refused.moved is not None) == ("signed-not-bound", row["expect"], True)


def test_bound_rows() -> None:
    """bound of fixed.P is H; each refused row is fixed.P with the one change its case names."""
    assert BINDING.bound(copy.deepcopy(F["P"])) == F["H"]
    for row in V["bound"]["rows"]:
        presented = copy.deepcopy(F["P"])
        for path, to in row["set"].items():
            presented = with_set(presented, path, to)
        out = BINDING.bound(presented)
        assert isinstance(out, Refusal) and out.code == row["expect"], row["case"]


@pytest.mark.parametrize("row", V["options"]["rows"], ids=[r["case"] for r in V["options"]["rows"]])
def test_read_offers_options_row(row: dict[str, Any]) -> None:
    read = BINDING.read(x402_doc(row["option"], F["resource"]))
    assert not isinstance(read, Refusal) and read.offer["options"] == [row["option"]], read


# ── B6 by the pairing's own steps over abc, then through the gate over A.


def test_b6_the_node_is_handed_the_schemes_invoice_and_its_preimage_completes_fixed_p(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: F["now"])
    p = Pairing(
        binding=BINDING,
        doc=copy.deepcopy(F["required"]),
        account=ACCOUNT,
        answer=lambda request: F["preimage"],
        inputs=as_input(F["request"]),
        placed=lambda h: x402_doc(F["O"], F["resource"], h),
    )
    signed, request = build_and_sign(p, lambda r: None)
    assert request == {"kind": "bolt11-pay", "invoice": F["x402Invoice"]}
    assert signed == F["P"]


# ── bolt11-pay's summary.


def summary(amount: str, payee: str, timestamp: int, expiry: int, deposit: str | None = None) -> Summary:
    return Summary(
        amount=amount,
        payees=(Payee(account=payee, amount=amount),),
        asset="BTC",
        network=MAINNET,
        validity=Validity(not_before=str(timestamp), not_after=str(timestamp + expiry), unit="seconds"),
        deposit=deposit,
        atr=ABC,
    )


def show(pairing: str, invoice: str) -> Summary | None:
    return summary_of(pairing, {"kind": "bolt11-pay", "invoice": invoice}, ABC, MAINNET)


INVOICES = [(name, row) for name, row in V["invoices"].items() if name != "noS"]


@pytest.mark.parametrize(("name", "row"), INVOICES, ids=[name for name, _ in INVOICES])
def test_summary_of_an_invoice_bolt11_wrote(name: str, row: dict[str, Any]) -> None:
    """The amount, the signer, the creation time and the expiry bolt11 1.4.1 wrote the invoice with."""
    e = row["encode"]
    expiry = next(t["data"] for t in e["tags"] if t["tagName"] == "expire_time")
    assert e["bech32"] == "bc"
    assert show("x402/exact/lnbtc/payment-hash", row["invoice"]) == summary(e["millisatoshis"], row["signer"], e["timestamp"], expiry)


def test_an_invoice_the_decoder_refuses_has_no_summary() -> None:
    """invoices.noS, which lacks its s field: the option filter refuses it ln/invoice-malformed (boundAccepted)."""
    assert show("x402/exact/lnbtc/payment-hash", V["invoices"]["noS"]["invoice"]) is None


@pytest.mark.parametrize(
    ("pairing", "row", "deposit"),
    [
        ("x402/exact/lnbtc/payment-hash", V["L4"], False),
        ("mpp/charge/lightning", L2, False),
        ("mpp/session/lightning", {**L2, "invoice": S1["request"]["depositInvoice"]}, True),
    ],
    ids=["x402-exact-lnbtc.json L4", "mpp-charge-lightning.json L2", "mpp-session-lightning.json S1's deposit invoice, L2"],
)
def test_summary_of_a_decoded_invoice(pairing: str, row: dict[str, Any], deposit: bool) -> None:
    """The fields and payee light-bolt11-decoder 3.2.0 and bolt11 1.4.1 read from the invoice; S1's deposit invoice is
    L2, its amount the session's deposit."""
    e = row["expect"]
    assert e["currency"] == "bc" and row["invoice"] in (V["L4"]["invoice"], L2["invoice"])
    expected = summary(e["amountMsat"], row["expectPayee"], e["timestamp"], e["expiry"], e["amountMsat"] if deposit else None)
    assert show(pairing, row["invoice"]) == expected
