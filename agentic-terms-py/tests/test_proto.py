"""B2, B6, B10 and B16 for the protocol-group pairings (card, AP2, UCP, ACP, ACK), with the pairings' own vector rows
for their buyer halves. Every expected request, answer and bound hash is the vector files' (card.json,
ap2-checkout-mandate.json, ucp.json, acp-checkout.json, ack-payment-request.json)."""

import base64
import dataclasses
import hashlib
import json
import re
from typing import Any

import ed25519
import pytest
from breadth import (
    ABC,
    offered,
    receipt,
    ABD,
    H,
    LINK,
    Pairing,
    Recording,
    build_and_sign,
    code,
    confirms_only,
    link_calls,
    never,
    plant,
    run,
)
from support import load, serving

from integraledger_terms import (
    ACK_PAYMENT_REQUEST,
    ACP_CHECKOUT_DELEGATED,
    ACP_CHECKOUT_UNDELEGATED,
    AP2_CHECKOUT_MANDATE,
    CARD_MASTERCARD_VI_AUTONOMOUS,
    CARD_MASTERCARD_VI_IMMEDIATE,
    CARD_SELLER_REFERENCE,
    CARD_VISA_TAP,
    UCP_BOOKING_AP2_MANDATE,
    UCP_BOOKING_UNSIGNED,
    UCP_CHECKOUT_AP2_MANDATE,
    UCP_CHECKOUT_UNSIGNED,
    Advertised,
    Binding,
    Checked,
    Chosen,
    Confirmed,
    Declined,
    Finished,
    Refusal,
    Transacted,
    check,
    confirm,
    finish,
    transact,
)
from integraledger_terms.bindings._jose import disclosure_digest
from integraledger_terms.bindings.ap2_checkout_mandate import checkout_binding, checkout_jwt_of, read_mandate
from integraledger_terms.pieces import PIECES

BUYER = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
# Accounts that name no buyer: the pairings whose offer has no network take any CAIP-10 account.
UNNAMED = ["not-an-account", "eip155:84532", ""]

ACK = load("ack-payment-request.json")


def http_link(p: Pairing, http_doc: Any, detail: str) -> None:
    """B10: a document whose link is http:// is offer-unreadable with the pairing's code, before any fetch."""
    link = serving(ABC)
    out = run(lambda c: confirm(http_doc, p.binding, p.account, c, p.inputs), link)
    assert out == Declined("offer-unreadable", detail), out
    signer = Recording(p.account, never)
    assert code(run(lambda c: transact(http_doc, p.binding, signer, c, inputs=p.inputs), link)) == "offer-unreadable"
    assert link.calls == 0
    assert signer.requests == []


def signs_over(p: Pairing, atr: bytes, h: str) -> dict[str, Any]:
    """B6 over the given ATR and its hash: confirm gives the request, finish with the test signer's answer returns a
    payment bound to h, transact signs once, and check confirms the payment against the ATR and declines it against
    other bytes."""
    confirmed = run(lambda c: confirm(p.doc, offered(p.binding), p.account, c, p.inputs), serving(atr))
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.h == h and confirmed.atr_bytes == atr
    assert confirmed.request is not None
    answer = p.answer(confirmed.request)
    chosen = Chosen(**json.loads(json.dumps(dataclasses.asdict(confirmed.chosen))))
    done = finish(atr, chosen, answer, p.binding)
    assert isinstance(done, Finished), done
    assert done.h == h
    signer = Recording(p.account, p.answer)
    whole = run(lambda c: transact(p.doc, offered(p.binding), signer, c, inputs=p.inputs), serving(atr))
    assert isinstance(whole, Transacted), whole
    assert len(signer.requests) == 1
    assert whole.signed == done.signed and whole.atr_bytes == atr
    assert whole.agreement == (None if getattr(p.binding, "public_proof", False) is True else receipt(h))
    assert check(atr, done.signed, p.binding) == Checked(h=h)
    assert code(check(ABD, done.signed, p.binding)) == "signed-not-bound"
    return done.signed


def confirms_only_over(p: Pairing, atr: bytes, h: str) -> Chosen:
    """B6 for a confirm-only pairing: confirm gives no request and the hash; transact gives no payment, unsigned."""
    confirmed = run(lambda c: confirm(p.doc, offered(p.binding), p.account, c, p.inputs), serving(atr))
    assert isinstance(confirmed, Confirmed), confirmed
    assert confirmed.request is None and confirmed.h == h and confirmed.atr_bytes == atr
    assert json.loads(json.dumps(confirmed.chosen.choice)) == confirmed.chosen.choice
    signer = Recording(p.account, never)
    whole = run(lambda c: transact(p.doc, offered(p.binding), signer, c, inputs=p.inputs), serving(atr))
    agreement = None if getattr(p.binding, "public_proof", False) is True else receipt(h)
    assert whole == Transacted(signed=None, atr_bytes=atr, h=h, agreement=agreement)
    assert signer.requests == []
    return confirmed.chosen


def unpayable(p: Pairing, accounts: list[str]) -> None:
    """B16: each account is declined no-payable-option before any fetch."""
    for account in accounts:
        out, calls = link_calls(p, account)
        assert code(out) == "no-payable-option", (account, out)
        assert calls == 0


def expand(value: Any) -> Any:
    """The vectors' {"$repeat": [s, n]} as s repeated n times, everywhere in value."""
    if isinstance(value, list):
        return [expand(v) for v in value]
    if isinstance(value, dict):
        if "$repeat" in value:
            text, times = value["$repeat"]
            return text * times
        return {k: expand(v) for k, v in value.items()}
    return value


def advertised(expect: dict[str, Any]) -> Advertised:
    return Advertised(h=expect["h"], link=expect["link"], offer=expect["offer"], agreement=expect.get("agreement"))


def refusal(expect: dict[str, Any]) -> Refusal:
    assert expect["refused"] is True
    return Refusal(expect["code"])


# ── ACK ──

ACK_O = ACK["fixed"]["O"]
ACK_BODY = ACK["K2"]["body"]
ACK_PAIRING = Pairing(ACK_PAYMENT_REQUEST, ACK_BODY, f"{ACK_O['network']}:{BUYER.split(':')[2]}", never)

def test_ack_payment_request_b6_confirm_only_option_on_the_account_network() -> None:
    assert ACK_PAYMENT_REQUEST.build({}, H) == refusal(ACK["K5"]["expect"])
    confirmed = confirms_only(ACK_PAIRING)
    assert confirmed.chosen.choice == {"option": ACK_O}
    assert ACK["fixed"]["H"] == H


def test_ack_payment_request_b10_http_link() -> None:
    lc = {**ACK_BODY["legalContext"], "legalContextUrl": ACK["fixed"]["L"].replace("https://", "http://")}
    http_link(ACK_PAIRING, {**ACK_BODY, "legalContext": lc}, "ack/link-not-https")


def test_ack_payment_request_b16_other_network_or_namespace() -> None:
    address = BUYER.split(":")[2]
    unpayable(ACK_PAIRING, [f"eip155:1:{address}", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:x", *UNNAMED])


def test_ack_payment_request_k2_read() -> None:
    assert ACK_PAYMENT_REQUEST.read(ACK_BODY) == advertised(ACK["K2"]["expect"])
    without = {k: v for k, v in ACK_BODY.items() if k != "paymentRequest"}
    assert ACK_PAYMENT_REQUEST.read(without) == advertised(ACK["K2"]["expect"])
    two = ACK["K2"]["twoSegmentToken"]
    assert ACK_PAYMENT_REQUEST.read(two["body"] if "body" in two else two) == Refusal("ack/token-malformed")


def test_ack_payment_request_k2_token_segments_read_as_every_jws_in_the_package() -> None:
    # RFC 8259 section 8.1 lets a JSON parser ignore or refuse a leading byte-order mark; every compact JWS is read by
    # one decoder, which refuses it. A segment is unpadded base64url, and may be empty.
    head, body, sig = ACK_BODY["paymentRequestToken"].split(".")
    bom = base64.urlsafe_b64encode(b"\xef\xbb\xbf" + base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    bom_body = bom.rstrip(b"=").decode("ascii")

    def read(token: str) -> Any:
        return ACK_PAYMENT_REQUEST.read({**ACK_BODY, "paymentRequestToken": token})

    assert read(f"{head}.{bom_body}.{sig}") == Refusal("ack/token-malformed")
    assert read(f"{head}.{body}=.{sig}") == Refusal("ack/token-malformed")
    assert read(f"{head}.{body}.") == advertised(ACK["K2"]["expect"])
    assert read(f".{body}.{sig}") == advertised(ACK["K2"]["expect"])


def test_ack_payment_request_k3_plant_signed_id_wins() -> None:
    k3 = ACK["K3"]
    assert ACK_PAYMENT_REQUEST.read(k3["body"]) == refusal(k3["expect"])


def test_ack_payment_request_k5_build_and_bound_refuse() -> None:
    expect = refusal(ACK["K5"]["expect"])
    for given in ACK["K5"]["inputs"]:
        assert ACK_PAYMENT_REQUEST.build(given, H) == expect
        assert ACK_PAYMENT_REQUEST.bound(given) == expect
    assert ACK["K5"]["pattern"]["buyerSigns"] is False


def test_ack_payment_request_agreed_refusals_read() -> None:
    rows = [r for r in ACK["agreedRefusals"]["rows"] if r["call"] == "paymentRequest.read"]
    assert rows
    for row in rows:
        out = ACK_PAYMENT_REQUEST.read(expand(row["args"][0]))
        expect = row["expect"]
        assert out == (refusal(expect) if "refused" in expect else advertised(expect)), row["case"]


def test_ack_payment_request_plant_through_the_gate_never_reads_the_unsigned_copy() -> None:
    """K3 through confirm: the offer is unreadable before any fetch."""
    link = serving(ABD)
    out = run(lambda c: confirm(ACK["K3"]["body"], ACK_PAYMENT_REQUEST, ACK_PAIRING.account, c), link)
    assert out == Declined("offer-unreadable", "ack/legal-context-conflict")
    assert link.calls == 0


# ── card ──

CARD = load("card.json")
TAP_DOC = CARD["C2"]["build"]["doc"]
CJ: str = CARD["vi"]["CJ"]
VI_REQUEST = {"kind": "vi-checkout-mandate", **CARD["C5"]["build"]["expect"]}


def _http_link_of(lc: dict[str, Any]) -> dict[str, Any]:
    return {**lc, "legalContextUrl": CARD["C1"]["httpLink"]["link"]}


def _cj_http() -> str:
    head, payload, signature = CJ.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    decoded["legalContext"] = _http_link_of(decoded["legalContext"])
    text = json.dumps(decoded, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return f"{head}.{base64.urlsafe_b64encode(text).rstrip(b'=').decode('ascii')}.{signature}"


def tap_answer(request: Any) -> dict[str, str]:
    """The agent's RFC 9421 signer, as the vectors publish it: sig2 over a base that carries the lcp-hash line."""
    c2 = CARD["C2"]
    assert request == {"kind": "tap-field", **c2["build"]["expect"]}
    base: str = c2["sig2Base"]
    assert f'"lcp-hash": {request["value"]}' in base.split("\n")
    assert hashlib.sha256(base.encode("utf-8")).hexdigest() == c2["expectSig2BaseSha256"]
    sig2 = re.search(r"sig2=:([^:]+):", c2["request"]["signature"])
    assert sig2 is not None
    spki = base64.b64decode(c2["testKeyEd25519Spki"])
    assert spki[:12] == bytes.fromhex("302a300506032b6570032100")
    signature = base64.b64decode(sig2.group(1))
    assert ed25519.verify(spki[12:], base.encode("utf-8"), signature)
    assert not ed25519.verify(spki[12:], base.encode("utf-8"), signature[:-1] + bytes([signature[-1] ^ 1]))
    return {"signatureInput": c2["request"]["signatureInput"], "signature": c2["request"]["signature"], "lcpHash": c2["request"]["lcpHash"]}


def vi_immediate_answer(request: Any) -> dict[str, str]:
    assert request == VI_REQUEST
    return {"l2": CARD["C6"]["bound"]["presented"]["l2"]}


def vi_autonomous_answer(request: Any) -> dict[str, str]:
    assert request == VI_REQUEST
    return dict(CARD["C7"]["bound"]["presented"])


CARD_TAP = Pairing(CARD_VISA_TAP, TAP_DOC, BUYER, tap_answer)
CARD_IMMEDIATE = Pairing(CARD_MASTERCARD_VI_IMMEDIATE, CJ, BUYER, vi_immediate_answer)
CARD_AUTONOMOUS = Pairing(CARD_MASTERCARD_VI_AUTONOMOUS, CJ, BUYER, vi_autonomous_answer)
CARD_SELLER = Pairing(CARD_SELLER_REFERENCE, TAP_DOC, BUYER, never)
CARD_PAIRINGS = [CARD_TAP, CARD_IMMEDIATE, CARD_AUTONOMOUS, CARD_SELLER]


def _through(p: Pairing, doc: Any) -> tuple[Any, Chosen, Any]:
    """The piece's choose, the choice revived from Chosen's JSON, and the binding's build over it with H."""
    piece = PIECES[p.binding.id]
    chosen = piece.choose(Advertised(h=H, link=LINK, offer={}), BUYER, {}, 1790000000, "r" * 32, doc)
    assert isinstance(chosen, Chosen), chosen
    revived = piece.choice(Chosen(**json.loads(json.dumps(dataclasses.asdict(chosen)))), ABC)
    return piece, chosen, p.binding.build(revived, H)


@pytest.mark.parametrize("p", [CARD_TAP, CARD_IMMEDIATE, CARD_AUTONOMOUS], ids=lambda p: p.binding.id)
def test_card_piece_keeps_the_document_and_completes_a_payment_bound_to_h(p: Pairing) -> None:
    piece, chosen, unsigned = _through(p, p.doc)
    assert chosen.choice == {"doc": p.doc}
    request = piece.request(unsigned)
    assert isinstance(request, dict)
    signed = piece.complete(unsigned, p.answer(request), chosen)
    assert isinstance(signed, dict), signed
    assert check(ABC, signed, p.binding) == Checked(h=H)
    assert code(check(ABD, signed, p.binding)) == "signed-not-bound"


def test_card_visa_tap_payment_carries_the_lines_the_signer_sent() -> None:
    # C2's repeated field is refused, an upper-case line is read, another hash is not bound, and an answer without
    # lcpHash is malformed.
    piece, chosen, unsigned = _through(CARD_TAP, TAP_DOC)
    c2 = CARD["C2"]
    answer = {"signatureInput": c2["request"]["signatureInput"], "signature": c2["request"]["signature"]}
    repeated = piece.complete(unsigned, {**answer, "lcpHash": c2["repeatedField"]["lcpHash"]}, chosen)
    assert CARD_VISA_TAP.bound(repeated) == Refusal(c2["repeatedField"]["expect"])
    assert code(check(ABC, repeated, CARD_VISA_TAP)) == "signed-not-bound"
    upper = piece.complete(unsigned, {**answer, "lcpHash": c2["upperCaseField"]["lcpHash"]}, chosen)
    assert check(ABC, upper, CARD_VISA_TAP) == Checked(h=c2["upperCaseField"]["expectBound"])
    other = piece.complete(unsigned, {**answer, "lcpHash": ["0x" + "11" * 32]}, chosen)
    assert code(check(ABC, other, CARD_VISA_TAP)) == "signed-not-bound"
    assert piece.complete(unsigned, answer, chosen) == Refusal("card/signature-malformed")


def test_card_visa_tap_payment_carries_the_one_line_and_the_signer_fields() -> None:
    piece, chosen, unsigned = _through(CARD_TAP, TAP_DOC)
    signed = piece.complete(unsigned, tap_answer(piece.request(unsigned)), chosen)
    request = CARD["C2"]["request"]
    assert signed == {
        "signatureInput": request["signatureInput"],
        "signature": request["signature"],
        "lcpHash": request["lcpHash"],
    }


def test_card_seller_reference_build_refuses_so_nothing_goes_to_a_signer() -> None:
    piece, _, unsigned = _through(CARD_SELLER, TAP_DOC)
    assert unsigned == Refusal(CARD["C8"]["expect"])
    assert isinstance(piece.request(unsigned), Refusal)


def test_card_account_not_caip10_is_no_payable_option() -> None:
    piece = PIECES["card/visa-tap"]
    for account in UNNAMED:
        out = piece.choose(Advertised(h=H, link=LINK, offer={}), account, {}, 0, "r", TAP_DOC)
        assert out == Refusal("card/no-payable-option")


def test_card_b10_http_link() -> None:
    tap_http = {"legalContext": _http_link_of(TAP_DOC["legalContext"])}
    http_link(CARD_TAP, tap_http, "card/link-not-https")
    http_link(CARD_SELLER, tap_http, "card/link-not-https")
    http_link(CARD_IMMEDIATE, _cj_http(), "card/link-not-https")
    http_link(CARD_AUTONOMOUS, _cj_http(), "card/link-not-https")

@pytest.mark.parametrize("p", CARD_PAIRINGS, ids=lambda p: p.binding.id)
def test_card_b16_unnamed_buyer(p: Pairing) -> None:
    unpayable(p, UNNAMED)


def test_card_visa_tap_b6() -> None:
    build_and_sign(CARD_TAP, lambda request: None)


def test_card_mastercard_vi_immediate_b6() -> None:
    build_and_sign(CARD_IMMEDIATE, lambda request: _equal(request, VI_REQUEST))


def test_card_mastercard_vi_autonomous_b6() -> None:
    build_and_sign(CARD_AUTONOMOUS, lambda request: _equal(request, VI_REQUEST))


def test_card_c7_vi_autonomous_bound_verifies_both_es256_signatures() -> None:
    c7 = CARD["C7"]
    assert CARD_MASTERCARD_VI_AUTONOMOUS.bound(c7["bound"]["presented"]) == c7["bound"]["expect"]
    assert CARD_MASTERCARD_VI_AUTONOMOUS.bound(c7["flippedSignature"]["presented"]) == Refusal(c7["flippedSignature"]["expect"])
    assert CARD_MASTERCARD_VI_AUTONOMOUS.bound(c7["withoutDco"]["presented"]) == Refusal(c7["withoutDco"]["expect"])


def test_card_c7_l2_bound_to_another_l1_or_a_kid_not_the_delegated_keys_is_refused() -> None:
    presented = CARD["C7"]["bound"]["presented"]
    l1, l2, l3b = presented["l1"], presented["l2"], presented["l3b"]
    out = CARD_MASTERCARD_VI_AUTONOMOUS.bound({"l1": l1 + "x~", "l2": l2, "l3b": l3b})
    assert out == Refusal("card/vi-sd-hash-mismatch")
    jws, disclosure = l3b.split("~")[0], l3b.split("~")[1]
    head, payload, sig = jws.split(".")
    header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    other = base64.urlsafe_b64encode(json.dumps({**header, "kid": "agent-2"}, separators=(",", ":")).encode()).rstrip(b"=")
    other_kid = f"{other.decode()}.{payload}.{sig}~{disclosure}~"
    assert CARD_MASTERCARD_VI_AUTONOMOUS.bound({"l1": l1, "l2": l2, "l3b": other_kid}) == Refusal("card/vi-kid-mismatch")


def test_card_seller_reference_b6_confirm_only() -> None:
    confirmed = confirms_only(CARD_SELLER)
    assert confirmed.chosen.choice == {"doc": TAP_DOC}


def _equal(a: Any, b: Any) -> None:
    assert a == b


# The card vectors' rows for the buyer half.


def test_card_c2_tap_bound_build_and_read() -> None:
    c2 = CARD["C2"]
    assert CARD_VISA_TAP.bound(c2["request"]) == c2["expectBound"]
    upper = {**c2["request"], "lcpHash": c2["upperCaseField"]["lcpHash"]}
    assert CARD_VISA_TAP.bound(upper) == c2["upperCaseField"]["expectBound"]
    repeated = {**c2["request"], "lcpHash": c2["repeatedField"]["lcpHash"]}
    assert CARD_VISA_TAP.bound(repeated) == Refusal(c2["repeatedField"]["expect"])
    assert CARD_VISA_TAP.bound({**c2["request"], "lcpHash": []}) == Refusal("card/tap-field-missing")
    assert CARD_VISA_TAP.build(c2["build"]["doc"], CARD["fixed"]["H"]) == c2["build"]["expect"]
    read = CARD_VISA_TAP.read(c2["build"]["doc"])
    assert read == Advertised(h=CARD["fixed"]["H"], link=CARD["fixed"]["link"], offer={})


def test_card_c3_tap_plant_the_listing_must_be_the_payer_signature() -> None:
    c3 = CARD["C3"]
    presented = {"signatureInput": c3["signatureInput"], "signature": c3["signature"], "lcpHash": c3["lcpHash"]}
    assert CARD_VISA_TAP.bound(presented) == Refusal(c3["expect"])


def test_card_c5_vi_read_and_build() -> None:
    c5 = CARD["C5"]
    assert CARD_MASTERCARD_VI_IMMEDIATE.read(c5["read"]["doc"]) == Advertised(
        h=c5["read"]["expect"]["h"], link=c5["read"]["expect"]["link"], offer={}
    )
    vi: Any = CARD_MASTERCARD_VI_IMMEDIATE
    assert vi.build(CJ, c5["build"]["h"]) == c5["build"]["expect"]
    assert vi.build(CJ, c5["conflict"]["h"]) == Refusal(c5["conflict"]["expect"])
    assert c5["build"]["expect"]["transactionId"] == CARD["vi"]["printed"]["CH"]


def test_card_c6_vi_immediate_bound_and_plant() -> None:
    c6 = CARD["C6"]
    assert CARD_MASTERCARD_VI_IMMEDIATE.bound(c6["bound"]["presented"]) == c6["bound"]["expect"]
    out = CARD_MASTERCARD_VI_IMMEDIATE.bound(c6["plant"]["presented"])
    assert out == Refusal(c6["plant"]["expect"])
    assert out != c6["plant"]["never"]


def test_card_c8_seller_reference_has_no_signed_place() -> None:
    expect = Refusal(CARD["C8"]["expect"])
    for given in CARD["C8"]["inputs"]:
        assert CARD_SELLER_REFERENCE.build(given, H) == expect
        assert CARD_SELLER_REFERENCE.bound(given) == expect
    assert CARD["C8"]["buyerSigns"] is False


# ── AP2 ──

AP2 = load("ap2-checkout-mandate.json")
AP2_F = AP2["fixed"]
AP2_J: str = AP2["built"]["J"]
AP2_M: str = AP2["built"]["M"]
AP2_ATR = AP2_F["A"].encode("utf-8")


def ap2_answer(request: Any) -> str:
    assert request == {
        "kind": "ap2-checkout-mandate",
        "content": {"vct": AP2["V4"]["expectVct"], "checkout_jwt": AP2_J, "checkout_hash": AP2["V4"]["expectCheckoutHash"]},
    }
    return AP2_M


AP2_PAIRING = Pairing(AP2_CHECKOUT_MANDATE, AP2_J, BUYER, ap2_answer)


def _b64u(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).rstrip(b"=").decode("ascii")

def test_ap2_checkout_mandate_b6_the_vectors_mandate_completes_a_payment_bound_to_h() -> None:
    signed = signs_over(AP2_PAIRING, AP2_ATR, AP2_F["H"])
    assert signed == {"checkout_mandate": AP2_M, "checkout_jwt": AP2_J}
    assert AP2_CHECKOUT_MANDATE.bound(signed) == AP2["V5"]["expectBound"]


def test_ap2_checkout_mandate_b10_http_link() -> None:
    row = next(r for r in AP2["implementation"] if r["name"] == "read-http-link")
    http_link(AP2_PAIRING, row["input"]["doc"], "ap2/link-not-https")


def test_ap2_checkout_mandate_b16_unnamed_buyer() -> None:
    unpayable(AP2_PAIRING, UNNAMED)


def test_ap2_checkout_mandate_v4_build() -> None:
    binding: Any = AP2_CHECKOUT_MANDATE
    read = binding.read(AP2_J)
    assert isinstance(read, Advertised)
    assert {"h": read.h, "link": read.link, "checkout": read.offer["checkout"]} == AP2["V2"]["expectRead"]
    assert read.offer["checkoutJwt"] == AP2_J
    unsigned = binding.build(read.offer, AP2_F["H"])
    assert unsigned.content == {
        "vct": AP2["V4"]["expectVct"],
        "checkout_jwt": AP2_J,
        "checkout_hash": AP2["V4"]["expectCheckoutHash"],
    }
    assert unsigned.complete(AP2_M) == {"checkout_mandate": AP2_M, "checkout_jwt": AP2_J}
    assert binding.build(read.offer, AP2["V4"]["otherHash"]) == refusal(AP2["V4"]["otherHashExpect"])


def test_ap2_checkout_mandate_v5_bound() -> None:
    v5 = AP2["V5"]
    assert AP2_CHECKOUT_MANDATE.bound({"checkout_mandate": AP2_M, "checkout_jwt": AP2_J}) == v5["expectBound"]
    without = {"checkout_mandate": v5["withoutDisclosure"]["mandate"], "checkout_jwt": AP2_J}
    assert AP2_CHECKOUT_MANDATE.bound(without) == v5["withoutDisclosure"]["expect"]
    irob = f"{_b64u(AP2_F['mandateHeader'])}.{_b64u(AP2_F['mandatePayload'])}.{AP2_F['signature']}~{v5['saltIroB']['disclosure']}~"
    out = AP2_CHECKOUT_MANDATE.bound({"checkout_mandate": irob, "checkout_jwt": AP2_J})
    assert out == refusal(v5["saltIroB"]["expect"])


def test_ap2_checkout_mandate_v6_the_published_example() -> None:
    v6 = AP2["V6"]
    token: str = v6["token"]
    assert len(token.encode("utf-8")) == v6["tokenBytes"]
    assert hashlib.sha256(token.encode("utf-8")).hexdigest() == v6["tokenSha256"]
    assert [disclosure_digest(d) for d in token.split("~")[1:-1]] == v6["expectDisclosureDigests"]
    mandate = read_mandate(token)
    assert not isinstance(mandate, Refusal)
    assert mandate.checkout_hash == v6["expectCheckoutHash"] and mandate.checkout_jwt == v6["checkoutJwt"]
    assert checkout_jwt_of(token) == v6["checkoutJwt"]
    presented = {"checkout_mandate": token, "checkout_jwt": v6["checkoutJwt"]}
    payload = checkout_binding(presented)
    assert isinstance(payload, dict) and payload["id"] == v6["expectCheckoutId"]
    assert AP2_CHECKOUT_MANDATE.bound(presented) == refusal(v6["expectBound"])


def test_ap2_checkout_mandate_plant_a_reissued_checkout_is_not_the_committed_one() -> None:
    reissued = AP2["plant"]["checkoutJwt"]
    for mandate in (AP2_M, AP2["V5"]["withoutDisclosure"]["mandate"]):
        out = AP2_CHECKOUT_MANDATE.bound({"checkout_mandate": mandate, "checkout_jwt": reissued})
        assert out == refusal(AP2["plant"]["expect"])


@pytest.mark.parametrize(
    "row", [r for r in AP2["implementation"] if r["fn"] != "advertise"], ids=lambda r: str(r["name"])
)
def test_ap2_checkout_mandate_implementation_rows(row: dict[str, Any]) -> None:
    given = expand(row["input"])
    expect = row["expect"]
    if row["fn"] == "read":
        r = AP2_CHECKOUT_MANDATE.read(given["doc"])
        got: Any = r if isinstance(r, Refusal) else {"h": r.h, "link": r.link, "checkout": r.offer["checkout"]}
    elif row["fn"] == "bound":
        got = AP2_CHECKOUT_MANDATE.bound(given)
    else:
        assert row["fn"] == "checkoutJwtOf"
        got = checkout_jwt_of(given["m"])
    assert got == (refusal(expect) if isinstance(expect, dict) and "refused" in expect else expect)


def test_ap2_checkout_mandate_a_non_https_link_gives_one_code_on_read_and_bound() -> None:
    # A well-formed legal context whose link is not https: the pairing's refusal codes list link-not-https, and read
    # and bound give it for the same checkout JWT (RFC 9901 section 4 builds the closed mandate's disclosure).
    def b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def sha256_b64u(text: str) -> str:
        return b64u(hashlib.sha256(text.encode("ascii")).digest())

    def compact(value: Any) -> bytes:
        return json.dumps(value, separators=(",", ":")).encode("utf-8")

    hx = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    context = {"type": "sha256", "value": hx, "legalContextUrl": f"http://atr.seller.example/{hx}"}
    signature = "A" * 86
    jwt_header = b64u(compact({"alg": "ES256", "typ": "JWT"}))
    j = f"{jwt_header}.{b64u(compact({'id': 'chk_2', 'legalContext': context}))}.{signature}"
    d = b64u(compact(["c2FsdA", "checkout_jwt", j]))
    claims = {"vct": "mandate.checkout.1", "checkout_hash": sha256_b64u(j), "_sd": [sha256_b64u(d)], "_sd_alg": "sha-256"}
    sd_header = b64u(compact({"alg": "ES256", "typ": "dc+sd-jwt"}))
    m = f"{sd_header}.{b64u(compact(claims))}.{signature}~{d}~"
    assert AP2_CHECKOUT_MANDATE.read(j) == Refusal("ap2/link-not-https")
    assert AP2_CHECKOUT_MANDATE.bound({"checkout_mandate": m, "checkout_jwt": j}) == Refusal("ap2/link-not-https")


# ── UCP ──

UCP = load("ucp.json")
UCP_F = UCP["fixed"]
UCP_ATR = UCP_F["A"].encode("utf-8")
UCP_BY_ID: dict[str, Binding] = {
    b.id: b for b in (UCP_CHECKOUT_AP2_MANDATE, UCP_CHECKOUT_UNSIGNED, UCP_BOOKING_AP2_MANDATE, UCP_BOOKING_UNSIGNED)
}


def _signed_by(c: dict[str, Any]) -> dict[str, Any]:
    return {**c, "ap2": {"merchant_authorization": UCP_F["merchantAuthorization"]}}


def _sha256_b64u(text: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(text.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def ucp_mandate_over(c: dict[str, Any]) -> tuple[str, str]:
    """The vectors' fixed recipe for J and M over a checkout the mandate discloses."""
    j = f"{_b64u(UCP_F['jwtHeader'])}.{_b64u(json.dumps(c, separators=(',', ':'), ensure_ascii=False))}.{UCP_F['signature']}"
    d = _b64u(UCP_F["disclosureTemplate"].replace("<J>", j))
    payload = (
        UCP_F["mandatePayload"]
        .replace(UCP["V4"]["expectCheckoutHash"], _sha256_b64u(j))
        .replace(UCP["V4"]["expectDisclosureDigest"], _sha256_b64u(d))
    )
    return j, f"{_b64u(UCP_F['mandateHeader'])}.{_b64u(payload)}.{UCP_F['signature']}~{d}~"


def _ucp_http(c: dict[str, Any]) -> dict[str, Any]:
    links = [
        {**link, "url": link["url"].replace("https://", "http://")} if link["type"] == "legal_context" else link
        for link in c["links"]
    ]
    return {**c, "links": links}


def test_ucp_the_recipe_reproduces_the_vectors_j_and_m() -> None:
    assert ucp_mandate_over(UCP["V2"]["expectCheckout"]) == (UCP["built"]["J"], UCP["built"]["M"])


UCP_MANDATES = [
    (UCP_CHECKOUT_AP2_MANDATE, UCP["V2"]["expectCheckout"]),
    (UCP_BOOKING_AP2_MANDATE, UCP["V2b"]["expectBooking"]),
]


def _ucp_mandate_pairing(binding: Binding, payload: dict[str, Any]) -> tuple[Pairing, str, str]:
    j, m = ucp_mandate_over(payload)
    doc = _signed_by(payload)

    def answer(request: Any) -> str:
        assert request == {"kind": "ucp-checkout", "checkout": doc}
        return m

    return Pairing(binding, doc, BUYER, answer), j, m

@pytest.mark.parametrize(("binding", "payload"), UCP_MANDATES, ids=lambda v: getattr(v, "id", ""))
def test_ucp_ap2_mandate_b6_the_checkout_goes_unchanged_and_the_mandate_completes(
    binding: Binding, payload: dict[str, Any]
) -> None:
    p, j, m = _ucp_mandate_pairing(binding, payload)
    signed = signs_over(p, UCP_ATR, UCP_F["H"])
    assert signed == {"checkout_mandate": m, "checkout_jwt": j}
    assert binding.bound(signed) == UCP["V4"]["expectBound"]


@pytest.mark.parametrize(("binding", "payload"), UCP_MANDATES, ids=lambda v: getattr(v, "id", ""))
def test_ucp_ap2_mandate_b10_http_link(binding: Binding, payload: dict[str, Any]) -> None:
    p = _ucp_mandate_pairing(binding, payload)[0]
    http_link(p, _ucp_http(p.doc), "ucp/link-not-https")


@pytest.mark.parametrize(("binding", "payload"), UCP_MANDATES, ids=lambda v: getattr(v, "id", ""))
def test_ucp_ap2_mandate_b16_unnamed_buyer(binding: Binding, payload: dict[str, Any]) -> None:
    unpayable(_ucp_mandate_pairing(binding, payload)[0], UNNAMED)


UCP_CONFIRM_ONLY = [
    (UCP_CHECKOUT_UNSIGNED, UCP["V2"]["expectCheckout"]),
    (UCP_BOOKING_UNSIGNED, UCP["V2b"]["expectBooking"]),
]

@pytest.mark.parametrize(("binding", "doc"), UCP_CONFIRM_ONLY, ids=lambda v: getattr(v, "id", ""))
def test_ucp_unsigned_b6_confirm_only(binding: Binding, doc: dict[str, Any]) -> None:
    assert binding.build({"checkout": doc}, UCP_F["H"]) == refusal(UCP["V4"]["expectUnsignedBuild"])
    confirms_only_over(Pairing(binding, doc, BUYER, never), UCP_ATR, UCP_F["H"])


@pytest.mark.parametrize(("binding", "doc"), UCP_CONFIRM_ONLY, ids=lambda v: getattr(v, "id", ""))
def test_ucp_unsigned_b10_http_link(binding: Binding, doc: dict[str, Any]) -> None:
    http_link(Pairing(binding, doc, BUYER, never), _ucp_http(doc), "ucp/link-not-https")


@pytest.mark.parametrize(("binding", "doc"), UCP_CONFIRM_ONLY, ids=lambda v: getattr(v, "id", ""))
def test_ucp_unsigned_b16_unnamed_buyer(binding: Binding, doc: dict[str, Any]) -> None:
    unpayable(Pairing(binding, doc, BUYER, never), UNNAMED)


def test_ucp_v2_read() -> None:
    doc = UCP["V2"]["expectCheckout"]
    r = UCP_CHECKOUT_UNSIGNED.read(doc)
    assert isinstance(r, Advertised) and {"h": r.h, "link": r.link} == UCP["V2"]["expectRead"]
    assert UCP_CHECKOUT_AP2_MANDATE.read(doc) == refusal(UCP["V2"]["expectAp2Read"])
    s = UCP_CHECKOUT_AP2_MANDATE.read(_signed_by(doc))
    assert isinstance(s, Advertised) and {"h": s.h, "link": s.link} == UCP["V2"]["expectRead"]
    b = UCP_BOOKING_UNSIGNED.read(UCP["V2b"]["expectBooking"])
    assert isinstance(b, Advertised) and {"h": b.h, "link": b.link} == UCP["V2b"]["expectRead"]


def test_ucp_v4_bound_build_and_complete() -> None:
    j, m = UCP["built"]["J"], UCP["built"]["M"]
    assert _sha256_b64u(j) == UCP["V4"]["expectCheckoutHash"]
    assert disclosure_digest(UCP["built"]["D"]) == UCP["V4"]["expectDisclosureDigest"]
    presented = {"checkout_mandate": m, "checkout_jwt": j}
    assert UCP_CHECKOUT_AP2_MANDATE.bound(presented) == UCP["V4"]["expectBound"]
    assert UCP_BOOKING_AP2_MANDATE.bound(presented) == UCP["V4"]["expectBound"]
    assert UCP_CHECKOUT_UNSIGNED.bound(presented) == refusal(UCP["V4"]["expectUnsignedBound"])
    signed = _signed_by(UCP["V2"]["expectCheckout"])
    r = UCP_CHECKOUT_AP2_MANDATE.read(signed)
    assert isinstance(r, Advertised)
    binding: Any = UCP_CHECKOUT_AP2_MANDATE
    unsigned = binding.build(r.offer, UCP_F["H"])
    assert unsigned.checkout is signed
    assert unsigned.complete(m) == presented


def test_ucp_v5_ap2_published_example_as_a_ucp_checkout() -> None:
    ap2_v6 = AP2["V6"]
    assert _sha256_b64u(ap2_v6["checkoutJwt"]) == UCP["V5"]["expectCheckoutHash"]
    presented = {"checkout_mandate": ap2_v6["token"], "checkout_jwt": ap2_v6["checkoutJwt"]}
    assert UCP_CHECKOUT_AP2_MANDATE.bound(presented) == refusal(UCP["V5"]["expectBound"])


def test_ucp_v6_names() -> None:
    for doc in (UCP["V6"]["policies"], UCP["V6"]["presentation"]):
        assert UCP_CHECKOUT_UNSIGNED.read(doc) == refusal(UCP["V6"]["expect"])


def test_ucp_plant_a_reissued_checkout_is_not_the_committed_one() -> None:
    plant_row = UCP["plant"]
    assert "0x" + hashlib.sha256(plant_row["A2"].encode("utf-8")).hexdigest() == plant_row["H2"]
    assert _sha256_b64u(plant_row["checkoutJwt"]) == plant_row["expectJ2Hash"]
    m = UCP["built"]["M"]
    for mandate in (m, m[: m.index("~") + 1]):
        out = UCP_CHECKOUT_AP2_MANDATE.bound({"checkout_mandate": mandate, "checkout_jwt": plant_row["checkoutJwt"]})
        assert out == refusal(plant_row["expect"])


@pytest.mark.parametrize(
    "row", [r for r in UCP["implementation"] if r["fn"] != "advertise"], ids=lambda r: str(r["name"])
)
def test_ucp_implementation_rows(row: dict[str, Any]) -> None:
    binding: Any = UCP_BY_ID[row["pairing"]]
    given = expand(row["input"])
    expect = row["expect"]
    if row["fn"] == "read":
        r = binding.read(given["doc"])
        got: Any = r if isinstance(r, Refusal) else {"h": r.h, "link": r.link}
    else:
        assert row["fn"] == "build"
        got = binding.build({"checkout": given["checkout"]}, given["h"])
    assert got == (refusal(expect) if "refused" in expect else expect)


# ── ACP ──

ACP = load("acp-checkout.json")
ACP_F = ACP["fixed"]
ACP_ATR = ACP_F["A"].encode("utf-8")
ACP_SESSION = ACP["V2"]["expectSession"]
ACP_VALUES = {k: v for k, v in ACP["V4"]["choice"].items() if k != "session"}
ACP_HTTP = {
    **ACP_SESSION,
    "metadata": {
        **ACP_SESSION["metadata"],
        "legal_context": {
            **ACP_SESSION["metadata"]["legal_context"],
            "legal_context_url": ACP_F["L"].replace("https://", "http://"),
        },
    },
}


def acp_answer(request: Any) -> dict[str, Any]:
    assert request == {"kind": "acp-allowance", "allowance": ACP["V4"]["expectAllowance"]}
    return {"allowance": request["allowance"]}


ACP_DELEGATED = Pairing(ACP_CHECKOUT_DELEGATED, ACP_SESSION, BUYER, acp_answer, ACP_VALUES)
ACP_UNDELEGATED = Pairing(ACP_CHECKOUT_UNDELEGATED, ACP["V5"]["session"], BUYER, never)

def test_acp_checkout_delegated_b6_the_allowance_from_the_buyer_inputs_is_bound_to_h() -> None:
    signed = signs_over(ACP_DELEGATED, ACP_ATR, ACP_F["H"])
    assert ACP_CHECKOUT_DELEGATED.bound(signed) == ACP["V4"]["expectBound"]


def test_acp_checkout_delegated_missing_allowance_input_is_input_missing() -> None:
    for key in ACP_VALUES:
        rest = {k: v for k, v in ACP_VALUES.items() if k != key}
        link = serving(ACP_ATR)
        out = run(lambda c: confirm(ACP_SESSION, ACP_CHECKOUT_DELEGATED, BUYER, c, rest), link)
        assert out == Declined("no-payable-option", "acp/input-missing"), key
        assert link.calls == 0


def test_acp_checkout_delegated_b10_http_link() -> None:
    http_link(ACP_DELEGATED, ACP_HTTP, "acp/link-not-https")


def test_acp_checkout_delegated_b16_unnamed_buyer() -> None:
    unpayable(ACP_DELEGATED, UNNAMED)

def test_acp_checkout_undelegated_b6_confirm_only() -> None:
    assert ACP_CHECKOUT_UNDELEGATED.build({}, ACP_F["H"]) == refusal(ACP["V5"]["expectBuild"])
    confirms_only_over(ACP_UNDELEGATED, ACP_ATR, ACP_F["H"])


def test_acp_checkout_undelegated_b10_http_link() -> None:
    http_link(ACP_UNDELEGATED, ACP_HTTP, "acp/link-not-https")


def test_acp_checkout_undelegated_b16_unnamed_buyer() -> None:
    unpayable(ACP_UNDELEGATED, UNNAMED)


def test_acp_v2_read() -> None:
    r = ACP_CHECKOUT_DELEGATED.read(ACP_SESSION)
    assert isinstance(r, Advertised)
    assert {"h": r.h, "link": r.link} == ACP["V2"]["expectRead"] and r.offer["session"] == ACP_SESSION
    upper = ACP_CHECKOUT_DELEGATED.read({**ACP_SESSION, "id": ACP["V2"]["readUpperCaseId"]["id"]})
    assert isinstance(upper, Advertised) and upper.h == ACP["V2"]["readUpperCaseId"]["expectH"]


def test_acp_v4_build_complete_and_bound() -> None:
    v4 = ACP["V4"]
    binding: Any = ACP_CHECKOUT_DELEGATED
    unsigned = binding.build(v4["choice"], v4["h"])
    assert unsigned.allowance == v4["expectAllowance"]
    assert list(unsigned.allowance) == list(v4["expectAllowance"])
    request = {"allowance": unsigned.allowance, "payment_method": {"type": "card"}}
    assert unsigned.complete(request) is request
    assert binding.bound(request) == v4["expectBound"]
    changed = {**request, "allowance": {**unsigned.allowance, "checkout_session_id": v4["changedSessionId"]["checkout_session_id"]}}
    assert unsigned.complete(changed) == refusal(v4["changedSessionId"]["expect"])
    upper = binding.build({**v4["choice"], "currency": v4["upperCurrency"]["currency"]}, v4["h"])
    assert upper == refusal(v4["upperCurrency"]["expect"])
    given = binding.build(v4["choice"], v4["h"])
    given.allowance["checkout_session_id"] = ACP_F["otherH"]
    assert given.complete({"allowance": given.allowance}) == refusal(v4["changedSessionId"]["expect"])


def test_acp_v5_undelegated_reads_and_neither_builds_nor_bounds() -> None:
    v5 = ACP["V5"]
    r = ACP_CHECKOUT_UNDELEGATED.read(v5["session"])
    assert isinstance(r, Advertised) and {"h": r.h, "link": r.link} == v5["expectRead"]
    assert ACP_CHECKOUT_UNDELEGATED.build(ACP["V4"]["choice"], H) == refusal(v5["expectBuild"])
    assert ACP_CHECKOUT_UNDELEGATED.bound({"allowance": ACP["V4"]["expectAllowance"]}) == refusal(v5["expectBound"])


def test_acp_v6_and_plant_read_only_the_id_and_metadata() -> None:
    for binding in (ACP_CHECKOUT_DELEGATED, ACP_CHECKOUT_UNDELEGATED):
        assert binding.read(ACP["V6"]["doc"]) == refusal(ACP["V6"]["expect"])
        assert binding.read(ACP["plant"]["doc"]) == refusal(ACP["plant"]["expect"])


@pytest.mark.parametrize(
    "row",
    [r for r in ACP["agreedRefusals"]["rows"] if not r["call"].endswith(".advertise")],
    ids=lambda r: str(r["case"]),
)
def test_acp_agreed_refusals(row: dict[str, Any]) -> None:
    name, fn = row["call"].split(".")
    binding: Any = {"delegated": ACP_CHECKOUT_DELEGATED, "undelegated": ACP_CHECKOUT_UNDELEGATED}[name]
    out = getattr(binding, fn)(*expand(row["args"]))
    got = {"allowance": out.allowance} if hasattr(out, "allowance") else out
    expect = row["expect"]
    assert got == (refusal(expect) if isinstance(expect, dict) and "refused" in expect else expect)
