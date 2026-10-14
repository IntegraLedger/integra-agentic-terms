"""x402/exact/eip155/eip3009 reads, builds and completes by the protocol package's field rules, as the TypeScript gate
does through it: an eip155 network is eip155: and a chain id of 1 to 16 decimal digits with no leading zero, within
the safe-integer range; an amount is 1 to 78 decimal digits below 2^256, signed as its text; the
chosen option is one the document offers by equal RFC 8785 form (section 3.2.2.1: true and 1 are written apart); two
link spellings conflict when both members are present; a legalContext member present as null is malformed and only an
absent one is missing; and every 2048 bound on a link counts UTF-16 code units, as String.prototype.length does. Each
expected answer is the protocol package's own for the same input. The option, payer, hash and clock are
x402-exact-eip155-eip3009.json's."""

import copy
import json
from typing import Any

from integraledger_terms import MPP_CHARGE_EVM_TRANSACTION, X402_EXACT_EIP155_EIP3009, Advertised, Declined, Refusal, confirm
from integraledger_terms.bindings._lcp import is_agreement_url, is_other_scheme_link
from integraledger_terms.bindings._codec import b64u_encode
from integraledger_terms.bindings._mpp_checks import decode_string_map
from integraledger_terms.bindings.x402_exact_eip155_eip3009 import passes

from breadth import run
from mpp_docs import issued, placed_doc
from support import ACCOUNT, PAIRING, load, serving

FIXED = PAIRING["fixed"]
H: str = FIXED["H"]
O: dict[str, Any] = FIXED["O"]
LINK = f"https://atr.seller.example/{H}"
GRIN = "\U0001f600"

# 27 + 1011 code points; 27 + 2022 UTF-16 code units: 2049, one over the bound.
LONG_LINK = "https://atr.seller.example/" + GRIN * 1011
# 26 + 1012 code points; 26 + 2024 UTF-16 code units: 2050.
LONG_OTHER_SCHEME = "http://atr.seller.example/" + GRIN * 1012
# 37 + 1006 code points; 37 + 2012 UTF-16 code units: 2049.
LONG_AGREEMENT = "https://api.seller.example/agreement/" + GRIN * 1006


def utf16_units(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def doc(option: dict[str, Any] | None = None, info: Any = None, extensions: Any = None) -> dict[str, Any]:
    lc = {"info": info if info is not None else {"type": "sha256", "value": H, "legalContextUrl": LINK}}
    return {
        "x402Version": 2,
        "resource": FIXED["resource"],
        "accepts": [copy.deepcopy(option if option is not None else O)],
        "extensions": extensions if extensions is not None else {"legalContext": lc},
    }


def choice(document: dict[str, Any], accepted: dict[str, Any]) -> dict[str, Any]:
    return {"required": document, "accepted": accepted, "from": FIXED["payer"], "now": FIXED["now"]}


def test_the_long_links_are_one_over_the_bound_in_utf16_units_and_under_it_in_code_points() -> None:
    for link in (LONG_LINK, LONG_OTHER_SCHEME, LONG_AGREEMENT):
        assert len(link) < 2048 < utf16_units(link)


def test_an_eip155_network_has_no_leading_zero_and_is_not_zero() -> None:
    assert passes(O)
    for network in ("eip155:0", "eip155:01", "eip155:" + "9" * 17):
        assert not passes({**O, "network": network})
        assert X402_EXACT_EIP155_EIP3009.read(doc({**O, "network": network})) == Refusal("x402/no-payable-option")


def test_an_amount_is_1_to_78_digits_and_is_signed_as_its_text() -> None:
    padded = {**O, "amount": "0001000"}
    unsigned = X402_EXACT_EIP155_EIP3009.build(choice(doc(padded), padded), H)
    assert not isinstance(unsigned, Refusal)
    presented = unsigned.complete("0x" + "11" * 65)
    assert not isinstance(presented, Refusal)
    assert presented["payload"]["authorization"]["value"] == "0001000"
    seventy_nine = {**O, "amount": "0" * 78 + "1"}
    assert X402_EXACT_EIP155_EIP3009.build(choice(doc(seventy_nine), seventy_nine), H) == Refusal("x402/option-malformed")


def test_the_chosen_option_is_offered_only_by_equal_rfc_8785_form() -> None:
    offered = {**O, "extra": {**O["extra"], "flag": 1}}
    chosen = {**O, "extra": {**O["extra"], "flag": True}}
    got = X402_EXACT_EIP155_EIP3009.build(choice(doc(offered), chosen), H)
    assert got == Refusal("x402/option-not-in-document")


def test_two_link_spellings_conflict_when_both_are_present() -> None:
    info = {"type": "sha256", "value": H, "legalContextUrl": LINK, "legal_context_url": None}
    assert X402_EXACT_EIP155_EIP3009.read(doc(info=info)) == Refusal("x402/legal-context-malformed")


def test_a_legal_context_present_as_null_is_malformed_and_only_an_absent_one_is_missing() -> None:
    assert X402_EXACT_EIP155_EIP3009.read(doc(extensions={"legalContext": None})) == Refusal(
        "x402/legal-context-malformed"
    )
    assert X402_EXACT_EIP155_EIP3009.read(doc(extensions={})) == Refusal("x402/no-legal-context")


def test_a_link_over_2048_utf16_units_is_malformed_at_every_reading() -> None:
    long_https = {"type": "sha256", "value": H, "legalContextUrl": LONG_LINK}
    long_other = {"type": "sha256", "value": H, "legalContextUrl": LONG_OTHER_SCHEME}
    assert X402_EXACT_EIP155_EIP3009.read(doc(info=long_https)) == Refusal("x402/legal-context-malformed")
    assert X402_EXACT_EIP155_EIP3009.read(doc(info=long_other)) == Refusal("x402/legal-context-malformed")
    assert not is_other_scheme_link(LONG_OTHER_SCHEME)
    assert is_other_scheme_link("http://atr.seller.example/" + GRIN)


def test_an_agreement_url_over_2048_utf16_units_is_not_an_agreement_url() -> None:
    assert not is_agreement_url(LONG_AGREEMENT)
    assert is_agreement_url("https://api.seller.example/agreement/" + GRIN)
    info = {"type": "sha256", "value": H, "legalContextUrl": LINK, "legalContextAgreementUrl": LONG_AGREEMENT}
    assert X402_EXACT_EIP155_EIP3009.read(doc(info=info)) == Refusal("x402/legal-context-malformed")


def test_through_the_gate_an_agreement_url_over_2048_utf16_units_declines_before_any_fetch() -> None:
    info = {"type": "sha256", "value": H, "legalContextUrl": LINK, "legalContextAgreementUrl": LONG_AGREEMENT}
    link = serving(b"abc")
    got = run(lambda client: confirm(doc(info=info), X402_EXACT_EIP155_EIP3009, ACCOUNT, client), link)
    assert got == Declined("offer-unreadable", "x402/legal-context-malformed")
    assert link.calls == 0


def test_an_mpp_link_over_2048_utf16_units_is_malformed() -> None:
    tx = load("mpp-charge-evm-transaction.json")
    placed = placed_doc(issued("evm", "charge", tx["fixed"]["R_ENoTypes"]), H, LINK)
    assert isinstance(MPP_CHARGE_EVM_TRANSACTION.read(placed), Advertised)
    opaque = decode_string_map(placed[0]["opaque"])
    assert opaque is not None
    edited = {**opaque, "legalContextUrl": LONG_LINK}
    text = json.dumps(edited, separators=(",", ":"), ensure_ascii=False)
    long_doc = [{**placed[0], "opaque": b64u_encode(text.encode("utf-8"))}]
    assert MPP_CHARGE_EVM_TRANSACTION.read(long_doc) == Refusal("mpp/legal-context-malformed")
