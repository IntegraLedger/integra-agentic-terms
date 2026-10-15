"""Every x402 pairing's read offers an option's amount only as the canonical decimal of a positive integer.

x402 v2's PaymentRequirements gives amount as a string of atomic token units, with "10000" in its examples
(specs/x402-specification-v2.md at x402-foundation/x402 e95b06661e), and @integraledger/lcp's option filters hold it to
digits only, the first not 0. Two schemes define the member otherwise, and their pairings keep that definition:
batch-settlement on EVM and Solana takes a zero price ("the facilitator MUST validate it as a non-negative base-10
integer string", specs/schemes/batch-settlement/scheme_batch_settlement_evm.md, "Not below claimed"), and XRPL exact
gives an issued currency's amount as "the exact XRPL issued-currency value string", with "10.5" and "0.01" as examples
(specs/schemes/exact/scheme_exact_xrpl.md, "IOU (Issued Currency)"). The options are the ones @integraledger/lcp's
vector files hold, and every expected answer is the protocol package's own for the same input."""

from typing import Any

import pytest

from integraledger_terms import (
    X402_BATCH_SETTLEMENT_EIP155,
    X402_BATCH_SETTLEMENT_SOLANA,
    X402_EXACT_XRPL,
    Refusal,
)
from integraledger_terms.bindings._lcp import to_lcp_string

from breadth import H, x402_doc
from support import load
from x402_options import BINDINGS, first_offered, offering

NOT_OFFERED = Refusal("x402/no-payable-option")
MALFORMED = Refusal("x402/option-malformed")

# Each amount outside the rule: zero, a leading zero, not an integer, negative, empty, and a number.
OUTSIDE: list[tuple[str, object]] = [
    ('"0"', "0"),
    ('"010"', "010"),
    ('"1.5"', "1.5"),
    ('"-1"', "-1"),
    ('""', ""),
    ("10000", 10000),
]
ZERO_PRICE = {"x402/batch-settlement/eip155", "x402/batch-settlement/solana"}


def with_amount(option: dict[str, Any], amount: object) -> dict[str, Any]:
    return {**option, "amount": amount}


def offered(pairing: str, *options: Any) -> Any:
    """The options the pairing's read offers of a document holding the options, or its refusal."""
    answer = BINDINGS[pairing].read(offering(*options))
    return answer if isinstance(answer, Refusal) else answer.offer["options"]


def test_the_rule_is_read_on_the_29_x402_pairings() -> None:
    """The test below runs once per x402 binding: the 29 x402 pairings of the protocol package's BINDINGS."""
    assert len(BINDINGS) == 29


@pytest.mark.parametrize("pairing", sorted(BINDINGS))
def test_an_x402_option_is_offered_only_with_an_amount_that_is_a_positive_integer(pairing: str) -> None:
    """The option set to "10" is offered; set to any amount outside the rule it is not, but for "0" on the two
    zero-price pairings; and of a document holding all seven, read offers the "10" one alone, or the "0" one beside it
    on those two."""
    option = first_offered(pairing, lambda o: with_amount(o, "10"))
    assert option is not None, f"no vector option that {pairing}'s read offers"
    assert offered(pairing, option) == [option]
    zero = pairing in ZERO_PRICE
    for label, amount in OUTSIDE:
        changed = with_amount(option, amount)
        expected = [changed] if zero and amount == "0" else NOT_OFFERED
        assert (label, offered(pairing, changed)) == (label, expected)
    every = [with_amount(option, amount) for _, amount in OUTSIDE] + [option]
    assert offered(pairing, *every) == ([every[0], option] if zero else [option])


def test_no_batch_settlement_pairing_offers_amount_00() -> None:
    """ "00" is zero written with a leading zero: the EVM and Solana pairings take a zero price only as "0", and the
    Cloudflare pairing takes none."""
    batch = sorted(p for p in BINDINGS if p.startswith("x402/batch-settlement/"))
    assert batch == ["x402/batch-settlement/cloudflare", "x402/batch-settlement/eip155", "x402/batch-settlement/solana"]
    for pairing in batch:
        option = first_offered(pairing, lambda o: with_amount(o, "10"))
        assert option is not None, pairing
        assert (pairing, offered(pairing, with_amount(option, "00"))) == (pairing, NOT_OFFERED)


# ── XRPL: an issued currency's amount, payTo and extra.issuer ─────────────────────────────────────────────────────

XRPL = load("x402-exact-xrpl.json")
XRP: dict[str, Any] = XRPL["fixed"]["option"]
# The issued-currency option of scheme_exact_xrpl.md, with x402-exact-xrpl.json's destination as payTo: the example's
# payTo, rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9, fails the classic address checksum.
ISSUER = "rMwjYedjc7qqtKYVLiAccJSmCwih4LnE2q"
IOU: dict[str, Any] = {
    "scheme": "exact",
    "network": "xrpl:0",
    "asset": "524C555344000000000000000000000000000000",
    "payTo": "rpjfAeE3DeeHPFnN2PgGFW5YxnZFAjrEyN",
    "amount": "10.5",
    "maxTimeoutSeconds": 600,
    "extra": {"areFeesSponsored": False, "assetTransferMethod": "ticketSequence", "issuer": ISSUER},
}


def zeros(n: int) -> str:
    return "0" * n


# rippled 3.4.1 (XRPLF/rippled 00e64075) reads an issued value with partsFromString
# (src/libxrpl/protocol/STNumber.cpp:159-216): no leading zero, and the digits with the point removed read as a uint64
# that STAmount::iou casts to int64 (src/libxrpl/protocol/STAmount.cpp:291). An STAmount value is 10^15 to 10^16 - 1 at
# an offset of -96 to 80 (include/xrpl/protocol/STAmount.h:35-40, 61-68), and IOUAmount rounds past 16 significant
# digits and reads a value below 10^-81 as zero (src/libxrpl/protocol/IOUAmount.cpp:29-36, 58-68).
ISSUED_OFFERED: list[tuple[str, str]] = [
    ("the scheme's example", "10.5"),
    ("the scheme's example", "0.01"),
    ("one", "1"),
    ("16 significant digits", "9999999999999999"),
    ("16 significant digits with a fraction", "1234567890.123456"),
    ("the largest value of 16 significant digits whose digits are below 2^63", "9223372036854775000"),
    ("10^-81, the smallest positive STAmount value", "0." + zeros(80) + "1"),
]
ISSUED_REFUSED: list[tuple[str, str]] = [
    ("zero", "0"),
    ("zero", "0.0"),
    ("zero", "0.00"),
    ("negative", "-1"),
    ("a leading zero", "010"),
    ("a leading zero", "010.5"),
    ("two zeros before the point", "00.5"),
    ("a fraction that ends in a zero", "10.50"),
    ("a fraction that is a bare zero", "1.0"),
    ("a fraction that ends in a zero", "0.10"),
    ("no digit before the point", ".5"),
    ("no digit after the point", "5."),
    ("an exponent", "1e3"),
    ("a sign", "+1"),
    ("17 significant digits", "12345678901234567"),
    ("17 significant digits", "1.2345678901234567"),
    ("2^63 - 1, 19 significant digits", "9223372036854775807"),
    ("17 significant digits at offset 80", "99999999999999999" + zeros(79)),
    ("10^-82, below the smallest positive STAmount value", "0." + zeros(81) + "1"),
    ("16 significant digits whose digits are not below 2^63", "9223372036854776000"),
    ("digits from 2^63 to 2^64 - 1, which rippled reads as negative", "9300000000000000000"),
    ("10^20, digits not below 2^64, which rippled cannot read", "1" + zeros(20)),
    ("the largest STAmount value written in full", "9999999999999999" + zeros(80)),
    ("10^95", "1" + zeros(95)),
    ("10^96, past the largest offset, 80", "1" + zeros(96)),
    ("10^200", "1" + zeros(200)),
    ("a value of 1,000,002 characters", "1" + zeros(1_000_000) + "1"),
    ("10^1,000,000, one significant digit in 1,000,001 characters", "1" + zeros(1_000_000)),
]


@pytest.mark.parametrize(("why", "amount"), ISSUED_OFFERED, ids=[why for why, _ in ISSUED_OFFERED])
def test_x402_exact_xrpl_offers_an_issued_value_rippled_reads_and_build_writes_it(why: str, amount: str) -> None:
    option = with_amount(IOU, amount)
    assert offered("x402/exact/xrpl", option) == [option], why
    placed = {**option, "extra": {**option["extra"], "invoiceId": to_lcp_string(H)}}
    choice = {
        "required": x402_doc(placed, {"url": "https://api.seller.example/v1/quote"}),
        "accepted": placed,
        "account": "r3sNTMefq5gsRumMYsNznnX6yzzxVH6dTC",
        "fee": "12",
        "sequence": 0,
        "ticketSequence": 7,
        "lastLedgerSequence": 1000,
    }
    unsigned = X402_EXACT_XRPL.build(choice, H)
    assert not isinstance(unsigned, Refusal), why
    tx = unsigned.request["txJson"]
    value = {"currency": IOU["asset"], "issuer": ISSUER, "value": amount}
    assert (tx["Amount"], tx["SendMax"]) == (value, value), why


@pytest.mark.parametrize(("why", "amount"), ISSUED_REFUSED, ids=[why for why, _ in ISSUED_REFUSED])
def test_x402_exact_xrpl_does_not_offer_an_issued_value_outside_that_form(why: str, amount: str) -> None:
    assert offered("x402/exact/xrpl", with_amount(IOU, amount)) == NOT_OFFERED, why


def test_x402_exact_xrpl_bound_refuses_a_payment_under_an_issued_value_of_a_million_digits() -> None:
    """More than 19 digits, leading zeros aside, are refused before any further step reads them, so the answer takes
    time linear in the amount's length. Two values: one of 1,000,002 significant digits, and 10^1,000,000, whose one
    significant digit passes the count of significant digits, so that only the guard keeps its 1,000,001 digits from
    int(), which reads no string of more than 4,300 digits. The payment is x402-exact-xrpl.json's, presented under its
    own option made this issued currency."""
    payment = XRPL["buyer"]["rows"][1]["input"]["presented"]
    accepted = payment["accepted"]
    assert not isinstance(X402_EXACT_XRPL.bound(payment), Refusal)
    for amount in ("1" + zeros(1_000_000) + "1", "1" + zeros(1_000_000)):
        issued = {**accepted, "asset": IOU["asset"], "amount": amount, "extra": {**accepted["extra"], "issuer": ISSUER}}
        assert X402_EXACT_XRPL.bound({**payment, "accepted": issued}) == MALFORMED, len(amount)


# The XRPL exact scheme gives payTo as an "XRPL classic address receiving the payment" and extra.issuer as the "Classic
# address of the IOU issuer" (scheme_exact_xrpl.md, "Field Definitions"): base58 with the XRPL alphabet of version 0, a
# 20-byte AccountID and a 4-byte checksum. rippled 3.4.1 refuses AccountID 0 as any Payment's Destination
# (src/libxrpl/tx/transactors/payment/Payment.cpp:178-184) and as an issuer (src/libxrpl/protocol/STAmount.cpp:155-158),
# and the payment engine every issued-currency Payment runs through (Payment.cpp:611-613, :638) refuses AccountID 1,
# noAccount(), as the destination or the issuer (src/libxrpl/tx/paths/PaySteps.cpp:188-190). The XRP Payment build
# writes, with no SendMax or paths, does not run through that engine (Payment.cpp:611, :756-758).
ACCOUNT_ZERO = "rrrrrrrrrrrrrrrrrrrrrhoLvTp"
EXAMPLE_PAY_TO = "rN7n3473SaZBCG4dFL83w7a1RXtXtbk2D9"
DESTINATION = "rpjfAeE3DeeHPFnN2PgGFW5YxnZFAjrEyN"
# The file's destination as a testnet X address.
TESTNET_X_ADDRESS = "T776755V6AJXyATM72Jk5jWeR6z1NhUFJdqSgjCYdD7CgN7"
ACCOUNT_ONE = "rrrrrrrrrrrrrrrrrrrrBZbvji"
IOU_ON_XRP_FILE: dict[str, Any] = {
    **XRP,
    "asset": "524C555344000000000000000000000000000000",
    "amount": "10.5",
    "extra": {"areFeesSponsored": False, "issuer": ISSUER},
}


def with_issuer(issuer: object) -> dict[str, Any]:
    return {**IOU_ON_XRP_FILE, "extra": {"areFeesSponsored": False, "issuer": issuer}}


ADDRESS_REFUSED: list[tuple[str, dict[str, Any]]] = [
    ("payTo, the scheme's example, whose checksum fails", {**XRP, "payTo": EXAMPLE_PAY_TO}),
    ("payTo, the file's destination with its last character changed", {**XRP, "payTo": DESTINATION[:-1] + "M"}),
    ("payTo, the file's destination as a testnet X address", {**XRP, "payTo": TESTNET_X_ADDRESS}),
    ("payTo with a trailing space", {**XRP, "payTo": "rpjfAeE3DeeHPFnN2PgGFW5YxnZFAjrEyN "}),
    ("payTo, an EVM address", {**XRP, "payTo": "0x0000000000000000000000000000000000000000"}),
    ("an issued currency's payTo, whose checksum fails", {**IOU_ON_XRP_FILE, "payTo": EXAMPLE_PAY_TO}),
    ("an issued currency's issuer, whose checksum fails", with_issuer("rMwjYedjc7qqtKYVLiAccJSmCwih4LnE2r")),
    ("an issued currency with no issuer", {**IOU_ON_XRP_FILE, "extra": {"areFeesSponsored": False}}),
    ("an issued currency's issuer 1, a number", with_issuer(1)),
    ("payTo AccountID 0", {**XRP, "payTo": ACCOUNT_ZERO}),
    ("an issued currency's payTo AccountID 0", {**IOU_ON_XRP_FILE, "payTo": ACCOUNT_ZERO}),
    ("an issued currency's payTo AccountID 1", {**IOU_ON_XRP_FILE, "payTo": ACCOUNT_ONE}),
    ("an issued currency's issuer AccountID 0", with_issuer(ACCOUNT_ZERO)),
    ("an issued currency's issuer AccountID 1", with_issuer(ACCOUNT_ONE)),
]


def test_x402_exact_xrpl_offers_the_file_option_an_issued_currency_and_an_xrp_pay_to_of_account_id_1() -> None:
    xrp_to_one = {**XRP, "payTo": ACCOUNT_ONE}
    for option in (XRP, IOU_ON_XRP_FILE, xrp_to_one):
        assert offered("x402/exact/xrpl", option) == [option], option["payTo"]


@pytest.mark.parametrize(("why", "option"), ADDRESS_REFUSED, ids=[why for why, _ in ADDRESS_REFUSED])
def test_x402_exact_xrpl_does_not_offer_a_pay_to_or_issuer_rippled_refuses(why: str, option: dict[str, Any]) -> None:
    assert offered("x402/exact/xrpl", option) == NOT_OFFERED, why


# ── batch settlement: a zero price ────────────────────────────────────────────────────────────────────────────────

BATCH = load("x402-batch-settlement.json")
EVM = BATCH["fixed"]["evm"]
SVM = BATCH["fixed"]["svm"]
RESOURCE = BATCH["fixed"]["resource"]


def evm_opening(amount: str) -> Any:
    option = {**EVM["option"], "amount": amount}
    doc = x402_doc(option, RESOURCE)
    choice = {
        "required": doc,
        "accepted": doc["accepts"][0],
        "from": EVM["payer"],
        "now": EVM["now"],
        "payerAuthorizer": EVM["payerAuthorizer"],
        "deposit": int(EVM["deposit"]),
        "authSalt": EVM["authSalt"],
    }
    return X402_BATCH_SETTLEMENT_EIP155.build(choice, H)


def test_x402_batch_settlement_eip155_a_zero_price_opens_no_channel() -> None:
    """On EVM a zero price is paid within a channel, never by its opening: the facilitator's "Not below claimed" check
    requires a voucher's maxClaimableAmount strictly greater than totalClaimed, 0 on a new channel, and the server's
    "Verify" step requires a deposit's voucher to equal chargedCumulativeAmount + amount, 0 there
    (scheme_batch_settlement_evm.md). So read offers amount "0", the opening's build refuses it x402/option-malformed
    and builds amount "1", and build_within writes a voucher of 1 under "0"."""
    zero = {**EVM["option"], "amount": "0"}
    doc = x402_doc(zero, RESOURCE)
    assert not isinstance(X402_BATCH_SETTLEMENT_EIP155.read(doc), Refusal)
    assert evm_opening("0") == MALFORMED
    assert not isinstance(evm_opening("1"), Refusal)
    within = {"required": doc, "accepted": doc["accepts"][0], "channelConfig": EVM["config"], "maxClaimableAmount": 1}
    unsigned = X402_BATCH_SETTLEMENT_EIP155.build_within(within, H)
    assert not isinstance(unsigned, Refusal), unsigned
    assert len(unsigned.requests) == 1


def test_x402_batch_settlement_solana_an_opening_takes_a_zero_price() -> None:
    """The Solana text's strict floor names voucher verify and the top-up deposit only ("Monotonic amount",
    scheme_batch_settlement_svm.md), so the Solana opening's build takes amount "0"."""
    zero = {**SVM["option"], "amount": "0", "extra": {**SVM["option"]["extra"], "memo": to_lcp_string(H)}}
    doc = x402_doc(zero, RESOURCE)
    choice = {
        "required": doc,
        "accepted": doc["accepts"][0],
        "payer": SVM["payer"],
        "payerAuthorizer": SVM["payer"],
        "deposit": int(SVM["deposit"]),
        "salt": int(SVM["salt"]),
        "openSlot": int(SVM["openSlot"]),
        "tokenProgram": SVM["tokenProgram"],
        "recentBlockhash": SVM["blockhash"],
    }
    assert not isinstance(X402_BATCH_SETTLEMENT_SOLANA.build(choice, H), Refusal)
