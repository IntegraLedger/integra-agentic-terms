"""The summaries of the Solana, XRP Ledger, Algorand, Stacks and Hedera requests (terms' profile buyer-gate.md, rule
13), each over a request the protocol package's vectors hold, as a stock library, a hand-written wire or the pairing's
build on the file's own inputs gives it, and each expected member read from the same file: the row is cited beside it.
These are summary-sol.test.ts's rows. A request is shown as the gate hands it to the signer, every byte string as 0x and
lowercase hex. A request whose bytes name no network is shown with the signer's account's, the network of the file's
option or challenge."""

import base64
import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

import pytest
from breadth import H, LINK, offered, x402_doc
from mpp_docs import b64u, place
from support import load, piece_confirm

from integraledger_terms import (
    MPP_CHARGE_USDC_STACKS,
    MPP_SESSION_SOLANA_MEMO,
    X402_BATCH_SETTLEMENT_SOLANA,
    Confirmed,
    Refusal,
)
from integraledger_terms._gate import json_form
from integraledger_terms._summary import SUMMARIES, summary_of
from integraledger_terms._summary_sol import (
    algorand_transfer,
    hedera_executor,
    hedera_transfer,
    solana_session_open,
    solana_transfer,
    solana_upto_open,
    stacks_transfer,
    xrpl_payment,
    xrpl_session_open,
)
from integraledger_terms._types import Payee, Summary, Validity
from integraledger_terms.bindings._svm import decode_svm_tx
from integraledger_terms.bindings._xrpl import decode_blob

SOLANA = load("x402-exact-solana.json")
UPTO = load("x402-upto-solana.json")
CHARGE = load("mpp-charge-solana.json")
USDC_SOLANA = load("mpp-charge-usdc-solana.json")
SESSION = load("mpp-session-solana.json")
XRPL = load("x402-exact-xrpl.json")
XRPL_CHARGE = load("mpp-charge-xrpl.json")
RAILS = load("mpp-session-hedera-solana-xrpl.json")
ALGORAND = load("x402-exact-algorand.json")
STACKS = load("mpp-charge-usdc-stacks.json")
HEDERA = load("x402-exact-hedera.json")
EXECUTOR = load("x402-exact-hedera-transfer-executor.json")
LCP_HEDERA = load("mpp-method-lcp-hedera.json")

DEVNET: str = SOLANA["fixed"]["option"]["network"]
XRPL_NET: str = XRPL["fixed"]["option"]["network"]
BLOCKS = Validity(not_before=None, not_after=None, unit="block")


def message_of(wire_base64: str) -> bytes:
    """The message every signer of a wire signs, by the protocol package's decoder."""
    tx = decode_svm_tx(base64.b64decode(wire_base64))
    assert not isinstance(tx, Refusal), tx
    return tx.message


def tx_json_of(blob: str) -> dict[str, Any]:
    """An XRP Ledger blob's fields, decoded, without the signature's two, as the wallet is handed them."""
    decoded = decode_blob(blob)
    assert not isinstance(decoded, Refusal), decoded
    return {k: v for k, v in decoded.tx.items() if k not in ("SigningPubKey", "TxnSignature")}


def claim_bytes(channel: str, drops: int) -> bytes:
    """A channel claim's bytes as xrpl.org's PaymentChannelClaim states them: CLM\\0, the channel id, drops as a u64
    big-endian."""
    return b"CLM\x00" + bytes.fromhex(channel) + drops.to_bytes(8, "big")


def b2(file: dict[str, Any], pairing: str) -> dict[str, Any]:
    """The B2 row of file for pairing: the offer, account and inputs the pairing's build takes."""
    found: dict[str, Any] = next(r for r in file["buyer"]["rows"] if r["name"] == "B2" and r["pairing"] == pairing)
    given: dict[str, Any] = found["input"]
    return given


def stacks_request() -> dict[str, Any]:
    r = b2(STACKS, "mpp/charge/usdc/stacks")
    confirmed = piece_confirm(r["doc"], offered(MPP_CHARGE_USDC_STACKS), r["account"], r.get("inputs", {}))
    assert isinstance(confirmed, Confirmed) and confirmed.request is not None, confirmed
    return confirmed.request


def one(account: str, amount: str) -> tuple[Payee, ...]:
    return (Payee(account=account, amount=amount),)


@dataclass(frozen=True)
class Row:
    pairing: str
    # Where the request and each expected member are read.
    source: str
    show: Callable[..., Summary | None]
    request: Callable[[], dict[str, Any]]
    # The signer's account's network, for a request that names none.
    network: str | None
    expect: Summary | None


_XS2 = RAILS["XS2"]
_XS2_DROPS = int(_XS2["expectOpenPayload"]["amount"])
_XS2_CLAIM = {"channelId": _XS2["expectChannel"], "drops": _XS2_DROPS, "bytes": claim_bytes(_XS2["expectChannel"], _XS2_DROPS)}
_HEDERA_VALIDITY = Validity(
    not_before=HEDERA["fixed"]["validStart"]["seconds"],
    not_after=str(int(HEDERA["fixed"]["validStart"]["seconds"]) + HEDERA["V2"]["expectReference"]["validDuration"]),
    unit="seconds",
)
_HEDERA_EXPECT = Summary(
    amount=HEDERA["fixed"]["O"]["amount"],
    payees=one(HEDERA["V2"]["expectReference"]["payee"], HEDERA["fixed"]["O"]["amount"]),
    asset=HEDERA["fixed"]["O"]["asset"],
    network=HEDERA["V2"]["expectReference"]["network"],
    validity=_HEDERA_VALIDITY,
    atr=b"",
)
_EXEC = EXECUTOR["build"]["expectRequest"]

ROWS = [
    Row(
        "x402/exact/solana",
        "x402-exact-solana.json V2.wireBase64 (solders 0.26.0); amount, mint, network: fixed; payee: V1.destinationAta",
        solana_transfer,
        lambda: {"kind": "solana-message", "message": message_of(SOLANA["V2"]["wireBase64"])},
        DEVNET,
        Summary(
            amount=SOLANA["fixed"]["amount"],
            payees=one(SOLANA["V1"]["destinationAta"], SOLANA["fixed"]["amount"]),
            asset=SOLANA["fixed"]["mint"],
            network=DEVNET,
            validity=BLOCKS,
            atr=b"",
        ),
    ),
    Row(
        "mpp/charge/usdc/solana",
        "mpp-charge-usdc-solana.json V2.wireBase64 (x402-exact-solana.json's V2 wire); amount, currency: fixed.request; "
        "payee: x402-exact-solana.json V1.destinationAta",
        solana_transfer,
        lambda: {"kind": "solana-message", "message": message_of(USDC_SOLANA["V2"]["wireBase64"])},
        DEVNET,
        Summary(
            amount=USDC_SOLANA["fixed"]["request"]["amount"],
            payees=one(SOLANA["V1"]["destinationAta"], USDC_SOLANA["fixed"]["request"]["amount"]),
            asset=USDC_SOLANA["fixed"]["request"]["currency"],
            network=DEVNET,
            validity=BLOCKS,
            atr=b"",
        ),
    ),
    Row(
        "mpp/charge/solana",
        "mpp-charge-solana.json sol.expectMessageBase64 (written by hand from the Solana message format); amount, "
        "recipient, currency: sol.request",
        solana_transfer,
        lambda: {"kind": "solana-message", "message": base64.b64decode(CHARGE["sol"]["expectMessageBase64"])},
        DEVNET,
        Summary(
            amount=CHARGE["sol"]["request"]["amount"],
            payees=one(CHARGE["sol"]["request"]["recipient"], CHARGE["sol"]["request"]["amount"]),
            asset=CHARGE["sol"]["request"]["currency"],
            network=DEVNET,
            validity=BLOCKS,
            atr=b"",
        ),
    ),
    Row(
        "x402/upto/solana",
        "x402-upto-solana.json EU3.wireBase64 (solders 0.26.0); amount, payTo, asset, network: fixed.option",
        solana_upto_open,
        lambda: {"kind": "solana-message", "message": message_of(UPTO["EU3"]["wireBase64"])},
        UPTO["fixed"]["option"]["network"],
        Summary(
            maximum=UPTO["fixed"]["option"]["amount"],
            payees=one(UPTO["fixed"]["option"]["payTo"], UPTO["fixed"]["option"]["amount"]),
            deposit=UPTO["fixed"]["option"]["amount"],
            asset=UPTO["fixed"]["option"]["asset"],
            network=UPTO["fixed"]["option"]["network"],
            validity=BLOCKS,
            atr=b"",
        ),
    ),
    Row(
        "mpp/session/solana/memo",
        "mpp-session-solana.json memo.expectMessageBase64 and expectChannel; cap (the deposit), recipient, currency: "
        "fixed.memoRequest",
        solana_session_open,
        lambda: {
            "kind": "solana-session-open",
            "message": base64.b64decode(SESSION["memo"]["expectMessageBase64"]),
            "size": SESSION["memo"]["expectSize"],
            "channel": SESSION["memo"]["expectChannel"],
        },
        DEVNET,
        Summary(
            payees=one(SESSION["fixed"]["memoRequest"]["recipient"], SESSION["fixed"]["memoRequest"]["cap"]),
            deposit=SESSION["fixed"]["memoRequest"]["cap"],
            asset=SESSION["fixed"]["memoRequest"]["currency"],
            network=DEVNET,
            validity=BLOCKS,
            atr=b"",
        ),
    ),
    Row(
        "x402/exact/xrpl",
        "x402-exact-xrpl.json V2.expectTxJson (xrpl-py 4.1.0); amount, payTo, asset, network: fixed.option; "
        "LastLedgerSequence: V2.build",
        xrpl_payment,
        lambda: {"kind": "xrpl-tx", "txJson": XRPL["V2"]["expectTxJson"]},
        XRPL_NET,
        Summary(
            amount=XRPL["fixed"]["option"]["amount"],
            payees=one(XRPL["fixed"]["option"]["payTo"], XRPL["fixed"]["option"]["amount"]),
            asset=XRPL["fixed"]["option"]["asset"],
            network=XRPL_NET,
            validity=Validity(not_before=None, not_after=str(XRPL["V2"]["build"]["lastLedgerSequence"]), unit="ledger"),
            atr=b"",
        ),
    ),
    Row(
        "mpp/charge/xrpl",
        "mpp-charge-xrpl.json V3.blob (xrpl-py 4.1.0) decoded, its fields but the signature's, as build.case states; "
        "amount, recipient, currency: fixed.request; LastLedgerSequence: build",
        xrpl_payment,
        lambda: {"kind": "xrpl-tx", "txJson": tx_json_of(XRPL_CHARGE["V3"]["blob"])},
        XRPL_NET,
        Summary(
            amount=XRPL_CHARGE["fixed"]["request"]["amount"],
            payees=one(XRPL_CHARGE["fixed"]["request"]["recipient"], XRPL_CHARGE["fixed"]["request"]["amount"]),
            asset=XRPL_CHARGE["fixed"]["request"]["currency"],
            network=XRPL_NET,
            validity=Validity(not_before=None, not_after=str(XRPL_CHARGE["build"]["lastLedgerSequence"]), unit="ledger"),
            atr=b"",
        ),
    ),
    Row(
        "mpp/charge/xrpl",
        "mpp-charge-xrpl.json build.issued.expectTxJson (the stock xrpl-mpp-sdk client's Payment of an issued currency): "
        "an amount with no base unit, not summarised",
        xrpl_payment,
        lambda: {"kind": "xrpl-tx", "txJson": XRPL_CHARGE["build"]["issued"]["expectTxJson"]},
        XRPL_NET,
        None,
    ),
    Row(
        "mpp/session/xrpl",
        "mpp-session-hedera-solana-xrpl.json XS2.expectTxJson (written by hand from xrpl.org), expectChannel; the first "
        "claim's drops, expectOpenPayload.amount; deposit, account: XS2",
        xrpl_session_open,
        lambda: {"kind": "xrpl-session-open", "txJson": _XS2["expectTxJson"], "claim": _XS2_CLAIM},
        XRPL_NET,
        Summary(
            amount=_XS2["expectOpenPayload"]["amount"],
            payees=one(_XS2["expectTxJson"]["Destination"], _XS2["expectOpenPayload"]["amount"]),
            deposit=_XS2["deposit"],
            closable_by=(_XS2["account"], _XS2["expectTxJson"]["Destination"]),
            asset="XRP",
            network=XRPL_NET,
            validity=Validity(not_before=None, not_after=str(_XS2["lastLedgerSequence"]), unit="ledger"),
            atr=b"",
        ),
    ),
    Row(
        "mpp/session/xrpl",
        "mpp-session-hedera-solana-xrpl.json XS2.withCancelAfter.expectTxJson; its end in Unix seconds, XS2.expectUntil",
        xrpl_session_open,
        lambda: {"kind": "xrpl-session-open", "txJson": _XS2["withCancelAfter"]["expectTxJson"], "claim": _XS2_CLAIM},
        XRPL_NET,
        Summary(
            amount=_XS2["expectOpenPayload"]["amount"],
            payees=one(_XS2["expectTxJson"]["Destination"], _XS2["expectOpenPayload"]["amount"]),
            end=str(_XS2["expectUntil"]),
            deposit=_XS2["deposit"],
            closable_by=(_XS2["account"], _XS2["expectTxJson"]["Destination"]),
            asset="XRP",
            network=XRPL_NET,
            validity=Validity(not_before=None, not_after=str(_XS2["lastLedgerSequence"]), unit="ledger"),
            atr=b"",
        ),
    ),
    Row(
        "x402/exact/algorand",
        "x402-exact-algorand.json V2.expectBytesToSign (py-algorand-sdk 2.12.0); amount, payTo, asset, network: fixed.O; "
        "firstValid: fixed.params; lastValid: V3.expectReference",
        algorand_transfer,
        lambda: {"kind": "algorand-txn", "bytes": bytes.fromhex(ALGORAND["V2"]["expectBytesToSign"].removeprefix("0x"))},
        None,
        Summary(
            amount=ALGORAND["fixed"]["O"]["amount"],
            payees=one(ALGORAND["fixed"]["O"]["payTo"], ALGORAND["fixed"]["O"]["amount"]),
            asset=ALGORAND["fixed"]["O"]["asset"],
            network=ALGORAND["fixed"]["O"]["network"],
            validity=Validity(
                not_before=ALGORAND["fixed"]["params"]["firstValid"],
                not_after=ALGORAND["V3"]["expectReference"]["lastValid"],
                unit="round",
            ),
            atr=b"",
        ),
    ),
    Row(
        "mpp/charge/usdc/stacks",
        "mpp-charge-usdc-stacks.json buyer B2's offer, account and inputs, through the pairing's build; amount, "
        "recipient, contract, network: fixed",
        stacks_transfer,
        stacks_request,
        None,
        Summary(
            amount=STACKS["fixed"]["amount"],
            payees=one(STACKS["fixed"]["recipient"], STACKS["fixed"]["amount"]),
            asset=STACKS["fixed"]["contract"],
            network=STACKS["fixed"]["network"],
            validity=Validity(not_before=None, not_after=None, unit="seconds"),
            atr=b"",
        ),
    ),
    Row(
        "x402/exact/hedera",
        "x402-exact-hedera.json V2.expectBodyBytes; payer, payee, rows, valid start and duration, network: "
        "V2.expectReference",
        hedera_transfer,
        lambda: {"kind": "hedera-body", "bodyBytes": bytes.fromhex(HEDERA["V2"]["expectBodyBytes"].removeprefix("0x"))},
        HEDERA["V2"]["expectReference"]["network"],
        _HEDERA_EXPECT,
    ),
    Row(
        "mpp/charge/lcp/hedera",
        "mpp-method-lcp-hedera.json build[0].expectBodyBytes (the same body as x402-exact-hedera.json V2); expected as "
        "that row's",
        hedera_transfer,
        lambda: {"kind": "hedera-body", "bodyBytes": bytes.fromhex(LCP_HEDERA["build"][0]["expectBodyBytes"].removeprefix("0x"))},
        HEDERA["V2"]["expectReference"]["network"],
        _HEDERA_EXPECT,
    ),
    Row(
        "x402/exact/hedera/transfer-executor",
        "x402-exact-hedera-transfer-executor.json build.expectRequest",
        hedera_executor,
        lambda: dict(_EXEC),
        None,
        Summary(
            amount=_EXEC["amount"],
            payees=one(_EXEC["payTo"], _EXEC["amount"]),
            asset=_EXEC["asset"],
            network=_EXEC["network"],
            validity=Validity(not_before=None, not_after=str(_EXEC["validBefore"]), unit="seconds"),
            grant={"executors": _EXEC["executors"], "asset": _EXEC["asset"], "payTo": _EXEC["payTo"], "amount": _EXEC["amount"]},
            atr=b"",
        ),
    ),
]


@pytest.mark.parametrize("row", [pytest.param(r, id=f"{r.pairing}: {r.source}") for r in ROWS])
def test_the_summary_of_a_request_the_vectors_hold(row: Row) -> None:
    assert SUMMARIES[row.pairing].show is row.show
    request = json_form(row.request())
    assert row.show(request, row.network, None) == row.expect
    if row.network is None and row.expect is not None:
        # A request that names its own network is summarised by the gate's registry as it stands.
        atr = b"{}"
        assert summary_of(row.pairing, request, atr) == replace(row.expect, atr=atr)


# x402/batch-settlement/solana's opening, a batch of the open message and the first voucher, built by the pairing's own
# build on x402-batch-settlement.json's fixed.svm inputs; and mpp/session/solana/memo's opening under the challenge whose
# request carries mpp-session-solana.json's fixed.splits8, whose built size is the file's memo.eightSplitsSize. Each
# expected member is read from the file: the deposit, the mint, the payee and the voucher's amount, the option's; the
# shares, each split's bps of the deposit and the payee the rest (the payment-channels program: "Each shareBps must be
# non-zero and Σbps must be at most 10_000", the channel's payee keeping the remainder). These are summary-sol.test.ts's.
BATCH = load("x402-batch-settlement.json")


def test_x402_batch_settlement_solana_the_openings_open_and_first_voucher_built_on_fixed_svm() -> None:
    s = BATCH["fixed"]["svm"]
    option = s["option"]
    doc = x402_doc({**option, "extra": {**option["extra"], "memo": "lcp:sha256:" + H}}, BATCH["fixed"]["resource"])
    inputs = {k: s[v] for k, v in (("payerAuthorizer", "payer"), ("deposit", "deposit"), ("openSlot", "openSlot"),
              ("tokenProgram", "tokenProgram"), ("recentBlockhash", "blockhash"), ("salt", "salt"))}
    confirmed = piece_confirm(doc, X402_BATCH_SETTLEMENT_SOLANA, f"{option['network']}:{s['payer']}", inputs)
    assert isinstance(confirmed, Confirmed) and confirmed.request is not None, confirmed
    atr = b"{}"
    assert summary_of("x402/batch-settlement/solana", confirmed.request, atr, option["network"]) == Summary(
        amount=option["amount"],
        payees=one(option["payTo"], option["amount"]),
        deposit=s["deposit"],
        asset=option["asset"],
        network=option["network"],
        validity=BLOCKS,
        atr=atr,
    )


def test_mpp_session_solana_memo_an_opening_whose_distribution_holds_the_eight_splits_of_100_bps() -> None:
    row = b2(SESSION, "mpp/session/solana/memo")
    challenge = {k: v for k, v in row["doc"][0].items() if k not in ("id", "opaque")}
    request = json.loads(base64.urlsafe_b64decode(challenge["request"] + "=" * (-len(challenge["request"]) % 4)))
    challenge["request"] = b64u(json.dumps({**request, "splits": SESSION["fixed"]["splits8"]}, separators=(",", ":")))
    doc = place([challenge], H, LINK, challenge)
    assert not isinstance(doc, Refusal), doc
    choice = {k: v for k, v in SESSION["memo"]["choice"].items() if k != "payer"}
    confirmed = piece_confirm(doc, MPP_SESSION_SOLANA_MEMO, row["account"], choice)
    assert isinstance(confirmed, Confirmed) and confirmed.request is not None, confirmed
    assert confirmed.request["kind"] == "solana-session-open"
    assert confirmed.request["size"] == SESSION["memo"]["eightSplitsSize"]
    cap = int(SESSION["fixed"]["memoRequest"]["cap"])
    shares = [(s["recipient"], cap * s["bps"] // 10_000) for s in SESSION["fixed"]["splits8"]]
    rest = cap - sum(a for _, a in shares)
    atr = b"{}"
    assert summary_of("mpp/session/solana/memo", confirmed.request, atr, DEVNET) == Summary(
        payees=tuple(Payee(account=r, amount=str(a)) for r, a in shares) + one(SESSION["fixed"]["memoRequest"]["recipient"], str(rest)),
        deposit=SESSION["fixed"]["memoRequest"]["cap"],
        asset=SESSION["fixed"]["memoRequest"]["currency"],
        network=DEVNET,
        validity=BLOCKS,
        atr=atr,
    )
