"""Every x402 build checks H first, then the members of the buyer's choice whose form needs neither the document nor
the option, then the document and the option, as @integraledger/lcp 0.4.1's builds do: one fault gets one code,
whatever else the choice holds. Each row gives a choice with two faults, H or one member malformed and a document that
is not x402 v2, and expects the code the protocol package gives the first of them. The valid members are the pairing's
vector file's fixed values; each malformed one is a value of another form, refused with the code the protocol
package's build gives that member."""

from typing import Any

import pytest

from integraledger_terms import Refusal
from integraledger_terms.bindings._svm import TOKEN

from breadth import H
from support import load
from x402_options import BINDINGS

# A document that is not x402 v2: the document check every build makes refuses it x402/not-v2.
NOT_V2 = {"required": {"x402Version": 1, "accepts": []}, "accepted": {}}
# A value that is not a 32-byte hash.
BAD_H = "0x12"

EVM = load("x402-exact-eip155-eip3009.json")["fixed"]
BATCH = load("x402-batch-settlement.json")["fixed"]
SOL = load("x402-exact-solana.json")["fixed"]
UPTO = load("x402-upto-solana.json")["fixed"]
NEAR = load("x402-exact-near.json")["fixed"]
TVM = load("x402-exact-tvm.json")["fixed"]
AVM = load("x402-exact-algorand.json")["fixed"]
XLM = load("x402-exact-stellar.json")["fixed"]
STARK = load("x402-exact-starknet.json")["fixed"]
TRON = load("x402-exact-tron-lcp-trc20-memo.json")["fixed"]
HBAR = load("x402-exact-hedera.json")["fixed"]
EXECUTOR = load("x402-exact-hedera-transfer-executor.json")["fixed"]
CASPER = load("x402-exact-casper.json")["fixed"]
CCD = load("x402-exact-ccd.json")["fixed"]
XRPL = load("x402-exact-xrpl.json")["fixed"]

EVM_MEMBERS = {"from": EVM["payer"], "now": EVM["now"]}
EVM_BAD = [("from", "0x12", "x402/option-malformed"), ("now", -1, "x402/option-malformed")]
SOL_PAYER = {"payer": SOL["payer"], "tokenProgram": TOKEN, "recentBlockhash": SOL["blockhash"]}
SOL_BAD = [
    ("payer", "x", "svm/input-malformed"),
    ("tokenProgram", SOL["payer"], "svm/input-malformed"),
    ("recentBlockhash", "x", "svm/input-malformed"),
    ("computeUnitLimit", 2**32, "svm/input-malformed"),
    ("computeUnitPrice", -1, "svm/input-malformed"),
]
ALGORAND_PARAMS = {
    "firstValid": int(AVM["params"]["firstValid"]),
    "genesisHash": AVM["params"]["genesisHash"],
    "genesisId": AVM["params"]["genesisId"],
    "minFee": int(AVM["params"]["minFee"]),
    "feePerByte": int(AVM["params"]["feePerByte"]),
}
TRON_BLOCK = {"number": int(TRON["refBlock"]["number"]), "id": TRON["refBlock"]["id"]}

# pairing: (the choice's valid members, H's code, [(member, malformed value, its code)]).
ROWS: dict[str, tuple[dict[str, Any], str, list[tuple[str, Any, str]]]] = {
    "x402/exact/eip155/eip3009": (EVM_MEMBERS, "x402/payload-malformed", EVM_BAD),
    "x402/exact/eip155/permit2": (EVM_MEMBERS, "x402/payload-malformed", EVM_BAD),
    "x402/upto/eip155/permit2": (EVM_MEMBERS, "x402/payload-malformed", EVM_BAD),
    "x402/exact/eip155/erc7710": (EVM_MEMBERS, "x402/payload-malformed", EVM_BAD),
    "x402/exact/eip155/erc7710-salt": (EVM_MEMBERS, "x402/payload-malformed", EVM_BAD),
    "x402/auth-capture/eip155/eip3009": (EVM_MEMBERS, "x402/payload-malformed", EVM_BAD),
    "x402/auth-capture/eip155/permit2": (EVM_MEMBERS, "x402/payload-malformed", EVM_BAD),
    "x402/batch-settlement/eip155": (
        {
            "from": BATCH["evm"]["payer"],
            "payerAuthorizer": BATCH["evm"]["payerAuthorizer"],
            "authSalt": BATCH["evm"]["authSalt"],
            "deposit": int(BATCH["evm"]["deposit"]),
            "now": BATCH["evm"]["now"],
        },
        "x402/option-malformed",
        [
            ("from", "0x12", "x402/option-malformed"),
            ("payerAuthorizer", "0x12", "x402/option-malformed"),
            ("authSalt", "0x01", "x402/option-malformed"),
            ("deposit", 0, "x402/option-malformed"),
            ("now", -1, "x402/option-malformed"),
        ],
    ),
    "x402/batch-settlement/cloudflare": ({}, "x402/legal-context-conflict", []),
    "x402/exact/solana": (
        {**SOL_PAYER, "decimals": SOL["decimals"]},
        "x402/payload-malformed",
        [*SOL_BAD, ("decimals", 256, "svm/input-malformed")],
    ),
    "x402/upto/solana": (
        {**SOL_PAYER, "nonce": int(UPTO["nonce"]), "openSlot": int(UPTO["openSlot"]), "now": UPTO["now"]},
        "x402/payload-malformed",
        [
            *SOL_BAD,
            ("nonce", -1, "svm/input-malformed"),
            ("openSlot", 2**53, "svm/input-malformed"),
            ("now", -1, "svm/input-malformed"),
        ],
    ),
    "x402/batch-settlement/solana": (
        {
            **SOL_PAYER,
            "deposit": int(BATCH["svm"]["deposit"]),
            "payerAuthorizer": BATCH["svm"]["config"]["payerAuthorizer"],
            "salt": int(BATCH["svm"]["salt"]),
            "openSlot": int(BATCH["svm"]["openSlot"]),
        },
        "x402/payload-malformed",
        [
            *SOL_BAD,
            ("deposit", 0, "svm/input-malformed"),
            ("payerAuthorizer", "x", "svm/input-malformed"),
            ("salt", -1, "svm/input-malformed"),
            ("openSlot", 2**53, "svm/input-malformed"),
        ],
    ),
    "x402/exact/near": (
        {
            "payer": NEAR["payer"],
            "publicKey": NEAR["publicKey"],
            "accessKeyNonce": int(NEAR["accessKeyNonce"]),
            "finalHeight": int(NEAR["finalHeight"]),
        },
        "x402/payload-malformed",
        [
            ("payer", "Payer", "x402/option-malformed"),
            ("publicKey", "ed25519:x", "x402/option-malformed"),
            ("accessKeyNonce", -1, "x402/option-malformed"),
            ("finalHeight", 2**64, "x402/option-malformed"),
        ],
    ),
    "x402/exact/tvm": (
        {
            "wallet": TVM["wallet"],
            "jettonWallet": TVM["jettonWallet"],
            "walletId": TVM["walletId"],
            "seqno": TVM["seqno"],
            "now": TVM["now"],
            "attachNanotons": int(TVM["attachNanotons"]),
        },
        "x402/payload-malformed",
        [
            ("wallet", "x", "x402/option-malformed"),
            ("jettonWallet", "0:12", "x402/option-malformed"),
            ("walletId", 2**32, "x402/option-malformed"),
            ("seqno", -1, "x402/option-malformed"),
            ("now", -1, "x402/option-malformed"),
            ("attachNanotons", 2**120, "x402/option-malformed"),
            ("stateInit", "AA=A", "tvm/boc-malformed"),
        ],
    ),
    "x402/exact/algorand": (
        {"payer": AVM["payer"], "params": ALGORAND_PARAMS},
        "x402/payload-malformed",
        [
            ("payer", AVM["payer"].lower(), "avm/option-malformed"),
            ("params", {**ALGORAND_PARAMS, "firstValid": -1}, "avm/option-malformed"),
            ("params", {**ALGORAND_PARAMS, "genesisHash": "AAA="}, "avm/network-mismatch"),
        ],
    ),
    "x402/exact/stellar": (
        {"currentLedger": 988, "payer": XLM["payer"]},
        "x402/payload-malformed",
        [
            ("currentLedger", -1, "stellar/tx-malformed"),
            ("payer", None, "stellar/payer-mismatch"),
            ("payer", "x", "stellar/payer-mismatch"),
        ],
    ),
    "x402/exact/starknet": (
        {"from": STARK["from"], "now": STARK["now"]},
        "x402/payload-malformed",
        [("from", "x", "starknet/felt-malformed"), ("now", -1, "starknet/option-malformed")],
    ),
    "x402/exact/tron/lcp-trc20-memo": (
        {"payer": TRON["payer"], "feeLimit": int(TRON["feeLimit"]), "refBlock": TRON_BLOCK, "now": int(TRON["now"])},
        "x402/payload-malformed",
        [
            ("payer", "x", "tron/address-malformed"),
            ("feeLimit", 0, "tron/fee-limit"),
            ("refBlock", {**TRON_BLOCK, "number": -1}, "tron/tx-malformed"),
            ("now", 0, "tron/tx-malformed"),
        ],
    ),
    "x402/exact/hedera": (
        {
            "payer": HBAR["payer"],
            "node": HBAR["node"],
            "validStart": {"seconds": int(HBAR["validStart"]["seconds"]), "nanos": HBAR["validStart"]["nanos"]},
            "maxFee": int(HBAR["maxFee"]),
        },
        "x402/payload-malformed",
        [
            ("payer", "x", "hedera/option-malformed"),
            ("node", "x", "hedera/option-malformed"),
            ("validStart", {"seconds": -1, "nanos": 0}, "hedera/option-malformed"),
            ("maxFee", -1, "hedera/option-malformed"),
            ("decimals", -1, "hedera/option-malformed"),
        ],
    ),
    "x402/exact/hedera/transfer-executor": (
        {"now": EXECUTOR["now"]},
        "x402/payload-malformed",
        [("now", -1, "hedera/option-malformed")],
    ),
    "x402/exact/casper": (
        {"from": CASPER["from"], "now": CASPER["now"]},
        "casper/payload-malformed",
        [("from", "x", "casper/address-malformed"), ("now", -1, "casper/option-malformed")],
    ),
    "x402/exact/ccd": ({"now": CCD["now"]}, "ccd/memo-not-lcp", [("now", -1, "ccd/option-malformed")]),
    "x402/exact/xrpl": (
        {"account": XRPL["payer"], "fee": "12", "lastLedgerSequence": 100},
        "x402/payload-malformed",
        [
            ("account", 5, "x402/option-malformed"),
            ("fee", "x", "x402/option-malformed"),
            ("lastLedgerSequence", -1, "x402/option-malformed"),
        ],
    ),
    "x402/exact/sui": ({}, "x402/payload-malformed", []),
    "x402/exact/aptos": ({}, "x402/payload-malformed", []),
    "x402/exact/cardano": ({}, "x402/payload-malformed", []),
    "x402/exact/polkadot/lcp-assets-remark": ({}, "x402/payload-malformed", []),
    "x402/exact/lnbtc": ({}, "ln/no-metadata", []),
}

# The one x402 build that reads no H: its option's invoice is held to the ATR's own slot.
NO_H = {"x402/exact/lnbtc/invoice-named"}

H_ROWS = [(pairing, h) for pairing in ROWS for h in (BAD_H, *(["any"] if pairing == "x402/exact/lnbtc" else []))]
MEMBER_ROWS = [
    (pairing, member, bad, code) for pairing, (_, _, bad_rows) in ROWS.items() for member, bad, code in bad_rows
]


def test_every_x402_build_has_a_row() -> None:
    assert sorted([*ROWS, *NO_H]) == sorted(BINDINGS)


@pytest.mark.parametrize(("pairing", "h"), H_ROWS, ids=[f"{p} {h}" for p, h in H_ROWS])
def test_h_is_checked_before_the_choice(pairing: str, h: str) -> None:
    members, h_code, _ = ROWS[pairing]
    assert BINDINGS[pairing].build({**members, **NOT_V2}, h) == Refusal(h_code)
    assert BINDINGS[pairing].build(None, h) == Refusal(h_code)


@pytest.mark.parametrize(
    ("pairing", "member", "bad", "code"),
    MEMBER_ROWS,
    ids=[f"{p} {m} {b!r}" for p, m, b, _ in MEMBER_ROWS],
)
def test_a_member_is_checked_before_the_document(pairing: str, member: str, bad: Any, code: str) -> None:
    members, _, _ = ROWS[pairing]
    assert BINDINGS[pairing].build({**members, member: bad, **NOT_V2}, H) == Refusal(code)


@pytest.mark.parametrize("pairing", list(ROWS))
def test_valid_members_reach_the_document(pairing: str) -> None:
    """The control: with every member well formed, the document that is not v2 is the fault refused."""
    members, _, _ = ROWS[pairing]
    assert BINDINGS[pairing].build({**members, **NOT_V2}, H) == Refusal("x402/not-v2")
