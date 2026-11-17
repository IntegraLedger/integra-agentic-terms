"""The four pairings whose wallet builds the transaction and picks its expiry (terms' profile buyer-gate.md, rule 8):
x402/exact/aptos, x402/exact/cardano (and its script lock), x402/exact/sui and x402/exact/polkadot/lcp-assets-remark. The
gate hands the wallet the pairing's ceiling as the latest deadline it may sign and shows it as the validity's end; after
the wallet signs and before the payment is returned, it reads the deadline the signed transaction signs and holds it to
that latest deadline. Every option, signed payment and expected deadline is a row of the pairing's vectors file: its
options, its B6 rows' payments, Sui's V2 and V3 transactions (built with @mysten/sui 2.35.0), Polkadot's eraNonce rows
(each era as @polkadot/types 17.0.1 decodes it) and Aptos's fixture F (a mainnet transaction's fields, expiring at
1790300895). The ATR paid through the gate is buyer.json's A; the same cases run in TypeScript."""

import base64
import hashlib
import os
from typing import Any

import pytest

import integraledger_terms as _terms
from integraledger_terms import (
    X402_EXACT_APTOS,
    X402_EXACT_CARDANO,
    X402_EXACT_CARDANO_LOCK,
    X402_EXACT_POLKADOT_LCP_ASSETS_REMARK,
    X402_EXACT_SUI,
    Confirmed,
    Declined,
    Finished,
    _gate,
)
from integraledger_terms.bindings.x402_exact_polkadot_lcp_assets_remark import era_of

import ed25519
from breadth import ABC, Recording, offered, run, x402_doc
from support import A, HASH_A, RESOURCE_REQUEST, approve_all, load, serving


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Any:
    def at(now: int) -> None:
        monkeypatch.setattr(_gate, "_now", lambda: now)

    return at


def confirmed(binding: Any, doc: Any, account: str, inputs: Any = None, ceilings: Any = None) -> Confirmed | Declined:
    """confirm over A, the document placed for A's hash."""
    out: Confirmed | Declined = run(
        lambda c: _terms.confirm(doc, binding, account, c, resource_request=RESOURCE_REQUEST, inputs=inputs, ceilings=ceilings),
        serving(A),
    )
    return out


def ok(out: Confirmed | Declined) -> Confirmed:
    assert isinstance(out, Confirmed) and out.request is not None and out.summary is not None, out
    return out


def finished(binding: Any, chosen: Any, answer: Any) -> str:
    """finish over the vectors' ATR abc, the hash the vectors' signed payment carries, with the choice confirm kept and
    the wallet's answer: "returned", or the decline's code, the decline carrying nothing of the payment."""
    out = _terms.finish(ABC, chosen, answer, binding)
    if isinstance(out, Finished):
        return "returned"
    assert isinstance(out, Declined) and out.moved is None, out
    return out.code


def validity(c: Confirmed) -> tuple[str | None, str | None, str]:
    assert c.summary is not None
    v = c.summary.validity
    return (v.not_before, v.not_after, v.unit)


# ── x402/exact/cardano and its script lock: the TTL, a slot, counted from the slot the caller gives.

ADA = load("x402-exact-cardano.json")
ADA_F = ADA["fixed"]
ADA_B6 = next(r for r in ADA["buyer"]["rows"] if r["name"] == "B6" and r["pairing"] == "x402/exact/cardano")["input"]["presented"]["payload"]
# The B6 row's transaction's TTL, as the protocol package's reference reads it.
ADA_TTL = 134620000


def ada_account(network: str) -> str:
    return f"{network}:{ADA_F['O']['payTo'].replace('_', '%5F')}"


ADA_DOC = x402_doc(ADA_F["O"], ADA_F["resource"], HASH_A)
ADA_ANSWER = {"transaction": ADA_B6["transaction"], "nonce": ADA_B6["nonce"]}


def test_cardano_request_carries_max_ttl_shown_as_the_validitys_end() -> None:
    c = ok(confirmed(X402_EXACT_CARDANO, ADA_DOC, ada_account(ADA_F["O"]["network"]), {"currentSlot": ADA_TTL - 600}))
    assert c.request is not None and c.request["maxTtl"] == str(ADA_TTL)
    assert validity(c) == (None, str(ADA_TTL), "slot")
    assert c.chosen.deadline == str(ADA_TTL)


def test_cardano_without_the_slot_the_caller_read_is_input_missing() -> None:
    out = confirmed(X402_EXACT_CARDANO, ADA_DOC, ada_account(ADA_F["O"]["network"]))
    assert out == Declined("no-payable-option", "cardano/input-missing")


def test_cardano_an_option_on_its_cip34_alias_is_shown() -> None:
    option = {**ADA_F["O"], "network": "cip34:0-1"}
    doc = x402_doc(option, ADA_F["resource"], HASH_A)
    c = ok(confirmed(X402_EXACT_CARDANO, doc, ada_account("cip34:0-1"), {"currentSlot": ADA_TTL - 600}))
    assert c.summary is not None and c.summary.network == "cip34:0-1"
    assert validity(c) == (None, str(ADA_TTL), "slot")


def test_cardano_b6_returned_at_its_ttl_and_discarded_one_slot_earlier() -> None:
    within = ok(confirmed(X402_EXACT_CARDANO, ADA_DOC, ada_account(ADA_F["O"]["network"]), {"currentSlot": ADA_TTL - 600}))
    assert finished(X402_EXACT_CARDANO, within.chosen, ADA_ANSWER) == "returned"
    past = ok(confirmed(X402_EXACT_CARDANO, ADA_DOC, ada_account(ADA_F["O"]["network"]), {"currentSlot": ADA_TTL - 601}))
    assert finished(X402_EXACT_CARDANO, past.chosen, ADA_ANSWER) == "past-ceiling"


def test_cardano_script_lock_is_shown_as_the_address_method() -> None:
    doc = x402_doc(ADA_F["OLock"], ADA_F["resource"], HASH_A)
    c = ok(confirmed(X402_EXACT_CARDANO_LOCK, doc, ada_account(ADA_F["OLock"]["network"]), {"currentSlot": ADA_TTL - 600}))
    assert c.summary is not None
    assert [(p.account, p.amount) for p in c.summary.payees] == [(ADA_F["OLock"]["payTo"], ADA_F["OLock"]["amount"])]
    assert validity(c) == (None, str(ADA_TTL), "slot")


# ── x402/exact/sui: the expiration epoch, which admits the whole of its epoch.

SUI = load("x402-exact-sui.json")
SUI_F = SUI["fixed"]
# V2's expiration epoch, as the protocol package's reference reads it.
SUI_EPOCH = 1234
SUI_ACCOUNT = f"{SUI_F['O']['network']}:{SUI_F['sender']}"
SUI_DOC = x402_doc(SUI_F["O"], SUI_F["resource"], HASH_A)
DAY = {"x402/exact/sui": 86_400}
NO_EXPIRATION = next(r for r in SUI["V3"] if r["case"].startswith("setExpiration({None: true})"))["tx"]["transactionBase64"]


def sui_answer(transaction: str) -> dict[str, str]:
    return {"signature": base64.b64encode(bytes(97)).decode(), "transaction": transaction}


def test_sui_at_the_600_s_ceiling_no_epoch_fits() -> None:
    out = confirmed(X402_EXACT_SUI, SUI_DOC, SUI_ACCOUNT, {"currentEpoch": SUI_EPOCH})
    assert isinstance(out, Declined) and out.code == "past-ceiling", out


def test_sui_raised_to_a_day_the_request_carries_max_epoch() -> None:
    c = ok(confirmed(X402_EXACT_SUI, SUI_DOC, SUI_ACCOUNT, {"currentEpoch": SUI_EPOCH}, DAY))
    assert c.request is not None and c.request["maxEpoch"] == str(SUI_EPOCH)
    assert validity(c) == (None, str(SUI_EPOCH), "epoch")


def test_sui_v2_returned_at_its_epoch_and_discarded_where_the_latest_is_earlier() -> None:
    within = ok(confirmed(X402_EXACT_SUI, SUI_DOC, SUI_ACCOUNT, {"currentEpoch": SUI_EPOCH}, DAY))
    assert finished(X402_EXACT_SUI, within.chosen, sui_answer(SUI["V2"]["tx"]["transactionBase64"])) == "returned"
    past = ok(confirmed(X402_EXACT_SUI, SUI_DOC, SUI_ACCOUNT, {"currentEpoch": SUI_EPOCH - 1}, DAY))
    assert finished(X402_EXACT_SUI, past.chosen, sui_answer(SUI["V2"]["tx"]["transactionBase64"])) == "past-ceiling"


def test_sui_v3_with_no_expiration_is_discarded_no_end() -> None:
    c = ok(confirmed(X402_EXACT_SUI, SUI_DOC, SUI_ACCOUNT, {"currentEpoch": SUI_EPOCH}, DAY))
    assert finished(X402_EXACT_SUI, c.chosen, sui_answer(NO_EXPIRATION)) == "no-end"


# ── x402/exact/polkadot/lcp-assets-remark: the mortal era's period, counted from the era's birth.

DOT = load("x402-exact-polkadot-lcp-assets-remark.json")
DOT_F = DOT["fixed"]
DOT_ACCOUNT = f"{DOT_F['O']['network']}:16SYiSu5tWgdV4sWiaxir7GYEiFfTc9GYnRd34PDGCUMgkmP"
DOT_DOC = x402_doc(DOT_F["O"], DOT_F["resource"], HASH_A)


def era_row(start: str) -> tuple[str, Any]:
    r = next(row for row in DOT["eraNonce"]["rows"] if row["case"].startswith(start))
    return (DOT["V3"]["extrinsic"] if r["extrinsic"] == "V3" else r["extrinsic"]), r["expect"]["era"]


def test_polkadot_era_read_as_polkadot_types_decodes_it() -> None:
    for row in DOT["eraNonce"]["rows"]:
        xt = DOT[row["extrinsic"]]["extrinsic"] if row["extrinsic"] in ("V1", "V3") else row["extrinsic"]
        era = era_of(bytes.fromhex(xt[2:]))
        want = row["expect"]["era"]
        assert era == (want if want == "immortal" else (want["period"], want["phase"])), row["case"]


def test_polkadot_request_carries_max_era_period_64() -> None:
    c = ok(confirmed(X402_EXACT_POLKADOT_LCP_ASSETS_REMARK, DOT_DOC, DOT_ACCOUNT))
    assert c.request is not None and c.request["maxEraPeriod"] == "64"
    assert validity(c) == ("0", "64", "block")


def test_polkadot_v3_returned_its_immortal_form_no_end_its_longest_era_past_ceiling() -> None:
    c = ok(confirmed(X402_EXACT_POLKADOT_LCP_ASSETS_REMARK, DOT_DOC, DOT_ACCOUNT))
    v3, v3_era = era_row("V3: era bytes a502")
    immortal, immortal_era = era_row("V3 with an immortal era")
    longest, longest_era = era_row("V3 with era bytes 0f10")
    assert (v3_era, immortal_era, longest_era["period"]) == ({"period": 64, "phase": 42}, "immortal", 65536)
    assert finished(X402_EXACT_POLKADOT_LCP_ASSETS_REMARK, c.chosen, v3) == "returned"
    assert finished(X402_EXACT_POLKADOT_LCP_ASSETS_REMARK, c.chosen, immortal) == "no-end"
    assert finished(X402_EXACT_POLKADOT_LCP_ASSETS_REMARK, c.chosen, longest) == "past-ceiling"


# ── x402/exact/aptos: expiration_timestamp_secs, in Unix seconds, through the gate over A.

AP = load("x402-exact-aptos.json")
AP_F = AP["fixed"]
F = AP_F["fixtureF"]


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def u64(n: int | str) -> bytes:
    return int(n).to_bytes(8, "little")


def bcs_str(text: str) -> bytes:
    return uleb(len(text.encode())) + text.encode()


def addr32(a: str) -> bytes:
    return bytes.fromhex(a[2:].rjust(64, "0"))


def bcs_bytes(b: bytes) -> bytes:
    return uleb(len(b)) + b


def fixture_f() -> str:
    """Fixture F's SignedTransaction: its RawTransaction in BCS and an Ed25519 authenticator from a key generated here."""
    raw = (
        addr32(F["sender"]) + u64(F["sequenceNumber"])
        + uleb(2) + addr32("0x1") + bcs_str("primary_fungible_store") + bcs_str("transfer")
        + uleb(1) + uleb(7) + addr32("0x1") + bcs_str("fungible_asset") + bcs_str("Metadata") + uleb(0)
        + uleb(3) + bcs_bytes(addr32(F["metadata"])) + bcs_bytes(addr32(F["recipient"])) + bcs_bytes(u64(F["amount"]))
        + u64(F["maxGasAmount"]) + u64(F["gasUnitPrice"]) + u64(F["expiresAt"]) + bytes([F["chainId"]])
    )  # fmt: skip
    seed = os.urandom(32)
    signature = ed25519.sign(seed, hashlib.sha3_256(b"APTOS::RawTransaction").digest() + raw)
    return base64.b64encode(raw + uleb(0) + bcs_bytes(ed25519.public_key(seed)) + bcs_bytes(signature)).decode()


def aptos_pay(now: int) -> tuple[Any, int]:
    def answer(r: Any) -> Any:
        assert r["maxExpirationTimestampSecs"] == str(now + 600)
        return {"transaction": fixture_f()}

    signer = Recording(f"{AP_F['O']['network']}:{F['sender']}", answer)
    doc = x402_doc(AP_F["O"], AP_F["resource"], HASH_A)
    out = run(
        lambda c: _terms.transact(
            doc, offered(X402_EXACT_APTOS), signer, c, approver=approve_all, resource_request=RESOURCE_REQUEST
        ),
        serving(A),
    )
    return out, len(signer.requests)


def test_aptos_fixture_f_returned_600_s_before_it_expires(clock: Any) -> None:
    now = int(F["expiresAt"]) - 600
    clock(now)
    out, calls = aptos_pay(now)
    assert isinstance(out, _terms.Transacted) and out.signed is not None, out
    assert calls == 1
    assert _terms.check(A, out.signed, X402_EXACT_APTOS).h == HASH_A  # type: ignore[union-attr]


def test_aptos_fixture_f_signed_300895_s_before_it_expires_is_discarded(clock: Any) -> None:
    now = int(F["expiresAt"]) - 300_895
    clock(now)
    out, calls = aptos_pay(now)
    assert calls == 1
    assert isinstance(out, Declined) and out.code == "past-ceiling" and out.moved is None, out
