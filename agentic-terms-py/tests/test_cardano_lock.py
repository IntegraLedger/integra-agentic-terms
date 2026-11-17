"""x402/exact/cardano/lock's buyer half over the protocol package's x402-exact-cardano.json, the file of both Cardano
pairings. The lock's document is the file's B2 document for the lock, the script method's option fixed.OLock advertising
H; the wallet answers with V2's transaction, whose body commits to V1's auxiliary data, and fixed.nonce, the input it
spends. Every expected value, and every input, is the file's."""

from typing import Any

import pytest

from integraledger_terms import X402_EXACT_CARDANO_LOCK, Refusal, _gate
from integraledger_terms.bindings.x402_exact_cardano import address_bytes

from breadth import H, Pairing, build_and_sign
from support import load

ADA = load("x402-exact-cardano.json")
F: dict[str, Any] = ADA["fixed"]
LOCK = "x402/exact/cardano/lock"
B2, B6 = (next(r for r in ADA["buyer"]["rows"] if r["name"] == name and r["pairing"] == LOCK) for name in ("B2", "B6"))


def check_request(r: Any) -> None:
    """The request the lock's build hands the wallet: the file's lock option and V1's auxiliary data, which carry H."""
    assert r["kind"] == "cardano-transaction"
    assert r["accepted"] == F["OLock"]
    assert r["auxiliaryData"] == "0x" + ADA["V1"]["auxiliaryDataHex"]


def answer(r: Any) -> Any:
    check_request(r)
    return {"transaction": ADA["V2"]["transactionBase64"], "nonce": F["nonce"]}


@pytest.fixture(autouse=True)
def at_b2_now(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: B2["input"]["now"])


def test_b6_the_request_is_the_files_and_the_answer_completes_the_b6_rows_payment() -> None:
    given = B2["input"]
    lock = Pairing(binding=X402_EXACT_CARDANO_LOCK, doc=given["doc"], account=given["account"], answer=answer)
    signed, _ = build_and_sign(lock, check_request)
    assert {k: signed[k] for k in ("x402Version", "accepted", "payload")} == B6["input"]["presented"]


def test_v6_the_lock_completes_no_payment_from_a_body_with_no_ttl() -> None:
    """V6 is V2's transaction with its TTL removed; the lock refuses a body with no TTL (V6's expectLock)."""
    assert ADA["V6"]["expectLock"] == "cardano/ttl-missing"
    u = X402_EXACT_CARDANO_LOCK.build({"required": B2["input"]["doc"], "accepted": F["OLock"]}, H)
    assert not isinstance(u, Refusal), u
    signed = {"transaction": ADA["V6"]["transactionBase64"], "nonce": F["nonce"]}
    assert u.complete(signed) == Refusal("x402/signed-not-bound")


def test_v8_a_bech32_address_decodes_to_the_files_bytes() -> None:
    """A Masumi lock names its seller and its escrow by Bech32 address; V8's address and its bytes, decoded by BIP-173's
    reference decoder, as the file's about states."""
    got = address_bytes(ADA["V8"]["payTo"])
    assert got is not None and got.hex() == ADA["V8"]["addressHex"]
