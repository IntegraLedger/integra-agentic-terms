"""mpp/charge/stellar: the TypeScript gate's placement, B2, B6, B10 and B16 rows, and the buyer half's vector rows.
Expected values are the vector files'; the payer signs with the Ed25519 seed x402-exact-stellar.json publishes."""

import base64
import hashlib
import json
from datetime import datetime
from typing import Any

import pytest

from integraledger_terms import MPP_CHARGE_STELLAR, X402_EXACT_STELLAR, Refusal, _gate
from integraledger_terms.bindings import _stellar, _stellar_xdr
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode
from integraledger_terms.bindings._mpp import Held

import ed25519
from breadth import H, LINK, Pairing, build_and_sign, plant
from mpp_docs import issued, place_carrier
from support import hexb, load
from xlm_support import EVM_ACCOUNT, b16, mpp_b10, muxed_for

V = load("mpp-charge-stellar.json")
X = load("x402-exact-stellar.json")
F: dict[str, Any] = V["fixed"]
SA: dict[str, Any] = V["sourceAccount"]
SEED = bytes.fromhex(X["fixed"]["payerSeed"])
# The entry's expiration is currentLedger + ceil((expires - now) / 5): 988 + 12 = 1000.
NOW = int(datetime.fromisoformat(F["expires"].replace("Z", "+00:00")).timestamp()) - 60


def muxed_carrier(h: str) -> Any:
    def carrier(value: Any) -> str | Refusal:
        if _stellar.unmux(value) is not None:
            return Refusal("stellar/carrier-occupied")
        try:
            return muxed_for(value, h)
        except ValueError:
            return Refusal("stellar/option-malformed")

    return carrier


def doc_of(challenge: dict[str, Any], h: str = H) -> Any:
    return place_carrier([challenge], h, LINK, challenge, muxed_carrier(h))


def answer(request: Any) -> Any:
    assert request["kind"] == "stellar-auth", request["kind"]
    return "0x" + ed25519.sign(SEED, hashlib.sha256(hexb(request["preimage"])).digest()).hex()


STELLAR = Pairing(
    binding=MPP_CHARGE_STELLAR,
    doc=doc_of(V["challenge"]),
    account=f"stellar:testnet:{X['fixed']['payer']}",
    answer=answer,
    inputs={"simulatedXdr": X["V2"]["simulatedXdr"], "currentLedger": X["V2"]["currentLedger"]},
)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)


def test_mpp_charge_stellar_placed_challenge_is_the_vectors() -> None:
    assert STELLAR.doc == [V["place"]["expect"]]
    assert X["V2"]["expectExpiration"] == X["V2"]["currentLedger"] + 12

@pytest.mark.usefixtures("clock")
def test_mpp_charge_stellar_b6_preimage_is_v3_digest_and_signature_completes_v3_envelope() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "stellar-auth"
        assert "0x" + hashlib.sha256(hexb(request["preimage"])).hexdigest() == V["V3"]["expectReference"]["authDigest"]

    signed, _ = build_and_sign(STELLAR, inspect)
    assert signed["payload"] == {"type": "transaction", "transaction": V["V3"]["envelope"]}


def test_mpp_charge_stellar_v3source_completion_sets_the_zero_source_only_under_fee_payer_true() -> None:
    """V3source: a simulation whose transaction source is the payer's key, not the all-zeros account. The entry's
    preimage holds no transaction source, so it is x402-exact-stellar.json V2's in both modes. Under the placed
    challenge (feePayer true) the completion writes the all-zeros source and is V3's envelope; under the sourceAccount
    section's challenge (feePayer false) it keeps the simulated source and is V3source's expectEnvelopeFeePayerFalse."""
    row = V["V3source"]
    modes = [(V["place"]["expect"], V["V3"]["envelope"]), (SA["challenge"], row["expectEnvelopeFeePayerFalse"])]
    for challenge, envelope in modes:
        choice = {
            "challenge": challenge,
            "simulatedXdr": row["simulatedXdr"],
            "currentLedger": X["V2"]["currentLedger"],
            "now": NOW,
            "payer": X["fixed"]["payer"],
        }
        unsigned = MPP_CHARGE_STELLAR.build(choice, F["H"])
        assert not isinstance(unsigned, Refusal), unsigned
        preimage = unsigned.request["preimage"]
        assert isinstance(preimage, bytes)
        digest = hashlib.sha256(preimage).digest()
        assert digest.hex() == X["V2"]["expectPreimageSha256"]
        completed = unsigned.complete(ed25519.sign(SEED, digest))
        assert completed == {"challenge": challenge, "payload": {"type": "transaction", "transaction": envelope}}


def test_mpp_charge_stellar_b10_http_link() -> None:
    mpp_b10(STELLAR)


def test_mpp_charge_stellar_b16_other_accounts() -> None:
    b16(STELLAR, [EVM_ACCOUNT, f"stellar:pubnet:{X['fixed']['payer']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def credential(payload: dict[str, Any], challenge: Any = None) -> dict[str, Any]:
    return {"challenge": challenge or STELLAR.doc[0], "payload": payload}


def pushed(envelope: str, challenge: Any, tx_hash: str) -> Held:
    """A hash credential naming tx_hash, with the envelope read by that hash held in Held, as @integraledger/lcp
    holds it under the payment's own FETCHED member."""
    return Held(credential({"type": "hash", "hash": tx_hash}, challenge), {"transaction": envelope})


def test_mpp_charge_stellar_v3_bound_plant_and_refusals() -> None:
    assert F["muxed"] == muxed_for(F["request"]["recipient"], H)
    tx = {"type": "transaction", "transaction": V["V3"]["envelope"]}
    assert MPP_CHARGE_STELLAR.bound(credential(tx)) == V["V3"]["expectBound"]
    plant_tx = {"type": "transaction", "transaction": V["plant"]["envelope"]}
    assert MPP_CHARGE_STELLAR.bound(credential(plant_tx)) == Refusal(V["plant"]["expect"])
    rows = V["refusals"]
    assert MPP_CHARGE_STELLAR.bound(credential(rows[0]["payload"], challenge_named(rows[0]["challenge"]))) == Refusal(
        rows[0]["expect"]
    )
    # The echoed challenge names H2 while its recipient is the muxed address of H's first 8 bytes.
    h2_doc = place_carrier([V["challenge"]], F["H2"], LINK, V["challenge"], lambda issued_value: F["muxed"])
    assert isinstance(h2_doc, list)
    assert MPP_CHARGE_STELLAR.bound(credential(tx, h2_doc[0])) == Refusal(rows[1]["expect"])
    assert MPP_CHARGE_STELLAR.bound(credential({"type": "other"})) == Refusal("mpp/credential-type")


def test_mpp_charge_stellar_a_landed_transaction_is_read_by_the_payer_entry_that_carries_the_transfer() -> None:
    """A hash credential presents a transaction that landed: its payer entry is the payer's first address-credential
    entry whose root invocation is the operation's transfer, and another entry of the payer rides unused, as the
    Soroban host authenticates them (x402-exact-stellar.json V5). V5's settled envelopes that carry two entries of the
    payer bind H under the sourceAccount section's challenge, which pays the same muxed recipient; in a transaction
    credential, before it lands, the same envelope is stellar/no-address-auth (x402-exact-stellar.json
    agreedRefusals)."""
    challenge = V["sourceAccount"]["challenge"]
    network = X["fixed"]["network"]
    rows = [
        row
        for row in X["V5"]["rows"]
        if row["expect"]["state"] == "settled"
        and isinstance(row.get("envelope"), str)
        and _stellar.read_signed_transfer(row["envelope"], network, False) == Refusal("stellar/no-address-auth")
    ]
    assert rows, "x402-exact-stellar.json V5 holds no settled envelope with two entries of the payer"
    for row in rows:
        assert MPP_CHARGE_STELLAR.bound(pushed(row["envelope"], challenge, X["V5"]["ref"]["transaction"])) == F["H"], row["case"]
        sent = {"type": "transaction", "transaction": row["envelope"]}
        assert MPP_CHARGE_STELLAR.bound(credential(sent, challenge)) == Refusal("stellar/no-address-auth"), row["case"]


# ── a push payment the payer authorized as the transaction's source account ─────────────────────────────────────────


def key_of(seed: str) -> bytes:
    """The Ed25519 key of the seed that repeats one byte, as the sourceAccount section names each account."""
    return ed25519.public_key(bytes.fromhex(seed) * 32)


def assert_written(envelope: str, write: dict[str, Any]) -> None:
    """The envelope is what the row's write says: the transaction's source, the operation's source (none when the
    write names none), and one entry with source-account credentials whose root invocation carries a sub-invocation
    only where the write says so."""
    env = _stellar_xdr.envelope(base64.b64decode(envelope))
    assert env.source == key_of(write["source"])
    assert env.operation_source == (key_of(write["operationSource"]) if "operationSource" in write else None)
    assert [e.kind for e in env.invoke.entries] == [0]
    assert env.invoke.entries[0].root.subs == (1 if write.get("subInvocation") else 0)


def with_fee_payer(challenge: dict[str, Any], value: object) -> dict[str, Any]:
    """The challenge with its request's methodDetails.feePayer set to value, or left out when value is Ellipsis; its
    id and opaque derive from H, not from the request."""
    raw = b64u_decode(challenge["request"])
    assert raw is not None
    request = json.loads(raw)
    if value is ...:
        del request["methodDetails"]["feePayer"]
    else:
        request["methodDetails"]["feePayer"] = value
    return {**challenge, "request": b64u_encode(json.dumps(request).encode("utf-8"))}


def test_mpp_charge_stellar_source_account_push_binds_h() -> None:
    """sourceAccount: the payer (seed 05) is the transaction's source, and its one entry has source-account credentials
    and is the operation's transfer. A hash credential presenting that landed transaction, under the section's
    challenge (feePayer false) and the same challenge with feePayer absent, binds H; read_source_transfer reads the
    transfer the section's expectReference names."""
    assert_written(SA["envelope"], SA["write"])
    for challenge in (SA["challenge"], with_fee_payer(SA["challenge"], ...)):
        assert MPP_CHARGE_STELLAR.bound(pushed(SA["envelope"], challenge, SA["hash"])) == SA["expectBound"]
    ref = SA["expectReference"]
    payment = _stellar.read_source_transfer(SA["envelope"], ref["network"])
    assert isinstance(payment, _stellar.SourcePayment), payment
    assert (payment.asset, payment.to_base, str(payment.to_id)) == (ref["asset"], ref["toBase"], ref["toId"])
    assert payment.source == _stellar.account(key_of(SA["write"]["source"]))


@pytest.mark.parametrize("fee_payer", [None, "false", 0, []])
def test_mpp_charge_stellar_source_account_push_reads_fee_payer_as_a_boolean(fee_payer: object) -> None:
    """A source-account push under a request whose feePayer is present and not a boolean is stellar/option-malformed,
    the code the challenge's checks give it (@integraledger/lcp 0.4.0's isFeePayer: absent or a boolean)."""
    challenge = with_fee_payer(SA["challenge"], fee_payer)
    assert MPP_CHARGE_STELLAR.bound(pushed(SA["envelope"], challenge, SA["hash"])) == Refusal("stellar/option-malformed")


def challenge_named(name: str) -> dict[str, Any]:
    """The challenge a row names: the place section's placed challenge (feePayer true), or a section's own."""
    challenge: dict[str, Any] = V["place"]["expect"] if name == "place" else V[name]["challenge"]
    return challenge


def test_mpp_charge_stellar_source_account_refusals() -> None:
    """sourceAccount.refusals: each row's credential under the challenge it names is refused with the row's code, and
    each row's envelope is what its write says. A transaction credential carries the row's envelope, or the section's;
    a hash credential names the row's hash, or the section's, and holds in Held the envelope read by that hash: the
    row's fetched transaction where it holds one, else its envelope, or the section's. Under the place section's
    challenge, whose feePayer is true, the hash credential is mpp/credential-type before any read (the section's
    about), whatever is held in Held and when nothing is. x402, whose entries must be address credentials, refuses
    the section's envelope stellar/no-address-auth."""
    rows = SA["refusals"]
    assert {row["challenge"] for row in rows} == {"place", "sourceAccount"}, [row["challenge"] for row in rows]
    assert [row for row in rows if "fetched" in row], "no row holds fetched"
    for row in rows:
        envelope = row.get("envelope", SA["envelope"])
        if "write" in row:
            assert_written(envelope, row["write"])
        challenge = challenge_named(row["challenge"])
        if row["type"] == "hash":
            given = row.get("fetched", {"transaction": envelope})
            presented: dict[str, Any] = Held(credential({"type": "hash", "hash": row.get("hash", SA["hash"])}, challenge), given)
        else:
            presented = credential({"type": row["type"], "transaction": envelope}, challenge)
        assert MPP_CHARGE_STELLAR.bound(presented) == Refusal(row["expect"]), row["case"]
    unfetched = {"type": "hash", "hash": SA["hash"]}
    assert MPP_CHARGE_STELLAR.bound(credential(unfetched, challenge_named("place"))) == Refusal("mpp/credential-type")
    x402 = {"x402Version": 2, "accepted": X["V3"]["accepted"], "payload": {"transaction": SA["envelope"]}}
    assert X402_EXACT_STELLAR.bound({**x402, "extensions": X["V3"]["extensions"]}) == Refusal("stellar/no-address-auth")


def test_mpp_charge_stellar_source_account_status_rows_name_the_transfer() -> None:
    """sourceAccount.status rows whose named transaction succeeded: the row settles exactly when
    read_source_transfer reads the landed envelope as the payer's source-account transfer to the reference's to id. A
    row names x402-exact-stellar.json's section whose envelope it carries, or none for the section's own."""
    rows = [row for row in SA["status"] if row["status"] == "SUCCESS"]
    assert any(row["expect"]["state"] == "settled" for row in rows)
    assert any(row["expect"]["state"] != "settled" for row in rows)
    ref = SA["expectReference"]
    for row in rows:
        envelope = X[row["envelope"]]["envelope"] if "envelope" in row else SA["envelope"]
        payment = _stellar.read_source_transfer(envelope, ref["network"])
        named = isinstance(payment, _stellar.SourcePayment) and str(payment.to_id) == ref["toId"]
        assert named is (row["expect"]["state"] == "settled"), row["case"]


def test_mpp_charge_stellar_occupied_and_option_malformed() -> None:
    occupied = issued("stellar", "charge", json.dumps(V["occupied"]["request"]), F["realm"], F["expires"])
    assert doc_of(occupied) == Refusal(V["occupied"]["expect"])
    not_g = {**F["request"], "recipient": F["request"]["currency"]}
    assert doc_of(issued("stellar", "charge", json.dumps(not_g), F["realm"], F["expires"])) == Refusal(
        "stellar/option-malformed"
    )


# ── the order of the checks: one fault, one code ─────────────────────────────────────────────────────────────────


def plain() -> dict[str, Any]:
    """The vectors' challenge placed for H with its recipient left the seller's plain G, which carries no muxed id."""
    placed = place_carrier([V["challenge"]], H, LINK, V["challenge"], lambda value: value)
    assert isinstance(placed, list)
    challenge: dict[str, Any] = placed[0]
    return challenge


def test_mpp_charge_stellar_build_checks_the_choice_before_the_recipient() -> None:
    """After the challenge, build checks the current ledger and the clock, the payer's strkey, the expiration ledger and
    the simulated transaction's form before the recipient's muxed id (@integraledger/lcp 0.4.1's mpp/charge/stellar
    build). Under a challenge whose recipient carries no muxed id, each of those is refused with its own code."""
    choice = {
        "challenge": plain(),
        "simulatedXdr": X["V2"]["simulatedXdr"],
        "currentLedger": X["V2"]["currentLedger"],
        "now": NOW,
        "payer": X["fixed"]["payer"],
    }
    assert MPP_CHARGE_STELLAR.build(choice, H) == Refusal("stellar/carrier-mismatch")
    assert MPP_CHARGE_STELLAR.build({**choice, "currentLedger": -1}, H) == Refusal("stellar/tx-malformed")
    assert MPP_CHARGE_STELLAR.build({**choice, "now": None}, H) == Refusal("stellar/tx-malformed")
    assert MPP_CHARGE_STELLAR.build({**choice, "payer": "x"}, H) == Refusal("stellar/payer-mismatch")
    assert MPP_CHARGE_STELLAR.build({**choice, "simulatedXdr": "x"}, H) == Refusal("stellar/tx-malformed")
    last = {**choice, "currentLedger": 0xFFFFFFFF}
    assert MPP_CHARGE_STELLAR.build(last, H) == Refusal("stellar/tx-malformed")


def test_mpp_charge_stellar_bound_reads_the_recipient_before_the_transaction() -> None:
    """bound checks the recipient against H's muxed id before it reads the transaction, as build does
    (@integraledger/lcp 0.4.1's mpp/charge/stellar bindingOf). Under a challenge whose recipient is the plain G, the
    plant's envelope, which pays that G, is stellar/carrier-mismatch, as is a transaction that is not base64."""
    challenge = plain()
    plant_tx = {"type": "transaction", "transaction": V["plant"]["envelope"]}
    assert MPP_CHARGE_STELLAR.bound(credential(plant_tx, challenge)) == Refusal("stellar/carrier-mismatch")
    not_base64 = {"type": "transaction", "transaction": "x"}
    assert MPP_CHARGE_STELLAR.bound(credential(not_base64, challenge)) == Refusal("stellar/carrier-mismatch")
    assert MPP_CHARGE_STELLAR.bound(credential(not_base64)) == Refusal("stellar/tx-malformed")
