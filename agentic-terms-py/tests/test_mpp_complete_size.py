"""Each MPP pairing whose build returns a complete that makes a credential, run on its vector file's B2 inputs and the
payment its B6 row carries (credential_size.PAIRINGS), against mpp-challenge.json's rows: buildChallenge (each build
holds the chosen challenge as bound holds the challenge a credential echoes); a change made to the caller's challenge
after build, which does not reach the credential; inChannelSize on the session pairings with channel members and no
build_within; completeOrder (each complete checks the credential it would return in its bound's order); credentialSize
(each complete measures its credential as bound does) and voucherSize (a session voucher measures as its complete
does); and mpp-charge-stellar.json's completeXdr and mpp-charge-xrpl.json's completeBlob. Expected values are the
rows' and @integraledger/lcp 0.4.1's (mpp-complete-size.test.ts)."""

import base64
import copy
from collections.abc import Callable
from typing import Any

import pytest

from integraledger_terms import (
    MPP_CHARGE_EVM_TRANSACTION,
    MPP_CHARGE_LIGHTNING,
    MPP_CHARGE_STELLAR,
    MPP_CHARGE_USDC_STACKS,
    MPP_CHARGE_XRPL,
    MPP_SUBSCRIPTION_TEMPO,
    Refusal,
)
from integraledger_terms.bindings import _xrpl_codec as xrpl_codec
from integraledger_terms.bindings._rlp import rlp_bytes, rlp_list
from integraledger_terms.bindings._tempo import encode_key_authorization

from credential_size import (
    MC,
    PAIRINGS,
    after_build,
    answered,
    buyer,
    built,
    described,
    description_for,
    footprinted,
    mv11_transaction,
    set_up,
    size_of,
    with_fault,
)
from support import load

CHALLENGE_ROWS: list[dict[str, Any]] = MC["buildChallenge"]["rows"]
assert len(CHALLENGE_ROWS) == 8
FAULTS = ("opaque", "legalContext", "leastSize", "id", "digest", "challenge")


def test_each_build_challenge_row_makes_one_fault() -> None:
    for row in CHALLENGE_ROWS:
        assert sum(k in row for k in FAULTS) == 1, row["case"]


@pytest.mark.parametrize("pairing", list(PAIRINGS))
@pytest.mark.parametrize("row", CHALLENGE_ROWS, ids=[r["case"] for r in CHALLENGE_ROWS])
def test_build_challenge_build_refuses_with_the_code_bound_gives(pairing: str, row: dict[str, Any]) -> None:
    """build refuses the row's challenge with the row's code before it returns a complete, and bound gives the same
    code for the pairing's credential with its challenge replaced by the row's."""
    s = set_up(pairing)
    assert "opaque" in s.placed
    plain = s.complete(s.placed)
    challenge = with_fault(s.placed, row)
    if "leastSize" in row:
        assert size_of({"challenge": challenge, "payload": {}}) == row["leastSize"]
    assert answered(lambda: s.complete(challenge)) == ("build", Refusal(row["expect"]))
    assert PAIRINGS[pairing].binding.bound({**plain, "challenge": challenge}) == Refusal(row["expect"])


@pytest.mark.parametrize("row", CHALLENGE_ROWS, ids=[r["case"] for r in CHALLENGE_ROWS])
def test_build_challenge_on_the_evm_transaction_charge_whatever_the_transaction(row: dict[str, Any]) -> None:
    """The EVM transaction charge's complete holds the echoed challenge (echoed_for) before it reads the transaction,
    as bound does: so whatever transaction it is given (0xzz, 0x02c0 or MV11's), build and complete give bound's code
    for the row's challenge."""
    b2 = buyer("mpp-charge-evm-transaction.json", "mpp/charge/evm/transaction", "B2")
    assert b2 is not None

    def run(challenge: Any, signature: str) -> Any:
        choice = {"challenge": challenge, "from": b2["input"]["account"].split(":")[2], "now": b2["input"]["now"]}
        return built(MPP_CHARGE_EVM_TRANSACTION.build(choice, b2["advertised"])).complete(signature)

    placed = set_up("mpp/charge/evm/transaction").placed
    plain = run(placed, mv11_transaction())
    challenge = with_fault(placed, row)
    for signature in ("0xzz", "0x02c0", mv11_transaction()):
        assert answered(lambda: run(challenge, signature))[1] == Refusal(row["expect"]), signature
        presented = {**plain, "challenge": challenge, "payload": {**plain["payload"], "signature": signature}}
        assert MPP_CHARGE_EVM_TRANSACTION.bound(presented) == Refusal(row["expect"]), signature


@pytest.mark.parametrize("pairing", list(PAIRINGS))
def test_a_change_to_the_callers_challenge_after_build_does_not_reach_the_credential(pairing: str) -> None:
    """Each build holds a snapshot of the chosen challenge's members, which its complete's credential carries, never
    the caller's object: removing opaque from the caller's challenge and changing its realm between build and complete
    leaves the credential as the run on the placed challenge makes it, and bound's answer with it."""
    s = set_up(pairing)
    plain = s.complete(s.placed)
    mine = dict(s.placed)

    def change() -> None:
        del mine["opaque"]
        mine["realm"] = "another.example"

    after_build.append(change)
    try:
        made = s.complete(mine)
    finally:
        after_build.clear()
    assert "opaque" not in mine and mine["realm"] == "another.example"
    assert made == plain
    assert made["challenge"] is not mine
    assert PAIRINGS[pairing].binding.bound(made) == s.answer
    assert PAIRINGS[pairing].binding.bound(copy.deepcopy(made)) == s.answer


IN_CHANNEL_ROWS: list[dict[str, Any]] = MC["inChannelSize"]["rows"]
assert len(IN_CHANNEL_ROWS) == 3


def channel_answers(binding: Any, c: Any) -> list[Any]:
    return [binding.channel_kind(c), binding.channel_ref(c), binding.bound_within(c)]


@pytest.mark.parametrize("pairing", ["mpp/session/lightning", "mpp/subscription/tempo"])
@pytest.mark.parametrize("row", IN_CHANNEL_ROWS, ids=[r["case"] for r in IN_CHANNEL_ROWS])
def test_in_channel_size_the_channel_members_of_the_sessions_without_a_build_within(
    pairing: str, row: dict[str, Any]
) -> None:
    """channel_kind, channel_ref and bound_within measure the payment they are given, here the pairing's opening,
    padded by a description to the row's size: a taken row is answered as the unpadded opening is, and the one over
    the bound is the row's code from all three."""
    s = set_up(pairing)
    binding = PAIRINGS[pairing].binding
    plain = s.complete(s.placed)
    sized = {**plain, "challenge": described(s.placed, description_for(plain, row["size"]))}
    assert size_of(sized) == row["size"]
    if row.get("taken"):
        assert channel_answers(binding, sized) == channel_answers(binding, plain)
    else:
        assert channel_answers(binding, sized) == [Refusal(row["expect"])] * 3


def _session_build(pairing: str) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    """The pairing's build on its B2 inputs under its placed challenge, and its B6 credential."""
    s = set_up(pairing)
    b2 = buyer(PAIRINGS[pairing].file, pairing, "B2")
    b6 = buyer(PAIRINGS[pairing].file, pairing, "B6")
    assert b2 is not None and b6 is not None
    account = b2["input"]["account"].split(":")[2]
    choice: dict[str, Any] = {"challenge": s.placed, "from": account}
    if pairing == "mpp/session/xrpl":
        i = b2["input"]["inputs"]
        choice |= {"deposit": int(i["deposit"]), "xrpl": {**i["xrpl"], "publicKey": i["xrpl"]["publicKey"][2:]}}
    unsigned = PAIRINGS[pairing].binding.build(choice, s.h)
    assert not isinstance(unsigned, Refusal), unsigned
    return unsigned, s.placed, b6["input"]["presented"]


def test_the_solana_session_complete_refuses_an_opening_that_is_not_an_object_as_bound_does() -> None:
    """complete holds {challenge, payload: open} to bound's read: a payload that is not an object is
    mpp/credential-malformed, from complete and from bound (mpp-complete-size.test.ts in @integraledger/lcp 0.4.1)."""
    unsigned, placed, _ = _session_build("mpp/session/solana")
    for opening in (None, "x", 5):
        assert unsigned.complete(opening) == Refusal("mpp/credential-malformed"), opening
        bound = PAIRINGS["mpp/session/solana"].binding.bound({"challenge": placed, "payload": opening})
        assert bound == Refusal("mpp/credential-malformed"), opening


def test_the_xrpl_session_complete_reads_the_blob_as_bound_reads_it_before_the_claim_signature() -> None:
    """A signedBlob that is not a string is xrpl/blob-malformed, bound's code for it, with B6's claim signature and
    with zz; B6's blob with the claim signature zz, which bound does not read, is mpp/credential-malformed from
    complete, while bound gives H (mpp-complete-size.test.ts in @integraledger/lcp 0.4.1)."""
    unsigned, _, b6 = _session_build("mpp/session/xrpl")
    binding = PAIRINGS["mpp/session/xrpl"].binding
    blob, signature = b6["payload"]["transaction"], b6["payload"]["signature"]
    for claim in (signature, "zz"):
        assert unsigned.complete({"signedBlob": 5, "claimSignature": claim}) == Refusal("xrpl/blob-malformed"), claim
        presented = {**b6, "payload": {**b6["payload"], "transaction": 5, "signature": claim}}
        assert binding.bound(presented) == Refusal("xrpl/blob-malformed"), claim
    assert unsigned.complete({"signedBlob": blob, "claimSignature": "zz"}) == Refusal("mpp/credential-malformed")
    assert binding.bound({**b6, "payload": {**b6["payload"], "signature": "zz"}}) == set_up("mpp/session/xrpl").h


# ── completeOrder: a complete checks the credential it would return in its bound's order. bound measures a credential
# before it reads the payment it carries, so a payment fault in a credential over the credential size bound is
# mpp/credential-malformed from complete as from bound, and at the bound each gives the fault's own code (bound the
# row's bound code, or H, where it reads nothing of the payment).

ORDER_ROWS: list[dict[str, Any]] = MC["completeOrder"]["rows"]
assert len(ORDER_ROWS) == 14
_ROOT_SIGNATURE = "0x" + "11" * 8192
_STACKS_WIRE = load("mpp-charge-usdc-stacks.json")["agreedRefusals"]["rows"][48]
_OTHER_CHAIN: str = load("mpp-charge-evm-transaction.json")["agreedRefusals"]["rows"][0]["transactions"][0]


def _b2(pairing: str) -> dict[str, Any]:
    row = buyer(PAIRINGS[pairing].file, pairing, "B2")
    assert row is not None
    return row


def _swapped(pairing: str, challenge: Any, field: str, value: Any) -> dict[str, Any]:
    """The credential complete would make under challenge: the pairing's own, its payload's field set to value."""
    s = set_up(pairing)
    c = s.complete(s.placed)
    return {**c, "challenge": challenge, "payload": {**c["payload"], field: value}}


def _stellar_complete(challenge: Any, key_bytes: int) -> Any:
    b2 = _b2("mpp/charge/stellar")
    i = b2["input"]["inputs"]
    choice = {
        "challenge": challenge,
        "payer": b2["input"]["account"].split(":")[2],
        "now": b2["input"]["now"],
        "simulatedXdr": footprinted(i["simulatedXdr"], key_bytes),
        "currentLedger": i["currentLedger"],
    }
    return built(MPP_CHARGE_STELLAR.build(choice, b2["advertised"])).complete(bytes([0x11]) * 64)


def _stellar_credential(challenge: Any) -> dict[str, Any]:
    within = _stellar_complete(set_up("mpp/charge/stellar").placed, 5401)
    over = footprinted(within["payload"]["transaction"], 5405)
    assert len(over) == 8200
    return _swapped("mpp/charge/stellar", challenge, "transaction", over)


def _stacks_complete(challenge: Any) -> Any:
    b2 = _b2("mpp/charge/usdc/stacks")
    choice = {"challenge": challenge, "from": b2["input"]["account"].split(":")[2]}
    wire = bytes.fromhex(_STACKS_WIRE["wireHex"].removeprefix("0x"))
    return built(MPP_CHARGE_USDC_STACKS.build(choice, b2["advertised"])).complete(wire)


def _stacks_credential(challenge: Any) -> dict[str, Any]:
    assert _STACKS_WIRE["bytes"] == 16_385
    wire = base64.b64encode(bytes.fromhex(_STACKS_WIRE["wireHex"].removeprefix("0x"))).decode("ascii")
    return _swapped("mpp/charge/usdc/stacks", challenge, "transaction", wire)


def _subscription_unsigned(challenge: Any) -> Any:
    b2 = _b2("mpp/subscription/tempo")
    choice = {"challenge": challenge, "from": b2["input"]["account"].split(":")[2], "now": b2["input"]["now"]}
    return built(MPP_SUBSCRIPTION_TEMPO.build(choice, b2["advertised"]))


def _subscription_credential(challenge: Any) -> dict[str, Any]:
    u = _subscription_unsigned(set_up("mpp/subscription/tempo").placed)
    unsigned = encode_key_authorization(u.request["authorization"])
    assert isinstance(unsigned, bytes)
    signed = rlp_list([unsigned, rlp_bytes(bytes.fromhex(_ROOT_SIGNATURE[2:]))])
    assert len(signed) > 8192
    return _swapped("mpp/subscription/tempo", challenge, "signature", "0x" + signed.hex())


def _xrpl_complete(challenge: Any, blob: str = "00" * 2049) -> Any:
    b2 = _b2("mpp/charge/xrpl")
    i = b2["input"]["inputs"]
    choice = {"challenge": challenge, "account": b2["input"]["account"].split(":")[2], "fee": i["fee"]}
    choice |= {"sequence": i["sequence"], "lastLedgerSequence": i["lastLedgerSequence"]}
    return built(MPP_CHARGE_XRPL.build(choice, b2["advertised"])).complete(blob)


def _evm_transaction_complete(challenge: Any) -> Any:
    b2 = _b2("mpp/charge/evm/transaction")
    choice = {"challenge": challenge, "from": b2["input"]["account"].split(":")[2], "now": b2["input"]["now"]}
    return built(MPP_CHARGE_EVM_TRANSACTION.build(choice, b2["advertised"])).complete(_OTHER_CHAIN)


def _lightning_complete(challenge: Any) -> Any:
    b2 = _b2("mpp/charge/lightning")
    return built(MPP_CHARGE_LIGHTNING.build({"challenge": challenge}, b2["advertised"])).complete("00")


def _solana_session_complete(challenge: Any) -> Any:
    b6 = buyer(PAIRINGS["mpp/session/solana"].file, "mpp/session/solana", "B6")
    assert b6 is not None
    opening = {**b6["input"]["presented"]["payload"], "action": "voucher"}
    return PAIRINGS["mpp/session/solana"].run(challenge, _b2("mpp/session/solana"), {"payload": opening})


# Each completeOrder fault: complete under a challenge, and the credential it would make, which bound is given.
ORDER_FAULTS: dict[str, tuple[Callable[[Any], Any], Callable[[Any], dict[str, Any]]]] = {
    "a signed envelope of 8,200 characters": (lambda c: _stellar_complete(c, 5405), _stellar_credential),
    "a transaction of 16,385 bytes": (_stacks_complete, _stacks_credential),
    "a signed key authorization over 8,192 bytes": (
        lambda c: _subscription_unsigned(c).complete(_ROOT_SIGNATURE),
        _subscription_credential,
    ),
    "a blob of 2,049 bytes": (_xrpl_complete, lambda c: _swapped("mpp/charge/xrpl", c, "blob", "00" * 2049)),
    "an EIP-1559 transaction for chain 1": (
        _evm_transaction_complete,
        lambda c: _swapped("mpp/charge/evm/transaction", c, "signature", _OTHER_CHAIN),
    ),
    "a preimage that is not 64 hex digits": (
        _lightning_complete,
        lambda c: _swapped("mpp/charge/lightning", c, "preimage", "00"),
    ),
    "an opening whose action is voucher": (
        _solana_session_complete,
        lambda c: _swapped("mpp/session/solana", c, "action", "voucher"),
    ),
}


def test_each_complete_order_row_names_a_pairing_of_credential_size_and_a_fault_this_test_makes() -> None:
    for row in ORDER_ROWS:
        assert row["pairing"] in PAIRINGS and row["fault"] in ORDER_FAULTS, row["case"]


@pytest.mark.parametrize("row", ORDER_ROWS, ids=[r["case"] for r in ORDER_ROWS])
def test_complete_order_a_complete_checks_the_credential_in_its_bounds_order(row: dict[str, Any]) -> None:
    s = set_up(row["pairing"])
    complete, credential = ORDER_FAULTS[row["fault"]]
    challenge = described(s.placed, description_for(credential(s.placed), row["size"]))
    presented = credential(challenge)
    assert size_of(presented) == row["size"]
    assert complete(challenge) == Refusal(row["expect"])
    expect = s.h if row.get("boundTakes") else Refusal(row.get("bound", row["expect"]))
    assert PAIRINGS[row["pairing"]].binding.bound(presented) == expect


# ── credentialSize (mpp-challenge.json): every complete measures the credential it would return as bound measures it.
# The pairing's credential, with a description bringing it to the row's size, is returned at a taken size, and bound
# gives it the answer it gives the credential without one; over the bound, complete and bound refuse with the row's
# code.

SIZE_ROWS: list[dict[str, Any]] = MC["credentialSize"]["rows"]
SIZE_TAKEN = [r for r in SIZE_ROWS if r.get("taken")]
SIZE_OVER = [r for r in SIZE_ROWS if "expect" in r]


def test_credential_size_rows_are_two_taken_sizes_and_one_over_the_bound() -> None:
    assert (len(SIZE_TAKEN), len(SIZE_OVER), len(SIZE_ROWS)) == (2, 1, 3)


@pytest.mark.parametrize("pairing", list(PAIRINGS))
@pytest.mark.parametrize("row", SIZE_TAKEN + SIZE_OVER, ids=lambda r: r["case"])
def test_credential_size_complete_measures_its_credential_as_bound_does(pairing: str, row: dict[str, Any]) -> None:
    s = set_up(pairing)
    bound = PAIRINGS[pairing].binding.bound
    assert "description" not in s.placed
    plain = s.complete(s.placed)
    assert bound(plain) == s.answer
    challenge = described(s.placed, description_for(plain, row["size"]))
    sized = {**plain, "challenge": challenge}
    assert size_of(sized) == row["size"]
    made = s.complete(challenge)
    if row.get("taken"):
        assert made == sized
        assert bound(made) == s.answer
    else:
        assert made == Refusal(row["expect"])
        assert bound(sized) == Refusal(row["expect"])


# ── voucherSize (mpp-challenge.json): a session build's voucher measures the credential its complete would give with a
# one-byte voucher signature, and refuses with complete's code before the voucher is signed. The EVM session runs on
# B2's inputs and B6's funding signature, the Tempo session on B2's inputs and B6's signed transaction.

VOUCHER_ROWS: list[dict[str, Any]] = MC["voucherSize"]["rows"]
VOUCHER_TAKEN = [r for r in VOUCHER_ROWS if r.get("taken")]
VOUCHER_OVER = [r for r in VOUCHER_ROWS if "expect" in r]
VOUCHER_FUNDING = {"mpp/session/evm": "signature", "mpp/session/tempo": "transaction"}


def test_voucher_size_rows_are_one_taken_size_and_one_over_the_bound() -> None:
    assert (len(VOUCHER_TAKEN), len(VOUCHER_OVER), len(VOUCHER_ROWS)) == (1, 1, 2)


def _session_unsigned(pairing: str, challenge: Any) -> Any:
    b2 = _b2(pairing)
    i = b2["input"]["inputs"]
    choice = {"challenge": challenge, "from": b2["input"]["account"].split(":")[2], "now": b2["input"].get("now", 0)}
    choice["deposit"] = int(i["deposit"])
    if pairing == "mpp/session/evm":
        choice |= {"credentialType": i["credentialType"], "tokenDomain": i["tokenDomain"]}
    return built(PAIRINGS[pairing].binding.build(choice, b2["advertised"]))


@pytest.mark.parametrize("pairing", list(VOUCHER_FUNDING))
@pytest.mark.parametrize("row", VOUCHER_TAKEN + VOUCHER_OVER, ids=lambda r: r["case"])
def test_voucher_size_a_session_voucher_measures_as_its_complete_does(pairing: str, row: dict[str, Any]) -> None:
    s = set_up(pairing)
    b6 = buyer(PAIRINGS[pairing].file, pairing, "B6")
    assert b6 is not None
    funded = b6["input"]["presented"]["payload"][VOUCHER_FUNDING[pairing]]
    shortest = _session_unsigned(pairing, s.placed).complete(funded, "0x00")
    assert not isinstance(shortest, Refusal), shortest
    challenge = described(s.placed, description_for(shortest, row["size"]))
    sized = {**shortest, "challenge": challenge}
    assert size_of(sized) == row["size"]
    u = _session_unsigned(pairing, challenge)
    if row.get("taken"):
        voucher = u.voucher(funded)
        assert voucher == _session_unsigned(pairing, s.placed).voucher(funded)
        assert voucher["primaryType"] == "Voucher"
        assert u.complete(funded, "0x00") == sized
    else:
        assert u.voucher(funded) == Refusal(row["expect"])
        assert u.complete(funded, "0x00") == Refusal(row["expect"])


# ── completeXdr (mpp-charge-stellar.json): complete writes the payer's signature into the simulated envelope, B2's
# with the row's footprint key (footprinted), and refuses a signed envelope over 8,192 base64 characters with
# stellar/tx-too-large, as bound refuses the credential carrying the envelope complete would have written.

XDR_ROWS: list[dict[str, Any]] = load("mpp-charge-stellar.json")["completeXdr"]["rows"]
XDR_TAKEN = [r for r in XDR_ROWS if r.get("taken")]
XDR_OVER = [r for r in XDR_ROWS if "expect" in r]


def test_complete_xdr_rows_are_two_taken_lengths_and_one_over_the_bound() -> None:
    assert (len(XDR_TAKEN), len(XDR_OVER), len(XDR_ROWS)) == (2, 1, 3)


@pytest.mark.parametrize("row", XDR_TAKEN + XDR_OVER, ids=lambda r: r["case"])
def test_complete_xdr_complete_refuses_a_signed_envelope_bound_refuses_for_its_length(row: dict[str, Any]) -> None:
    placed = set_up("mpp/charge/stellar").placed
    b2 = _b2("mpp/charge/stellar")
    assert len(footprinted(b2["input"]["inputs"]["simulatedXdr"], row["keyBytes"])) == row["simulatedLength"]
    made = _stellar_complete(placed, row["keyBytes"])

    def credential(transaction: str) -> dict[str, Any]:
        return {"challenge": placed, "payload": {"type": "transaction", "transaction": transaction}}

    if row.get("taken"):
        transaction = made["payload"]["transaction"]
        assert len(transaction) == row["signedLength"]
        assert made == credential(transaction)
        assert MPP_CHARGE_STELLAR.bound(made) == b2["advertised"]
    else:
        assert made == Refusal(row["expect"])
        taken = _stellar_complete(placed, XDR_TAKEN[0]["keyBytes"])
        over = footprinted(taken["payload"]["transaction"], row["keyBytes"])
        assert len(over) == row["signedLength"]
        assert MPP_CHARGE_STELLAR.bound(credential(over)) == Refusal(row["expect"])


# ── completeBlob (mpp-charge-xrpl.json): complete reads the signed blob as bound reads the credential it makes, after
# the credential's size. A padded row's blob is B6's transaction with its TxnSignature (Blob field 4) written as as many
# bytes of 0x11 as bring the blob to the row's size, in the canonical serialization (xrpl.org Binary Format: fields in
# type code then field code order, a Blob with its length prefix), which is what ripple-binary-codec's encode of the
# decoded transaction with that TxnSignature writes; any other row's blob is that many zero bytes.

BLOB_ROWS: list[dict[str, Any]] = load("mpp-charge-xrpl.json")["completeBlob"]["rows"]
BLOB_PADDED = [r for r in BLOB_ROWS if r.get("padded")]
BLOB_ZEROS = [r for r in BLOB_ROWS if not r.get("padded")]


def test_complete_blob_rows_are_five_zero_blobs_and_three_that_decode() -> None:
    assert (len(BLOB_ZEROS), len(BLOB_PADDED), len(BLOB_ROWS)) == (5, 3, 8)
    assert [r.get("taken", False) for r in BLOB_PADDED] == [True, True, False]


def _with_signature(blob: str, n: int) -> str:
    """The canonical blob with its TxnSignature written as n bytes of 0x11, and the fields around it as they are."""
    data = bytes.fromhex(blob)
    r = xrpl_codec._Reader(data)
    span = None
    while not r.end():
        start = r.at
        type_code, nth = r.field()
        xrpl_codec._value(r, type_code, nth, 0)
        if (type_code, nth) == (xrpl_codec.BLOB, 4):
            span = (start, r.at)
    assert span is not None, "no TxnSignature"
    signature = xrpl_codec._header(xrpl_codec.BLOB, 4) + xrpl_codec._length_prefix(n) + b"\x11" * n
    return (data[: span[0]] + signature + data[span[1] :]).hex().upper()


def _padded(blob: str, size: int) -> str:
    """B6's blob with a TxnSignature of as many bytes as bring it to size bytes."""
    n = size - (len(_with_signature(blob, 1000)) // 2 - 1000)
    out = _with_signature(blob, n)
    assert len(out) // 2 == size
    assert xrpl_codec.decode(bytes.fromhex(out))["TxnSignature"].upper() == "11" * n
    return out


@pytest.mark.parametrize("row", BLOB_ZEROS + BLOB_PADDED, ids=lambda r: r["case"])
def test_complete_blob_complete_reads_the_blob_as_bound_reads_it_after_its_size(row: dict[str, Any]) -> None:
    s = set_up("mpp/charge/xrpl")
    b6 = buyer("mpp-charge-xrpl.json", "mpp/charge/xrpl", "B6")
    assert b6 is not None
    size = row["blobBytes"]
    blob = _padded(b6["input"]["presented"]["payload"]["blob"], size) if row.get("padded") else "00" * size
    made = _xrpl_complete(s.placed, blob)
    credential = {"challenge": s.placed, "payload": {"type": "transaction", "blob": blob}}
    if row.get("taken"):
        assert made == credential
        assert MPP_CHARGE_XRPL.bound(made) == s.h
    else:
        assert made == Refusal(row["expect"])
        assert MPP_CHARGE_XRPL.bound(credential) == Refusal(row["expect"])


def test_complete_blob_the_credential_measures_65535_and_65537_at_32400_and_32401_bytes() -> None:
    placed = set_up("mpp/charge/xrpl").placed
    payloads = [{"type": "transaction", "blob": "00" * n} for n in (32_400, 32_401)]
    sizes = [size_of({"challenge": placed, "payload": p}) for p in payloads]
    assert sizes == [65_535, 65_537]
