"""Version-0 address table lookups in the Solana wires the buyer half decodes. The wire is
mpp-session-hedera-solana-xrpl.json's SV6 opening that names no index through its lookup, which that file keeps as a wire;
the presented payments are each pairing's own vector file's."""

import base64
from typing import Any

from integraledger_terms import (
    MPP_CHARGE_SOLANA,
    X402_BATCH_SETTLEMENT_SOLANA,
    X402_EXACT_SOLANA,
    X402_UPTO_SOLANA,
    Refusal,
)
from integraledger_terms.bindings import _svm
from support import load

HS = load("mpp-session-hedera-solana-xrpl.json")
SV6: dict[str, Any] = HS["SV6"]
S = load("x402-exact-solana.json")
U = load("x402-upto-solana.json")
BV = load("x402-batch-settlement.json")
MS = load("mpp-charge-solana.json")


def test_a_lookup_that_names_no_index_is_tx_malformed_in_every_solana_decode() -> None:
    """The runtime's sanitize refuses a version-0 message whose address table lookup loads no account ("each lookup
    table must be used to load at least one account", anza-xyz/solana-sdk 648387ee message/src/versions/v0/mod.rs
    L118-129): the decoder refuses it svm/tx-malformed, as the protocol package's decoder does, and so does every
    pairing that decodes a Solana wire, with that wire in the member it decodes. SV2's opening, the same message without
    the lookup, decodes."""
    # SV6.openings.emptyLookup: SV2's opening with one address table lookup appended that names no writable and no
    # read-only index, signed again by the payer.
    empty_lookup: str = SV6["openings"]["emptyLookup"]["wireBase64"]
    malformed = Refusal("svm/tx-malformed")
    assert not isinstance(_svm.decode_svm_tx(base64.b64decode(HS["SV2"]["wireBase64"])), Refusal)
    wire = base64.b64decode(empty_lookup)
    assert _svm.decode_svm_tx(wire) == malformed
    assert _svm.signed_wire(wire[1 + 64 * wire[0] :], HS["SV3"]["payer"], bytes(64)) == malformed
    deposit = {"amount": BV["fixed"]["svm"]["deposit"], "transaction": empty_lookup}
    voucher = {"channelId": BV["ES1"]["channelPda"], "maxClaimableAmount": "1000", "expiresAt": 0, "signature": "x"}
    presented: list[tuple[Any, dict[str, Any]]] = [
        (MPP_CHARGE_SOLANA, {"challenge": MS["place"]["expect"], "payload": {"type": "transaction", "transaction": empty_lookup}}),
        (X402_EXACT_SOLANA, {"x402Version": 2, "accepted": S["V2"]["accepted"], "payload": {"transaction": empty_lookup}}),
        (
            X402_UPTO_SOLANA,
            {"x402Version": 2, "accepted": U["EU4"]["accepted"], "payload": {"channelId": U["EU4"]["channelId"], "openTransaction": empty_lookup}},
        ),
        (
            X402_BATCH_SETTLEMENT_SOLANA,
            {
                "x402Version": 2,
                "accepted": BV["ES4"]["accepted"],
                "payload": {"type": "deposit", "channelConfig": BV["ES4"]["config"], "voucher": voucher, "deposit": deposit},
            },
        ),
    ]
    for binding, payment in presented:
        assert binding.bound(payment) == malformed, binding.id
