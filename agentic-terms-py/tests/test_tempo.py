"""The buyer pieces of mpp/charge/tempo/split-memo and mpp/charge/tempo/split-memo/push, over the protocol package's
mpp-charge-tempo-split-memo.json, as tempo.test.ts runs them. The buyer's stock MPP client builds and signs the Tempo
transaction from the placed challenge, so nothing is handed to the signer: confirmed over each form's placed challenge,
the build gives no request and the payment nothing signed. The payments are the file's: the Authorization header the
stock mppx 0.17.6 client returned for each placed challenge (pull with the fee paid for the payer, in a 0x78 envelope;
pull with the payer paying it, in a 0x76 envelope; push, which the client broadcast and names by its hash), and, for
push, the read of the named transaction (fetched) its server holds. check gives the file's expect.bound for each; the
push payment is read with that read as the landed receipt the caller's own reader read, and without it the push
payment is not yet bound. The account is each file's B2 row's.

mpp/session/tempo's opening, a tempo-call request, is shown from mpp-session-tempo.json's L1, a live open on Tempo
Moderato recorded with its receipt: the request is the call its signed bytes make, and every member the summary shows
is the receipt's own: the token's Transfer of the deposit from the payer to the escrow, and the escrow's ChannelOpened
(topics: event, channel id, payer, payee; data: operator, token, authorizedSigner, salt, expiring nonce hash,
deposit)."""

import base64
import copy
import json
from typing import Any

import pytest
from breadth import ABC, Pairing, confirms_only, never
from support import load

from integraledger_terms import MPP_CHARGE_TEMPO_SPLIT_MEMO, MPP_CHARGE_TEMPO_SPLIT_MEMO_PUSH, Checked, Declined, check
from integraledger_terms._summary import Opened, summary_of
from integraledger_terms._types import Payee, Summary, Validity
from integraledger_terms.bindings._tempo import TempoTx, decode_tempo_tx

A = b'{"atr":"A"}'

V = load("mpp-charge-tempo-split-memo.json")
FORMS = [("pullSponsored", MPP_CHARGE_TEMPO_SPLIT_MEMO), ("pullPayerPays", MPP_CHARGE_TEMPO_SPLIT_MEMO), ("push", MPP_CHARGE_TEMPO_SPLIT_MEMO_PUSH)]


def credential_of(authorization: str) -> Any:
    """The credential an Authorization header value carries: the base64url JSON after "Payment "."""
    scheme, value = authorization.split(" ")
    assert scheme == "Payment"
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def account_of(pairing: str) -> str:
    rows = [r for r in V["buyer"]["rows"] if r["pairing"] == pairing and r["name"] == "B2"]
    assert len(rows) == 1, pairing
    account: str = rows[0]["input"]["account"]
    return account


@pytest.mark.parametrize(("name", "binding"), FORMS, ids=[n for n, _ in FORMS])
def test_confirm_only_nothing_is_handed_to_the_signer(name: str, binding: Any) -> None:
    v = V[name]
    assert binding.id == v["pairing"]
    confirmed = confirms_only(Pairing(binding=binding, doc=[copy.deepcopy(v["placed"])], account=account_of(v["pairing"]), answer=never))
    assert confirmed.chosen.pairing == v["pairing"]


@pytest.mark.parametrize(("name", "binding"), FORMS, ids=[n for n, _ in FORMS])
def test_check_reads_the_bound_hash_from_the_stock_clients_payment(name: str, binding: Any) -> None:
    v = V[name]
    credential = credential_of(v["authorization"])
    assert credential["challenge"] == v["placed"]
    assert check(ABC, copy.deepcopy(credential), binding, v.get("fetched")) == Checked(h=v["expect"]["bound"])
    if "fetched" in v:
        # The push payment moved before it was presented: until the caller's reader has read the named transaction,
        # nothing it holds carries H.
        out = check(ABC, copy.deepcopy(credential), binding)
        assert isinstance(out, Declined) and out.code == "signed-not-bound", out


def test_the_tempo_call_summary_of_l1_is_its_receipts() -> None:
    l1 = load("mpp-session-tempo.json")["L1"]
    tx = decode_tempo_tx(bytes.fromhex(l1["raw"][2:]))
    assert isinstance(tx, TempoTx) and len(tx.calls) == 1, tx
    call = tx.calls[0]
    request = {
        "kind": "tempo-call",
        "chainId": tx.chain_id,
        "call": {"to": call.to, "data": "0x" + call.input.hex()},
        "validBefore": tx.valid_before,
        "broadcast": False,
    }
    transfer, opened = l1["receipt"]["logs"][:2]

    def address(w: str) -> str:
        return "0x" + w[-40:]

    def word(i: int) -> str:
        data: str = opened["data"][2:]
        return data[64 * i : 64 * i + 64]

    assert [address(t) for t in transfer["topics"][1:]] == [l1["sender"], opened["address"]]
    deposit = str(int(transfer["data"], 16))
    assert (int(word(0), 16), address(word(1))) == (0, transfer["address"])
    assert summary_of("mpp/session/tempo", request, A) == Summary(
        payees=(Payee(account=address(opened["topics"][3]), amount=deposit),),
        asset=transfer["address"],
        network="eip155:42431",
        validity=Validity(not_before=None, not_after=str(tx.valid_before), unit="seconds"),
        deposit=str(int(word(5), 16)),
        grant={"escrow": opened["address"], "authorizedSigner": address(word(2))},
        atr=A,
    )


# mpp/session/tempo's voucher, shown from the opening the gate hands its summary with the signer's account: L1's live v2
# open, whose receipt's ChannelOpened names the channel id (topic 1) the protocol package's tempoChannelId gives over the
# opening's call, L1's recorded sender and the expiring nonce hash of L1's signed bytes; and TS5's v1 opening on the
# earlier escrow, with TS2's validBefore, whose channel id TS5 holds for fixed.payer. The voucher is the one the build
# hands after an opening, cumulativeAmount 0, under the escrow's voucher domain as TS4 and TS5 name each. A voucher
# naming another channel, TS3's, has no summary.
T = load("mpp-session-tempo.json")


def _voucher(name: str, width: str, escrow: str, channel: str) -> dict[str, Any]:
    return {
        "kind": "eip712",
        "typedData": {
            "domain": {"name": name, "version": "1", "chainId": 42431, "verifyingContract": escrow},
            "primaryType": "Voucher",
            "types": {"Voucher": [{"name": "channelId", "type": "bytes32"}, {"name": "cumulativeAmount", "type": width}]},
            "message": {"channelId": channel, "cumulativeAmount": 0},
        },
    }


def _opened_by(request: dict[str, Any], signature: str) -> Opened:
    shown = summary_of("mpp/session/tempo", request, A)
    assert shown is not None
    return Opened(request=request, summary=shown, signature=signature)


def _shown_for(o: Opened) -> Summary:
    """What the voucher's summary shows: the opening's payee, asset, network and validity, with amount 0."""
    s = o.summary
    return Summary(amount="0", payees=(Payee(account=s.payees[0].account, amount="0"),), asset=s.asset, network=s.network, validity=s.validity, atr=A)  # fmt: skip


def test_the_voucher_on_l1s_channel_shows_l1s_payee_token_and_network() -> None:
    l1 = T["L1"]
    tx = decode_tempo_tx(bytes.fromhex(l1["raw"][2:]))
    assert isinstance(tx, TempoTx)
    call = tx.calls[0]
    assert call.to is not None
    request = {"kind": "tempo-call", "chainId": tx.chain_id, "call": {"to": call.to, "data": "0x" + call.input.hex()}, "validBefore": tx.valid_before, "broadcast": False}  # fmt: skip
    opened = _opened_by(request, l1["raw"])
    channel = l1["receipt"]["logs"][1]["topics"][1]
    assert (channel[:10], channel[-8:]) == (l1["expectChannelId"]["prefix"], l1["expectChannelId"]["suffix"])
    account = f"eip155:42431:{l1['sender']}"
    voucher = _voucher("TIP20 Channel Reserve", "uint96", call.to, channel)
    assert summary_of("mpp/session/tempo", voucher, A, None, opened, account) == _shown_for(opened)
    other = _voucher("TIP20 Channel Reserve", "uint96", call.to, T["TS3"]["expectChannelId"])
    assert summary_of("mpp/session/tempo", other, A, None, opened, account) is None


def test_the_voucher_on_ts5s_channel_shows_the_v1_openings_payee_token_and_network() -> None:
    f = T["fixed"]
    request = {"kind": "tempo-call", "chainId": f["chainId"], "call": {"to": f["escrowV1"], "data": T["TS5"]["expectOpenCalldata"]}, "validBefore": 1790000060, "broadcast": False}  # fmt: skip
    opened = _opened_by(request, "0x00")
    voucher = _voucher("Tempo Stream Channel", "uint128", f["escrowV1"], T["TS5"]["expectChannelId"])
    assert summary_of("mpp/session/tempo", voucher, A, None, opened, f"eip155:42431:{f['payer']}") == _shown_for(opened)
    assert opened.summary.payees[0].account == f["recipient"].lower()
