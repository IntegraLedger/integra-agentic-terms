"""The buyer half of mpp/session/solana/memo and mpp/session/solana/stock, over the protocol package's
mpp-session-solana.json, as solsession.test.ts runs it. The memo opening there was composed with @solana/kit 8.4.0 and
not by the protocol package's builder: the memo piece's build, given the file's choice, hands the payer the file's
message, and the payer's signature with the key of 32 bytes 0x01, the file's payer, completes the file's credential;
the opening holds the file's channel; and the piece pays the challenge placed for buyer.json's ATR A through the gate.
pairings_of reads the file's session challenges, bound refuses the file's refusal rows with their codes, and the stock
session's opening, the buyer's stock client's, has no signed place for H, so the gate hands the signer nothing."""

import base64
import copy
from typing import Any

from breadth import ABC, LINK, Pairing, build_and_sign, offered, run
from ed25519 import sign
from mpp_docs import place
from support import HASH_A, A, confirm, hexb, load, serving

from integraledger_terms import MPP_SESSION_SOLANA_MEMO, MPP_SESSION_SOLANA_STOCK, Confirmed, Declined, Refusal, open_channel
from integraledger_terms.bindings._mpp import pairings_of

V = load("mpp-session-solana.json")
DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"


def pointer(path: str) -> Any:
    """The value at an RFC 6901 JSON Pointer into the file."""
    at: Any = V
    for part in path.split("/")[1:]:
        at = at[int(part)] if isinstance(at, list) else at[part]
    return at


def b2(pairing: str) -> dict[str, Any]:
    found: list[dict[str, Any]] = [r for r in V["buyer"]["rows"] if r["pairing"] == pairing and r["name"] == "B2"]
    assert len(found) == 1, pairing
    return found[0]


def issued(placed: dict[str, Any]) -> dict[str, Any]:
    """The challenge as issued: the placed one without the id and opaque that carry H."""
    return {k: v for k, v in placed.items() if k not in ("id", "opaque")}


def placed_for(challenge: dict[str, Any], h: str) -> list[dict[str, Any]]:
    out = place([challenge], h, LINK, challenge)
    assert not isinstance(out, Refusal), out
    return out


def payer_signature(request: Any) -> str:
    """The payer's Ed25519 signature over the session's open message, as 0x hex."""
    assert request["kind"] == "solana-session-open"
    return "0x" + sign(bytes(32 * [1]), hexb(request["message"])).hex()


def test_pairings_of_reads_the_session_challenges_as_the_file_does() -> None:
    """The readings rows: memo under modes ["pull"] and clientVoucher, stock under any other, the operated voucher and a
    challenge the stock schema refuses refused with the row's code."""
    rows = V["readings"]["rows"]
    assert len(rows) == 9
    for row in rows:
        expect = row["expect"]
        want = Refusal(expect["code"]) if isinstance(expect, dict) else tuple(expect)
        assert pairings_of(row["challenge"]) == want, row["case"]


def test_memo_build_hands_the_payer_the_files_open_and_its_signature_completes_the_files_credential() -> None:
    row = b2("mpp/session/solana/memo")
    choice = {k: v for k, v in V["memo"]["choice"].items() if k != "payer"}
    assert row["input"]["account"] == f"{DEVNET}:{V['fixed']['payer']}"

    def inspect(request: Any) -> None:
        assert request["kind"] == "solana-session-open"
        assert base64.b64encode(hexb(request["message"])).decode() == V["memo"]["expectMessageBase64"]
        assert [request["size"], request["channel"]] == [int(V["memo"]["expectSize"]), V["memo"]["expectChannel"]]

    p = Pairing(
        binding=MPP_SESSION_SOLANA_MEMO,
        doc=row["input"]["doc"],
        account=row["input"]["account"],
        answer=payer_signature,
        inputs=choice,
        placed=lambda h: placed_for(issued(row["input"]["doc"][0]), h),
    )
    signed, _ = build_and_sign(p, inspect)
    assert signed == pointer(V["memo"]["credential"])


def test_memo_bound_refuses_the_files_refusal_rows() -> None:
    """memoRefusals: an open action with no transaction, the stock open with no memo, a voucher; boundChallenge: the
    credential echoing a challenge pairings_of does not name the memo session for, with pairings_of's code."""
    credential = pointer(V["memo"]["credential"])
    for row in V["memoRefusals"]:
        payload = row.get("payload") or {**credential["payload"], **({"transaction": row["transaction"]} if "transaction" in row else {})}
        if "drop" in row:
            payload = {k: v for k, v in payload.items() if k != row["drop"]}
        assert MPP_SESSION_SOLANA_MEMO.bound({**credential, "payload": payload}) == Refusal(row["expect"]), row["case"]
    for row in V["boundChallenge"]["rows"]:
        binding = {"mpp/session/solana/memo": MPP_SESSION_SOLANA_MEMO, "mpp/session/solana/stock": MPP_SESSION_SOLANA_STOCK}[row["pairing"]]
        presented = {**pointer(row["credential"]), "challenge": row["challenge"]}
        assert binding.bound(presented) == Refusal(row["expect"]), row["case"]


def test_memo_opening_holds_the_files_channel() -> None:
    hold = open_channel(ABC, copy.deepcopy(pointer(V["memo"]["credential"])), MPP_SESSION_SOLANA_MEMO)
    assert not isinstance(hold, Declined), hold
    assert [hold["pairing"], hold["network"], hold["channel"], hold["h"]] == ["mpp/session/solana/memo", DEVNET, V["memo"]["expectChannel"], V["fixed"]["H"]]


def test_stock_opening_has_no_signed_place_and_the_payer_broadcasts_it() -> None:
    credential = V["stock"]["credential"]
    assert MPP_SESSION_SOLANA_STOCK.bound(credential) == Refusal("mpp/no-signed-place")
    assert MPP_SESSION_SOLANA_STOCK.broadcaster(credential) == "payer"


def test_stock_confirm_only_keeps_the_challenge_for_the_agreement() -> None:
    row = b2("mpp/session/solana/stock")
    doc = placed_for(issued(row["input"]["doc"][0]), HASH_A)
    out = run(lambda c: confirm(doc, offered(MPP_SESSION_SOLANA_STOCK), row["input"]["account"], c), serving(A))
    assert isinstance(out, Confirmed), out
    assert [out.chosen.pairing, out.request, out.atr_bytes, out.h] == ["mpp/session/solana/stock", None, A, HASH_A]
    assert out.chosen.choice["challenge"] == doc[0]
