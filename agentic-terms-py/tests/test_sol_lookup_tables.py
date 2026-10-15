"""Version-0 address table lookups in the Solana wires the buyer half decodes, and the mpp/session/solana opening read
through the tables held for it in Held, as @integraledger/lcp holds them under the payment's own FETCHED member.
Expected codes, wires and tables are mpp-session-hedera-solana-xrpl.json's (its
agreedRefusals and SV6 rows, each read through its members) and each pairing's own vector file's."""

import base64
import copy
import json
from typing import Any

from integraledger_terms import (
    MPP_CHARGE_SOLANA,
    MPP_SESSION_SOLANA,
    X402_BATCH_SETTLEMENT_SOLANA,
    X402_EXACT_SOLANA,
    X402_UPTO_SOLANA,
    Refusal,
)
from integraledger_terms.bindings import _svm
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode, canonical_json
from integraledger_terms.bindings._mpp import Held

from mpp_docs import placed_doc
from support import load

HS = load("mpp-session-hedera-solana-xrpl.json")
# The rows SV6 holds; a package whose session file holds none fails each test that reads them, by name.
SV6: dict[str, Any] = HS.get("SV6", {})
S = load("x402-exact-solana.json")
U = load("x402-upto-solana.json")
BV = load("x402-batch-settlement.json")
MS = load("mpp-charge-solana.json")


def test_a_lookup_that_names_no_index_is_tx_malformed_in_every_solana_decode() -> None:
    """The runtime's sanitize refuses a version-0 message whose address table lookup loads no account ("each lookup
    table must be used to load at least one account", anza-xyz/solana-sdk 648387ee message/src/versions/v0/mod.rs
    L118-129): the decoder refuses it svm/tx-malformed, the code of the SV6 row whose opening it is, and so does every
    pairing that decodes a Solana wire, with that wire in the member it decodes. SV2's opening, the same message without
    the lookup, decodes."""
    # SV6.openings.emptyLookup: SV2's opening with one address table lookup appended that names no writable and no
    # read-only index, signed again by the payer (SV6.rows' liteSvm for it: SanitizeFailure).
    empty_lookup: str = SV6["openings"]["emptyLookup"]["wireBase64"]
    rows = [r for r in SV6["rows"] if r["opening"] == "SV6.openings.emptyLookup"]
    assert len(rows) == 1, [r["case"] for r in rows]
    malformed = Refusal(rows[0]["before"])
    assert malformed == Refusal("svm/tx-malformed")
    assert not isinstance(_svm.decode_svm_tx(base64.b64decode(HS["SV2"]["wireBase64"])), Refusal)
    wire = base64.b64decode(empty_lookup)
    assert _svm.decode_svm_tx(wire) == malformed
    assert _svm.signed_wire(wire[1 + 64 * wire[0] :], HS["SV3"]["payer"], bytes(64)) == malformed
    opening = {"action": "open", "channelId": HS["SV2"]["channel"], "transaction": empty_lookup}
    deposit = {"amount": BV["fixed"]["svm"]["deposit"], "transaction": empty_lookup}
    voucher = {"channelId": BV["ES1"]["channelPda"], "maxClaimableAmount": "1000", "expiresAt": 0, "signature": "x"}
    presented: list[tuple[Any, dict[str, Any]]] = [
        (MPP_SESSION_SOLANA, {"challenge": HS["SS1"]["solana"]["placed"], "payload": opening}),
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


# ── mpp/session/solana: the opening read through its tables ──────────────────────────────────────────────────────

H: str = HS["fixed"]["H"]
R: list[dict[str, Any]] = HS["agreedRefusals"]["rows"]
# The agreedRefusals rows that hold an opening whose open names account 4 or account 5 through an address lookup table.
TABLE_ROWS = [r for r in R if "wireBase64" in r and "channel" in r]
# SV6.about: the operator challenge names the operator of the one table row that names one.
OPERATORS = [r["operator"] for r in TABLE_ROWS if "operator" in r]


def solana_placed(details: dict[str, Any]) -> dict[str, Any]:
    """SS1's Solana challenge with its methodDetails updated by details, placed with H and the file's link as SS1's
    placed challenge is: its id and opaque derive from H, not from the request."""
    issued = HS["SS1"]["solana"]["challenge"]
    raw = b64u_decode(issued["request"])
    assert raw is not None
    request = json.loads(raw)
    request["methodDetails"].update(details)
    changed = {**issued, "request": b64u_encode(canonical_json(request).encode("utf-8"))}
    return placed_doc(changed, H, HS["fixed"]["link"])[0]


C_S: dict[str, Any] = HS["SS1"]["solana"]["placed"]


def challenge_of(c: str) -> dict[str, Any]:
    """A challenge SV6.about names: C_S, SS1's placed Solana challenge; client, it with voucherSigner client; or
    operator, it with voucherSigner operator and the table rows' operator."""
    if c == "C_S":
        return C_S
    if c == "client":
        return solana_placed({"voucherSigner": "client"})
    assert c == "operator" and len(OPERATORS) == 1, (c, OPERATORS)
    return solana_placed({"voucherSigner": "operator", "operator": OPERATORS[0]})


def at(path: str) -> Any:
    """The value a row's opening member names: a path into the file, such as agreedRefusals.rows[21]."""
    out: Any = HS
    for part in path.split("."):
        name, _, index = part.partition("[")
        out = out[name]
        if index:
            out = out[int(index.rstrip("]"))]
    return out


# The channel of each SV6 opening, which carries none of its own: the channel of the opening its composed text makes
# it from, or the channel that text names.
MADE_FROM = {
    "SV6.openings.channelAtOne": "agreedRefusals.rows[22]",
    "SV6.openings.bothTables": "agreedRefusals.rows[21]",
    "SV6.openings.threeNoOpen": "agreedRefusals.rows[21]",
    "SV6.openings.emptyLookup": "SV2",
}
WRONG_SALT_CHANNEL = "58wwaqTCtqNbnDHV3F4MPwvqhXMxbbnRdfcqEByHeVyx"


def channel_of(path: str) -> str:
    opening = at(path)
    if "channel" in opening:
        channel: str = opening["channel"]
        return channel
    if path == "SV6.openings.threeWrongSalt":
        assert f"the channel is {WRONG_SALT_CHANNEL}" in opening["composed"]
        return WRONG_SALT_CHANNEL
    assert f"{MADE_FROM[path]}'s opening" in opening["composed"], path
    return channel_of(MADE_FROM[path])


def presented_for(wire: str, channel: str, c: str) -> dict[str, Any]:
    """An opening of wire and channel answering challenge c, with authentication naming the challenge's id for
    operator."""
    challenge = challenge_of(c)
    payload: dict[str, Any] = {"action": "open", "channelId": channel, "transaction": wire}
    if c == "operator":
        payload["authentication"] = {"type": "proof", "challengeId": challenge["id"], "payer": HS["SV3"]["payer"], "signature": "x"}
    return {"challenge": challenge, "payload": payload}


def presented_of(path: str, c: str) -> dict[str, Any]:
    """The opening path names, answering challenge c."""
    return presented_for(at(path)["wireBase64"], channel_of(path), c)


def complete(c: str, payload: dict[str, Any]) -> Any:
    """build's complete under challenge c, for the composed open payload."""
    unsigned = MPP_SESSION_SOLANA.build({"challenge": challenge_of(c)}, H)
    assert not isinstance(unsigned, Refusal), unsigned
    return unsigned.complete(payload)


def within(c: str, opening: Any, action: str = "voucher") -> Any:
    return MPP_SESSION_SOLANA.build_within({"challenge": challenge_of(c), "opening": opening, "cumulativeAmount": 100, "action": action}, H)


def served_tables(row: dict[str, Any]) -> list[dict[str, Any]]:
    """The tables a reader serving the row's accounts gives for its opening: for each lookup in order, the table's
    address and the served table's entries at the lookup's writable and read-only indexes."""
    tx = _svm.decode_svm_tx(base64.b64decode(at(row["opening"])["wireBase64"]))
    assert not isinstance(tx, Refusal), tx
    out = []
    for lookup in tx.lookups:
        entries = SV6["tables"][row["accounts"][lookup.table]]["entries"]
        out.append({"address": lookup.table, "writable": [entries[i] for i in lookup.writable], "readonly": [entries[i] for i in lookup.readonly]})
    return out


def test_the_placed_challenges_are_ss1s() -> None:
    assert len(TABLE_ROWS) == 3 and len(OPERATORS) == 1, [r["case"] for r in TABLE_ROWS]
    assert solana_placed({}) == C_S
    for c in ("client", "operator"):
        assert (challenge_of(c)["id"], challenge_of(c)["opaque"]) == (C_S["id"], C_S["opaque"]), c
        assert challenge_of(c)["request"] != C_S["request"], c


def test_the_table_rows_of_agreed_refusals_are_read_first_without_their_tables() -> None:
    """agreedRefusals' table rows (each holding an opening and its channel): an open that names account 4 or account
    5 through an address lookup table, under the operator challenge naming the row's operator where it names one and
    under client and C_S otherwise. bound, build's complete and build_within (a voucher and a close) read the open's
    accounts only through the tables held for the opening in Held, so each gives the row's code without them."""
    assert len(TABLE_ROWS) == 3, [r["case"] for r in TABLE_ROWS]
    for row in TABLE_ROWS:
        assert row["expect"] == "svm/read-first", row["case"]
        for c in ("operator",) if "operator" in row else ("client", "C_S"):
            presented = presented_for(row["wireBase64"], row["channel"], c)
            answers = [
                MPP_SESSION_SOLANA.bound(presented),
                complete(c, presented["payload"]),
                within(c, presented, "voucher"),
                within(c, presented, "close"),
            ]
            assert answers == [Refusal(row["expect"])] * 4, (row["case"], c, answers)


def test_the_read_free_checks_come_before_the_tables_on_an_opening_with_lookups() -> None:
    """agreedRefusals' table row that names an operator, whose opening's message has address table lookups, under its
    operator challenge with no tables held: each check that reads no account gives its own code, and none is
    svm/read-first, which the opening gives once every such check passes. Each expected code is what
    @integraledger/lcp's sessionSolana.bound gives for the same opening: without authentication,
    mpp/credential-malformed; with authentication naming another challenge, svm/proof-not-challenge; with a channelId
    that is not a key, svm/channel-mismatch; and under the challenge with its request's operator not a key (its id and
    opaque kept), svm/input-malformed."""
    rows = [r for r in TABLE_ROWS if "operator" in r]
    assert len(rows) == 1, [r["case"] for r in rows]
    row = rows[0]
    challenge = challenge_of("operator")
    auth = {"type": "proof", "challengeId": challenge["id"], "payer": HS["SV3"]["payer"], "signature": "x"}

    def bound(c: dict[str, Any], **members: Any) -> Any:
        payload = {"action": "open", "channelId": row["channel"], "transaction": row["wireBase64"], **members}
        return MPP_SESSION_SOLANA.bound({"challenge": c, "payload": payload})

    raw = b64u_decode(challenge["request"])
    assert raw is not None
    request = json.loads(raw)
    request["methodDetails"]["operator"] = "not-a-key"
    no_key = {**challenge, "request": b64u_encode(canonical_json(request).encode("utf-8"))}
    assert bound(challenge, authentication=auth) == Refusal("svm/read-first")
    answers = [
        bound(challenge),
        bound(challenge, authentication={**auth, "challengeId": "another"}),
        bound(challenge, channelId="not-a-key", authentication=auth),
        bound(no_key, authentication={**auth, "challengeId": no_key["id"]}),
    ]
    codes = ["mpp/credential-malformed", "svm/proof-not-challenge", "svm/channel-mismatch", "svm/input-malformed"]
    assert answers == [Refusal(c) for c in codes], answers


LOADED = "InvalidProgramForExecution"
# fetchPresented's read verdicts: the rows whose answer comes from a table account's read, which terms makes none of.
READ_VERDICTS = {"svm/not-found", "svm/table-unusable", "svm/unreadable"}


def sv6_kind(row: dict[str, Any]) -> str:
    """How the buyer half reads an SV6 row, by its members: before, refused by a read-free check; given, tables given
    to bound; loaded, whose opening's addresses the runtime loaded from the served tables (SV6.about: liteSvm
    InvalidProgramForExecution), so its tables are the served tables' entries; read, the rest, whose answer is
    fetchPresented's read of a table account."""
    if "before" in row:
        return "before"
    if "given" in row:
        return "given"
    return "loaded" if row.get("liteSvm") == LOADED else "read"


def test_sv6_rows_each_read_by_its_members() -> None:
    rows = SV6["rows"]
    assert len(rows) == 19
    kinds = [sv6_kind(r) for r in rows]
    assert all(kinds.count(k) > 0 for k in ("before", "given", "loaded", "read")), kinds
    for row in rows:
        for c in row["challenges"]:
            presented = presented_of(row["opening"], c)
            answer = Refusal(row.get("before", "svm/read-first"))
            # Without tables: bound and build's complete, which reads no table.
            assert (MPP_SESSION_SOLANA.bound(presented), complete(c, presented["payload"])) == (answer, answer), (row["case"], c)
            kind = sv6_kind(row)
            if kind == "before":
                assert row["expect"] == row["before"], row["case"]
            elif kind == "given":
                for tables in row["given"]:
                    assert MPP_SESSION_SOLANA.bound(Held(presented, {"tables": tables})) == Refusal(row["bound"]), tables
            elif kind == "loaded":
                tables = served_tables(row)
                held = Held(presented, {"tables": tables})
                if isinstance(row["expect"], str):
                    assert MPP_SESSION_SOLANA.bound(held) == Refusal(row["expect"]), (row["case"], c)
                    continue
                assert tables == row["expect"]["tables"], row["case"]
                if "bound" in row:
                    assert MPP_SESSION_SOLANA.bound(held) == (H if row["bound"] == "H" else Refusal(row["bound"])), (row["case"], c)
                if "signer" in row:
                    for action in ("voucher", "close"):
                        built = within(c, held, action)
                        assert not isinstance(built, Refusal), (row["case"], c, built)
                        assert [(r["kind"], r["signer"]) for r in built.requests] == [("ed25519-raw", row["signer"])]
            else:
                assert row["expect"] in READ_VERDICTS and "accounts" in row, row["case"]


def test_the_tables_are_read_only_beside_the_opening() -> None:
    """The tables are read only from what is held for the opening in Held, as @integraledger/lcp holds them under the
    payment's own FETCHED member: an attribute no JSON decode makes. The agreedRefusals row that carries a tables
    member holds the opening of SV6's operator row whose read names the channel at account 4
    (svm/signer-not-operator). Held for it, tables naming the operator there give H; the same
    tables as the opening's own member give the row's code to bound and build_within, as the opening without them
    does; held with both, the held tables alone are read. A JSON round trip or dict() of the held opening drops them,
    and copy.copy keeps them. On a client channel, build_within names the held tables' signer, and the opening's own
    tables naming another signer are not read."""
    rows = [r for r in R if "tables" in r]
    assert len(rows) == 1, [r["case"] for r in rows]
    row = rows[0]
    sent = presented_of(row["opening"], "operator")
    forged = {"tables": row["tables"]}
    assert MPP_SESSION_SOLANA.bound(Held(sent, forged)) == H
    string_keyed = {**sent, "tables": row["tables"]}
    assert (MPP_SESSION_SOLANA.bound(string_keyed), within("operator", string_keyed)) == (Refusal(row["expect"]),) * 2
    read = [r for r in SV6["rows"] if r["opening"] == row["opening"] and r.get("bound") == "svm/signer-not-operator"]
    assert len(read) == 1, [r["case"] for r in read]
    fetched = Held(sent, read[0]["expect"])
    assert MPP_SESSION_SOLANA.bound(fetched) == Refusal("svm/signer-not-operator")
    assert MPP_SESSION_SOLANA.bound(Held(string_keyed, read[0]["expect"])) == Refusal("svm/signer-not-operator")
    held = Held(sent, forged)
    for copied in (json.loads(json.dumps(held)), dict(held), {**held}):
        assert MPP_SESSION_SOLANA.bound(copied) == Refusal(row["expect"])
    assert MPP_SESSION_SOLANA.bound(copy.copy(held)) == H
    client = [r for r in SV6["rows"] if "signer" in r]
    assert len(client) == 1, [r["case"] for r in client]
    opening = presented_of(client[0]["opening"], "client")
    # The same tables naming another signer, the operator row's channel, at each read-only index.
    another = next(r["channel"] for r in TABLE_ROWS if "operator" in r)
    other = [{**t, "readonly": [another] * len(t["readonly"])} for t in client[0]["expect"]["tables"]]
    for held_opening in (Held(opening, client[0]["expect"]), Held({**opening, "tables": other}, client[0]["expect"])):
        built = within("client", held_opening)
        assert not isinstance(built, Refusal), built
        assert [r["signer"] for r in built.requests] == [client[0]["signer"]]
    assert within("client", {**opening, "tables": other}) == Refusal("svm/read-first")


def test_an_opening_without_lookups_is_checked_in_the_same_order() -> None:
    """SV5's operator opening, whose message has no lookups, under its operator challenge: authentication is checked
    before the open's channel is compared with the payload's channelId, as on an opening with lookups, so a channelId
    of another channel gives authentication's code where authentication is missing or names another challenge."""
    sv5 = HS["SV5"]
    challenge = solana_placed(sv5["methodDetails"])
    auth = {"type": "proof", "challengeId": challenge["id"], "payer": HS["SV3"]["payer"], "signature": "x"}

    def bound(channel: str, **members: Any) -> Any:
        payload = {"action": "open", "channelId": channel, "transaction": sv5["opening"]["wireBase64"], **members}
        return MPP_SESSION_SOLANA.bound({"challenge": challenge, "payload": payload})

    other = HS["SV2"]["channel"]
    assert bound(sv5["opening"]["channel"], authentication=auth) == H
    assert bound(other, authentication=auth) == Refusal("svm/channel-mismatch")
    assert bound(other) == Refusal("mpp/credential-malformed")
    assert bound(other, authentication={**auth, "challengeId": "another"}) == Refusal("svm/proof-not-challenge")
