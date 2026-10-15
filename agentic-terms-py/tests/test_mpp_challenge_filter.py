"""Each MPP pairing's one challenge filter: pairings_of makes every check the pairing's build and bound make on the
challenge alone, and those take only a challenge pairings_of_placed names for the pairing, refusing any other with the
code pairings_of gives it (mpp/not-this-pairing where it names only other pairings). The vector files' boundChallenge
rows hold bound to it. The build cases are the protocol package's own (lcp 0.4.0, test/mpp-build-filter.test.ts): each
pairing's build, given the vector file's B2 inputs with the changed challenge in place of B2's, refuses with the code
the case names."""

import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

import integraledger_terms as terms
from integraledger_terms import Refusal
from integraledger_terms.bindings._bolt11 import decode as decode_bolt11
from integraledger_terms.bindings._codec import b64u_decode, b64u_encode, canonical_json
from integraledger_terms.bindings._mpp import pairings_of
from integraledger_terms.pieces._mpp import pairings_of_placed

from support import VECTORS, load

BINDINGS: dict[str, Any] = {
    v.id: v for n in dir(terms) if n.startswith("MPP_") and hasattr(v := getattr(terms, n), "id") and hasattr(v, "bound")
}


def pointer(doc: Any, path: str) -> Any:
    """The value at an RFC 6901 JSON Pointer."""
    at = doc
    for part in path.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        at = at[int(key)] if isinstance(at, list) else at[key]
    return at


def issued(c: dict[str, Any]) -> dict[str, Any]:
    """The challenge as the seller issued it: no id and no opaque."""
    return {k: v for k, v in c.items() if k not in ("id", "opaque")}


# ── The vector files' boundChallenge rows.

BOUND_ROWS: list[tuple[str, dict[str, Any]]] = [
    (f.name, row)
    for f in sorted(VECTORS.glob("mpp-*.json"))
    for row in load(f.name).get("boundChallenge", {}).get("rows", [])
]


def test_the_bound_challenge_rows_are_read() -> None:
    assert len(BOUND_ROWS) > 0


@pytest.mark.parametrize(("file", "row"), BOUND_ROWS, ids=[f"{f}: {r['case']}" for f, r in BOUND_ROWS])
def test_bound_refuses_a_challenge_the_filter_does_not_name_for_its_pairing(file: str, row: dict[str, Any]) -> None:
    credential = copy.deepcopy(pointer(load(file), row["credential"]))
    pairing = row["pairing"]
    named = pairings_of(issued(row["challenge"]))
    assert isinstance(named, Refusal) or pairing not in named
    assert pairing not in pairings_of_placed(row["challenge"])
    assert BINDINGS[pairing].bound({**credential, "challenge": copy.deepcopy(row["challenge"])}) == Refusal(row["expect"])


# ── The build cases.

FILES = {
    "mpp/charge/lightning": "mpp-charge-lightning.json",
    "mpp/session/lightning": "mpp-session-lightning.json",
    "mpp/charge/solana": "mpp-charge-solana.json",
    "mpp/charge/usdc/solana": "mpp-charge-usdc-solana.json",
    "mpp/charge/evm/permit2": "mpp-charge-evm-permit2.json",
    "mpp/charge/xrpl": "mpp-charge-xrpl.json",
    "mpp/session/xrpl": "mpp-session-hedera-solana-xrpl.json",
    "mpp/subscription/tempo": "mpp-subscription-tempo.json",
    "mpp/charge/hedera": "mpp-charge-hedera.json",
    "mpp/charge/stellar": "mpp-charge-stellar.json",
}


def b2(pairing: str) -> dict[str, Any]:
    rows = [r for r in load(FILES[pairing])["buyer"]["rows"] if r["name"] == "B2" and r["pairing"] == pairing]
    assert len(rows) == 1, pairing
    row: dict[str, Any] = rows[0]
    return row


def own(pairing: str) -> dict[str, Any]:
    """B2's placed challenge that offers pairing."""
    found: dict[str, Any] = next(c for c in b2(pairing)["input"]["doc"] if pairing in pairings_of_placed(c))
    return copy.deepcopy(found)


def account(row: dict[str, Any]) -> str:
    return ":".join(row["input"]["account"].split(":")[2:])


def decoded(c: dict[str, Any]) -> dict[str, Any]:
    raw = b64u_decode(c["request"], 8192)
    assert raw is not None
    request: dict[str, Any] = json.loads(raw)
    return request


def with_request(c: dict[str, Any], edit: Callable[[dict[str, Any]], object]) -> dict[str, Any]:
    r = decoded(c)
    edit(r)
    return {**c, "request": b64u_encode(canonical_json(r).encode("utf-8"))}


def details(r: dict[str, Any]) -> dict[str, Any]:
    md: dict[str, Any] = r["methodDetails"]
    return md


def solana_build(pairing: str, row: dict[str, Any], challenge: dict[str, Any], mine: dict[str, Any]) -> Any:
    """The Solana charges' build, given the buyer's own decimals, token program and blockhash: those of B2's challenge."""
    i = row["input"]["inputs"]
    choice = {
        "challenge": challenge,
        "payer": account(row),
        "computeUnitLimit": i["computeUnitLimit"],
        "computeUnitPrice": int(i["computeUnitPrice"]),
        "decimals": mine.get("decimals"),
        "tokenProgram": mine.get("tokenProgram"),
        "recentBlockhash": mine.get("recentBlockhash"),
    }
    return BINDINGS[pairing].build({k: v for k, v in choice.items() if v is not None}, row["advertised"])


def build(pairing: str, challenge: dict[str, Any]) -> Any:
    """The pairing's build, with the B2 row's account, inputs and time."""
    row = b2(pairing)
    h, i, binding = row["advertised"], row["input"].get("inputs", {}), BINDINGS[pairing]
    if pairing == "mpp/charge/lightning":
        return binding.build({"challenge": challenge}, h)
    if pairing == "mpp/session/lightning":
        return binding.build({"challenge": challenge, "returnInvoice": i["returnInvoice"]}, h)
    if pairing == "mpp/charge/solana":
        return solana_build(pairing, row, challenge, details(decoded(row["input"]["doc"][0])))
    if pairing == "mpp/charge/usdc/solana":
        return solana_build(pairing, row, challenge, details(decoded(row["input"]["doc"][0]))["solana"])
    if pairing == "mpp/charge/evm/permit2":
        return binding.build({"challenge": challenge, "from": account(row), "now": row["input"]["now"], "spender": i["spender"]}, h)
    if pairing == "mpp/charge/xrpl":
        return binding.build({"challenge": challenge, "account": account(row), **i}, h)
    if pairing == "mpp/session/xrpl":
        xrpl = {**i["xrpl"], "publicKey": i["xrpl"]["publicKey"].removeprefix("0x")}
        return binding.build({"challenge": challenge, "from": account(row), "now": 0, "deposit": int(i["deposit"]), "xrpl": xrpl}, h)
    if pairing == "mpp/subscription/tempo":
        return binding.build({"challenge": challenge, "from": account(row), "now": row["input"]["now"]}, h)
    if pairing == "mpp/charge/stellar":
        return binding.build({"challenge": challenge, "payer": account(row), "now": row["input"]["now"], **i}, h)
    assert pairing == "mpp/charge/hedera"
    valid_start = {"seconds": int(i["validStart"]["seconds"]), "nanos": i["validStart"]["nanos"]}
    choice = {"challenge": challenge, "payer": account(row), "node": i["node"], "validStart": valid_start, "maxFee": int(i["maxFee"])}
    return binding.build(choice, h)


def past_invoice(c: dict[str, Any], invoice: str) -> dict[str, Any]:
    """The challenge with expires one second after its invoice's expiry (BOLT 11: the timestamp plus x)."""
    b = decode_bolt11(invoice)
    assert not isinstance(b, Refusal)
    at = datetime.fromtimestamp(b.timestamp + b.expiry + 1, UTC)
    return {**c, "expires": at.strftime("%Y-%m-%dT%H:%M:%SZ")}


def set_in(path: list[str], value: Any) -> Callable[[dict[str, Any]], object]:
    def edit(r: dict[str, Any]) -> None:
        at = r
        for k in path[:-1]:
            at = at[k]
        at[path[-1]] = value

    return edit


def recipient_checksum_fails(r: dict[str, Any]) -> None:
    to: str = r["recipient"]
    r["recipient"] = to[:-1] + ("p" if to.endswith("r") else "r")


Case = tuple[str, str, Callable[[dict[str, Any]], dict[str, Any]], str, str | None]
MD = "methodDetails"
CASES: list[Case] = [
    # draft-lightning-charge-00 and BOLT 11: the invoice decodes, carries the challenge's payment hash, no inline
    # description, and the currency of the network the challenge names; expires is no later than the invoice's expiry.
    ("an invoice that does not decode", "mpp/charge/lightning", lambda c: with_request(c, set_in([MD, "invoice"], "lnbc1abc")), "ln/invoice-malformed", None),
    ("another payment hash", "mpp/charge/lightning", lambda c: with_request(c, set_in([MD, "paymentHash"], "00" * 32)), "ln/payment-hash-mismatch", None),
    ("network signet for a bc invoice", "mpp/charge/lightning", lambda c: with_request(c, set_in([MD, "network"], "signet")), "ln/currency-network", None),
    ("a request description", "mpp/charge/lightning", lambda c: with_request(c, set_in(["description"], "Weather")), "ln/description-present", None),
    ("expires one second after the invoice's", "mpp/charge/lightning", lambda c: past_invoice(c, details(decoded(c))["invoice"]), "ln/expires-after-invoice", None),
    ("expires one second after the deposit invoice's", "mpp/session/lightning", lambda c: past_invoice(c, decoded(c)["depositInvoice"]), "ln/expires-after-invoice", None),
    ("a deposit invoice that does not decode", "mpp/session/lightning", lambda c: with_request(c, set_in(["depositInvoice"], "lnbc1abc")), "ln/invoice-malformed", None),
    ("another payment hash", "mpp/session/lightning", lambda c: with_request(c, set_in(["paymentHash"], "00" * 32)), "ln/payment-hash-mismatch", None),
    # MPP's Solana charge (sol [S7]): what build writes of methodDetails in place of its own inputs.
    ("methodDetails.splits", "mpp/charge/solana", lambda c: with_request(c, lambda r: details(r).__setitem__("splits", [{"recipient": r["recipient"], "amount": "1"}])), "svm/input-malformed", None),
    ("methodDetails.confidential true", "mpp/charge/solana", lambda c: with_request(c, set_in([MD, "confidential"], True)), "svm/input-malformed", None),
    ("methodDetails.decimals 256, past a token's u8", "mpp/charge/solana", lambda c: with_request(c, set_in([MD, "decimals"], 256)), "svm/input-malformed", None),
    ("methodDetails.tokenProgram the System program", "mpp/charge/solana", lambda c: with_request(c, set_in([MD, "tokenProgram"], "1" * 32)), "svm/input-malformed", None),
    ("methodDetails.recentBlockhash not a key", "mpp/charge/solana", lambda c: with_request(c, set_in([MD, "recentBlockhash"], "abc")), "svm/input-malformed", None),
    ("methodDetails.solana.decimals 1.5", "mpp/charge/usdc/solana", lambda c: with_request(c, set_in([MD, "solana", "decimals"], 1.5)), "svm/input-malformed", None),
    # MPP's EVM charge: permit2 pays the recipient amount less the splits, which "MUST be strictly less than amount".
    ("splits adding up to amount", "mpp/charge/evm/permit2", lambda c: with_request(c, lambda r: details(r).__setitem__("splits", [{"recipient": r["recipient"], "amount": r["amount"]}])), "mpp/input-malformed", None),
    ("amount 0 with permit2 alone listed", "mpp/charge/evm/permit2", lambda c: with_request(c, lambda r: (r.__setitem__("amount", "0"), details(r).__setitem__("credentialTypes", ["permit2"]))), "mpp/input-malformed", None),
    ("amount 0 with authorization listed too", "mpp/charge/evm/permit2", lambda c: with_request(c, set_in(["amount"], "0")), "mpp/not-this-pairing", "mpp/charge/evm/authorization"),
    # draft-xrpl-charge-00: build writes no memo but the LCP one; the session's channel id derives from the
    # recipient's AccountID.
    ("methodDetails.memos", "mpp/charge/xrpl", lambda c: with_request(c, set_in([MD, "memos"], [{"Memo": {"MemoData": "6C6370"}}])), "xrpl/memos-not-carried", None),
    ("a recipient whose checksum fails", "mpp/session/xrpl", lambda c: with_request(c, recipient_checksum_fails), "mpp/request-malformed", None),
    # draft-tempo-subscription-00: the key authorization's uint64 expiry and period.
    ("periodCount 10^16 - 1 weeks", "mpp/subscription/tempo", lambda c: with_request(c, lambda r: r.update(periodCount="9999999999999999", periodUnit="week")), "mpp/request-malformed", None),
    ("subscriptionExpires in 1969", "mpp/subscription/tempo", lambda c: with_request(c, set_in(["subscriptionExpires"], "1969-12-31T23:59:59Z")), "mpp/request-malformed", None),
    # Hedera's chain ids: 295 mainnet and 296 testnet.
    ("methodDetails.chainId 1", "mpp/charge/hedera", lambda c: with_request(c, set_in([MD, "chainId"], 1)), "hedera/chain-id-unnamed", None),
    # SEP-41's transfer takes an i128.
    ("amount 2^127", "mpp/charge/stellar", lambda c: with_request(c, set_in(["amount"], str(2**127))), "stellar/option-malformed", None),
]


def test_the_build_cases_are_read() -> None:
    assert len(CASES) == 23


@pytest.mark.parametrize(("name", "pairing", "change", "code", "other"), CASES, ids=[f"{p}: {n}" for n, p, _, _, _ in CASES])
def test_pairings_of_makes_each_check_build_makes_on_the_challenge_alone(
    name: str, pairing: str, change: Callable[[dict[str, Any]], dict[str, Any]], code: str, other: str | None
) -> None:
    mine = own(pairing)
    assert not isinstance(build(pairing, mine), Refusal)
    changed = change(mine)
    assert pairing not in pairings_of_placed(changed)
    assert pairings_of(issued(changed)) == (Refusal(code) if other is None else (other,))
    assert build(pairing, changed) == Refusal(code)


# draft-lightning-charge-00: the seller's node writes the invoice after the payment hash, so pairings_of takes a
# challenge without it, and the pairing's filter requires it once placed. A challenge without the invoice that
# pairings_of refuses for another reason gives that refusal from build and bound too; one it names gives
# ln/invoice-malformed.
INVOICELESS: list[tuple[str, str, Callable[[dict[str, Any]], object], str]] = [
    ("without the invoice", "mpp/charge/lightning", lambda r: details(r).pop("invoice"), "ln/invoice-malformed"),
    ("without the invoice, with a request description", "mpp/charge/lightning", lambda r: (details(r).pop("invoice"), r.update(description="Weather")), "ln/description-present"),
    ("without the invoice, network testnet, which MPP Lightning does not define", "mpp/charge/lightning", lambda r: (details(r).pop("invoice"), details(r).update(network="testnet")), "ln/currency-network"),
    ("without the deposit invoice, with a request description", "mpp/session/lightning", lambda r: (r.pop("depositInvoice"), r.update(description="Weather")), "ln/description-present"),
]


@pytest.mark.parametrize(("name", "pairing", "edit", "code"), INVOICELESS, ids=[f"{p}: {n}" for n, p, _, _ in INVOICELESS])
def test_a_lightning_challenge_without_its_invoice(name: str, pairing: str, edit: Callable[[dict[str, Any]], object], code: str) -> None:
    changed = with_request(own(pairing), edit)
    assert pairings_of(issued(changed)) == ((pairing,) if code == "ln/invoice-malformed" else Refusal(code))
    assert pairings_of_placed(changed) == ()
    assert build(pairing, changed) == Refusal(code)
    payment = {"challenge": changed, "payload": {"action": "open", "preimage": "00" * 32}}
    assert BINDINGS[pairing].bound(payment) == Refusal(code)


# A placed challenge whose opaque does not decode as a JSON object of strings (mpp/opaque-malformed): no pairing
# pairings_of_placed names, and build refuses it with that code. The Hedera charge's build takes the challenge's id,
# realm and request, and no opaque.
@pytest.mark.parametrize("pairing", sorted(FILES))
def test_a_placed_challenge_whose_opaque_does_not_read(pairing: str) -> None:
    changed = {**own(pairing), "opaque": "!!"}
    assert pairings_of_placed(changed) == ()
    if pairing != "mpp/charge/hedera":
        assert build(pairing, changed) == Refusal("mpp/opaque-malformed")


# The EVM transaction and hash charges' bound, which no signed place carries H in, holds the echoed challenge to the
# filter first: a challenge it does not name for the pairing is refused with its code.
@pytest.mark.parametrize("pairing", ["mpp/charge/evm/transaction", "mpp/charge/evm/hash"])
def test_the_evm_charges_without_a_signed_place_hold_the_filter(pairing: str) -> None:
    v = load("mpp-charge-evm-authorization.json")
    credential = copy.deepcopy(next(r for r in v["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"])
    r = decoded(credential["challenge"])
    r[MD] = {k: x for k, x in r[MD].items() if k != "credentialTypes"}
    offered = {**credential, "challenge": {**credential["challenge"], "request": b64u_encode(canonical_json(r).encode("utf-8"))}}
    assert BINDINGS[pairing].bound(offered) == Refusal("mpp/no-signed-place")
    del r["amount"]
    changed = {**credential, "challenge": {**credential["challenge"], "request": b64u_encode(canonical_json(r).encode("utf-8"))}}
    assert pairings_of(issued(changed["challenge"])) == Refusal("mpp/request-malformed")
    assert BINDINGS[pairing].bound(changed) == Refusal("mpp/request-malformed")
    permit2 = {**r, "amount": "1", MD: {**r[MD], "credentialTypes": ["permit2"]}}
    other = {**credential, "challenge": {**credential["challenge"], "request": b64u_encode(canonical_json(permit2).encode("utf-8"))}}
    assert BINDINGS[pairing].bound(other) == Refusal("mpp/not-this-pairing")
