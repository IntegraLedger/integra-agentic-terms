"""The lcp MPP method's charge on Hedera, mpp/charge/lcp/hedera, against the protocol package's vectors
mpp-method-lcp.json and mpp-method-lcp-hedera.json. The method's filter over each filter row of the first, whose
challenges mppx 0.17.6 wrote. Each build row of the second, through the buyer piece and the gate, under the challenge
the first holds for its request: the body hiero-sdk-python 0.2.10 froze, and the payer's Ed25519 signature from the
file's seed completing the credential whose transaction is the one the SDK signed. bound over the second file's
payments: each row that states what bound gives, the credential mppx wrote with one member changed, and a hash
credential beside the Mirror Node's recorded testnet entry, as recorded and with its memo H's LCP string. Every input
and expected value is the files'."""

import base64
import json
from typing import Any

import pytest

import ed25519
from breadth import Pairing, build_and_sign
from support import hexb, load

from integraledger_terms import MPP_CHARGE_LCP_HEDERA, Refusal
from integraledger_terms.bindings._mpp import Held, pairings_of

C = load("mpp-method-lcp.json")
V = load("mpp-method-lcp-hedera.json")
F: dict[str, Any] = V["fixed"]
SEED = bytes.fromhex(F["seed"])
H: str = F["H"]

# The challenge mpp-method-lcp.json holds, placed for H, for each of the hedera file's requests.
CHALLENGE: dict[str, dict[str, Any]] = {
    "settlerPays": C["challenges"]["hedera"]["wire"],
    "buyerPays": C["challenges"]["hederaBuyerPays"]["wire"],
    "token": C["challenges"]["hederaToken"]["wire"],
}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def challenge_for(request: dict[str, Any]) -> dict[str, Any]:
    """The challenge placed for H for request, as the protocol package's own tests write it: the file's id, realm,
    expires and opaque, the request in its RFC 8785 form, which for these requests of strings, a list and objects is
    JSON with sorted member names and no whitespace."""
    text = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "id": C["fixed"]["id"],
        "realm": C["fixed"]["realm"],
        "method": "lcp",
        "intent": "charge",
        "request": b64u(text.encode("utf-8")),
        "expires": C["fixed"]["expires"],
        "opaque": CHALLENGE["settlerPays"]["opaque"],
    }


def expand(value: Any) -> Any:
    """A row's value with each {"$repeat": [s, n]} replaced by s repeated n times."""
    if isinstance(value, list):
        return [expand(item) for item in value]
    if not isinstance(value, dict):
        return value
    repeat = value.get("$repeat")
    if isinstance(repeat, list):
        text: str = repeat[0] * repeat[1]
        return text
    return {key: expand(item) for key, item in value.items()}


def code(value: Any) -> Any:
    return value.code if isinstance(value, Refusal) else value


def test_each_requests_challenge_holds_that_request() -> None:
    for name, c in CHALLENGE.items():
        padded = c["request"] + "=" * (-len(c["request"]) % 4)
        assert json.loads(base64.urlsafe_b64decode(padded)) == F["requests"][name], name
        assert c == challenge_for(F["requests"][name]), name


# ── The method's filter.


@pytest.mark.parametrize("row", C["filter"], ids=[r["case"] for r in C["filter"]])
def test_filter(row: dict[str, Any]) -> None:
    got = pairings_of(row["challenge"])
    assert (list(got) if isinstance(got, tuple) else code(got)) == row["expect"]


# ── The build, through the piece and the gate.


def hedera_answer(request: Any) -> Any:
    if request["kind"] != "hedera-body":
        raise AssertionError(request["kind"])
    body = hexb(request["bodyBytes"])
    return {
        "publicKey": "0x" + ed25519.public_key(SEED).hex(),
        "signature": "0x" + ed25519.sign(SEED, body).hex(),
        "type": "ed25519",
    }


def test_the_payer_key_is_the_files_public_key() -> None:
    assert ed25519.public_key(SEED).hex() == F["publicKey"]


@pytest.mark.parametrize("row", V["build"], ids=[r["case"] for r in V["build"]])
def test_build(row: dict[str, Any]) -> None:
    challenge = CHALLENGE[row["request"]]
    inputs: dict[str, Any] = {"node": F["node"], "validStart": F["validStart"], "maxFee": F["maxFee"]}
    if "decimals" in row:
        inputs["decimals"] = row["decimals"]
    p = Pairing(
        binding=MPP_CHARGE_LCP_HEDERA,
        doc=[challenge],
        account=f"{F['requests'][row['request']]['methodDetails']['network']}:{row['payer']}",
        answer=hedera_answer,
        inputs=inputs,
    )

    def inspect(request: Any) -> None:
        assert request["kind"] == "hedera-body"
        assert hexb(request["bodyBytes"]).hex() == row["expectBodyBytes"]

    signed, _ = build_and_sign(p, inspect)
    payload = {"type": "transaction", "transaction": row["expectTransactionBase64"]}
    assert signed == {"challenge": challenge, "payload": payload}


# ── bound.

# The rows whose expected value states what bound gives: H for an accepted payment, and each refusal bound makes.
BOUND = [r for r in V["accepted"]] + [r for r in V["refusals"] if r["fn"] == "bound"]


@pytest.mark.parametrize("row", BOUND, ids=[r["case"] for r in BOUND])
def test_bound(row: dict[str, Any]) -> None:
    presented = {
        "challenge": challenge_for(F["requests"][row["request"]]),
        "payload": {"type": "transaction", "transaction": row["transactionBase64"]},
    }
    expect = row["expect"]["h"] if isinstance(row["expect"], dict) else row["expect"]
    assert code(MPP_CHARGE_LCP_HEDERA.bound(presented)) == expect


CREDENTIAL = [r for r in V["credentialRefusals"]["rows"] if r["fn"] == "bound"]


@pytest.mark.parametrize("row", CREDENTIAL, ids=[r["case"] for r in CREDENTIAL])
def test_bound_refuses_the_credential(row: dict[str, Any]) -> None:
    assert code(MPP_CHARGE_LCP_HEDERA.bound(expand(row["presented"]))) == row["expect"]


LANDED = V["landed"]
# The landed rows that state what bound gives: bound's own rows, and the row whose validation gives H.
LANDED_ROWS = [r for r in LANDED["rows"] if r["fn"] == "bound" or isinstance(r["expect"], dict)]


@pytest.mark.parametrize("row", LANDED_ROWS, ids=[r["case"] for r in LANDED_ROWS])
def test_bound_reads_a_hash_credential_from_its_landed_entry(row: dict[str, Any]) -> None:
    credential = {
        "challenge": challenge_for(LANDED["request"]),
        "payload": {"type": "hash", "transactionId": LANDED["transactionId"]},
    }
    held = Held(credential, {"entry": LANDED[row["entry"]]})
    expect = row["expect"]["h"] if isinstance(row["expect"], dict) else row["expect"]
    assert code(MPP_CHARGE_LCP_HEDERA.bound(held)) == expect
