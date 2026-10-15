"""MPP's challenge framing on the buyer's path against mpp-challenge.json: the id and its inverse, the challenge
hash, the buyer's reading of placed challenges, the agreement URL, the subscription's bare id, the network each
challenge pays on, and the issued checks and refusals the file records."""

import hashlib
import json
from typing import Any

from integraledger_terms import (
    MPP_CHARGE_EVM_AUTHORIZATION,
    MPP_CHARGE_EVM_HASH,
    MPP_CHARGE_EVM_TRANSACTION,
    MPP_CHARGE_TEMPO_MEMO,
    MPP_CHARGE_TEMPO_PUSH,
    Advertised,
    Refusal,
)
from integraledger_terms.bindings._codec import b64u_decode
from integraledger_terms.bindings._rlp import rlp_bytes, rlp_list, rlp_uint_bytes
from integraledger_terms.bindings.mpp_session import session_resume
from integraledger_terms.bindings._mpp import (
    attribution_memo,
    challenge_h,
    challenge_id_h,
    challenge_hash,
    challenge_id,
    check_attribution,
    network,
    pairings_of,
    read,
)

from mpp_docs import MC, b64u, issued, place, placed_doc
from support import load

V = MC
H: str = V["fixed"]["H"]
REALM: str = V["fixed"]["realm"]
LINK: str = V["fixed"]["link"]
AGREEMENT: str = V["fixed"]["agreementUrl"]
C_E = issued("evm", "charge", V["fixed"]["R_E"])
C_T = issued("tempo", "charge", V["fixed"]["R_T"])
H2 = "0x88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"
NOT_OURS = Refusal(V["MV1"]["expectNotOurs"]["code"])


def refused(code: str) -> Refusal:
    return Refusal(code)


def test_mv1_the_id_and_its_inverse() -> None:
    assert challenge_id(H, 0) == V["MV1"]["expectId"]
    assert challenge_h(V["MV1"]["expectId"]) == H
    for id_ in V["MV1"]["notOurs"]:
        assert challenge_h(id_) == NOT_OURS
    assert challenge_h(V["MV1"]["expectId"] + "0") == NOT_OURS
    assert challenge_h("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa1.0") == NOT_OURS
    assert challenge_id(H, 32) == refused("mpp/challenge-malformed")
    assert challenge_id("0x12", 0) == refused("mpp/challenge-malformed")


def test_mv2_challenge_hash() -> None:
    assert challenge_hash(V["MV1"]["expectId"], REALM) == V["MV2"]["expect"]


def test_mv3_place_writes_id_and_opaque_and_read_gives_h_and_link() -> None:
    for c in (C_E, C_T):
        placed = placed_doc(c, H, LINK)
        assert placed[0]["id"] == V["MV3"]["expectId"]
        assert placed[0]["opaque"] == V["MV3"]["expectOpaque"]
        assert placed[0]["request"] == c["request"]
        assert read(placed) == Advertised(h=H, link=LINK, offer={"challenges": placed})
        assert place(placed, H, LINK, c) == placed


# The seller's placement refuses a challenge list holding any challenge that carries a refused member, the member
# refusals use, with mpp/challenge-malformed, whatever the member's value, as the protocol package's place does.
def test_place_refuses_a_list_holding_a_challenge_with_a_refused_member() -> None:
    assert not isinstance(place([C_E, C_T], H, LINK, C_E), Refusal)
    for value in (True, False, {"code": "x"}):
        assert place([C_E, {**C_T, "refused": value}], H, LINK, C_E) == refused("mpp/challenge-malformed")


def test_mv14_the_agreement_url_in_opaque() -> None:
    placed = placed_doc(C_E, H, LINK, AGREEMENT)
    opaque = placed[0]["opaque"]
    assert len(opaque) == V["MV14"]["expectOpaqueLength"]
    assert "0x" + hashlib.sha256(opaque.encode("ascii")).hexdigest() == V["MV14"]["expectOpaqueSha256"]
    assert read(placed) == Advertised(h=H, link=LINK, offer={"challenges": placed}, agreement=AGREEMENT)
    decoded = b64u_decode(opaque)
    assert decoded is not None
    assert json.loads(decoded) == {
        "legalContext": f"lcp:sha256:{H}",
        "legalContextAgreementUrl": AGREEMENT,
        "legalContextUrl": LINK,
    }


def test_s1_a_tempo_subscription_id_is_the_bare_base64url_of_h() -> None:
    sub = issued(
        "tempo",
        "subscription",
        json.dumps(
            {
                "amount": "10000000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "methodDetails": {
                    "accessKey": {"accessKeyAddress": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8", "keyType": "secp256k1"},
                    "chainId": 42431,
                },
                "periodCount": "30",
                "periodUnit": "day",
                "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00",
                "subscriptionExpires": "2026-12-20T00:00:00Z",
            }
        ),
    )
    placed = place([C_E, sub], H, LINK, sub)
    assert not isinstance(placed, Refusal)
    assert placed[1]["id"] == V["S1"]["expectBareId"]
    assert challenge_h(V["S1"]["expectBareId"]) == H
    assert read(placed) == Advertised(h=H, link=LINK, offer={"challenges": [placed[1]]})
    assert place([sub, {**sub, "realm": "api.other.example"}], H, LINK, sub) == refused("mpp/witness-taken")


def test_network_each_row_issued_and_placed() -> None:
    for r in V["network"]["rows"]:
        c = issued(r["method"], r["intent"], r["request"])
        expect: Any = r["expect"] if isinstance(r["expect"], str) else Refusal(r["expect"]["code"])
        assert (r["case"], network(c)) == (r["case"], expect)
        placed = place([c], H, LINK, c)
        if not isinstance(placed, Refusal):
            assert (r["case"], network(placed[0])) == (r["case"], expect)


def _md(details: dict[str, Any], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    request = {
        "amount": "10000",
        "currency": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "recipient": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "methodDetails": {"chainId": 84532, **details},
        **(extra or {}),
    }
    return issued("evm", "charge", json.dumps(request))


def test_the_issued_checks_of_step_2() -> None:
    without_expires = {k: v for k, v in C_E.items() if k != "expires"}
    assert pairings_of(without_expires) == refused("mpp/expires-required")
    assert pairings_of({**C_E, "expires": "tomorrow"}) == refused("mpp/expires-required")
    assert pairings_of(_md({"credentialTypes": ["permit2", "card"]})) == refused("mpp/credential-types")
    assert pairings_of(_md({"credentialTypes": []})) == refused("mpp/credential-types")
    assert pairings_of(_md({"credentialTypes": ["permit2"], "splits": []})) == refused("mpp/splits-malformed")
    # A split of amount 0 is accepted, as @integraledger/lcp's pairingsOf reads it: the recipient and the decimal form
    # are checked.
    zero = [{"recipient": "0x8Ba1f109551bD432803012645Ac136ddd64DBA72", "amount": "0"}]
    assert pairings_of(_md({"credentialTypes": ["permit2"], "splits": zero})) == ("mpp/charge/evm/permit2",)
    eleven = [{"recipient": "0x8Ba1f109551bD432803012645Ac136ddd64DBA72", "amount": "1"}] * 11
    assert pairings_of(_md({"credentialTypes": ["permit2"], "splits": eleven})) == refused("mpp/splits-malformed")
    assert pairings_of({**C_E, "opaque": b64u(json.dumps({"legalContext": "x"}))}) == refused("mpp/carrier-taken")
    agreement_only = {"legalContextAgreementUrl": "https://a.example/"}
    assert pairings_of({**C_E, "opaque": b64u(json.dumps(agreement_only))}) == refused("mpp/carrier-taken")
    assert pairings_of({**C_E, "opaque": b64u(json.dumps({"order": "42"}))}) == (
        "mpp/charge/evm/permit2",
        "mpp/charge/evm/authorization",
    )
    tempo = {"amount": "1", "currency": "0x20c0000000000000000000000000000000000000", "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00"}
    memo = issued("tempo", "charge", json.dumps({**tempo, "methodDetails": {"memo": "0x" + "00" * 32}}))
    assert pairings_of(memo) == refused("mpp/carrier-taken")
    push_only = issued("tempo", "charge", json.dumps({**tempo, "methodDetails": {"supportedModes": ["push"], "feePayer": True}}))
    assert pairings_of(push_only) == refused("mpp/modes-pull-only")


_A1, _A2, _A3 = "0x" + "11" * 20, "0x" + "22" * 20, "0x" + "33" * 20
_EVM = {"amount": "1000", "currency": _A1, "recipient": _A2}
_NEAR = {"originNetwork": "near:mainnet"}

# Each request's pairings as @integraledger/lcp's pairingsOf names them for the same challenge (expires present): a
# check reads only the members its pairing's build reads or carries H in.
_READS_ONLY_WHAT_IS_BUILT: list[tuple[str, str, dict[str, Any], tuple[str, ...] | str]] = [
    ("evm", "transaction and hash, permit2Address 7", {**_EVM, "methodDetails": {"chainId": 1, "permit2Address": 7}},
     ("mpp/charge/evm/transaction", "mpp/charge/evm/hash")),
    ("evm", "transaction and hash, externalId 7", {**_EVM, "externalId": 7, "methodDetails": {"chainId": 1}},
     ("mpp/charge/evm/transaction", "mpp/charge/evm/hash")),
    ("evm", "permit2, externalId 7", {**_EVM, "externalId": 7, "methodDetails": {"chainId": 1, "credentialTypes": ["permit2"]}},
     "mpp/request-malformed"),
    ("hedera", "a split of 0", {"amount": "100", "currency": "0.0.456858", "recipient": "0.0.1234",
     "splits": [{"recipient": "0.0.5678", "amount": "0"}]}, ("mpp/charge/hedera",)),
    ("card", "amount abc, currency empty", {"amount": "abc", "currency": ""}, ("mpp/charge/card",)),
    ("card", "externalId 7", {"amount": "1", "currency": "usd", "externalId": 7}, "mpp/request-malformed"),
    ("stripe", "externalId 7, no currency", {"amount": "1", "externalId": 7}, ("mpp/charge/stripe",)),
    ("usdc", "evm, credentialTypes x", {**_EVM, "amount": "1", "methodDetails": {"type": "evm", "evm": {"chainId": 1, "credentialTypes": ["x"]}}},
     ("mpp/charge/usdc/evm",)),
    ("usdc", "gateway, no details", {"amount": "1", "recipient": "r", "methodDetails": {"type": "gateway", "gateway": {}}},
     ("mpp/charge/usdc/gateway",)),
    ("nearintents", "origin network only", {"methodDetails": _NEAR}, ("mpp/charge/nearintents",)),
    ("nearintents", "credentialTypes x", {"methodDetails": {**_NEAR, "credentialTypes": ["x"]}}, ("mpp/charge/nearintents",)),
    ("nearintents", "origin network not CAIP-2", {"methodDetails": {"originNetwork": "near"}}, "mpp/request-malformed"),
    ("nearintents", "externalId 7", {"externalId": 7, "methodDetails": _NEAR}, "mpp/request-malformed"),
]


def test_each_charge_check_reads_only_what_its_build_reads() -> None:
    assert len(_READS_ONLY_WHAT_IS_BUILT) == 13
    for method, case, request, expect in _READS_ONLY_WHAT_IS_BUILT:
        # The request in its RFC 8785 form, which the usdc EVM and Gateway derivations hash as received.
        out = pairings_of(issued(method, "charge", json.dumps(request, separators=(",", ":"), sort_keys=True)))
        assert (case, out) == (case, expect if isinstance(expect, tuple) else refused(expect))


def test_read_refusals() -> None:
    placed = placed_doc(C_E, H, LINK)
    assert place(placed, H2, LINK, C_E) == refused("mpp/legal-context-conflict")
    assert place(placed, H, LINK + "?v=2", C_E) == refused("mpp/legal-context-conflict")
    assert read([C_E]) == refused("mpp/no-legal-context")
    other = placed_doc(C_T, H2, LINK)
    second = {**other[0], "id": challenge_id(H2, 1)}
    assert read([placed[0], second]) == refused("mpp/legal-context-conflict")
    assert read([{**placed[0], "id": challenge_id(H2, 0)}]) == refused("mpp/no-legal-context")
    http = b64u(json.dumps({"legalContext": f"lcp:sha256:{H}", "legalContextUrl": "http://atr.seller.example/x"}))
    assert read([{**placed[0], "opaque": http}]) == refused("mpp/link-not-https")
    assert read("not a list") == refused("mpp/challenge-malformed")
    assert read([C_E] * 33) == refused("mpp/challenge-malformed")


def _agreed(prefix: str) -> str:
    for r in V["agreedRefusals"]["rows"]:
        if r["case"].startswith(prefix):
            found: str = r["expect"]
            return found
    raise KeyError(prefix)


def test_agreed_refusals_on_the_buyer_path() -> None:
    i = V["agreedRefusals"]["inputs"]
    assert pairings_of(issued("evm", "charge", i["requestMalformed"])) == refused(_agreed("pairingsOf with an EVM charge"))
    assert pairings_of(issued("tempo", "charge", i["modesMalformed"])) == refused(_agreed("pairingsOf with a Tempo charge"))
    assert pairings_of({**C_E, "opaque": b64u(i["opaqueNotFlat"])}) == refused(_agreed("pairingsOf with an opaque"))
    assert pairings_of({**C_E, "method": "no-such-method"}) == refused(_agreed("pairingsOf with an intent and method"))
    assert _agreed("pairingsOf with a duplicate credentialTypes") == "no refusal"
    assert pairings_of(issued("evm", "charge", i["duplicateTypes"])) == ("mpp/charge/evm/permit2",)
    not_https = _agreed("read with a legalContextAgreementUrl of at most 2048")
    malformed = _agreed("read with a legalContextAgreementUrl that does not parse")
    placed = placed_doc(C_E, H, LINK)

    def with_agreement(a: object) -> list[dict[str, Any]]:
        opaque = {"legalContext": f"lcp:sha256:{H}", "legalContextAgreementUrl": a, "legalContextUrl": LINK}
        return [{**placed[0], "opaque": b64u(json.dumps(opaque))}]

    got = read(with_agreement(AGREEMENT))
    assert isinstance(got, Advertised) and (got.h, got.link, got.agreement) == (H, LINK, AGREEMENT)
    for a in ("http://pay.seller.example/agreement", "HTTP://pay.seller.example/agreement", "ftp://pay.seller.example/a"):
        assert (a, read(with_agreement(a))) == (a, refused(not_https))
    long, long_http = "https://pay.seller.example/" + "a" * 2030, "http://pay.seller.example/" + "a" * 2030
    for a in ("https://", "", "not a url", "https://u@pay.seller.example/", long, long_http):
        assert (a[:40], read(with_agreement(a))) == (a[:40], refused(malformed))
    # MPP's opaque is a flat string-to-string map (draft-httpauth-payment-01), so an agreement URL that is not a string
    # makes the opaque no opaque: read reads no challenge from it, as @integraledger/lcp 0.4.0's read answers.
    for value in (7, None, [LINK], {"url": LINK}):
        assert (value, read(with_agreement(value))) == (value, refused("mpp/no-legal-context"))
    assert _agreed("read with two challenges whose links") == "mpp/legal-context-conflict"
    challenge_malformed = refused(_agreed("challengeId or place with an H"))
    for h, position in ((H[:-1], 0), (H, 32), (H, -1)):
        assert (h, position, challenge_id(h, position)) == (h, position, challenge_malformed)


# The EVM and Tempo charge builds over the challenges placed with H: C_E; C_E's request without credentialTypes, which
# offers the transaction and hash pairings; C_T; and C_T's request without supportedModes, which offers memo and push.
# The payer and the token's EIP-712 domain are mpp-charge-evm-authorization.json's.
_PAYER = load("mpp-charge-evm-authorization.json")["fixed"]
_R_E, _R_T = json.loads(V["fixed"]["R_E"]), json.loads(V["fixed"]["R_T"])
_CALLS = issued("evm", "charge", json.dumps({**_R_E, "methodDetails": {"chainId": _R_E["methodDetails"]["chainId"]}}))
_PUSH = issued("tempo", "charge", json.dumps({**_R_T, "methodDetails": {"chainId": _R_T["methodDetails"]["chainId"]}}))
_BUILDS: dict[str, tuple[Any, dict[str, Any], dict[str, Any]]] = {
    "authorization": (MPP_CHARGE_EVM_AUTHORIZATION, C_E, {"tokenDomain": _PAYER["tokenDomain"]}),
    "hash": (MPP_CHARGE_EVM_HASH, _CALLS, {}),
    "transaction": (MPP_CHARGE_EVM_TRANSACTION, _CALLS, {}),
    "memo": (MPP_CHARGE_TEMPO_MEMO, C_T, {}),
    "push": (MPP_CHARGE_TEMPO_PUSH, _PUSH, {}),
}


def _choice(name: str) -> dict[str, Any]:
    _, challenge, extra = _BUILDS[name]
    return {"challenge": placed_doc(challenge, H, LINK)[0], "from": _PAYER["payer"], "now": 0, **extra}


def _built(name: str) -> Any:
    unsigned = _BUILDS[name][0].build(_choice(name), H)
    assert not isinstance(unsigned, Refusal), (name, unsigned)
    return unsigned


def test_a_charge_build_refuses_an_h_its_challenge_id_does_not_derive_from() -> None:
    """mpp-challenge.json's agreedRefusals row for a build with an H the challenge's id does not derive from: each
    charge build builds with H, and refuses with the row's code H with its last hex digit changed, H without its last
    digit, and H without 0x."""
    expect = refused(_agreed("build with an H the challenge's id does not derive from"))
    other = H[:-1] + ("f" if H.endswith("e") else "e")
    for name, (binding, _, _) in _BUILDS.items():
        _built(name)
        for h in (other, H[:-1], H[2:]):
            assert (name, h, binding.build(_choice(name), h)) == (name, h, expect)


def _tempo_wire_of(size: int) -> str:
    """A 0x76 transaction of exactly size bytes on C_T's chain, which memo's complete decodes as bound does: the memo
    build's call, then one more call to C_T's currency whose input is zero bytes enough to reach size, in
    rlp([chainId, 1, 2, 100000, calls, [], 0, 0, validBefore, "", currency, "", [], 0x11 × 65])."""
    request = _built("memo").request
    calls = [request["call"]["to"], request["call"]["data"]]

    def wire(n: int) -> bytes:
        both = [(calls[0], calls[1]), (calls[0], "0x" + "00" * n)]
        call_list = rlp_list([rlp_list([rlp_bytes(bytes.fromhex(t[2:])), rlp_uint_bytes(0), rlp_bytes(bytes.fromhex(d[2:]))]) for t, d in both])
        fields = [rlp_uint_bytes(request["chainId"]), rlp_uint_bytes(1), rlp_uint_bytes(2), rlp_uint_bytes(100000), call_list, rlp_list([]),
                  rlp_uint_bytes(0), rlp_uint_bytes(0), rlp_uint_bytes(request["validBefore"]), rlp_bytes(b""),
                  rlp_bytes(bytes.fromhex(calls[0][2:])), rlp_bytes(b""), rlp_list([]), rlp_bytes(b"\x11" * 65)]  # fmt: skip
        return b"\x76" + rlp_list(fields)

    for n in range(size - len(wire(0)) - 8, size):
        w = wire(n)
        if len(w) == size:
            return "0x" + w.hex()
    raise AssertionError(f"no padding gives {size} bytes")


def test_a_charge_complete_refuses_an_answer_past_its_bound() -> None:
    """mpp-challenge.json's agreedRefusals row for complete with a signature outside 1 to 8192 bytes, a transaction hash
    not 32 bytes, or a signed transaction over 64 KiB: an answer at each bound completes, and one past it is the row's
    refusal."""
    expect = refused(_agreed("complete with a signature outside 1 to 8192 bytes"))
    wire, over = "0x" + "11" * 65_536, "0x" + "11" * 65_537
    at_bound = [("authorization", "0x11"), ("authorization", "0x" + "11" * 8192), ("hash", H), ("push", H),
                ("transaction", wire), ("memo", _tempo_wire_of(65_536))]  # fmt: skip
    past = [("authorization", "0x"), ("authorization", "0x" + "11" * 8193), ("hash", "0x" + "11" * 31),
            ("push", "0x" + "11" * 33), ("transaction", over), ("memo", over)]  # fmt: skip
    for name, answer in at_bound:
        assert not isinstance(_built(name).complete(answer), Refusal), (name, len(answer))
    for name, answer in past:
        assert (name, len(answer), _built(name).complete(answer)) == (name, len(answer), expect)


def test_read_holds_a_legal_context_url_to_the_link_rule() -> None:
    """mpp-challenge.json's agreedRefusals rows for read with no challenge read and a legalContextUrl in a challenge
    whose id derives from its legalContext: one of at most 2048 characters that parses as an absolute URL whose scheme
    is not https gives the first row's code; one that is absent, does not parse, is an https URL the link rule refuses,
    or is over 2048 characters gives the second's."""
    not_https = refused(_agreed("place with a link or agreement URL that is not an https link"))
    malformed = refused(_agreed("place with a link or agreement URL that is an https link over 2048 characters"))
    placed = placed_doc(C_E, H, LINK)[0]

    def with_opaque(members: dict[str, str]) -> list[dict[str, Any]]:
        return [{**placed, "opaque": b64u(json.dumps({"legalContext": f"lcp:sha256:{H}", **members}))}]

    for u in ("http://atr.seller.example/x", "HTTP://atr.seller.example/x", "ftp://atr.seller.example/x"):
        assert (u, read(with_opaque({"legalContextUrl": u}))) == (u, not_https)
    assert read(with_opaque({})) == malformed
    long, long_http = "https://pay.seller.example/" + "a" * 2030, "http://pay.seller.example/" + "a" * 2030
    for u in ("", "https://", "not a url", "https://u@atr.seller.example/", long, long_http):
        assert (u[:40], read(with_opaque({"legalContextUrl": u}))) == (u[:40], malformed)


def test_session_resume_of_a_charge_challenge() -> None:
    expect = refused(_agreed("sessionResume of a challenge of no session pairing"))
    assert (session_resume(C_E), session_resume(C_T)) == (expect, expect)


def test_nearintents_pairings_of_refuses_an_origin_network_or_external_id_it_cannot_read() -> None:
    """mpp-charge-nearintents.json's agreedRefusals row for pairingsOf with originNetwork not CAIP-2, or externalId not
    a string, over the file's request."""
    n = load("mpp-charge-nearintents.json")
    expect = refused(next(r["expect"] for r in n["agreedRefusals"]["rows"] if r["case"].startswith("pairingsOf with")))
    request = n["fixed"]["request"]
    details = {**request["methodDetails"], "originNetwork": "near"}

    def of(r: dict[str, Any]) -> Any:
        return pairings_of(issued("nearintents", "charge", json.dumps(r)))

    assert of(request) == ("mpp/charge/nearintents",)
    assert of({**request, "methodDetails": details}) == expect
    assert of({**request, "externalId": 7}) == expect


def test_mv7_attribution_memo_and_its_check() -> None:
    m = load("mpp-charge-tempo-memo.json")["MV7"]
    id0, id1 = V["MV1"]["expectId"], challenge_id(H, 1)
    assert isinstance(id1, str)
    assert attribution_memo(REALM, id0) == m["expectMemo"]
    assert attribution_memo(REALM, id1) == m["expectMemoPosition1"]
    assert check_attribution(m["expectMemo"], REALM, id0) is True
    assert check_attribution(m["expectMemoPosition1"], REALM, id0) == Refusal(m["expectMismatch"]["code"])
    assert check_attribution(m["memoMalformed"], REALM, id0) == Refusal(m["expectMalformed"]["code"])
    other = load("mpp-charge-tempo-memo.json")["fixed"]["otherRealm"]
    assert check_attribution(m["expectMemo"], other, id0) == Refusal(m["expectMismatch"]["code"])


def test_a_challenge_id_is_read_in_the_form_its_intent_and_method_take() -> None:
    # Profile mpp/charge rule 2: "The challenge `id` is the base64url (no padding) of H's 32 bytes, then `.` and the
    # challenge's position in the 402, except that a Tempo `subscription` challenge's id is exactly the base64url (no
    # padding) of H".
    positioned = V["MV1"]["expectId"]
    bare = V["S1"]["expectBareId"]
    assert challenge_id_h({"id": positioned, "intent": "charge", "method": "evm"}) == H
    assert challenge_id_h({"id": bare, "intent": "charge", "method": "evm"}) == NOT_OURS
    assert challenge_id_h({"id": bare, "intent": "subscription", "method": "tempo"}) == H
    assert challenge_id_h({"id": positioned, "intent": "subscription", "method": "tempo"}) == NOT_OURS
    assert challenge_id_h({"id": bare, "intent": "session", "method": "tempo"}) == NOT_OURS
    assert challenge_id_h({"intent": "charge", "method": "evm"}) == NOT_OURS
