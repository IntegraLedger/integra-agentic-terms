"""MPP's challenge framing on the buyer's path against mpp-challenge.json: the id and its inverse, the challenge
hash, the buyer's reading of placed challenges, the agreement URL, the subscription's bare id, the network each
challenge pays on, and the issued checks and refusals the file records."""

import hashlib
import json
from typing import Any

from integraledger_terms import Advertised, Refusal
from integraledger_terms.bindings._codec import b64u_decode
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
    zero = [{"recipient": "0x8Ba1f109551bD432803012645Ac136ddd64DBA72", "amount": "0"}]
    assert pairings_of(_md({"credentialTypes": ["permit2"], "splits": zero})) == refused("mpp/splits-malformed")
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
    malformed = _agreed("read with a legalContextAgreementUrl that is not a string")
    placed = placed_doc(C_E, H, LINK)

    def with_agreement(a: str) -> list[dict[str, Any]]:
        opaque = {"legalContext": f"lcp:sha256:{H}", "legalContextAgreementUrl": a, "legalContextUrl": LINK}
        return [{**placed[0], "opaque": b64u(json.dumps(opaque))}]

    got = read(with_agreement(AGREEMENT))
    assert isinstance(got, Advertised) and (got.h, got.link, got.agreement) == (H, LINK, AGREEMENT)
    for a in ("http://pay.seller.example/agreement", "HTTP://pay.seller.example/agreement", "ftp://pay.seller.example/a"):
        assert (a, read(with_agreement(a))) == (a, refused(not_https))
    long, long_http = "https://pay.seller.example/" + "a" * 2030, "http://pay.seller.example/" + "a" * 2030
    for a in ("https://", "", "not a url", "https://u@pay.seller.example/", long, long_http):
        assert (a[:40], read(with_agreement(a))) == (a[:40], refused(malformed))
    assert _agreed("read with two challenges whose links") == "mpp/legal-context-conflict"
    assert _agreed("challengeId, place or build with an H") == "mpp/challenge-malformed"


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
