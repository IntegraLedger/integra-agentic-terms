"""The buyer-side vectors for x402/exact/eip155/eip3009: V1 (build), V2 (complete and bound), V5 (read), and the
refusal codes of the file's agreedRefusals rows."""

import copy
from typing import Any

from integraledger_terms import X402_EXACT_EIP155_EIP3009 as BINDING
from integraledger_terms import Advertised, Refusal

from support import PAIRING, digest, recover, sign_typed

FIXED = PAIRING["fixed"]
H: str = FIXED["H"]
O: dict[str, Any] = FIXED["O"]
V1 = PAIRING["V1"]
V2 = PAIRING["V2"]
V5 = PAIRING["V5"]


def agreed(case: str) -> Refusal:
    """The agreedRefusals code for the row whose case begins with these words."""
    matches = [row["expect"] for row in PAIRING["agreedRefusals"]["rows"] if row["case"].startswith(case)]
    assert len(matches) == 1, case
    return Refusal(matches[0])


def choice(option: dict[str, Any] | None = None, /, **changes: Any) -> dict[str, Any]:
    offered = copy.deepcopy(option if option is not None else O)
    value = {"required": {"x402Version": 2, "resource": FIXED["resource"], "accepts": [offered]}, "accepted": offered,
             "from": FIXED["payer"], "now": FIXED["now"]}
    value.update(changes)
    return value


def refused(code: str) -> Refusal:
    return Refusal(code)


def as_strings(message: dict[str, Any]) -> dict[str, str]:
    return {key: str(value) for key, value in message.items()}


def test_v1_build_gives_the_published_digest() -> None:
    unsigned = BINDING.build(choice(), H)
    assert not isinstance(unsigned, Refusal)
    assert unsigned.typed_data["domain"] == V1["expectDomain"]
    assert as_strings(unsigned.typed_data["message"]) == V1["expectMessage"]
    assert digest(unsigned.typed_data) == V1["expectDigest"]
    assert sign_typed(unsigned.typed_data) == V1["expectSignature"]
    assert recover(unsigned.typed_data, V1["expectSignature"]) == V1["expectRecovers"]


def test_v2_complete_and_bound() -> None:
    unsigned = BINDING.build(choice(), H)
    assert not isinstance(unsigned, Refusal)
    presented = unsigned.complete(V1["expectSignature"])
    assert presented == V2["expectPayload"]
    assert not isinstance(presented, Refusal)
    assert BINDING.bound(presented) == V2["expectBound"]
    upper = copy.deepcopy(presented)
    upper["payload"]["authorization"]["nonce"] = "0x" + H[2:].upper()
    assert BINDING.bound(upper) == V2["boundOfUpperCaseNonce"]
    permit2 = copy.deepcopy(presented)
    permit2["accepted"]["extra"]["assetTransferMethod"] = "permit2"
    assert BINDING.bound(permit2) == refused(V2["permit2"]["expect"]["code"])


def test_v5_read() -> None:
    advertised = BINDING.read(V5["expectDocument"])
    assert isinstance(advertised, Advertised)
    assert advertised.h == V5["expectRead"]["h"]
    assert advertised.link == V5["expectRead"]["link"]
    assert advertised.offer["options"] == V5["expectRead"]["options"]
    http = V5["readHttpLink"]
    assert BINDING.read(http["doc"]) == Refusal(http["expect"]["code"])


def test_agreed_refusals() -> None:
    doc = V5["expectDocument"]
    info = doc["extensions"]["legalContext"]["info"]

    def with_info(**changes: Any) -> dict[str, Any]:
        changed: dict[str, Any] = copy.deepcopy(doc)
        changed["extensions"]["legalContext"]["info"].update(changes)
        return changed

    assert BINDING.read(dict(doc, accepts=O)) == agreed("read or build with accepts")
    assert BINDING.read(dict(doc, accepts=[O] * 33)) == agreed("read or build with accepts")
    assert BINDING.build(choice(required={"x402Version": 2, "accepts": [O] * 33}), H) == agreed("read or build with accepts")
    assert BINDING.read(with_info(legalContextUrl="https://atr.seller.example/" + "a" * 2048)) == agreed("read with a legalContext link over")
    assert BINDING.read(with_info(legal_context_url=info["legalContextUrl"] + "x")) == agreed("read with legalContextUrl and legal_context_url")
    assert BINDING.read(with_info(legal_context_url=info["legalContextUrl"])) != agreed("read with legalContextUrl and legal_context_url")
    for malformed in (choice(**{"from": "0x1234"}), choice(now=-1), choice(now=1.5),
                      choice(dict(O, asset="0xnothex")), choice(dict(O, payTo="0x" + "1" * 39)),
                      choice(dict(O, maxTimeoutSeconds=0)), choice(dict(O, amount=str(2**256))),
                      choice(dict(O, amount="9" * 5000))):
        assert BINDING.build(malformed, H) == agreed("build with a malformed")
    top = BINDING.build(choice(dict(O, amount=str(2**256 - 1))), H)
    assert not isinstance(top, Refusal) and top.typed_data["message"]["value"] == 2**256 - 1
    assert BINDING.build(choice(), "0X" + H[2:]) == agreed("build with a nonce")
    assert BINDING.build(choice(), H[:-1]) == agreed("build with a nonce")
    unsigned = BINDING.build(choice(), H)
    assert not isinstance(unsigned, Refusal)
    for signature in ("0x" + "11" * 64, "0x" + "11" * 8193):
        assert unsigned.complete(signature) == agreed("complete with a signature")
    presented = unsigned.complete(V1["expectSignature"])
    assert not isinstance(presented, Refusal)
    for signature in ("0x", "0x" + "11" * 8193, "0x123", "11" * 65):
        bad = copy.deepcopy(presented)
        bad["payload"]["signature"] = signature
        assert BINDING.bound(bad) == agreed("bound with a signature")
