"""The gate's rows for the x402 pairings on Starknet, Casper, Aptos, Polkadot, Concordium, Cardano and Sui (B2, B6, the
payment identifier, B10 and B16 where the TypeScript gate's tests run them), and each pairing's buyer-side vector rows.
Every expected value is the pairing's vector file's; the signers answer with the values those files publish, or with a
key generated here."""

import base64
import copy
import hashlib
import json
import os
import re
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_APTOS, X402_EXACT_CARDANO, X402_EXACT_CASPER, X402_EXACT_CCD, X402_EXACT_SUI, X402_EXACT_POLKADOT_LCP_ASSETS_REMARK, X402_EXACT_STARKNET, Declined, Refusal, Transacted, _gate, transact
from integraledger_terms._keccak import keccak256
from integraledger_terms.bindings._cbor import CborMap, decode_cbor, is_tag, map_get
from integraledger_terms.bindings._codec import b58_encode, canonical_json
from integraledger_terms.bindings.x402_exact_cardano import LCP_MARKER, auxiliary_data, cardano_option_check, decode_cardano_tx
from integraledger_terms.bindings.x402_exact_ccd import account_bytes, ccd_memo, memo_carrier, plt_memo
from integraledger_terms.bindings.x402_exact_aptos import aptos_option_check, decode_aptos_tx
from integraledger_terms.bindings._ss58 import ss58_decode
from integraledger_terms.bindings.x402_exact_polkadot_lcp_assets_remark import split_signed
from integraledger_terms.bindings.x402_exact_sui import decode_sui_tx, sui_carrier, sui_option_check
from integraledger_terms.bindings.x402_exact_starknet import MASK_250, SELECTOR_TRANSFER, sn_nonce

import ed25519
from breadth import ABC, LINK, Pairing, Recording, build_and_sign, code, link_calls, offered, plant, run, x402_doc
from support import load, serving

EVM_ACCOUNT = "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PAYMENT_ID = re.compile(r"[A-Za-z0-9_-]{32}")


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Any:
    def at(now: int) -> None:
        monkeypatch.setattr(_gate, "_now", lambda: now)

    return at


def http_doc(doc: dict[str, Any]) -> dict[str, Any]:
    """The same document with its legal-context link written as http://."""
    d = copy.deepcopy(doc)
    d["extensions"]["legalContext"]["info"]["legalContextUrl"] = LINK.replace("https://", "http://")
    return d


def payment_identifier(p: Pairing) -> None:
    """B6 · payment identifier: appended to the echoed extension where the challenge advertises it."""
    doc = copy.deepcopy(p.doc)
    doc["extensions"]["payment-identifier"] = {"info": {}, "schema": {}}
    signer = Recording(p.account, p.answer)
    out = run(lambda c: transact(doc, offered(p.binding), signer, c, inputs=p.inputs), serving(ABC))
    assert isinstance(out, Transacted) and out.signed is not None, out
    assert PAYMENT_ID.fullmatch(out.signed["extensions"]["payment-identifier"]["info"]["id"])


def http_link(p: Pairing) -> None:
    """B10: an http:// link is offer-unreadable, x402/link-not-https, with no fetch."""
    out, calls = link_calls(p, p.account, http_doc(p.doc))
    assert out == Declined("offer-unreadable", "x402/link-not-https")
    assert calls == 0


def wrong_account(p: Pairing, other_network: str) -> None:
    """B16: an account of another namespace, then one on another network, is no-payable-option with no fetch."""
    for account in (EVM_ACCOUNT, other_network):
        out, calls = link_calls(p, account)
        assert code(out) == "no-payable-option", (account, out)
        assert calls == 0


# ── x402/exact/starknet

SN = load("x402-exact-starknet.json")
SN_F = SN["fixed"]


def sn_check_request(r: Any) -> None:
    """The typed data's members the vectors fix, compared as numbers where they are felts."""
    assert r["kind"] == "starknet-snip12"
    assert int(r["account"], 16) == int(SN_F["from"], 16)
    td = r["typedData"]
    assert int(td["domain"]["chainId"], 16) == int(SN["S3"]["expectChainId"], 16)
    assert int(td["message"]["Nonce"], 16) == int(SN["S2"]["expectNonce"], 16)
    assert td["message"]["Execute Before"] == SN["S3"]["expectExecuteBefore"]
    assert len(td["message"]["Calls"]) == 1
    assert [int(x, 16) for x in td["message"]["Calls"][0]["Calldata"]] == [int(x, 16) for x in SN["S3"]["expectCalldata"]]


def sn_answer(r: Any) -> Any:
    sn_check_request(r)
    return SN["S3"]["signature"]


STARKNET = Pairing(
    binding=X402_EXACT_STARKNET,
    doc=x402_doc(SN_F["O"], SN_F["resource"]),
    account=f"{SN_F['O']['network']}:{SN_F['from']}",
    answer=sn_answer,
)

def test_starknet_b6_request_is_the_vectors_and_the_answer_completes_a_payment_bound_to_h(clock: Any) -> None:
    clock(SN_F["now"])
    build_and_sign(STARKNET, sn_check_request)


def test_starknet_b6_payment_identifier(clock: Any) -> None:
    clock(SN_F["now"])
    payment_identifier(STARKNET)


def test_starknet_b10_http_link(clock: Any) -> None:
    clock(SN_F["now"])
    http_link(STARKNET)


def test_starknet_b16_wrong_account(clock: Any) -> None:
    clock(SN_F["now"])
    wrong_account(STARKNET, f"starknet:SN_MAIN:{SN_F['from']}")


def sn_advertised(extensions: dict[str, Any] | None = None) -> dict[str, Any]:
    doc = x402_doc(SN_F["O"], SN_F["resource"], link=SN_F["link"])
    if extensions is not None:
        doc["extensions"] = extensions
    return doc


def sn_build(required: dict[str, Any] | None = None, **changes: Any) -> Any:
    c = {"required": required or sn_advertised(), "accepted": SN_F["O"], "from": SN_F["from"], "now": SN_F["now"]}
    c.update(changes)
    return X402_EXACT_STARKNET.build(c, SN_F["H"])


def sn_pay(required: dict[str, Any] | None = None) -> dict[str, Any]:
    u = sn_build(required)
    assert not isinstance(u, Refusal), u
    out = u.complete(SN["S3"]["signature"])
    assert isinstance(out, dict)
    return out


def sn_keccak(text: str) -> str:
    return hex(int.from_bytes(keccak256(text.encode()), "big") & MASK_250)


def test_starknet_s1_selectors() -> None:
    assert "0x" + keccak256(b"transfer").hex() == SN["S1"]["keccakTransfer"]
    assert int(sn_keccak("transfer"), 16) == int(SN["S1"]["expectSelectorTransfer"], 16)
    assert int(SELECTOR_TRANSFER, 16) == int(SN["S1"]["expectSelectorTransfer"], 16)


def test_starknet_s2_nonce_for_either_spelling_of_h() -> None:
    assert sn_nonce(SN_F["H"]) == SN["S2"]["expectNonce"]
    assert sn_nonce(SN["S2"]["upperCaseH"]) == SN["S2"]["expectNonce"]


def test_starknet_s3_build_gives_the_typed_data_whose_type_hashes_are_snip9s() -> None:
    u = sn_build()
    assert not isinstance(u, Refusal), u
    r = u.request
    td = r["typedData"]
    assert r["kind"] == "starknet-snip12" and int(r["account"], 16) == int(SN_F["from"], 16)
    assert td["primaryType"] == "OutsideExecution"
    assert td["domain"] == {"name": "Account.execute_from_outside", "version": 2, "chainId": SN["S3"]["expectChainId"], "revision": 1}
    assert td["message"]["Nonce"] == SN["S2"]["expectNonce"]
    assert td["message"]["Execute After"] == "1"
    assert td["message"]["Execute Before"] == SN["S3"]["expectExecuteBefore"]
    assert int(td["message"]["Caller"], 16) == int(SN_F["O"]["extra"]["feePayer"], 16)
    assert td["message"]["Calls"] == [
        {"To": hex(int(SN_F["O"]["asset"], 16)), "Selector": SELECTOR_TRANSFER, "Calldata": SN["S3"]["expectCalldata"]}
    ]

    def enc(name: str) -> str:
        return f'"{name}"(' + ",".join(f'"{f["name"]}":"{f["type"]}"' for f in td["types"][name]) + ")"

    assert sn_keccak(enc("OutsideExecution") + enc("Call")) == SN["S3"]["expectTypeHashOutsideExecution"]
    assert sn_keccak(enc("Call")) == SN["S3"]["expectTypeHashCall"]


def test_starknet_s4_bound() -> None:
    p = sn_pay()
    assert X402_EXACT_STARKNET.bound(p) == SN["S4"]["expectBound"]
    empty = SN["S4"]["boundWithEmptyHash"]
    lc = {"legalContext": {"info": {"type": "sha256", "value": empty["value"], "legalContextUrl": SN_F["link"]}, "schema": {}}}
    other = sn_pay({"x402Version": 2, "resource": SN_F["resource"], "accepts": [SN_F["O"]], "extensions": lc})
    assert X402_EXACT_STARKNET.bound(other) == Refusal(empty["expect"]["code"])
    bare = sn_pay({"x402Version": 2, "resource": SN_F["resource"], "accepts": [SN_F["O"]]})
    assert X402_EXACT_STARKNET.bound(bare) == Refusal(SN["S4"]["boundWithoutExtension"]["code"])
    short = copy.deepcopy(p)
    short["payload"]["outsideExecution"]["typedData"]["domain"]["chainId"] = SN["S4"]["chainIdShortString"]
    assert X402_EXACT_STARKNET.bound(short) == SN["S4"]["expectBound"]


def test_starknet_agreed_refusals() -> None:
    """The buyer-side rows: an option the filter refuses (through build), the payer as fee payer, the signature
    lengths, and bound's domain checks. The status row is the seller's."""
    ran = 0
    for row in SN["agreedRefusals"]["rows"]:
        want = Refusal(row["expect"]) if isinstance(row["expect"], str) else None
        if "option" in row:
            required = {"x402Version": 2, "resource": SN_F["resource"], "accepts": [row["option"]]}
            assert (row["case"], sn_build(required, accepted=row["option"])) == (row["case"], want)
            assert X402_EXACT_STARKNET.read(x402_doc(row["option"], SN_F["resource"])) == Refusal("x402/no-payable-option")
        elif "from" in row:
            assert sn_build(**{"from": row["from"]}) == want
        elif "signatureLengths" in row:
            u = sn_build()
            assert not isinstance(u, Refusal)
            for n in row["signatureLengths"]:
                assert u.complete(["0x1"] * n) == want
        elif "revision" in row:
            p = sn_pay()
            p["payload"]["outsideExecution"]["typedData"]["domain"]["revision"] = row["revision"]
            assert X402_EXACT_STARKNET.bound(p) == want
        elif "chainId" in row:
            p = sn_pay()
            p["payload"]["outsideExecution"]["typedData"]["domain"]["chainId"] = row["chainId"]
            assert X402_EXACT_STARKNET.bound(p) == want
        else:
            assert row.get("twoMatches") is True
            continue
        ran += 1
    assert ran == 10



# ── x402/exact/casper

CS = load("x402-exact-casper.json")
CS_F = CS["fixed"]
NOW = 1_790_000_000


def cs_inspect(r: Any) -> None:
    """C1's typed data."""
    assert r["kind"] == "casper-eip712"
    assert r["typedData"]["domain"] == CS["C1"]["expectDomain"]
    for k, v in CS["C1"]["expectMessage"].items():
        assert str(r["typedData"]["message"][k]) == str(v)


CASPER = Pairing(
    binding=X402_EXACT_CASPER,
    doc=x402_doc(CS_F["O"], CS_F["resource"]),
    account=f"{CS_F['O']['network']}:{CS_F['from']}",
    answer=lambda r: {"publicKey": CS_F["publicKey"], "signature": CS_F["signature"]},
)

def test_casper_b6_c1_typed_data_and_the_answer_completes_c2_payload_bound_to_h(clock: Any) -> None:
    clock(NOW)
    signed, _ = build_and_sign(CASPER, cs_inspect)
    assert signed["payload"] == CS["C2"]["expectPayload"]["payload"]


def cs_required(option: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"x402Version": 2, "resource": CS_F["resource"], "accepts": [option or CS_F["O"]]}


def cs_unsigned() -> Any:
    u = X402_EXACT_CASPER.build({"required": cs_required(), "accepted": CS_F["O"], "from": CS_F["from"], "now": CS_F["now"]}, CS_F["H"])
    assert not isinstance(u, Refusal), u
    return u


def mutate(base: Any, changes: dict[str, Any]) -> Any:
    """A copy with each dotted path set, or removed where the value is None."""
    out = copy.deepcopy(base)
    for path, value in changes.items():
        keys = path.split(".")
        at = out
        for k in keys[:-1]:
            at = at[k]
        if value is None:
            del at[keys[-1]]
        else:
            at[keys[-1]] = value
    return out


def test_casper_c1_build_typed_data_and_type_hashes() -> None:
    r = cs_unsigned().request
    td = r["typedData"]
    assert r["kind"] == "casper-eip712"
    assert td["domain"] == CS["C1"]["expectDomain"]
    assert {k: str(v) for k, v in td["message"].items()} == CS["C1"]["expectMessage"]

    def type_hash(name: str) -> str:
        fields = ",".join(f"{f['type']} {f['name']}" for f in td["types"][name])
        return "0x" + keccak256(f"{name}({fields})".encode()).hex()

    assert type_hash("TransferWithAuthorization") == CS["C1"]["expectTypeHash"]
    assert type_hash("EIP712Domain") == CS["C1"]["expectDomainTypeHash"]


def test_casper_c2_complete_then_bound() -> None:
    c2 = CS["C2"]
    payment = cs_unsigned().complete(CS_F["publicKey"], CS_F["signature"])
    assert payment == c2["expectPayload"]
    assert X402_EXACT_CASPER.bound(payment) == c2["expectBound"]
    prefixed = mutate(payment, {"payload.authorization.nonce": CS_F["H"]})
    assert X402_EXACT_CASPER.bound(prefixed) == c2["boundOfPrefixedNonce"]
    upper = mutate(payment, {"payload.authorization.nonce": CS_F["H"][2:].upper()})
    assert X402_EXACT_CASPER.bound(upper) == c2["boundOfUpperCaseNonce"]
    mismatch = c2["tagMismatch"]
    assert cs_unsigned().complete(mismatch["publicKey"], mismatch["signature"]) == Refusal(mismatch["expect"]["code"])


def test_casper_refusals() -> None:
    """Every bound, build and complete row; reference's row is the seller's."""
    ran = 0
    for row in CS["refusals"]["rows"]:
        want = Refusal(row["expect"]["code"])
        if row["fn"] == "bound":
            got = X402_EXACT_CASPER.bound(mutate(CS["C2"]["expectPayload"], row["mutate"]))
        elif row["fn"] == "build":
            option = {**CS_F["O"], **row.get("optionMutate", {})}
            choice = {"required": cs_required(option), "accepted": option, "from": row.get("from", CS_F["from"]), "now": CS_F["now"]}
            got = X402_EXACT_CASPER.build(choice, CS_F["H"])
        elif row["fn"] == "complete":
            got = cs_unsigned().complete(row["publicKey"], row["signature"])
        else:
            assert row["fn"] == "reference"
            continue
        assert (row["case"], got) == (row["case"], want)
        ran += 1
    assert ran == len(CS["refusals"]["rows"]) - 1


# ── x402/exact/aptos

AP = load("x402-exact-aptos.json")
AP_F = AP["fixed"]
AP_FX = AP_F["fixtureF"]


def uleb(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def u64(n: int | str) -> bytes:
    return int(n).to_bytes(8, "little")


def bcs_str(text: str) -> bytes:
    return uleb(len(text.encode())) + text.encode()


def addr32(a: str) -> bytes:
    return bytes.fromhex(a[2:].rjust(64, "0"))


def bcs_bytes(b: bytes) -> bytes:
    return uleb(len(b)) + b


def aptos_raw(chain_id: int | None = None, payload: bytes | None = None) -> bytes:
    """Fixture F's RawTransaction in BCS: 0x1::primary_fungible_store::transfer<0x1::fungible_asset::Metadata>."""
    F = AP_FX
    entry = (
        uleb(2)
        + addr32("0x1") + bcs_str("primary_fungible_store") + bcs_str("transfer")
        + uleb(1) + uleb(7) + addr32("0x1") + bcs_str("fungible_asset") + bcs_str("Metadata") + uleb(0)
        + uleb(3) + bcs_bytes(addr32(F["metadata"])) + bcs_bytes(addr32(F["recipient"])) + bcs_bytes(u64(F["amount"]))
    )  # fmt: skip
    return (
        addr32(F["sender"]) + u64(F["sequenceNumber"]) + (entry if payload is None else payload)
        + u64(F["maxGasAmount"]) + u64(F["gasUnitPrice"]) + u64(F["expiresAt"])
        + bytes([F["chainId"] if chain_id is None else chain_id])
    )  # fmt: skip


def aptos_signed(raw: bytes) -> str:
    """The wallet's SignedTransaction: the raw transaction and an Ed25519 authenticator from a key generated here."""
    seed = os.urandom(32)
    prefix = hashlib.sha3_256(b"APTOS::RawTransaction").digest()
    signature = ed25519.sign(seed, prefix + raw)
    return base64.b64encode(raw + uleb(0) + bcs_bytes(ed25519.public_key(seed)) + bcs_bytes(signature)).decode()


def aptos_reference_wire(raw: bytes) -> str:
    """x402's reference wire form: base64 of the JSON {transaction, senderAuthenticator}, the transaction a
    SimpleTransaction with the fee payer."""
    simple = raw + b"\x01" + addr32(AP_FX["feePayer"])
    return base64.b64encode(json.dumps({"transaction": list(simple), "senderAuthenticator": [0]}).encode()).decode()


def ap_check_request(r: Any) -> None:
    assert r["kind"] == "aptos-transaction"
    assert r["accepted"] == AP_F["O"]


def ap_inspect(r: Any) -> None:
    ap_check_request(r)
    raw = aptos_raw()
    assert len(raw) == AP_FX["rawTransactionBytes"]
    assert "0x" + hashlib.sha256(raw).hexdigest() == AP_FX["rawTransactionSha256"]


def ap_answer(r: Any) -> Any:
    ap_check_request(r)
    return {"transaction": aptos_signed(aptos_raw())}


APTOS = Pairing(
    binding=X402_EXACT_APTOS,
    doc=x402_doc(AP_F["O"], AP_F["resource"]),
    account=f"{AP_F['O']['network']}:{AP_FX['sender']}",
    answer=ap_answer,
)

def test_aptos_b6_request_is_the_vectors_and_the_answer_completes_a_payment_bound_to_h(clock: Any) -> None:
    clock(NOW)
    build_and_sign(APTOS, ap_inspect)


def test_aptos_b6_payment_identifier(clock: Any) -> None:
    clock(NOW)
    payment_identifier(APTOS)


def test_aptos_b10_http_link(clock: Any) -> None:
    clock(NOW)
    http_link(APTOS)


def test_aptos_b16_wrong_account(clock: Any) -> None:
    clock(NOW)
    wrong_account(APTOS, f"aptos:2:{AP_FX['sender']}")


def ap_unsigned() -> Any:
    required = x402_doc(AP_F["O"], AP_F["resource"], link=AP_F["link"])
    u = X402_EXACT_APTOS.build({"required": required, "accepted": AP_F["O"]}, AP_F["H"])
    assert not isinstance(u, Refusal), u
    return u


def ap_payment(transaction: str, extensions: Any = None, accepted: Any = None) -> dict[str, Any]:
    p: dict[str, Any] = {"x402Version": 2, "accepted": accepted or AP_F["O"], "payload": {"transaction": transaction}}
    if extensions is not None:
        p["extensions"] = extensions
    return p


def test_aptos_v1_v2_both_wire_forms_decode_to_the_rails_normal_form_and_id_digest() -> None:
    """complete reads the RawTransaction prefix; its normal form is V1's, whose RFC 8785 SHA-256 is V1's idDigest."""
    for wire in (aptos_reference_wire(aptos_raw()), aptos_signed(aptos_raw())):
        instrument = decode_aptos_tx(wire)
        assert not isinstance(instrument, Refusal), instrument
        normal = {k: str(instrument[k]) if k == "sequenceNumber" else instrument[k] for k in V1_KEYS}
        assert normal == AP["V1"]["expectNormalForm"]
        assert canonical_json(normal) == AP["V1"]["expectCanonical"]
        assert "0x" + hashlib.sha256(canonical_json(normal).encode()).hexdigest() == AP["V1"]["expectIdDigest"]
        assert str(instrument["expiresAt"]) == AP["V2"]["expectReference"]["expiresAt"]


V1_KEYS = ("arguments", "function", "sender", "sequenceNumber", "typeArguments")


def test_aptos_v2_complete_refuses_a_chain_mismatch_and_a_script() -> None:
    u = ap_unsigned()
    assert u.complete({"transaction": aptos_reference_wire(aptos_raw(chain_id=2))}) == Refusal("x402/signed-not-bound")
    script = uleb(0) + bcs_bytes(bytes([0xA1, 0x1C, 0xEB, 0x0B])) + uleb(0) + uleb(0)
    assert decode_aptos_tx(aptos_reference_wire(aptos_raw(payload=script))) == Refusal(AP["V2"]["script"]["expect"])
    assert u.complete({"transaction": aptos_signed(aptos_raw(payload=script))}) == Refusal("x402/signed-not-bound")
    assert decode_aptos_tx(base64.b64encode(bytes(64 * 1024 + 1)).decode()) == Refusal("aptos/tx-too-large")
    assert decode_aptos_tx(base64.b64encode(aptos_raw()[:100]).decode()) == Refusal("aptos/tx-malformed")


def test_aptos_v3_bound_reads_the_echoed_legal_context() -> None:
    extensions = {"legalContext": {"info": AP["V3"]["echoedInfo"], "schema": {}}}
    assert X402_EXACT_APTOS.bound(ap_payment(aptos_reference_wire(aptos_raw()), extensions)) == AP["V3"]["expectBound"]
    assert X402_EXACT_APTOS.bound(ap_payment(aptos_reference_wire(aptos_raw()))) == Refusal(AP["V3"]["noLegalContext"])
    assert X402_EXACT_APTOS.bound(ap_payment("AAAA", None, {**AP_F["O"], "network": "aptos:0"})) == Refusal("aptos/network-malformed")


def test_aptos_build_returns_the_schemes_own_request_and_complete_echoes_the_extensions() -> None:
    u = ap_unsigned()
    assert u.request == {"kind": "aptos-transaction", "accepted": AP_F["O"]}
    wire = aptos_reference_wire(aptos_raw())
    signed = u.complete({"transaction": wire})
    required = x402_doc(AP_F["O"], AP_F["resource"], link=AP_F["link"])
    assert signed == {"x402Version": 2, "resource": AP_F["resource"], "accepted": AP_F["O"], "payload": {"transaction": wire}, "extensions": required["extensions"]}
    assert X402_EXACT_APTOS.bound(signed) == AP_F["H"]


def test_aptos_agreed_refusals() -> None:
    """The buyer-side rows of the vector file's agreedRefusals; the status row is the seller's."""
    rows = {row["case"]: row["expect"] for row in AP["agreedRefusals"]["rows"]}
    raw = aptos_raw()
    assert decode_aptos_tx("AAA") == Refusal(rows["a transaction that is not padded standard base64"])
    ends_early = "a RawTransaction prefix that ends early, or a ULEB128 that is over 2^32-1 or not in its shortest form"
    assert decode_aptos_tx(base64.b64encode(raw[:40]).decode()) == Refusal(rows[ends_early])
    long_uleb = raw[:40] + bytes([0x82, 0x00]) + raw[41:]
    assert decode_aptos_tx(base64.b64encode(long_uleb).decode()) == Refusal(rows[ends_early])
    over = raw[:40] + bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]) + raw[41:]
    assert decode_aptos_tx(base64.b64encode(over).decode()) == Refusal(rows[ends_early])
    not_struct = "a type argument that is not a struct, or a struct with type arguments"
    at = raw.index(bytes([1, 7]) + addr32("0x1")) + 1
    assert decode_aptos_tx(base64.b64encode(raw[:at] + bytes([1]) + raw[at + 1 :]).decode()) == Refusal(rows[not_struct])
    generic = raw.index(bcs_str("Metadata")) + len(bcs_str("Metadata"))
    with_args = raw[:generic] + bytes([1, 1]) + raw[generic + 1 :]
    assert decode_aptos_tx(base64.b64encode(with_args).decode()) == Refusal(rows[not_struct])
    network = "an option with scheme exact and an aptos: network whose chain id is not 1 to 255 without a leading zero"
    for bad in ("aptos:0", "aptos:01", "aptos:256"):
        assert aptos_option_check({**AP_F["O"], "network": bad}) == Refusal(rows[network])
    assert X402_EXACT_APTOS.bound(ap_payment(1)) == Refusal(rows["payload.transaction not a string"])  # type: ignore[arg-type]
    u = ap_unsigned()
    refusing = "complete with a transaction whose reference refuses"
    assert u.complete({"transaction": "AAA"}) == Refusal(rows[refusing])


# ── x402/exact/polkadot/lcp-assets-remark

DOT = load("x402-exact-polkadot-lcp-assets-remark.json")
DOT_F = DOT["fixed"]
# The payer of V3's extrinsic: SS58 of the public key its signature preamble names.
DOT_PAYER = "16SYiSu5tWgdV4sWiaxir7GYEiFfTc9GYnRd34PDGCUMgkmP"
DOT_BINDING = X402_EXACT_POLKADOT_LCP_ASSETS_REMARK


def dot_check_request(r: Any) -> None:
    assert r["kind"] == "substrate-call"
    assert r["network"] == DOT_F["O"]["network"]
    assert r["call"] == DOT["V2"]["expectCall"]


def dot_inspect(r: Any) -> None:
    dot_check_request(r)
    # V3's signer (bytes 4..36 after the length prefix and 0x84 0x00) is the payer's account.
    payer = ss58_decode(DOT_PAYER)
    assert payer is not None and "0x" + payer.hex() == "0x" + DOT["V3"]["extrinsic"][10:74]


def dot_answer(r: Any) -> Any:
    dot_check_request(r)
    return DOT["V3"]["extrinsic"]


POLKADOT = Pairing(
    binding=DOT_BINDING,
    doc=x402_doc(DOT_F["O"], DOT_F["resource"]),
    account=f"{DOT_F['O']['network']}:{DOT_PAYER}",
    answer=dot_answer,
)

def test_polkadot_b6_request_is_the_vectors_and_the_answer_completes_a_payment_bound_to_h(clock: Any) -> None:
    clock(NOW)
    build_and_sign(POLKADOT, dot_inspect)


def test_polkadot_b6_payment_identifier(clock: Any) -> None:
    clock(NOW)
    payment_identifier(POLKADOT)


def test_polkadot_b10_http_link(clock: Any) -> None:
    clock(NOW)
    http_link(POLKADOT)


def test_polkadot_b16_wrong_account(clock: Any) -> None:
    clock(NOW)
    wrong_account(POLKADOT, f"polkadot:67f9723393ef76214df0118c34bbbd3d:{DOT_PAYER}")


def dot_unsigned() -> Any:
    required = {"x402Version": 2, "resource": DOT_F["resource"], "accepts": [DOT_F["O"]]}
    u = DOT_BINDING.build({"required": required, "accepted": DOT_F["O"]}, DOT_F["H"])
    assert not isinstance(u, Refusal), u
    return u


def dot_presented(extrinsic: str, call: str) -> dict[str, Any]:
    return {"x402Version": 2, "accepted": DOT_F["O"], "payload": {"extrinsic": extrinsic, "call": call}}


def test_polkadot_v1_a_real_extrinsics_signer_and_its_transfer_call_is_not_the_profile() -> None:
    xt = bytes.fromhex(DOT["V1"]["extrinsic"][2:])
    split = split_signed(xt)
    assert not isinstance(split, Refusal), split
    assert "0x" + split[0].hex() == DOT["V1"]["expectSigner"]
    call = "0x" + xt[len(xt) - DOT["V1"]["callBytes"] :].hex()
    assert DOT_BINDING.bound(dot_presented(DOT["V1"]["extrinsic"], call)) == Refusal(DOT["V1"]["expectBound"])


def test_polkadot_v2_builds_call_and_the_payees_account() -> None:
    r = dot_unsigned().request
    assert r["kind"] == "substrate-call" and r["network"] == DOT_F["O"]["network"]
    assert "0x" + r["call"].hex() == DOT["V2"]["expectCall"]
    assert len(r["call"]) == DOT["V2"]["expectCallLength"]
    dest = ss58_decode(DOT_F["O"]["payTo"])
    assert dest is not None and "0x" + dest.hex() == DOT["V2"]["expectDest"]


def test_polkadot_v3_complete_bound_and_the_refusals() -> None:
    xt = bytes.fromhex(DOT["V3"]["extrinsic"][2:])
    assert len(xt) == DOT["V3"]["expectLength"]
    payment = dot_unsigned().complete(xt)
    assert not isinstance(payment, Refusal), payment
    assert payment["payload"] == {"extrinsic": DOT["V3"]["extrinsic"], "call": DOT["V2"]["expectCall"]}
    assert DOT_BINDING.bound(payment) == DOT["V3"]["expectBound"]
    for row in DOT["V3"]["refusals"]:
        assert (row["case"], DOT_BINDING.bound(dot_presented(row["extrinsic"], row["call"]))) == (row["case"], Refusal(row["expect"]))


def test_polkadot_the_option_filter() -> None:
    """Each option row, through build (the filter's refusal) and read (not payable)."""
    for row in DOT["options"]:
        required = {"x402Version": 2, "resource": DOT_F["resource"], "accepts": [row["option"]]}
        got = DOT_BINDING.build({"required": required, "accepted": row["option"]}, DOT_F["H"])
        assert (row["case"], got) == (row["case"], Refusal(row["expect"]))
        assert DOT_BINDING.read(x402_doc(row["option"], DOT_F["resource"])) == Refusal("x402/no-payable-option")
    read = DOT_BINDING.read(x402_doc(DOT_F["O"], DOT_F["resource"], link=DOT_F["link"]))
    assert not isinstance(read, Refusal)
    assert (read.h, read.link, read.offer["options"]) == (DOT_F["H"], DOT_F["link"], [DOT_F["O"]])


# ── x402/exact/ccd

CCD = load("x402-exact-ccd.json")
CCD_F = CCD["fixed"]


def ccd_inspect(r: Any) -> None:
    """The transfer carries D1's memo."""
    assert r["kind"] == "ccd-transfer"
    assert r["memo"] == "0x" + CCD["D1"]["expectCcdMemo"]
    assert r["sponsor"] == CCD_F["sponsor"]
    assert r["toAddress"] == CCD_F["payee"]
    assert r["expiresBy"] == NOW + CCD_F["O"]["maxTimeoutSeconds"]


CONCORDIUM = Pairing(
    binding=X402_EXACT_CCD,
    doc=x402_doc(CCD_F["O"], CCD_F["resource"]),
    account=f"{CCD_F['O']['network']}:{CCD_F['payer']}",
    answer=lambda r: copy.deepcopy(CCD["D3"]["ccd"]["payment"]["payload"]["signedTransaction"]),
)

def test_ccd_b6_the_transfer_carries_d1s_memo_and_d3s_signed_transaction_is_bound_to_h(clock: Any) -> None:
    clock(NOW)
    build_and_sign(CONCORDIUM, ccd_inspect)


def test_ccd_the_fixed_accounts_are_base58check_of_version_byte_01_and_sha256_of_their_labels() -> None:
    for who in ("payer", "payee", "sponsor"):
        body = hashlib.sha256(CCD_F[f"{who}Label"].encode()).digest()
        raw = b"\x01" + body
        assert b58_encode(raw + hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]) == CCD_F[who]
        assert account_bytes(CCD_F[who]) == body
    assert account_bytes(CCD_F["payer"]) == bytes.fromhex(CCD_F["payerBytes"])


def test_ccd_d1_memos() -> None:
    assert ccd_memo(CCD_F["H"]).hex() == CCD["D1"]["expectCcdMemo"]
    assert decode_cbor(bytes.fromhex(CCD["D1"]["expectCcdMemo"])) == CCD["D1"]["lcpString"]
    assert plt_memo(CCD_F["H"]).hex() == CCD["D1"]["expectPltMemo"]
    assert memo_carrier(ccd_memo(CCD_F["H"])) == CCD_F["H"]


def test_ccd_d2_the_plt_operations_fixture_decodes_as_the_stewards_encoder_writes_it() -> None:
    ops = bytes.fromhex(CCD["D2"]["operations"])
    assert len(ops) == CCD["D2"]["length"]
    decoded = decode_cbor(ops)
    assert isinstance(decoded, list) and isinstance(decoded[0], CborMap)
    transfer = map_get(decoded[0], "transfer")
    assert isinstance(transfer, CborMap)
    e = CCD["D2"]["expectDecoded"]
    memo = map_get(transfer, "memo")
    assert is_tag(memo, e["memoTag"]) and memo.value == bytes.fromhex(e["memo"])
    amount = map_get(transfer, "amount")
    assert is_tag(amount, e["amountTag"]) and amount.value == e["amount"]
    recipient = map_get(transfer, "recipient")
    assert is_tag(recipient, e["recipientTag"]) and map_get(recipient.value, e["recipientKey"]) == bytes.fromhex(e["recipient"])


def test_ccd_d3_bound_gives_h_for_a_ccd_and_a_plt_transfer() -> None:
    assert X402_EXACT_CCD.bound(CCD["D3"]["ccd"]["payment"]) == CCD["D3"]["ccd"]["expect"]
    assert X402_EXACT_CCD.bound(CCD["D3"]["plt"]["payment"]) == CCD["D3"]["plt"]["expect"]


def set_paths(base: Any, changes: dict[str, Any]) -> Any:
    out = copy.deepcopy(base)
    for path, value in changes.items():
        keys = path.split(".")
        at = out
        for k in keys[:-1]:
            at = at[k]
        at[keys[-1]] = value
    return out


def test_ccd_d3_bounds_refusals() -> None:
    for row in CCD["D3"]["rows"]:
        payment = set_paths(CCD["D3"][row["base"]]["payment"], row["set"])
        assert (row["case"], X402_EXACT_CCD.bound(payment)) == (row["case"], Refusal(row["expect"]["code"]))


def test_ccd_build_the_transfer_the_wallet_signs_and_complete_wraps_what_it_returns() -> None:
    def required(o: dict[str, Any]) -> dict[str, Any]:
        return {"x402Version": 2, "resource": CCD_F["resource"], "accepts": [o]}

    u = X402_EXACT_CCD.build({"required": required(CCD_F["O"]), "accepted": CCD_F["O"], "now": CCD_F["now"]}, CCD_F["H"])
    assert not isinstance(u, Refusal), u
    assert u.request == {
        "kind": "ccd-transfer",
        "network": CCD_F["network"],
        "sponsor": CCD_F["sponsor"],
        "toAddress": CCD_F["payee"],
        "asset": "CCD",
        "amount": "1000000",
        "memo": bytes.fromhex(CCD["D1"]["expectCcdMemo"]),
        "expiresBy": 1790000060,
    }
    payment = u.complete(CCD["D3"]["ccd"]["payment"]["payload"]["signedTransaction"])
    assert payment == CCD["D3"]["ccd"]["payment"]
    assert X402_EXACT_CCD.bound(payment) == CCD_F["H"]
    plt = X402_EXACT_CCD.build({"required": required(CCD_F["OPlt"]), "accepted": CCD_F["OPlt"], "now": CCD_F["now"]}, CCD_F["H"])
    assert not isinstance(plt, Refusal), plt
    assert plt.request["memo"].hex() == CCD["D1"]["expectPltMemo"]


# ── x402/exact/cardano

ADA = load("x402-exact-cardano.json")
ADA_F = ADA["fixed"]


def ada_check_request(r: Any) -> None:
    assert r["kind"] == "cardano-transaction"
    assert r["accepted"] == ADA_F["O"]
    assert r["auxiliaryData"] == "0x" + ADA["V1"]["auxiliaryDataHex"]


def ada_answer(r: Any) -> Any:
    """The wallet answers V2, the vectors' transaction whose body commits to V1's auxiliary data."""
    ada_check_request(r)
    return {"transaction": ADA["V2"]["transactionBase64"], "nonce": ADA_F["nonce"]}


# The pairing never reads the payer's address; the account reuses the vectors' one preprod address, with CAIP-10's
# escape for the underscore.
ADA_ADDRESS = ADA_F["O"]["payTo"].replace("_", "%5F")

CARDANO = Pairing(
    binding=X402_EXACT_CARDANO,
    doc=x402_doc(ADA_F["O"], ADA_F["resource"]),
    account=f"{ADA_F['O']['network']}:{ADA_ADDRESS}",
    answer=ada_answer,
)

def test_cardano_b6_request_is_the_vectors_and_the_answer_completes_a_payment_bound_to_h(clock: Any) -> None:
    clock(NOW)
    build_and_sign(CARDANO, ada_check_request)


def test_cardano_b6_payment_identifier(clock: Any) -> None:
    clock(NOW)
    payment_identifier(CARDANO)


def test_cardano_b10_http_link(clock: Any) -> None:
    clock(NOW)
    http_link(CARDANO)


def test_cardano_b16_wrong_account(clock: Any) -> None:
    clock(NOW)
    wrong_account(CARDANO, f"cardano:mainnet:{ADA_ADDRESS}")


def ada_payment(transaction: str, accepted: Any = None) -> dict[str, Any]:
    return {"x402Version": 2, "accepted": accepted or ADA_F["O"], "payload": {"transaction": transaction, "nonce": ADA_F["nonce"]}}


def test_cardano_v1_the_auxiliary_data() -> None:
    a = auxiliary_data(ADA_F["H"])
    assert isinstance(a, bytes)
    assert len(a) == ADA["V1"]["bytes"]
    assert a.hex() == ADA["V1"]["auxiliaryDataHex"]
    assert "0x" + hashlib.blake2b(a, digest_size=32).hexdigest() == ADA["V1"]["blake2b"]
    assert LCP_MARKER == "lcp:sha256:0x"


def test_cardano_v2_bound_and_the_transaction_id() -> None:
    tx = decode_cardano_tx(ADA["V2"]["transactionBase64"])
    assert not isinstance(tx, Refusal), tx
    assert tx.tx_id == ADA["V2"]["expectReference"]["txId"]
    assert str(tx.ttl_slot) == ADA["V2"]["expectReference"]["ttlSlot"]
    assert X402_EXACT_CARDANO.bound(ada_payment(ADA["V2"]["transactionBase64"])) == ADA["V2"]["expectBound"]
    alias = {**ADA_F["O"], "network": "cip34:0-1"}
    assert X402_EXACT_CARDANO.bound(ada_payment(ADA["V2"]["transactionBase64"], alias)) == ADA["V2"]["expectBound"]


def test_cardano_v3_the_real_rail() -> None:
    tx = decode_cardano_tx(ADA["V3"]["transactionBase64"])
    assert not isinstance(tx, Refusal), tx
    assert tx.tx_id == ADA["V3"]["txId"]
    assert tx.ttl_slot is None
    assert X402_EXACT_CARDANO.bound(ada_payment(ADA["V3"]["transactionBase64"])) == Refusal(ADA["V3"]["expectBound"])


def test_cardano_v4_refusals() -> None:
    for row in ADA["V4"]:
        accepted = {**ADA_F["O"], "network": row["network"]} if "network" in row else None
        got = X402_EXACT_CARDANO.bound(ada_payment(row["transactionBase64"], accepted))
        assert (row["case"], got) == (row["case"], Refusal(row["expectBound"]))
    assert decode_cardano_tx(base64.b64encode(bytes(64 * 1024 + 1)).decode()) == Refusal("cardano/tx-too-large")
    deep = base64.b64encode(bytes([0x81] * 70 + [0x00])).decode()
    assert decode_cardano_tx(deep) == Refusal("cardano/tx-malformed")


def test_cardano_plant_metadata_the_signed_body_does_not_commit_to_is_refused_never_read() -> None:
    got = X402_EXACT_CARDANO.bound(ada_payment(ADA["plant"]["transactionBase64"]))
    assert got == Refusal(ADA["plant"]["expectBound"])


def test_cardano_the_filter_build_and_complete() -> None:
    O = ADA_F["O"]
    for network in ("cardano:mainnet", "cardano:preview", "cip34:1-764824073", "cip34:0-2"):
        assert cardano_option_check({**O, "network": network}) is None
    for m in ("script", "masumi"):
        assert cardano_option_check({**O, "extra": {"assetTransferMethod": m}}) is None
    assert cardano_option_check({**O, "extra": {"assetTransferMethod": "eip3009"}}) is not None
    assert cardano_option_check({**O, "extra": {"paymentFlow": "upfront"}}) is not None
    assert cardano_option_check({**O, "network": "cip34:0-4"}) == Refusal("cardano/network-malformed")
    required = x402_doc(O, ADA_F["resource"], link=ADA_F["link"])
    read = X402_EXACT_CARDANO.read(required)
    assert not isinstance(read, Refusal)
    assert (read.h, read.link, read.offer["options"]) == (ADA_F["H"], ADA_F["link"], [O])
    u = X402_EXACT_CARDANO.build({"required": required, "accepted": O}, ADA_F["H"])
    assert not isinstance(u, Refusal), u
    assert u.request["kind"] == "cardano-transaction"
    assert u.request["auxiliaryData"].hex() == ADA["V1"]["auxiliaryDataHex"]
    signed = u.complete({"transaction": ADA["V2"]["transactionBase64"], "nonce": ADA_F["nonce"]})
    assert signed == {
        "x402Version": 2,
        "resource": ADA_F["resource"],
        "accepted": O,
        "payload": {"transaction": ADA["V2"]["transactionBase64"], "nonce": ADA_F["nonce"]},
        "extensions": required["extensions"],
    }
    assert u.complete({"transaction": ADA["V3"]["transactionBase64"], "nonce": ADA_F["nonce"]}) == Refusal("x402/signed-not-bound")
    assert u.complete({"transaction": ADA["V2"]["transactionBase64"], "nonce": "x" * 257}) == Refusal("x402/signed-not-bound")


# ── x402/exact/sui

SUI = load("x402-exact-sui.json")
SUI_F = SUI["fixed"]


def sui_check_request(r: Any) -> None:
    assert r["kind"] == "sui-transaction"
    assert r["accepted"] == SUI_F["O"]
    assert r["pureInput"] == SUI_F["H"]
    assert r["expiration"] == "epoch-bounded"


def sui_answer(r: Any) -> Any:
    """The wallet answers V2, the vectors' transaction carrying H as its one unused Pure input. The pairing reads the
    carrier from the transaction and never verifies the signature, so the signature is 97 zero bytes."""
    sui_check_request(r)
    return {"signature": base64.b64encode(bytes(97)).decode(), "transaction": SUI["V2"]["tx"]["transactionBase64"]}


SUI_PAIRING = Pairing(
    binding=X402_EXACT_SUI,
    doc=x402_doc(SUI_F["O"], SUI_F["resource"]),
    account=f"{SUI_F['O']['network']}:{SUI_F['sender']}",
    answer=sui_answer,
)

def test_sui_b6_request_is_the_vectors_and_the_answer_completes_a_payment_bound_to_h(clock: Any) -> None:
    clock(NOW)
    build_and_sign(SUI_PAIRING, sui_check_request)


def test_sui_b6_payment_identifier(clock: Any) -> None:
    clock(NOW)
    payment_identifier(SUI_PAIRING)


def test_sui_b10_http_link(clock: Any) -> None:
    clock(NOW)
    http_link(SUI_PAIRING)


def test_sui_b16_wrong_account(clock: Any) -> None:
    clock(NOW)
    wrong_account(SUI_PAIRING, f"sui:mainnet:{SUI_F['sender']}")


def sui_payment(transaction: str, accepted: Any = None) -> dict[str, Any]:
    return {"x402Version": 2, "accepted": accepted or SUI_F["O"], "payload": {"signature": "AAAA", "transaction": transaction}}


def sui_decoded(tx: dict[str, Any]) -> Any:
    decoded = decode_sui_tx(tx["transactionBase64"])
    assert not isinstance(decoded, Refusal), decoded
    assert len(decoded.data) == tx["bytes"]
    assert "0x" + hashlib.blake2b(b"TransactionData::" + decoded.data, digest_size=32).hexdigest() == tx["blake2b"]
    assert decoded.digest == tx["digest"]
    return decoded


def test_sui_v1_the_real_rail_decodes_to_the_chains_digest_and_every_input_is_used() -> None:
    tx = sui_decoded(SUI["V1"]["tx"])
    assert tx.digest == "EV7D7z9gjzjrAQSKWSW8S1iLGdk8aEVPjn3zLA1aUSLE"
    assert tx.until_epoch == SUI["V1"]["expectUntilEpoch"]
    assert X402_EXACT_SUI.bound(sui_payment(SUI["V1"]["tx"]["transactionBase64"])) == Refusal(SUI["V1"]["expectBound"])


def test_sui_v2_carried() -> None:
    tx = sui_decoded(SUI["V2"]["tx"])
    assert sui_carrier(tx) == SUI_F["H"]
    assert X402_EXACT_SUI.bound(sui_payment(SUI["V2"]["tx"]["transactionBase64"])) == SUI["V2"]["expectBound"]
    ref = SUI["V2"]["expectReference"]
    assert (tx.digest, str(tx.until_epoch)) == (ref["digest"], ref["untilEpoch"])


def test_sui_the_validity_expiration() -> None:
    for row in SUI["validity"]["rows"]:
        tx = sui_decoded(row["tx"])
        assert X402_EXACT_SUI.bound(sui_payment(row["tx"]["transactionBase64"])) == row["expectBound"]
        if isinstance(row["expectReference"], str):
            assert (row["case"], tx.until_epoch) == (row["case"], None)
        else:
            assert (tx.digest, str(tx.until_epoch)) == (row["expectReference"]["digest"], row["expectReference"]["untilEpoch"])


def test_sui_v3_refusals() -> None:
    for row in SUI["V3"]:
        if "zeroBytes" in row:
            b64 = base64.b64encode(bytes(row["zeroBytes"])).decode()
        else:
            b64 = row["tx"]["transactionBase64"]
            sui_decoded(row["tx"])
        bound = X402_EXACT_SUI.bound(sui_payment(b64))
        expected = row["expectBound"] if row["expectBound"].startswith("0x") else Refusal(row["expectBound"])
        assert (row["case"], bound) == (row["case"], expected)
        if "expectReference" in row:
            tx = decode_sui_tx(b64)
            assert not isinstance(tx, Refusal) and tx.until_epoch is None


def test_sui_agreed_refusals() -> None:
    """The buyer-side rows: a non-canonical or trailing byte, base64, the network, the signature and the
    transaction's type."""
    rows = {row["case"]: row["expect"] for row in SUI["agreedRefusals"]["rows"]}
    v2 = base64.b64decode(SUI["V2"]["tx"]["transactionBase64"])
    canonical = "bytes that parse as TransactionData but do not serialise back to themselves (trailing or non-canonical bytes)"
    assert decode_sui_tx(base64.b64encode(v2 + b"\x00").decode()) == Refusal(rows[canonical])
    # The input count 3 (byte 2) written as the two-byte ULEB128 83 00.
    assert v2[2] == 3
    assert decode_sui_tx(base64.b64encode(v2[:2] + bytes([0x83, 0x00]) + v2[3:]).decode()) == Refusal(rows[canonical])
    assert decode_sui_tx("AAA") == Refusal(rows["a transaction that is not padded standard base64"])
    network = "an option with scheme exact and a sui: network other than mainnet, testnet or devnet"
    assert X402_EXACT_SUI.bound(sui_payment(SUI["V2"]["tx"]["transactionBase64"], {**SUI_F["O"], "network": "sui:localnet"})) == Refusal(rows[network])
    signature = "payload.signature not a string, empty, or over 8192 characters"
    for bad in (1, "", "A" * 8193):
        p = sui_payment(SUI["V2"]["tx"]["transactionBase64"])
        p["payload"]["signature"] = bad
        assert X402_EXACT_SUI.bound(p) == Refusal(rows[signature])
    p = sui_payment(SUI["V2"]["tx"]["transactionBase64"])
    p["payload"]["transaction"] = 1
    assert X402_EXACT_SUI.bound(p) == Refusal(rows["payload.transaction not a string"])


def test_sui_the_pairings_filter() -> None:
    O = SUI_F["O"]
    assert sui_option_check(O) is None
    for network in ("sui:mainnet", "sui:devnet"):
        assert sui_option_check({**O, "network": network}) is None
    assert sui_option_check({**O, "extra": {"paymentFlow": "authorization"}}) is None
    assert sui_option_check({**O, "extra": {"paymentFlow": "upfront"}}) is not None
    assert sui_option_check({**O, "extra": {"assetTransferMethod": "eip3009"}}) is not None
    assert sui_option_check({**O, "payTo": O["payTo"].upper().replace("0X", "0x")}) is not None
    assert sui_option_check({**O, "asset": "SUI"}) is not None
    assert sui_option_check({**O, "amount": "18446744073709551616"}) is not None
    assert sui_option_check({**O, "amount": "18446744073709551615"}) is None
    assert sui_option_check({**O, "network": "eip155:84532"}) is not None


def test_sui_build_asks_for_one_unused_pure_input_holding_h_and_complete_accepts_only_a_payment_bound_to_h() -> None:
    doc = x402_doc(SUI_F["O"], SUI_F["resource"], link=SUI_F["link"])
    read = X402_EXACT_SUI.read(doc)
    assert not isinstance(read, Refusal)
    assert (read.h, read.link, read.offer["options"]) == (SUI_F["H"], SUI_F["link"], [SUI_F["O"]])
    u = X402_EXACT_SUI.build({"required": doc, "accepted": SUI_F["O"]}, SUI_F["H"])
    assert not isinstance(u, Refusal), u
    assert u.request["kind"] == "sui-transaction" and u.request["expiration"] == "epoch-bounded"
    assert u.request["pureInput"].hex() == SUI_F["H"][2:]
    v2 = SUI["V2"]["tx"]["transactionBase64"]
    assert u.complete({"signature": "AAAA", "transaction": v2}) == {
        "x402Version": 2,
        "resource": SUI_F["resource"],
        "accepted": SUI_F["O"],
        "payload": {"signature": "AAAA", "transaction": v2},
        "extensions": doc["extensions"],
    }
    assert u.complete({"signature": "AAAA", "transaction": SUI["V1"]["tx"]["transactionBase64"]}) == Refusal("x402/signed-not-bound")
    unbounded = next(r for r in SUI["V3"] if r["case"].startswith("setExpiration"))["tx"]["transactionBase64"]
    assert u.complete({"signature": "AAAA", "transaction": unbounded}) == Refusal("x402/signed-not-bound")
