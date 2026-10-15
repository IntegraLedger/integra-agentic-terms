"""B2, B6, B10, B16, the payment identifier and the inputs rows for x402/exact/near, and the buyer half's vector rows.
Expected values are x402-exact-near.json's."""

import base64
import dataclasses
import hashlib
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_NEAR, Refusal, _gate

import ed25519
from breadth import Pairing, build_and_sign, plant, x402_doc
from hbar_support import EVM_ACCOUNT, b10, b16, identifier_row, inputs_row
from support import hexb, load

N = load("x402-exact-near.json")
F: dict[str, Any] = N["fixed"]
SEED = bytes.fromhex(F["seedHex"])
NOW = 1790000000


def near_answer(request: Any) -> Any:
    if request["kind"] != "near-delegate":
        raise AssertionError(request["kind"])
    return {"keyType": 0, "bytes": "0x" + ed25519.sign(SEED, hexb(request["hash"])).hex()}


NEAR = Pairing(
    binding=X402_EXACT_NEAR,
    doc=x402_doc(F["O"], F["resource"]),
    account=f"{F['O']['network']}:{F['payer']}",
    answer=near_answer,
    inputs={"publicKey": F["publicKey"], "accessKeyNonce": F["accessKeyNonce"], "finalHeight": F["finalHeight"]},
)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: NOW)

def test_x402_exact_near_b6_request_is_the_vectors_and_signature_completes_v2() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "near-delegate"
        assert hexb(request["hash"]).hex() == N["V1"]["expectRequestHash"]
        sig = ed25519.sign(SEED, hexb(request["hash"])).hex()
        assert sig.startswith(N["V1"]["expectSignature"]["prefix"]) and sig.endswith(N["V1"]["expectSignature"]["suffix"])

    signed, _ = build_and_sign(NEAR, inspect)
    assert signed["payload"]["signedDelegateAction"] == N["V2"]["expectSignedDelegateAction"]


def test_x402_exact_near_b6_payment_identifier() -> None:
    identifier_row(NEAR)


def test_x402_exact_near_b10_http_link() -> None:
    b10(NEAR)


def test_x402_exact_near_b16_other_accounts() -> None:
    b16(NEAR, [EVM_ACCOUNT, f"near:mainnet:{F['payer']}"])


def test_x402_exact_near_inputs() -> None:
    inputs_row(NEAR, {"publicKey": F["publicKey"], "accessKeyNonce": "100"}, "x402/input-missing")
    inputs_row(NEAR, {"publicKey": F["publicKey"], "accessKeyNonce": 100, "finalHeight": "200000000"}, "x402/input-missing")


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def presented(sda: str) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": F["O"], "payload": {"signedDelegateAction": sda}}


def near_choice(option: dict[str, Any] | None = None, **changes: Any) -> dict[str, Any]:
    offered = option if option is not None else F["O"]
    value: dict[str, Any] = {
        "required": {"x402Version": 2, "resource": F["resource"], "accepts": [offered]},
        "accepted": offered,
        "payer": F["payer"],
        "publicKey": F["publicKey"],
        "accessKeyNonce": int(F["accessKeyNonce"]),
        "finalHeight": int(F["finalHeight"]),
    }
    value.update(changes)
    return value


def test_x402_exact_near_v1_args_and_request_hash() -> None:
    from integraledger_terms.bindings.x402_exact_near import ft_transfer_args

    args = ft_transfer_args(F["O"]["payTo"], F["O"]["amount"], F["H"])
    assert isinstance(args, bytes)
    assert args.decode() == N["V1"]["expectArgsUtf8"]
    assert hashlib.sha256(args).hexdigest() == N["V1"]["expectArgsSha256"]
    unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    assert unsigned.request["hash"].hex() == N["V1"]["expectRequestHash"]
    sda = base64.b64decode(N["V2"]["expectSignedDelegateAction"])
    assert len(sda) - 65 == N["V1"]["expectDelegateActionBytes"]
    assert (1073742190).to_bytes(4, "little").hex() == N["V1"]["expectPrefix"]
    assert hashlib.sha256(bytes.fromhex(N["V1"]["expectPrefix"]) + sda[:-65]).hexdigest() == N["V1"]["expectRequestHash"]


def test_x402_exact_near_v2_presented_options() -> None:
    """V2's signed delegate action under each presented option of V2.presentedOptions: bound holds the presented option
    to the filter read applies, so a row whose option read does not offer gives its expect refusal, and a row whose
    option read offers gives its expectBound."""
    rows = N["V2"]["presentedOptions"]
    assert any("expect" in row for row in rows), "the vector file holds no refused V2.presentedOptions row"
    for row in rows:
        p = {**presented(N["V2"]["expectSignedDelegateAction"]), "accepted": row["accepted"]}
        want = Refusal(row["expect"]) if "expect" in row else row["expectBound"]
        assert X402_EXACT_NEAR.bound(p) == want, row["case"]


def test_x402_exact_near_v2_complete_and_bound() -> None:
    unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete({"keyType": 0, "bytes": ed25519.sign(SEED, unsigned.request["hash"])})
    assert not isinstance(signed, Refusal)
    assert signed["payload"]["signedDelegateAction"] == N["V2"]["expectSignedDelegateAction"]
    assert X402_EXACT_NEAR.bound(signed) == N["V2"]["expectBound"]
    for row in N["V2"]["refusals"]:
        assert X402_EXACT_NEAR.bound(presented(row["signedDelegateAction"])) == Refusal(row["expect"]), row["case"]


def delegate_with_height(height: int) -> bytes:
    """V2's delegate action with its maxBlockHeight, the u64 before the 33-byte public key, set to height."""
    delegate = base64.b64decode(N["V2"]["expectSignedDelegateAction"])[:-65]
    at = len(delegate) - 33 - 8
    return delegate[:at] + height.to_bytes(8, "little") + delegate[at + 8 :]


def test_x402_exact_near_a_positive_timeout_opens_a_window_of_that_many_blocks() -> None:
    # x402's scheme_exact_near opens max(1, ceil(maxTimeoutSeconds / estimatedBlockSeconds)) blocks, with one-second
    # blocks; under the positive safe integer the filter holds, that is maxTimeoutSeconds blocks. Each expected request
    # hash is V2's delegate action with maxBlockHeight finalHeight plus the window, under V1's prefix; a window of 60
    # gives V1's expectRequestHash.
    prefix = bytes.fromhex(N["V1"]["expectPrefix"])
    final = int(F["finalHeight"])
    assert hashlib.sha256(prefix + delegate_with_height(final + 60)).hexdigest() == N["V1"]["expectRequestHash"]
    for timeout, blocks in ((1, 1), (60, 60), (60.0, 60)):
        option = {**F["O"], "maxTimeoutSeconds": timeout}
        read = X402_EXACT_NEAR.read(x402_doc(option, F["resource"]))
        assert not isinstance(read, Refusal) and read.offer["options"] == [option], timeout
        unsigned = X402_EXACT_NEAR.build(near_choice(option), F["H"])
        assert not isinstance(unsigned, Refusal), timeout
        want = hashlib.sha256(prefix + delegate_with_height(final + blocks)).hexdigest()
        assert unsigned.request["hash"].hex() == want, timeout
        under = {**presented(N["V2"]["expectSignedDelegateAction"]), "accepted": option}
        assert X402_EXACT_NEAR.bound(under) == N["V2"]["expectBound"], timeout
    absent = {k: v for k, v in F["O"].items() if k != "maxTimeoutSeconds"}
    refused = (0, -60, -(2**53 - 1), "60", 1.5, 2**53, None, True)
    for option in [absent, *({**F["O"], "maxTimeoutSeconds": v} for v in refused)]:
        assert X402_EXACT_NEAR.read(x402_doc(option, F["resource"])) == Refusal("x402/no-payable-option"), option
        assert X402_EXACT_NEAR.build(near_choice(option), F["H"]) == Refusal("near/option-malformed"), option
        under = {**presented(N["V2"]["expectSignedDelegateAction"]), "accepted": option}
        assert X402_EXACT_NEAR.bound(under) == Refusal("near/option-malformed"), option


V2_SDA = base64.b64decode(N["V2"]["expectSignedDelegateAction"])


def with_sender(sender: bytes) -> bytes:
    """V2's signed delegate action with its sender_id string's bytes replaced."""
    n = int.from_bytes(V2_SDA[:4], "little")
    return len(sender).to_bytes(4, "little") + sender + V2_SDA[4 + n :]


def with_byte(at: int, value: int) -> bytes:
    data = bytearray(V2_SDA)
    data[at] = value
    return bytes(data)


def test_x402_exact_near_strings_are_utf8() -> None:
    # The borsh specification writes a String as its UTF-8 bytes, so a delegate action whose sender, receiver or method
    # name is not UTF-8 is near/sda-malformed, and a UTF-8 one reads and writes back to the same bytes.
    from integraledger_terms.bindings._borsh_near import decode_signed_delegate, encode_signed_delegate

    receiver_at = 4 + int.from_bytes(V2_SDA[:4], "little") + 4
    method_at = receiver_at + int.from_bytes(V2_SDA[receiver_at - 4 : receiver_at], "little") + 4 + 1 + 4
    assert V2_SDA[receiver_at : receiver_at + 12] == F["O"]["asset"].encode()
    assert V2_SDA[method_at : method_at + 11] == b"ft_transfer"
    not_utf8 = [
        with_byte(receiver_at + 4, 0xFF),
        with_byte(method_at, 0xE9),
        with_sender("payer-é.testnet".encode("latin-1")),
        with_sender(b"payer\xc0\xaetestnet"),
        with_sender(b"a\xed\xa0\x80\xed\xb0\x80.testnet"),
        with_sender(b"payer.testnet\xc3"),
    ]
    for sda in not_utf8:
        assert X402_EXACT_NEAR.bound(presented(base64.b64encode(sda).decode())) == Refusal("near/sda-malformed"), sda
    utf8 = with_sender("payer-é.testnet".encode("utf-8"))
    assert X402_EXACT_NEAR.bound(presented(base64.b64encode(utf8).decode())) == N["V2"]["expectBound"]
    decoded = decode_signed_delegate(utf8)
    assert not isinstance(decoded, str) and decoded[0].sender_id == "payer-é.testnet"
    assert encode_signed_delegate(*decoded) == utf8


def test_x402_exact_near_key_type_written_as_a_float() -> None:
    # V2.keyTypeWritten: keyType written 0.0, which Python's json reads as a float, is keyType 0, and the binding's
    # complete and the gate's piece both give V2's signed delegate action.
    key_type = N["V2"]["keyTypeWritten"]["keyType"]
    assert isinstance(key_type, float)
    unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signed = unsigned.complete({"keyType": key_type, "bytes": ed25519.sign(SEED, unsigned.request["hash"])})
    assert not isinstance(signed, Refusal)
    assert signed["payload"]["signedDelegateAction"] == N["V2"]["expectSignedDelegateAction"]

    def answer(request: Any) -> Any:
        return {**near_answer(request), "keyType": key_type}

    signed, _ = build_and_sign(dataclasses.replace(NEAR, answer=answer), lambda request: None)
    assert signed["payload"]["signedDelegateAction"] == N["V2"]["expectSignedDelegateAction"]


def base64_bytes(text: object) -> bytes:
    try:
        return base64.b64decode(text) if isinstance(text, str) else b""
    except ValueError:
        return b""


def test_x402_exact_near_agreed_refusals_count_utf16_code_units() -> None:
    # The file's about: a signedDelegateAction's length is counted in UTF-16 code units; U+10000 counts two.
    rows = [r for r in N["agreedRefusals"]["rows"] if any(ord(c) > 0xFFFF for c in r.get("signedDelegateAction", ""))]
    assert rows, "agreedRefusals rows whose signedDelegateAction holds a character past U+FFFF"
    for row in rows:
        assert X402_EXACT_NEAR.bound(presented(row["signedDelegateAction"])) == Refusal(row["expect"]), row["case"]


def test_x402_exact_near_agreed_refusals_args_led_by_a_byte_order_mark() -> None:
    # A byte-order mark leading the ft_transfer arguments is a character of their text, so the text is not JSON.
    rows = [r for r in N["agreedRefusals"]["rows"] if b"\xef\xbb\xbf{" in base64_bytes(r.get("signedDelegateAction"))]
    assert rows, "agreedRefusals rows whose ft_transfer arguments begin with a byte-order mark"
    for row in rows:
        assert X402_EXACT_NEAR.bound(presented(row["signedDelegateAction"])) == Refusal(row["expect"]), row["case"]


# The agreedRefusals rows whose code the file's about gives to the TypeScript implementation alone: the two recover rows
# and the missing-peer row. The Python half has no recover, and decodes NEAR with no optional package.
TYPESCRIPT_ONLY = {"near/unreadable", "near/no-relayer", "near/peer-missing"}


def test_x402_exact_near_agreed_refusals() -> None:
    """Each agreedRefusals row through the functions its input names, every member read: an option through build, a
    signedDelegateAction through near_carrier and bound, a publicKey through build, and signatureBytes zero bytes, the
    last set to signatureLastByte when the row gives one, through complete. A row with no input is one of the
    TypeScript implementation's alone; a row with any other set of members fails."""
    from integraledger_terms.bindings.x402_exact_near import near_carrier

    rows = N["agreedRefusals"]["rows"]
    ran, left = 0, 0
    for row in rows:
        want = Refusal(row["expect"])
        members = set(row) - {"case", "expect"}
        got: object
        if members == {"option"}:
            got = X402_EXACT_NEAR.build(near_choice(row["option"]), F["H"])
        elif members == {"signedDelegateAction"}:
            assert near_carrier(row["signedDelegateAction"]) == want, row["case"]
            got = X402_EXACT_NEAR.bound(presented(row["signedDelegateAction"]))
        elif members == {"publicKey"}:
            got = X402_EXACT_NEAR.build(near_choice(publicKey=row["publicKey"]), F["H"])
        elif members in ({"signatureBytes"}, {"signatureBytes", "signatureLastByte"}):
            unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
            assert not isinstance(unsigned, Refusal)
            data = bytearray(row["signatureBytes"])
            if "signatureLastByte" in row:
                data[-1] = row["signatureLastByte"]
            got = unsigned.complete({"keyType": 0, "bytes": bytes(data)})
        elif not members and row["expect"] in TYPESCRIPT_ONLY:
            left += 1
            continue
        else:
            pytest.fail(f"no runner for the agreedRefusals row {row['case']!r} with members {sorted(members)}")
        assert got == want, row["case"]
        ran += 1
    assert (ran, left) == (len(rows) - len(TYPESCRIPT_ONLY), len(TYPESCRIPT_ONLY))


def test_x402_exact_near_key_forms() -> None:
    """keyForms: build reads each spelling of the payer's key that nearcore's PublicKey::from_str reads and gives the
    row's expectRequestHash. The payment it completes is V2's signed delegate action under fixed.publicKey's key, signed
    with the seed, or the secp256k1 vector's under its key, signed with its signature: each carries the key's type
    byte and bytes, whatever the spelling, and bound reads V2's hash from it."""
    rows = N["keyForms"]["rows"]
    assert rows, "the vector file holds no keyForms rows"
    secp = N["secp256k1"]
    for row in rows:
        unsigned = X402_EXACT_NEAR.build(near_choice(publicKey=row["publicKey"]), F["H"])
        assert not isinstance(unsigned, Refusal), row["case"]
        assert unsigned.request["hash"].hex() == row["expectRequestHash"], row["case"]
        if row["expectRequestHash"] == secp["expectRequestHash"]:
            signed = unsigned.complete({"keyType": 1, "bytes": bytes.fromhex(secp["signature"])})
            want = secp["expectSignedDelegateAction"]
        else:
            signed = unsigned.complete({"keyType": 0, "bytes": ed25519.sign(SEED, unsigned.request["hash"])})
            want = N["V2"]["expectSignedDelegateAction"]
        assert not isinstance(signed, Refusal), row["case"]
        assert signed["payload"]["signedDelegateAction"] == want, row["case"]
        assert X402_EXACT_NEAR.bound(signed) == N["V2"]["expectBound"], row["case"]


def overwrite(data: bytes, at: int, new: bytes) -> bytes:
    return data[:at] + new + data[at + len(new) :]


def test_x402_exact_near_reads_the_sender_and_receiver_then_the_count_then_the_variant() -> None:
    # nearcore reads a delegate action's sender and receiver as account ids, each a borsh String that must be UTF-8
    # (near-account-id src/borsh.rs), then the u32 count of actions, then the first action's u8 variant index, where
    # FunctionCall is 2 (core/primitives/src/action/mod.rs). A sender or receiver that is not UTF-8 is
    # near/sda-malformed whatever the count; a count other than one is near/actions whatever follows it; and a variant
    # index other than 2 is near/not-ft-transfer whatever bytes follow it. Each case is V2's signed delegate action
    # with those bytes changed.
    from integraledger_terms.bindings.x402_exact_near import near_carrier

    sender_end = 4 + int.from_bytes(V2_SDA[:4], "little")
    receiver_at = sender_end + 4
    count_at = receiver_at + int.from_bytes(V2_SDA[sender_end:receiver_at], "little")
    assert V2_SDA[count_at : count_at + 5] == (1).to_bytes(4, "little") + b"\x02"
    two = overwrite(V2_SDA, count_at, (2).to_bytes(4, "little"))
    for at in (4, receiver_at):
        for lead in (b"\xc3\x41", b"\xc0\x80", b"\xed\xa0\x80", b"\xff"):
            sda = base64.b64encode(overwrite(two, at, lead)).decode()
            assert near_carrier(sda) == Refusal("near/sda-malformed"), (at, lead)
            assert X402_EXACT_NEAR.bound(presented(sda)) == Refusal("near/sda-malformed"), (at, lead)
    assert near_carrier(base64.b64encode(overwrite(two, 4, "é".encode())).decode()) == Refusal("near/actions")
    for count in (0, 2, 2**32 - 1):
        for variant in (2, 3, 11):
            sda = base64.b64encode(overwrite(V2_SDA, count_at, count.to_bytes(4, "little") + bytes([variant]))).decode()
            assert near_carrier(sda) == Refusal("near/actions"), (count, variant)
            assert X402_EXACT_NEAR.bound(presented(sda)) == Refusal("near/actions"), (count, variant)
    for variant in range(256):
        sda = base64.b64encode(overwrite(V2_SDA, count_at + 4, bytes([variant]))).decode()
        want = N["V2"]["expectBound"] if variant == 2 else Refusal("near/not-ft-transfer")
        assert near_carrier(sda) == want, variant
        assert X402_EXACT_NEAR.bound(presented(sda)) == want, variant


def test_x402_exact_near_ed25519_signature_last_byte_below_0x20() -> None:
    # nearcore's Signature reader refuses an Ed25519 signature whose last byte has any of its top three bits set
    # (core/crypto/src/signature.rs). The last 32 bytes are S, little-endian, and RFC 8032 §5.1.7 requires S below the
    # group order, which is below 2^253, so every valid signature's last byte is below 0x20, as V2's is. With 0x20,
    # 0x40 or 0x80 set it is near/sda-malformed when read and x402/signature-malformed in complete; 0x1f is read.
    from integraledger_terms.bindings.x402_exact_near import near_carrier

    assert V2_SDA[-1] < 0x20
    unsigned = X402_EXACT_NEAR.build(near_choice(), F["H"])
    assert not isinstance(unsigned, Refusal)
    signature = ed25519.sign(SEED, unsigned.request["hash"])
    for bit in (0x20, 0x40, 0x80):
        sda = base64.b64encode(V2_SDA[:-1] + bytes([V2_SDA[-1] | bit])).decode()
        assert near_carrier(sda) == Refusal("near/sda-malformed"), bit
        assert X402_EXACT_NEAR.bound(presented(sda)) == Refusal("near/sda-malformed"), bit
        high = signature[:-1] + bytes([signature[-1] | bit])
        assert unsigned.complete({"keyType": 0, "bytes": high}) == Refusal("x402/signature-malformed"), bit
    assert near_carrier(base64.b64encode(V2_SDA[:-1] + b"\x1f").decode()) == N["V2"]["expectBound"]
    assert not isinstance(unsigned.complete({"keyType": 0, "bytes": signature[:-1] + b"\x1f"}), Refusal)
