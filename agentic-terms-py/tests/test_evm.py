"""The x402 EVM breadth pairings: the gate's B2 (the plant) and B6 (build and sign) for each, and the bindings' rows
(EV1-EV4, EV7, EV8 and the plants). Every expected digest, signature, salt, nonce and refusal is the vector files';
the payer is the published Anvil key #0 the files name. permit2_typed_data's witness cases are the protocol package's
own test's."""

import copy
import hashlib
import re
from collections import UserString
from collections.abc import Callable, Iterator, Mapping
from typing import Any

import pytest
from eth_abi.abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_typed_data

from integraledger_terms import (
    X402_AUTH_CAPTURE_EIP155_EIP3009,
    X402_AUTH_CAPTURE_EIP155_PERMIT2,
    X402_EXACT_EIP155_ERC7710,
    X402_EXACT_EIP155_ERC7710_SALT,
    X402_EXACT_EIP155_PERMIT2,
    X402_UPTO_EIP155_PERMIT2,
    Binding,
    Refusal,
    _gate,
)
from integraledger_terms.bindings import _evm

from breadth import ABD, H, LINK, Pairing, build_and_sign, plant, x402_doc
from support import load

PERMIT2 = load("x402-exact-eip155-permit2.json")
UPTO = load("x402-upto-eip155-permit2.json")
ERC7710 = load("x402-exact-eip155-erc7710.json")
ERC7710_SALT = load("x402-exact-eip155-erc7710-salt.json")
AC_EIP3009 = load("x402-auth-capture-eip155-eip3009.json")
AC_PERMIT2 = load("x402-auth-capture-eip155-permit2.json")

DELEGATION_ABI = "(address,address,bytes32,(address,bytes,bytes)[],uint256,bytes)[]"
DELEGATION_TYPES = {
    "Delegation": [
        {"name": "delegate", "type": "address"},
        {"name": "delegator", "type": "address"},
        {"name": "authority", "type": "bytes32"},
        {"name": "caveats", "type": "Caveat[]"},
        {"name": "salt", "type": "uint256"},
    ],
    "Caveat": [{"name": "enforcer", "type": "address"}, {"name": "terms", "type": "bytes"}],
}


def assert_truncated(value: str, expected: dict[str, str]) -> None:
    assert value.startswith(expected["prefix"]) and value.endswith(expected["suffix"]), (value, expected)


def _digest(typed_data: dict[str, Any]) -> str:
    signable = encode_typed_data(full_message=copy.deepcopy(typed_data))
    return "0x" + bytes(Account.sign_message(signable, PERMIT2["fixed"]["payerKey"]).message_hash).hex()


def sign(key: str, typed_data: dict[str, Any]) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=copy.deepcopy(typed_data)), key)
    return "0x" + bytes(signed.signature).hex()


def eip712(fixed: dict[str, Any]) -> Callable[[Any], str]:
    def answer(request: Any) -> str:
        assert request["kind"] == "eip712", request
        return sign(fixed["payerKey"], request["typedData"])

    return answer


def doc_of(fixed: dict[str, Any]) -> dict[str, Any]:
    """The seller's document for the fixed option, as the pairing's advertise places H and the link."""
    return x402_doc(fixed["option"], fixed["resource"])


def eip712_pairing(binding: Binding, fixed: dict[str, Any]) -> Pairing:
    return Pairing(binding, doc_of(fixed), f"{fixed['option']['network']}:{fixed['payer']}", eip712(fixed))


def choice(fixed: dict[str, Any], option: dict[str, Any] | None = None) -> dict[str, Any]:
    offered = copy.deepcopy(option if option is not None else fixed["option"])
    return {"required": x402_doc(offered, fixed["resource"]), "accepted": offered, "from": fixed["payer"],
            "now": fixed["now"]}  # fmt: skip


def built(binding: Binding, fixed: dict[str, Any], option: dict[str, Any] | None = None) -> Any:
    unsigned = binding.build(choice(fixed, option), H)
    assert not isinstance(unsigned, Refusal), unsigned
    return unsigned


def completed(binding: Binding, fixed: dict[str, Any], signature: str | None = None) -> dict[str, Any]:
    unsigned = built(binding, fixed)
    answer = signature if signature is not None else sign(fixed["payerKey"], unsigned.request["typedData"])
    presented = unsigned.complete(answer)
    assert not isinstance(presented, Refusal), presented
    return dict(presented)


def frozen(monkeypatch: pytest.MonkeyPatch, fixed: dict[str, Any]) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: fixed["now"])


def b6_inspect(fixed: dict[str, Any], row: dict[str, Any]) -> Callable[[Any], None]:
    """The request's digest is the vectors', its signature where the vectors give one, and its verifyingContract is in
    lower case."""

    def inspect(request: Any) -> None:
        typed_data = request["typedData"]
        assert _digest(typed_data) == row["expectDigest"]
        if "expectSignature" in row:
            assert eip712(fixed)(request) == row["expectSignature"]

    return inspect


# ── The gate's B2 and B6 for the four EIP-712 pairings.

EIP712_ROWS: list[tuple[str, Binding, dict[str, Any], str]] = [
    ("x402/exact/eip155/permit2", X402_EXACT_EIP155_PERMIT2, PERMIT2, "EV1"),
    ("x402/upto/eip155/permit2", X402_UPTO_EIP155_PERMIT2, UPTO, "EV2"),
    ("x402/auth-capture/eip155/eip3009", X402_AUTH_CAPTURE_EIP155_EIP3009, AC_EIP3009, "EV4"),
    ("x402/auth-capture/eip155/permit2", X402_AUTH_CAPTURE_EIP155_PERMIT2, AC_PERMIT2, "EV4"),
]


def _b2(monkeypatch: pytest.MonkeyPatch, index: int) -> None:
    _, binding, vectors, _ = EIP712_ROWS[index]
    frozen(monkeypatch, vectors["fixed"])
    plant(eip712_pairing(binding, vectors["fixed"]))


def _b6(monkeypatch: pytest.MonkeyPatch, index: int) -> None:
    _, binding, vectors, row = EIP712_ROWS[index]
    fixed = vectors["fixed"]
    frozen(monkeypatch, fixed)
    build_and_sign(eip712_pairing(binding, fixed), b6_inspect(fixed, vectors[row]))

def test_x402_exact_eip155_permit2_b6_build_and_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    _b6(monkeypatch, 0)

def test_x402_upto_eip155_permit2_b6_build_and_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    _b6(monkeypatch, 1)

def test_x402_auth_capture_eip155_eip3009_b6_build_and_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    _b6(monkeypatch, 2)

def test_x402_auth_capture_eip155_permit2_b6_build_and_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    _b6(monkeypatch, 3)


# ── ERC-7710: the delegation tooling signs the leaf delegation with the request's salt.

SALT_FIXED = ERC7710_SALT["fixed"]
EV8 = ERC7710_SALT["EV8"]


def delegation_tuple(d: dict[str, Any], salt: int, signature: str) -> tuple[Any, ...]:
    caveats = [
        (c["enforcer"], bytes.fromhex(c["terms"][2:]), bytes.fromhex(c["args"][2:])) for c in d["caveats"]
    ]
    return (d["delegate"], d["delegator"], bytes.fromhex(d["authority"][2:]), caveats, salt, bytes.fromhex(signature[2:]))


def context_of(delegations: list[tuple[Any, ...]]) -> str:
    return "0x" + abi_encode([DELEGATION_ABI], [delegations]).hex()


def signed_leaf(salt: int) -> str:
    """The leaf delegation with this salt, signed by the Anvil key under the DelegationManager's domain."""
    leaf = {**SALT_FIXED["leaf"], "salt": salt}
    typed_data = {"domain": SALT_FIXED["delegationDomain"], "types": DELEGATION_TYPES, "primaryType": "Delegation",
                  "message": leaf}  # fmt: skip
    return sign(SALT_FIXED["payerKey"], typed_data)


def tooling(manager: str) -> Callable[[Any], dict[str, str]]:
    """The buyer's delegation tooling: the leaf delegation with the request's salt, signed and ABI-encoded."""

    def answer(request: Any) -> dict[str, str]:
        assert request["kind"] == "erc7710", request
        salt = int(request["salt"], 16)
        signature = signed_leaf(salt)
        assert signature == EV8["expectSignature"]
        context = context_of([delegation_tuple(SALT_FIXED["leaf"], salt, signature)])
        assert (len(context) - 2) // 2 == EV8["expectContextBytes"]
        assert "0x" + hashlib.sha256(bytes.fromhex(context[2:])).hexdigest() == EV8["expectContextSha256"]
        return {"delegationManager": manager, "permissionContext": context, "delegator": SALT_FIXED["payer"]}

    return answer


def erc7710_pairing(binding: Binding, manager: str) -> Pairing:
    return Pairing(binding, doc_of(SALT_FIXED), f"{SALT_FIXED['option']['network']}:{SALT_FIXED['payer']}",
                   tooling(manager))  # fmt: skip


def erc7710_inspect(request: Any) -> None:
    assert request["kind"] == "erc7710"
    assert request["salt"] == H
    assert request["payTo"] == SALT_FIXED["option"]["payTo"]

def test_x402_exact_eip155_erc7710_salt_b6_build_and_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    frozen(monkeypatch, SALT_FIXED)
    build_and_sign(erc7710_pairing(X402_EXACT_EIP155_ERC7710_SALT, SALT_FIXED["delegationManager"]), erc7710_inspect)

def test_x402_exact_eip155_erc7710_b6_build_and_sign(monkeypatch: pytest.MonkeyPatch) -> None:
    frozen(monkeypatch, ERC7710["fixed"])
    signed, _ = build_and_sign(erc7710_pairing(X402_EXACT_EIP155_ERC7710, ERC7710["EV7"]["otherManager"]), erc7710_inspect)
    assert X402_EXACT_EIP155_ERC7710.bound(signed) == ERC7710["EV7"]["expectBound"]


# ── The bindings' buyer-side rows: EV1 and EV2 (Permit2).


def test_ev1_exact_permit2_build_complete_and_bound() -> None:
    fixed, ev1 = PERMIT2["fixed"], PERMIT2["EV1"]
    unsigned = built(X402_EXACT_EIP155_PERMIT2, fixed)
    assert _digest(unsigned.request["typedData"]) == ev1["expectDigest"]
    presented = completed(X402_EXACT_EIP155_PERMIT2, fixed)
    assert presented["payload"]["signature"] == ev1["expectSignature"]
    authorization = presented["payload"]["permit2Authorization"]
    assert authorization["spender"] == ev1["expectSpender"]
    assert authorization["nonce"] == ev1["expectNonceDecimal"]
    assert authorization["deadline"] == ev1["expectDeadline"]
    assert X402_EXACT_EIP155_PERMIT2.bound(presented) == ev1["expectBound"]

    hex_nonce = copy.deepcopy(presented)
    hex_nonce["payload"]["permit2Authorization"]["nonce"] = "0x" + format(int(ev1["expectNonceDecimal"]), "064x")
    assert X402_EXACT_EIP155_PERMIT2.bound(hex_nonce) == ev1["boundOfHexNonce"]

    upto_spender = copy.deepcopy(presented)
    upto_spender["payload"]["permit2Authorization"]["spender"] = ev1["uptoProxyAsSpender"]["spender"]
    assert X402_EXACT_EIP155_PERMIT2.bound(upto_spender) == Refusal(ev1["uptoProxyAsSpender"]["expect"]["code"])

    short = copy.deepcopy(presented)
    short["payload"]["permit2Authorization"]["nonce"] = ev1["nonceMalformed"]["nonce"]
    assert X402_EXACT_EIP155_PERMIT2.bound(short) == Refusal(ev1["nonceMalformed"]["expect"]["code"])


def test_ev2_upto_permit2_build_complete_and_bound() -> None:
    fixed, ev2 = UPTO["fixed"], UPTO["EV2"]
    unsigned = built(X402_UPTO_EIP155_PERMIT2, fixed)
    assert _digest(unsigned.request["typedData"]) == ev2["expectDigest"]
    presented = completed(X402_UPTO_EIP155_PERMIT2, fixed)
    authorization = presented["payload"]["permit2Authorization"]
    assert authorization["spender"] == ev2["expectSpender"]
    assert authorization["nonce"] == ev2["expectNonceHex"]
    assert authorization["deadline"] == ev2["expectDeadline"]
    assert authorization["witness"]["facilitator"] == fixed["option"]["extra"]["facilitatorAddress"]
    assert X402_UPTO_EIP155_PERMIT2.bound(presented) == ev2["expectBound"]


def test_ev2_upto_without_facilitator_is_refused() -> None:
    fixed = UPTO["fixed"]
    option = copy.deepcopy(fixed["option"])
    del option["extra"]["facilitatorAddress"]
    expect = Refusal(UPTO["facilitatorMissing"]["expect"]["code"])
    assert X402_UPTO_EIP155_PERMIT2.build(choice(fixed, option), H) == expect
    presented = completed(X402_UPTO_EIP155_PERMIT2, fixed)
    presented["accepted"] = option
    assert X402_UPTO_EIP155_PERMIT2.bound(presented) == expect


def test_payment_members_are_bounded_in_utf16_code_units() -> None:
    """U+10000 is one code point and two UTF-16 code units: 129 of them are 258 units, over the 256 a payment member
    holds, and the payment is x402/payload-malformed; 128 of them are 256 units, and bound reads the payment.
    @integraledger/lcp's bound counts a member's length as JavaScript's String length does, and answers each case so."""
    over, at_bound = "\U00010000" * 129, "\U00010000" * 128
    malformed = Refusal("x402/payload-malformed")

    exact = completed(X402_EXACT_EIP155_PERMIT2, PERMIT2["fixed"])
    for key in ("from", "deadline"):
        changed = copy.deepcopy(exact)
        changed["payload"]["permit2Authorization"][key] = over
        assert X402_EXACT_EIP155_PERMIT2.bound(changed) == malformed
    for member, key in (("permitted", "token"), ("witness", "to")):
        changed = copy.deepcopy(exact)
        changed["payload"]["permit2Authorization"][member][key] = over
        assert X402_EXACT_EIP155_PERMIT2.bound(changed) == malformed
    changed = copy.deepcopy(exact)
    changed["payload"]["permit2Authorization"]["from"] = at_bound
    assert X402_EXACT_EIP155_PERMIT2.bound(changed) == PERMIT2["EV1"]["expectBound"]

    upto = completed(X402_UPTO_EIP155_PERMIT2, UPTO["fixed"])
    upto["payload"]["permit2Authorization"]["witness"]["facilitator"] = over
    assert X402_UPTO_EIP155_PERMIT2.bound(upto) == malformed

    capture = completed(X402_AUTH_CAPTURE_EIP155_EIP3009, AC_EIP3009["fixed"])
    capture["payload"]["authorization"]["to"] = over
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.bound(capture) == malformed

    delegated = delegation_payment(ERC7710["EV7"]["otherManager"], leaf_context(int(H, 16)), ERC7710["fixed"])
    delegated["payload"]["delegator"] = over
    assert X402_EXACT_EIP155_ERC7710.bound(delegated) == malformed


def test_permission_context_is_bounded_in_utf16_code_units() -> None:
    """A permissionContext holds at most 0x and the hex digits of 32 KiB, 65,538 UTF-16 code units. 32,770 U+10000 are
    65,540 units, and the payment is x402/payload-malformed at both levels; 32,769 are 65,538 units, and the unsigned
    level reads H from the echo. @integraledger/lcp's bound counts the context's length as JavaScript's String length
    does, and answers each case so."""
    over, at_bound = "\U00010000" * 32770, "\U00010000" * 32769
    unsigned = delegation_payment(ERC7710["EV7"]["otherManager"], leaf_context(int(H, 16)), ERC7710["fixed"])
    salted = delegation_payment(SALT_FIXED["delegationManager"], leaf_context(int(H, 16)))
    for binding, presented in ((X402_EXACT_EIP155_ERC7710, unsigned), (X402_EXACT_EIP155_ERC7710_SALT, salted)):
        changed = copy.deepcopy(presented)
        changed["payload"]["permissionContext"] = over
        assert binding.bound(changed) == Refusal("x402/payload-malformed"), binding.id
    unsigned["payload"]["permissionContext"] = at_bound
    assert X402_EXACT_EIP155_ERC7710.bound(unsigned) == ERC7710["EV7"]["expectBound"]


# ── EV3 and EV4 (auth-capture).


def test_ev3_auth_capture_salt_commitment_and_nonces() -> None:
    fixed, ev3 = AC_EIP3009["fixed"], AC_EIP3009["EV3"]
    extra = fixed["option"]["extra"]
    zero = _evm.ZERO_ADDRESS
    bound_salt = _evm.bind_salt(extra["receiverAuthorizer"], zero, H)
    assert bound_salt == ev3["expectBindSalt"]
    assert _evm.PAYMENT_INFO_TYPEHASH == ev3["expectPaymentInfoTypeHash"]
    assert _evm.ESCROW_V1_1.escrow == ev3["escrow"]

    def info(payer: str, salt: str) -> _evm.PaymentInfo:
        return _evm.PaymentInfo(extra["captureAuthorizer"], payer, fixed["option"]["payTo"], fixed["option"]["asset"],
                                int(fixed["option"]["amount"]), fixed["now"] + fixed["option"]["maxTimeoutSeconds"],
                                extra["captureDeadline"], extra["refundDeadline"], extra["minFeeBps"],
                                extra["maxFeeBps"], extra["feeRecipient"], salt)  # fmt: skip

    assert isinstance(bound_salt, str)
    assert _evm.payment_hash(84532, ev3["escrow"], info(zero, bound_salt)) == ev3["bound"]["expectSignatureNonce"]
    assert _evm.payment_hash(84532, ev3["escrow"], info(fixed["payer"], bound_salt)) == ev3["bound"]["expectPaymentHash"]
    unbound_nonce = _evm.payment_hash(84532, ev3["escrow"], info(zero, H))
    unbound_hash = _evm.payment_hash(84532, ev3["escrow"], info(fixed["payer"], H))
    assert isinstance(unbound_nonce, str) and isinstance(unbound_hash, str)
    assert_truncated(unbound_nonce, ev3["unbound"]["expectSignatureNonce"])
    assert_truncated(unbound_hash, ev3["unbound"]["expectPaymentHash"])


def test_payment_hash_answers_a_payment_info_that_is_not_one() -> None:
    """evm/field-malformed: the code @integraledger/lcp's paymentHash gives the same arguments."""
    infos: list[Any] = [None, 42, "x", True, [None], {}]
    for info in infos:
        assert _evm.payment_hash(84532, AC_EIP3009["EV3"]["escrow"], info) == Refusal("evm/field-malformed")


# ── permit2_typed_data. Its witness cases are the protocol package's own test of permit2TypedData's witness (lcp 0.4.0,
# test/failures-are-values.test.ts), each in Python's form: a witness is an _evm.Witness, the protocol's undefined is no
# witness argument, and its null is None. The well-formed witness is x402-exact-eip155-permit2.json's: the Witness struct
# of EV1's witnessTypeString, with the value {to: payTo, validAfter: "0"}, over EV1's spender, nonce and deadline.

_EV1, _OPTION = PERMIT2["EV1"], PERMIT2["fixed"]["option"]
_STRUCT = re.fullmatch(r".*\)Witness\(([^)]*)\)", _EV1["witnessTypeString"])
assert _STRUCT is not None
WITNESS_FIELDS = [{"name": name, "type": kind} for kind, name in (member.split(" ") for member in _STRUCT[1].split(","))]
WITNESS_VALUE = {"to": _OPTION["payTo"], "validAfter": "0"}
WITNESS = _evm.Witness("Witness", WITNESS_FIELDS, WITNESS_VALUE)


def a_witness(kind: Any, fields: Any, value: Any) -> _evm.Witness:
    return _evm.Witness(kind, fields, value)


def permit2_typed(**given: Any) -> dict[str, Any] | Refusal:
    """permit2_typed_data over EV1's chain id, permitted, spender, nonce and deadline, with the witness argument given."""
    chain_id = int(_OPTION["network"].removeprefix("eip155:"))
    permitted = {"token": _OPTION["asset"], "amount": int(_OPTION["amount"])}
    return _evm.permit2_typed_data(chain_id, permitted, _EV1["expectSpender"], int(_EV1["expectNonceDecimal"]),
                                   int(_EV1["expectDeadline"]), **given)  # fmt: skip


def without(member: str) -> _evm.Witness:
    """WITNESS with the named member left unset: the protocol's witness object without that key."""
    w = object.__new__(_evm.Witness)
    for name in ("type", "fields", "value"):
        if name != member:
            object.__setattr__(w, name, getattr(WITNESS, name))
    return w


class Named:
    """An object whose str is "Witness", which is not a str."""

    def __str__(self) -> str:
        return "Witness"


class WithMap:
    """An object with a map method, which is not a list."""

    def map(self, f: Any) -> list[Any]:
        return []


class IndexOnly(list[Any]):
    """A list of fields whose own iteration fails: a reader that takes each entry by its index never calls it."""

    def __iter__(self) -> Iterator[Any]:
        raise AssertionError("the fields were iterated")


class ShiftingName(Mapping[str, Any]):
    """A field whose name is WITNESS's first field name on its first read and 7 on any later one."""

    def __init__(self) -> None:
        self.reads = 0

    def __getitem__(self, key: str) -> Any:
        if key == "name":
            self.reads += 1
            return WITNESS_FIELDS[0]["name"] if self.reads == 1 else 7
        if key == "type":
            return WITNESS_FIELDS[0]["type"]
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(("name", "type"))

    def __len__(self) -> int:
        return 2


class ShiftingType(_evm.Witness):
    """WITNESS's fields and value, under a type that is "Witness" on its first read and 1 on any later one."""

    __slots__ = ("reads",)
    reads: int

    def __init__(self) -> None:
        object.__setattr__(self, "fields", WITNESS_FIELDS)
        object.__setattr__(self, "value", WITNESS_VALUE)
        object.__setattr__(self, "reads", 0)

    @property
    def type(self) -> Any:
        object.__setattr__(self, "reads", self.reads + 1)
        return "Witness" if self.reads == 1 else 1


MALFORMED_WITNESSES: list[tuple[str, Any]] = [
    ("a witness of None", None),
    ("a witness of 0x1234", "0x1234"),
    ("a witness of 1", 1),
    ("a witness that is a list", [WITNESS]),
    ("a type that is a list", a_witness(["Witness"], WITNESS_FIELDS, WITNESS_VALUE)),
    ("a type that is an object whose str is Witness", a_witness(Named(), WITNESS_FIELDS, WITNESS_VALUE)),
    ("a type that is a UserString", a_witness(UserString("Witness"), WITNESS_FIELDS, WITNESS_VALUE)),
    ("a type that is a number", a_witness(1, WITNESS_FIELDS, WITNESS_VALUE)),
    ("no fields", without("fields")),
    ("fields of None", a_witness("Witness", None, WITNESS_VALUE)),
    ("fields that are a string", a_witness("Witness", "to", WITNESS_VALUE)),
    ("fields that are an object with a map method", a_witness("Witness", WithMap(), WITNESS_VALUE)),
    ("a field of None", a_witness("Witness", [None], WITNESS_VALUE)),
    ("a field that is a number", a_witness("Witness", [1], WITNESS_VALUE)),
    ("a field that is a list", a_witness("Witness", [["address", "to"]], WITNESS_VALUE)),
    ("fields with a hole, None after a field", a_witness("Witness", [WITNESS_FIELDS[0], None], WITNESS_VALUE)),
    ("a field whose name is not a str", a_witness("Witness", [{"name": 1, "type": "address"}], WITNESS_VALUE)),
    ("a field with no type", a_witness("Witness", [{"name": "to"}], WITNESS_VALUE)),
    ("no value", without("value")),
    ("a value of None", a_witness("Witness", WITNESS_FIELDS, None)),
    ("a value that is a string", a_witness("Witness", WITNESS_FIELDS, "0x1234")),
    ("a value that is a list", a_witness("Witness", WITNESS_FIELDS, [WITNESS_VALUE])),
]

# The type name rule (the protocol package's permit2TypedData docblock: an upper-case letter followed by up to 63
# letters and digits, not TokenPermissions, not starting with Permit), and the forms Python adds: a mapping of a
# witness's members is not a Witness, and a mapping is not a list of fields.
MALFORMED_NAMES_AND_FORMS: list[tuple[str, Any]] = [
    ("a type of TokenPermissions", a_witness("TokenPermissions", WITNESS_FIELDS, WITNESS_VALUE)),
    ("a type that starts with Permit", a_witness("PermitWitness", WITNESS_FIELDS, WITNESS_VALUE)),
    ("a type that starts lower-case", a_witness("witness", WITNESS_FIELDS, WITNESS_VALUE)),
    ("a type of 65 characters", a_witness("W" + "a" * 64, WITNESS_FIELDS, WITNESS_VALUE)),
    ("a mapping of a witness's members", {"type": "Witness", "fields": WITNESS_FIELDS, "value": WITNESS_VALUE}),
    ("fields that are a mapping", a_witness("Witness", {"name": "to", "type": "address"}, WITNESS_VALUE)),
]


def test_permit2_typed_data_reads_the_vector_files_witness() -> None:
    assert len(MALFORMED_WITNESSES) == 22
    assert WITNESS_FIELDS == [{"name": "to", "type": "address"}, {"name": "validAfter", "type": "uint256"}]
    typed = permit2_typed(witness=WITNESS)
    assert not isinstance(typed, Refusal)
    assert typed["primaryType"] == "PermitWitnessTransferFrom"
    assert typed["types"]["Witness"] == WITNESS_FIELDS and typed["message"]["witness"] == WITNESS_VALUE
    assert not isinstance(permit2_typed(witness=a_witness("W" + "a" * 63, WITNESS_FIELDS, WITNESS_VALUE)), Refusal)
    absent = permit2_typed()
    assert not isinstance(absent, Refusal) and absent["primaryType"] == "PermitTransferFrom"


def test_permit2_typed_data_reads_the_fields_by_index() -> None:
    typed = permit2_typed(witness=a_witness("Witness", IndexOnly(WITNESS_FIELDS), WITNESS_VALUE))
    assert not isinstance(typed, Refusal) and typed["types"]["Witness"] == WITNESS_FIELDS


def test_permit2_typed_data_reads_each_member_of_a_witness_once() -> None:
    """A later answer of a field's name, or of the witness's type, never reaches the typed data."""
    field = ShiftingName()
    typed = permit2_typed(witness=a_witness("Witness", [field], WITNESS_VALUE))
    assert not isinstance(typed, Refusal) and typed["types"]["Witness"] == [WITNESS_FIELDS[0]]
    assert field.reads == 1
    shifting = ShiftingType()
    typed = permit2_typed(witness=shifting)
    assert not isinstance(typed, Refusal) and typed["types"]["Witness"] == WITNESS_FIELDS
    assert typed["types"]["PermitWitnessTransferFrom"][-1] == {"name": "witness", "type": "Witness"}
    assert shifting.reads == 1


@pytest.mark.parametrize("witness", [w for _, w in MALFORMED_WITNESSES], ids=[n for n, _ in MALFORMED_WITNESSES])
def test_permit2_typed_data_refuses_a_malformed_witness(witness: Any) -> None:
    assert permit2_typed(witness=witness) == Refusal("evm/field-malformed")


@pytest.mark.parametrize(
    "witness", [w for _, w in MALFORMED_NAMES_AND_FORMS], ids=[n for n, _ in MALFORMED_NAMES_AND_FORMS]
)
def test_permit2_typed_data_refuses_a_witness_type_name_or_form_it_does_not_take(witness: Any) -> None:
    assert permit2_typed(witness=witness) == Refusal("evm/field-malformed")


PAYMENT_WITNESS = a_witness("PaymentWitness", [{"name": "externalId", "type": "string"}], {"externalId": ""})


@pytest.mark.parametrize("permitted", [None, 42, [42], [None], [[]], "x"], ids=["none", "int", "list-int", "list-none", "list-list", "str"])
@pytest.mark.parametrize("witness", [None, PAYMENT_WITNESS], ids=["no-witness", "witness"])
def test_permit2_typed_data_refuses_a_permitted_entry_that_is_not_an_object(permitted: Any, witness: Any) -> None:
    # The expected refusal is the protocol package's permit2TypedData answer for each of these inputs (its
    # failures-are-values test, "a permitted entry that is not an object").
    given = {} if witness is None else {"witness": witness}
    out = _evm.permit2_typed_data(chain_id=1, permitted=permitted, spender="0x" + "11" * 20, nonce=0, deadline=1, **given)
    assert out == Refusal("evm/field-malformed")


# ── The files' agreedRefusals rows, each with the input it carries.

AGREED_FILES: list[tuple[Binding, dict[str, Any]]] = [
    (X402_EXACT_EIP155_PERMIT2, PERMIT2),
    (X402_UPTO_EIP155_PERMIT2, UPTO),
    (X402_EXACT_EIP155_ERC7710, ERC7710),
    (X402_EXACT_EIP155_ERC7710_SALT, ERC7710_SALT),
    (X402_AUTH_CAPTURE_EIP155_EIP3009, AC_EIP3009),
    (X402_AUTH_CAPTURE_EIP155_PERMIT2, AC_PERMIT2),
]
@pytest.mark.parametrize("binding, vectors", AGREED_FILES, ids=[b.id for b, _ in AGREED_FILES])
def test_agreed_refusals(binding: Binding, vectors: dict[str, Any]) -> None:
    """The file holds agreedRefusals rows. A row with choice is build's choice, with the file's H; a row with permitted
    is permit2TypedData over EV1's chain id, spender, nonce and deadline."""
    rows = vectors.get("agreedRefusals", {}).get("rows", [])
    assert rows, f"{binding.id}: the vector file holds no agreedRefusals rows"
    for row in rows:
        if "choice" in row:
            got = binding.build(copy.deepcopy(row["choice"]), vectors["fixed"]["H"])
        elif "permitted" in row:
            ev1 = vectors["EV1"]
            chain_id = int(vectors["fixed"]["option"]["network"].removeprefix("eip155:"))
            got = _evm.permit2_typed_data(chain_id, copy.deepcopy(row["permitted"]), ev1["expectSpender"],
                                          int(ev1["expectNonceDecimal"]), int(ev1["expectDeadline"]))  # fmt: skip
        else:
            raise AssertionError(f"no input this runner reads: {row['case']}")
        assert got == Refusal(row["expect"]), row["case"]


def test_ev4_auth_capture_eip3009_build_complete_and_bound() -> None:
    fixed, ev3, ev4 = AC_EIP3009["fixed"], AC_EIP3009["EV3"], AC_EIP3009["EV4"]
    unsigned = built(X402_AUTH_CAPTURE_EIP155_EIP3009, fixed)
    typed_data = unsigned.request["typedData"]
    assert typed_data["primaryType"] == "ReceiveWithAuthorization"
    assert typed_data["message"]["to"] == ev4["expectTo"]
    assert typed_data["message"]["nonce"] == ev3["bound"]["expectSignatureNonce"]
    assert _digest(typed_data) == ev4["expectDigest"]
    presented = completed(X402_AUTH_CAPTURE_EIP155_EIP3009, fixed)
    assert presented["payload"]["signature"] == ev4["expectSignature"]
    assert presented["payload"]["salt"] == ev3["expectBindSalt"]
    assert presented["payload"]["saltNonce"] == H
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.bound(presented) == ev4["expectBound"]


def test_ev4_auth_capture_permit2_build_complete_and_bound() -> None:
    fixed, ev3, ev4 = AC_PERMIT2["fixed"], AC_PERMIT2["EV3"], AC_PERMIT2["EV4"]
    unsigned = built(X402_AUTH_CAPTURE_EIP155_PERMIT2, fixed)
    typed_data = unsigned.request["typedData"]
    assert typed_data["primaryType"] == "PermitTransferFrom"
    assert typed_data["message"]["spender"] == ev4["expectSpender"]
    assert typed_data["message"]["nonce"] == int(ev3["bound"]["expectSignatureNonce"], 16)
    assert _digest(typed_data) == ev4["expectDigest"]
    presented = completed(X402_AUTH_CAPTURE_EIP155_PERMIT2, fixed)
    assert presented["payload"]["salt"] == ev3["expectBindSalt"]
    assert X402_AUTH_CAPTURE_EIP155_PERMIT2.bound(presented) == ev4["expectBound"]


def test_ev4_auth_capture_unbound_salt_is_h() -> None:
    fixed = AC_EIP3009["fixed"]
    option = copy.deepcopy(fixed["option"])
    del option["extra"]["receiverAuthorizer"]
    unsigned = built(X402_AUTH_CAPTURE_EIP155_EIP3009, fixed, option)
    assert_truncated(unsigned.request["typedData"]["message"]["nonce"], AC_EIP3009["EV3"]["unbound"]["expectSignatureNonce"])
    presented = unsigned.complete(sign(fixed["payerKey"], unsigned.request["typedData"]))
    assert not isinstance(presented, Refusal)
    assert presented["payload"]["salt"] == H and "saltNonce" not in presented["payload"]
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.bound(presented) == H


def test_auth_capture_plant_nonce_not_payment() -> None:
    """A bound payload whose signed nonce is the unbound signatureNonce commits to another salt: nonce-not-payment,
    never H."""
    fixed = AC_EIP3009["fixed"]
    presented = completed(X402_AUTH_CAPTURE_EIP155_EIP3009, fixed)
    unbound = copy.deepcopy(fixed["option"])
    del unbound["extra"]["receiverAuthorizer"]
    unbound_nonce = built(X402_AUTH_CAPTURE_EIP155_EIP3009, fixed, unbound).request["typedData"]["message"]["nonce"]
    assert_truncated(unbound_nonce, AC_EIP3009["EV3"]["unbound"]["expectSignatureNonce"])
    presented["payload"]["authorization"]["nonce"] = unbound_nonce
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.bound(presented) == Refusal(AC_EIP3009["plantNonceNotPayment"]["expect"]["code"])


def test_auth_capture_salt_refusals() -> None:
    fixed = AC_EIP3009["fixed"]
    presented = completed(X402_AUTH_CAPTURE_EIP155_EIP3009, fixed)
    not_bound = copy.deepcopy(presented)
    not_bound["payload"]["salt"] = H
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.bound(not_bound) == Refusal(AC_EIP3009["saltNotBound"]["expect"]["code"])
    short = copy.deepcopy(presented)
    short["payload"]["salt"] = AC_EIP3009["saltMalformed"]["salt"]
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.bound(short) == Refusal(AC_EIP3009["saltMalformed"]["expect"]["code"])


def test_auth_capture_option_refusals() -> None:
    fixed = AC_EIP3009["fixed"]
    other = copy.deepcopy(fixed["option"])
    other["extra"]["authCaptureEscrow"] = AC_EIP3009["escrowNotCanonical"]["authCaptureEscrow"]
    expect = Refusal(AC_EIP3009["escrowNotCanonical"]["expect"]["code"])
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.build(choice(fixed, other), H) == expect
    auto = copy.deepcopy(fixed["option"])
    auto["extra"]["autoCapture"] = True
    expect = Refusal(AC_EIP3009["autoCapture"]["expect"]["code"])
    assert X402_AUTH_CAPTURE_EIP155_EIP3009.build(choice(fixed, auto), H) == expect


# ── EV7 and EV8 (ERC-7710).


def delegation_payment(manager: str, context: str, fixed: dict[str, Any] = SALT_FIXED) -> dict[str, Any]:
    unsigned = built(X402_EXACT_EIP155_ERC7710_SALT, fixed)
    presented = unsigned.complete({"delegationManager": manager, "permissionContext": context, "delegator": fixed["payer"]})
    assert not isinstance(presented, Refusal), presented
    return dict(presented)


def leaf_context(salt: int) -> str:
    return context_of([delegation_tuple(SALT_FIXED["leaf"], salt, signed_leaf(salt))])


def test_ev7_erc7710_unsigned_level_reads_the_echo() -> None:
    fixed, ev7 = ERC7710["fixed"], ERC7710["EV7"]
    presented = delegation_payment(ev7["otherManager"], leaf_context(int(H, 16)), fixed)
    assert X402_EXACT_EIP155_ERC7710.bound(presented) == ev7["expectBound"]
    del presented["extensions"]["legalContext"]
    assert X402_EXACT_EIP155_ERC7710.bound(presented) == Refusal(ev7["withoutExtension"]["expect"]["code"])


def test_ev8_erc7710_salt_level() -> None:
    context = leaf_context(int(H, 16))
    presented = delegation_payment(SALT_FIXED["delegationManager"], context)
    assert X402_EXACT_EIP155_ERC7710_SALT.bound(presented) == EV8["expectBound"]

    other = delegation_payment(EV8["otherManager"]["manager"], context)
    assert X402_EXACT_EIP155_ERC7710_SALT.bound(other) == Refusal(EV8["otherManager"]["expectSaltBound"]["code"])

    empty = delegation_payment(SALT_FIXED["delegationManager"], EV8["emptyContext"]["context"])
    assert X402_EXACT_EIP155_ERC7710_SALT.bound(empty) == Refusal(EV8["emptyContext"]["expect"]["code"])
    for case in EV8["malformedContext"]["cases"]:
        malformed = delegation_payment(SALT_FIXED["delegationManager"], context)
        malformed["payload"]["permissionContext"] = case
        assert X402_EXACT_EIP155_ERC7710_SALT.bound(malformed) == Refusal(EV8["malformedContext"]["expect"]["code"])


def test_ev8_leaf_signature_and_digest() -> None:
    leaf = {**SALT_FIXED["leaf"], "salt": int(H, 16)}
    typed_data = {"domain": SALT_FIXED["delegationDomain"], "types": DELEGATION_TYPES, "primaryType": "Delegation",
                  "message": leaf}  # fmt: skip
    assert _digest(typed_data) == EV8["expectDigest"]
    assert signed_leaf(int(H, 16)) == EV8["expectSignature"]


def test_erc7710_salt_plant_leaf_not_root() -> None:
    """A root carrying H and a leaf carrying SHA-256(abd): bound gives the leaf's salt, never H."""
    plant_row = ERC7710_SALT["plantLeafNotRoot"]
    leaf_salt = int(plant_row["leafSalt"], 16)
    assert "0x" + hashlib.sha256(ABD).hexdigest() == plant_row["leafSalt"]
    root = {**SALT_FIXED["leaf"], "delegate": SALT_FIXED["payer"], "delegator": SALT_FIXED["leaf"]["delegate"]}
    context = context_of([
        delegation_tuple(SALT_FIXED["leaf"], leaf_salt, "0x" + "11" * 65),
        delegation_tuple(root, int(H, 16), "0x" + "22" * 65),
    ])  # fmt: skip
    presented = delegation_payment(SALT_FIXED["delegationManager"], context)
    assert X402_EXACT_EIP155_ERC7710_SALT.bound(presented) == plant_row["expectBound"]


def test_the_link_is_the_vectors() -> None:
    for vectors in (PERMIT2, UPTO, ERC7710, ERC7710_SALT, AC_EIP3009, AC_PERMIT2):
        assert vectors["fixed"]["H"] == H and vectors["fixed"]["link"] == LINK
