"""ft_transfer's arguments as the token contract reads them. near-sdk reads a JSON method's arguments with
serde_json::from_slice into a struct serde derives from the method's parameters (near-sdk-macros,
src/core_impl/code_generator/impl_item_method_info.rs and attr_sig_info.rs), and NEP-141's method is
ft_transfer(receiver_id: AccountId, amount: U128, memo: Option<String>) (near-contract-standards,
src/fungible_token/core.rs). The derived reader refuses a field it names that appears twice, and skips any other key
each time it appears (serde_derive, src/de/struct_.rs); a missing Option field is None and any other missing field is
refused (serde, src/private/de.rs). serde_json reads each key of the object as a string and refuses an escape that
decodes to a lone surrogate, while a skipped value's strings and keys are not held to that (serde_json, src/read.rs and
src/de.rs). A U128 is a JSON string that Rust's u128::from_str reads (near-sdk, src/json_types/integers.rs): an
optional '+', then one or more ASCII digits, at most 2^128 - 1 (core, src/num/mod.rs). The pairing binds H only from
arguments the contract reads, and refuses the others as near/args-malformed; a memo keeps the pairing's own codes,
near/memo-missing and near/memo-not-lcp. The cases are those @integraledger/lcp's tests hold its own reading to;
expected values are x402-exact-near.json's."""

import base64
import json
from typing import Any

from integraledger_terms import X402_EXACT_NEAR, Refusal
from integraledger_terms.bindings.x402_exact_near import ft_transfer_args, near_carrier

from support import load

N = load("x402-exact-near.json")
F: dict[str, Any] = N["fixed"]
O: dict[str, Any] = F["O"]
H: str = F["H"]
assert N["V2"]["expectBound"] == H

# V2's signed delegate action with its arguments, u32-length bytes after the method name, replaced.
V2_SDA = base64.b64decode(N["V2"]["expectSignedDelegateAction"])
SENDER_END = 4 + int.from_bytes(V2_SDA[:4], "little")
RECEIVER_END = SENDER_END + 4 + int.from_bytes(V2_SDA[SENDER_END : SENDER_END + 4], "little")
METHOD_AT = RECEIVER_END + 4 + 1
ARGS_AT = METHOD_AT + 4 + int.from_bytes(V2_SDA[METHOD_AT : METHOD_AT + 4], "little")
ARGS_END = ARGS_AT + 4 + int.from_bytes(V2_SDA[ARGS_AT : ARGS_AT + 4], "little")

# V1's arguments, member by member: R, A and M.
R = '"receiver_id":"merchant.testnet"'
A = '"amount":"1000000"'
MEMO: str = json.loads(N["V1"]["expectArgsUtf8"])["memo"]
M = f'"memo":{json.dumps(MEMO)}'
MAX = str((1 << 128) - 1)
OVER = str(1 << 128)


def args(*members: str) -> str:
    return "{" + ",".join(members) + "}"


def with_amount(amount: str) -> str:
    return args(R, f'"amount":{amount}', M)


def answer(text: str) -> str:
    """bound's answer, "H" or the refusal's code, once near_carrier gives the same; else both."""
    data = text.encode("utf-8", "surrogatepass")
    sda = base64.b64encode(V2_SDA[:ARGS_AT] + len(data).to_bytes(4, "little") + data + V2_SDA[ARGS_END:]).decode()
    presented = {"x402Version": 2, "resource": F["resource"], "accepted": O, "payload": {"signedDelegateAction": sda}}
    each = [X402_EXACT_NEAR.bound(presented), near_carrier(sda)]
    named = ["H" if a == H else a.code if isinstance(a, Refusal) else repr(a) for a in each]
    return named[0] if named[0] == named[1] else f"differ: {named}"


def check(rows: list[tuple[str, str, str]], count: int) -> None:
    assert len(rows) == count
    assert [(label, answer(text)) for label, text, _ in rows] == [(label, want) for label, _, want in rows]


def test_v1_arguments_bind_h() -> None:
    assert N["V1"]["expectArgsUtf8"] == args(R, A, M)
    assert answer(args(R, A, M)) == "H"


def test_a_key_the_contract_reads_named_more_than_once_is_args_malformed() -> None:
    # serde_derive src/de/struct_.rs: a field the struct names, met a second time, is duplicate_field; a JSON reader that
    # keeps the last of two equal keys cannot see it in the object it gives.
    check(
        [
            ("receiver_id twice, Not An Id first", args('"receiver_id":"Not An Id"', R, A, M), "near/args-malformed"),
            ("receiver_id twice, Not An Id last", args(R, '"receiver_id":"Not An Id"', A, M), "near/args-malformed"),
            ("receiver_id twice, each merchant.testnet", args(R, A, M, R), "near/args-malformed"),
            ("receiver_id twice, two account ids", args(R, A, M, '"receiver_id":"other.testnet"'), "near/args-malformed"),
            ("receiver_id three times", args(R, R, A, M, R), "near/args-malformed"),
            ("amount twice, each 1000000", args(R, A, A, M), "near/args-malformed"),
            ("amount twice, a number first", args(R, '"amount":1', A, M), "near/args-malformed"),
            ("memo twice, the LCP string last", args(R, A, '"memo":"a free-form memo"', M), "near/args-malformed"),
            ("memo twice, the LCP string first", args(R, A, M, '"memo":"a free-form memo"'), "near/args-malformed"),
            ("memo twice, each the LCP string", args(R, A, M, M), "near/args-malformed"),
            ("memo twice, null first", args(R, A, '"memo":null', M), "near/args-malformed"),
            ("receiver\\u005fid after receiver_id", args(R, A, M, '"receiver\\u005fid":"merchant.testnet"'), "near/args-malformed"),
            ("receiver\\u005Fid before receiver_id", args('"receiver\\u005Fid":"merchant.testnet"', R, A, M), "near/args-malformed"),
            ("\\u0061mount after amount", args(R, A, M, '"\\u0061mount":"1000000"'), "near/args-malformed"),
            ("m\\u0065mo after memo", args(R, A, M, f'"m\\u0065mo":{json.dumps(MEMO)}'), "near/args-malformed"),
            ("memo written all in escapes, after memo", args(R, A, M, '"\\u006d\\u0065\\u006d\\u006f":"x"'), "near/args-malformed"),
        ],
        16,
    )  # fmt: skip


def test_any_other_key_is_skipped_however_often_it_repeats() -> None:
    # serde_derive src/de/struct_.rs skips every other key as IgnoredAny, each time it appears; near-sdk refuses unknown
    # keys only for a method marked deny_unknown_arguments (attr_sig_info.rs). A skipped value's strings and keys are
    # skipped by ignore_str, which takes a lone surrogate escape (serde_json src/read.rs, src/de.rs).
    check(
        [
            ("note twice", args(R, A, M, '"note":"a"', '"note":"b"'), "H"),
            ("Receiver_id, another key", args(R, A, M, '"Receiver_id":"Not An Id"'), "H"),
            ("receiver_id and a space, another key", args(R, A, M, '"receiver_id ":"Not An Id"'), "H"),
            ("memo and NUL, another key", args(R, A, M, '"memo\\u0000":"x"'), "H"),
            ("receiver_id twice inside another key's object", args(R, A, M, '"extra":{"receiver_id":"x","receiver_id":"y"}'), "H"),
            ("memo twice inside another key's array", args(R, A, M, '"extra":[{"memo":1,"memo":2},{"memo":3}]'), "H"),
            ("a lone surrogate key inside another key's object", args(R, A, M, '"extra":{"\\ud800":1}'), "H"),
            ("a lone surrogate in another key's value", args(R, A, M, '"note":"\\ud800"'), "H"),
            ("a surrogate pair key", args(R, A, M, '"\\ud83d\\ude00":1'), "H"),
            ("a key holding an escaped quote and receiver_id", args(R, A, M, '"a\\",\\"receiver_id":1'), "H"),
            ("a value holding receiver_id's text", args(R, A, M, '"note":"\\",\\"receiver_id\\":\\"Not An Id"'), "H"),
            ("a value holding braces and a comma", args(R, A, M, '"note":"}{,[\\"memo\\":"'), "H"),
            ("whitespace around each token", f"\t{{ {R.replace(':', ' : ')} ,\n{A} ,\r{M} }}\n", "H"),
        ],
        13,
    )  # fmt: skip


def test_a_key_that_decodes_to_a_lone_surrogate_is_args_malformed() -> None:
    # serde_json src/de.rs (MapKey) reads each key of the object with parse_str, which validates escapes; a lone
    # surrogate is refused (src/read.rs, parse_unicode_escape), whatever key it is.
    check(
        [
            ("\\ud800", args(R, A, M, '"\\ud800":1'), "near/args-malformed"),
            ("\\udc00", args(R, A, M, '"\\udc00":1'), "near/args-malformed"),
            ("\\ud800 inside a key", args(R, A, M, '"a\\ud800b":1'), "near/args-malformed"),
            ("two leading surrogates", args(R, A, M, '"\\ud800\\ud800":1'), "near/args-malformed"),
            ("a pair written trailing first", args(R, A, M, '"\\ude00\\ud83d":1'), "near/args-malformed"),
            ("a leading surrogate first in the object", args('"\\udbff":null', R, A, M), "near/args-malformed"),
        ],
        6,
    )


def test_amount_is_read_as_u128_from_str_reads_it() -> None:
    # near-sdk src/json_types/integers.rs: U128 reads a String, then str::parse::<u128>; Rust's from_str_radix (core
    # src/num/mod.rs) takes an optional '+' and then ASCII digits only, leading zeros included, and refuses an empty
    # string, a sign alone, '-' on an unsigned type, any other character and a value past u128::MAX.
    check(
        [
            ("1000000", with_amount('"1000000"'), "H"),
            ("+1000000", with_amount('"+1000000"'), "H"),
            ("0001000000", with_amount('"0001000000"'), "H"),
            ("0", with_amount('"0"'), "H"),
            ("+0", with_amount('"+0"'), "H"),
            ("00", with_amount('"00"'), "H"),
            ("2^128 - 1", with_amount(f'"{MAX}"'), "H"),
            ("+ and 2^128 - 1", with_amount(f'"+{MAX}"'), "H"),
            ("200 zeros and 1", with_amount(f'"{"0" * 200}1"'), "H"),
            ("200 zeros and 2^128 - 1", with_amount(f'"{"0" * 200}{MAX}"'), "H"),
            ("digits written as escapes", with_amount('"\\u0031\\u0030"'), "H"),
            ("no amount", args(R, M), "near/args-malformed"),
            ("no amount and no memo", args(R), "near/args-malformed"),
            ("null", with_amount("null"), "near/args-malformed"),
            ("the number 1000000", with_amount("1000000"), "near/args-malformed"),
            ("the number 1e6", with_amount("1e6"), "near/args-malformed"),
            ("true", with_amount("true"), "near/args-malformed"),
            ("an array", with_amount('["1000000"]'), "near/args-malformed"),
            ("an object", with_amount('{"amount":"1000000"}'), "near/args-malformed"),
            ("empty", with_amount('""'), "near/args-malformed"),
            ("+ alone", with_amount('"+"'), "near/args-malformed"),
            ("- alone", with_amount('"-"'), "near/args-malformed"),
            ("-1", with_amount('"-1"'), "near/args-malformed"),
            ("-0", with_amount('"-0"'), "near/args-malformed"),
            ("++1", with_amount('"++1"'), "near/args-malformed"),
            ("+-1", with_amount('"+-1"'), "near/args-malformed"),
            ("a space first", with_amount('" 1"'), "near/args-malformed"),
            ("a space last", with_amount('"1 "'), "near/args-malformed"),
            ("1.0", with_amount('"1.0"'), "near/args-malformed"),
            ("1e6", with_amount('"1e6"'), "near/args-malformed"),
            ("0x10", with_amount('"0x10"'), "near/args-malformed"),
            ("1_000", with_amount('"1_000"'), "near/args-malformed"),
            ("Arabic-Indic digits", with_amount('"١٠"'), "near/args-malformed"),
            ("fullwidth 1", with_amount('"１"'), "near/args-malformed"),
            ("a lone surrogate", with_amount('"\\ud800"'), "near/args-malformed"),
            ("2^128", with_amount(f'"{OVER}"'), "near/args-malformed"),
            ("+ and 2^128", with_amount(f'"+{OVER}"'), "near/args-malformed"),
            ("200 zeros and 2^128", with_amount(f'"{"0" * 200}{OVER}"'), "near/args-malformed"),
            ("a bad amount before a bad receiver_id", args('"amount":"x"', '"receiver_id":"Not An Id"', M), "near/args-malformed"),
            ("a bad amount and no memo", args(R, '"amount":"x"'), "near/args-malformed"),
        ],
        40,
    )  # fmt: skip


def test_memo_keeps_the_pairing_codes_after_the_contract_rules() -> None:
    # serde src/private/de.rs and serde_json src/de.rs: an absent Option field and null are None; anything else is read
    # as a String. The pairing refuses a memo that carries no hash with its own codes.
    def memo(m: str) -> str:
        return args(R, A, f'"memo":{m}')

    check(
        [
            ("no memo", args(R, A), "near/memo-missing"),
            ("null", memo("null"), "near/memo-missing"),
            ("a number", memo("7"), "near/memo-missing"),
            ("true", memo("true"), "near/memo-missing"),
            ("an object", memo("{}"), "near/memo-missing"),
            ("an array", memo('["x"]'), "near/memo-missing"),
            ("empty", memo('""'), "near/memo-not-lcp"),
            ("free-form", memo('"a free-form memo"'), "near/memo-not-lcp"),
            ("a lone surrogate", memo('"\\ud800"'), "near/memo-not-lcp"),
        ],
        9,
    )


def test_ft_transfer_args_writes_the_canonical_decimal_of_a_positive_integer_below_2_128() -> None:
    # Each amount written is one u128::from_str reads. Any other is near/option-malformed, before the hash.
    written = ["1000000", "1", MAX]
    for amount in written:
        data = ft_transfer_args(O["payTo"], amount, H)
        assert isinstance(data, bytes), amount
        assert json.loads(data) == {"receiver_id": O["payTo"], "amount": amount, "memo": MEMO}, amount
    refused: list[Any] = [
        "0", "0001000000", f"0{MAX}", "+1000000", "", "-1", "1.0", " 1", "1e6", "0x10", "1_000", "١٠",
        "１", OVER, "0" * 79, 1000000, None,
    ]  # fmt: skip
    assert len(refused) == 17
    assert [(a, ft_transfer_args(O["payTo"], a, H)) for a in refused] == [
        (a, Refusal("near/option-malformed")) for a in refused
    ]
    # The amount is read before the hash, as build's filter reads the option before the hash.
    assert ft_transfer_args(O["payTo"], "+1", "0x12") == Refusal("near/option-malformed")
    assert ft_transfer_args(O["payTo"], O["amount"], "0x12") == Refusal("x402/payload-malformed")
