"""NEAR account ids as nearcore reads them, at every place the x402/exact/near binding reads one. The oracle is
near-account-id 3.0.0's validate (src/validation.rs), the crate version nearcore locks, written out below; its borsh
reader (src/borsh.rs) and its serde reader (src/serde.rs) each call it, so nearcore refuses a delegate action whose
sender or receiver it refuses, and a NEP-141 contract refuses ft_transfer arguments whose receiver_id it refuses
(near-contract-standards: fn ft_transfer(&mut self, receiver_id: AccountId, ...)). Each place is held to the oracle
over one generated sweep, the one the shared vectors' implementation is tested with, whose size and answers per group
are its: boundary lengths, each separator first, last and doubled, uppercase, non-ASCII, every printable ASCII
character, ASCII controls, the typed forms the crate names, and drawn strings. Other expected values are
x402-exact-near.json's."""

import base64
import hashlib
import json
from collections import Counter
from collections.abc import Callable
from typing import Any

from integraledger_terms import X402_EXACT_NEAR, Refusal
from integraledger_terms.bindings._borsh_near import decode_signed_delegate, is_near_account_id
from integraledger_terms.bindings.x402_exact_near import ft_transfer_args, near_carrier

from breadth import x402_doc
from support import load

N = load("x402-exact-near.json")
F: dict[str, Any] = N["fixed"]
O: dict[str, Any] = F["O"]
H: str = F["H"]
BOUND = N["V2"]["expectBound"]
V2_SDA = base64.b64decode(N["V2"]["expectSignedDelegateAction"])


def validate(account_id: str) -> str | None:
    """near-account-id 3.0.0's validate (src/validation.rs, lines 43-94), written out. account_id.len() is the
    string's length in UTF-8 bytes, a lone surrogate counted as the three bytes a JavaScript string's UTF-8 gives it;
    MIN_LEN is 2 and MAX_LEN 64 (lines 3-6). chars() gives each code point; a lowercase ASCII letter or a digit is no
    separator, '-', '_' and '.' are separators, and any other character is InvalidChar. The last character is taken to
    be a separator before the first, so a separator first, a separator after a separator, and a separator last are
    each RedundantSeparator. None where it answers Ok."""
    length = len(account_id.encode("utf-8", "surrogatepass"))
    if length < 2:
        return "TooShort"
    if length > 64:
        return "TooLong"
    last_char_is_separator = True
    for c in account_id:
        if "a" <= c <= "z" or "0" <= c <= "9":
            current_char_is_separator = False
        elif c in ("-", "_", "."):
            current_char_is_separator = True
        else:
            return "InvalidChar"
        if current_char_is_separator and last_char_is_separator:
            return "RedundantSeparator"
        last_char_is_separator = current_char_is_separator
    if last_char_is_separator:
        return "RedundantSeparator"
    return None


# near-account-id 3.0.0's own test data (src/test_data.rs, lines 1-55): ids it reads, and ids it refuses.
OK_ACCOUNT_IDS = [
    "aa", "a-a", "a-aa", "100", "0o", "com", "near", "bowen", "b-o_w_e-n", "b.owen", "bro.wen", "a.ha", "a.b-a.ra",
    "system", "over.9000", "google.com", "illia.cheapaccounts.near", "0o0ooo00oo00o", "alex-skidanov", "10-4.8-2",
    "b-o_w_e-n", "no_lols", "0123456789012345678901234567890123456789012345678901234567890123", "near.a",
]  # fmt: skip
BAD_ACCOUNT_IDS = [
    "a", "A", "Abc", "-near", "near-", "-near-", "near.", ".near", "near@", "@near", "неар", "@@@@@",
    "0__0", "0_-_0", "0_-_0", "..", "a..near", "nEar", "_bowen", "hello world",
    "abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz.abcdefghijklmnopqrstuvwxyz",
    "01234567890123456789012345678901234567890123456789012345678901234", "some-complex-address@gmail.com",
    "sub.buy_d1gitz@atata@b0-rg.c_0_m",
]  # fmt: skip
ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789"
SEPARATORS = ["-", "_", "."]
BASE = "alice.near"
NON_ASCII = [
    "é", "ƒ", "K", "ſ", "İ", "ı", "ａ", "０", "а", " ",
    "﻿", "​", "․", "﹒", "．", "‐", "­", "\U0001f600", "\ud800", "\udc00",
]  # fmt: skip


def placed(c: str) -> list[str]:
    """c first, in the middle and last of BASE."""
    return [f"{c}{BASE}", f"{BASE[:3]}{c}{BASE[3:]}", f"{BASE}{c}"]


def hex_digits(n: int) -> str:
    return "".join("0123456789abcdef"[(i * 7 + 3) % 16] for i in range(n))


def units(s: str) -> bytes:
    """s as UTF-16 code units, the unit JavaScript slices a string by."""
    return s.encode("utf-16-le", "surrogatepass")


def from_units(u: bytes) -> str:
    return u.decode("utf-16-le", "surrogatepass")


def drawn() -> list[str]:
    """Half an id of one to five parts of 1 to 12 letters and digits joined by separators, then edited once (a
    character inserted, replaced or removed, at a UTF-16 index) half the time; half drawn character by character. The
    bytes are SHA-256 of near-account-ids:<counter>, one digest after another, read four at a time big-endian."""
    stream = bytearray()
    counter = 0

    def below(n: int) -> int:
        nonlocal stream, counter
        while len(stream) < 4:
            stream += hashlib.sha256(f"near-account-ids:{counter}".encode()).digest()
            counter += 1
        b, stream = stream[:4], stream[4:]
        return int.from_bytes(b, "big") % n

    def any_char() -> str:
        k = below(20)
        if k < 13:
            return ALNUM[below(len(ALNUM))]
        if k < 16:
            return SEPARATORS[below(3)]
        if k < 17:
            return chr(0x41 + below(26))
        if k < 19:
            return chr(0x20 + below(95))
        return NON_ASCII[below(len(NON_ASCII))]

    out: list[str] = []
    for i in range(4096):
        if i % 2 == 0:
            parts = []
            for _ in range(1 + below(5)):
                parts.append("".join(ALNUM[below(len(ALNUM))] for _ in range(1 + below(12))))
            text = "".join(p if j == 0 else SEPARATORS[below(3)] + p for j, p in enumerate(parts))
            if below(2) == 0:
                u = units(text)
                at = 2 * below(len(u) // 2 + 1)
                edit = below(3)
                if edit == 0:
                    u = u[:at] + units(any_char()) + u[at:]
                elif edit == 1:
                    u = u[:at] + units(any_char()) + u[at + 2 :]
                else:
                    u = u[:at] + u[at + 2 :]
                text = from_units(u)
            out.append(text)
        else:
            out.append("".join(any_char() for _ in range(below(71))))
    return out


def sweep() -> dict[str, list[str]]:
    lengths: list[str] = []
    for n in (0, 1, 2, 3, 63, 64, 65, 66):
        lengths += ["a" * n, "9" * n]
        # a, then each separator in turn and a: valid at an odd length, a separator last at an even one.
        lengths.append("".join("a" if i % 2 == 0 else SEPARATORS[(i >> 1) % 3] for i in range(n)))
    separators: list[str] = []
    for s in SEPARATORS:
        separators += [s, s + s, f"{s}a", f"a{s}", f"{s}a{s}", f"ali{s}ce", *placed(s)]
        for t in SEPARATORS:
            separators += [f"ali{s}{t}ce", f"ali{s}ce{t}x"]
    uppercase = [BASE.upper(), "Alice.near", "alice.NEAR"]
    for code in range(0x41, 0x5B):
        uppercase += placed(chr(code))
    non_ascii: list[str] = []
    for c in NON_ASCII:
        non_ascii += [*placed(c), f"a{c}", c]
    printable: list[str] = []
    for code in range(0x20, 0x7F):
        printable += placed(chr(code))
    controls = [placed(chr(code))[1] for code in range(0x20)] + [placed("\x7f")[1]]
    # The typed forms near-account-id names (get_account_type): NEAR-implicit, ETH-implicit, deterministic, universal.
    typed = [
        hex_digits(64), hex_digits(64).upper(), hex_digits(63), hex_digits(65), f"{hex_digits(63)}g",
        f"0x{hex_digits(40)}", f"0x{hex_digits(40).upper()}", f"0X{hex_digits(40)}", f"0x{hex_digits(39)}",
        f"0x{hex_digits(41)}", f"0s{hex_digits(40)}", f"0u{('0123456789abcdefghjkmnpqrstvwxyz' * 2)[:52]}",
        f"0u{'z' * 52}",
    ]  # fmt: skip
    return {
        "crate": OK_ACCOUNT_IDS + BAD_ACCOUNT_IDS,
        "lengths": lengths,
        "separators": separators,
        "uppercase": uppercase,
        "nonAscii": non_ascii,
        "printable": printable,
        "controls": controls,
        "typed": typed,
        "drawn": drawn(),
    }


GROUPS = sweep()
ALL = [s for group in GROUPS.values() for s in group]
# What the oracle answers over each group: its size and how many of each answer, as the shared vectors'
# implementation counts them over the same sweep.
COUNTS = {
    "crate": {"total": 48, "ok": 24, "TooShort": 2, "TooLong": 2, "InvalidChar": 9, "RedundantSeparator": 11},
    "lengths": {"total": 24, "ok": 10, "TooShort": 6, "TooLong": 6, "InvalidChar": 0, "RedundantSeparator": 2},
    "separators": {"total": 45, "ok": 15, "TooShort": 3, "TooLong": 0, "InvalidChar": 0, "RedundantSeparator": 27},
    "uppercase": {"total": 81, "ok": 0, "TooShort": 0, "TooLong": 0, "InvalidChar": 81, "RedundantSeparator": 0},
    "nonAscii": {"total": 100, "ok": 0, "TooShort": 0, "TooLong": 0, "InvalidChar": 100, "RedundantSeparator": 0},
    "printable": {"total": 285, "ok": 111, "TooShort": 0, "TooLong": 0, "InvalidChar": 168, "RedundantSeparator": 6},
    "controls": {"total": 33, "ok": 0, "TooShort": 0, "TooLong": 0, "InvalidChar": 33, "RedundantSeparator": 0},
    "typed": {"total": 13, "ok": 9, "TooShort": 0, "TooLong": 1, "InvalidChar": 3, "RedundantSeparator": 0},
    "drawn": {
        "total": 4096, "ok": 1962, "TooShort": 88, "TooLong": 324, "InvalidChar": 1265, "RedundantSeparator": 457,
    },
}  # fmt: skip
OK = sum(c["ok"] for c in COUNTS.values())
REFUSED = sum(c["total"] - c["ok"] for c in COUNTS.values())


def differences(answer: Callable[[str], str]) -> tuple[int, int, list[str]]:
    """Runs each string of the sweep through answer, which gives "ok", "refused" or what it read instead; returns how
    many were read and refused, and the first strings where it differs from the oracle."""
    assert len(ALL) == OK + REFUSED
    ok = refused = 0
    differ: list[str] = []
    for s in ALL:
        want = "ok" if validate(s) is None else "refused"
        got = answer(s)
        ok += got == "ok"
        refused += got == "refused"
        if got != want and len(differ) < 10:
            differ.append(f"{s!r}: {got}, oracle {want}")
    return ok, refused, differ


def borsh_string(s: str) -> bytes:
    """A borsh String of s's UTF-8; a lone surrogate is written as the three bytes that are no UTF-8."""
    b = s.encode("utf-8", "surrogatepass")
    return len(b).to_bytes(4, "little") + b


# V2's signed delegate action: the sender and the receiver as u32-length strings, the count of actions, the action's
# variant index, the method name and the arguments as u32-length bytes, then the rest.
SENDER_END = 4 + int.from_bytes(V2_SDA[:4], "little")
RECEIVER_END = SENDER_END + 4 + int.from_bytes(V2_SDA[SENDER_END : SENDER_END + 4], "little")
METHOD_AT = RECEIVER_END + 4 + 1
ARGS_AT = METHOD_AT + 4 + int.from_bytes(V2_SDA[METHOD_AT : METHOD_AT + 4], "little")
ARGS_END = ARGS_AT + 4 + int.from_bytes(V2_SDA[ARGS_AT : ARGS_AT + 4], "little")
V1_ARGS: dict[str, Any] = json.loads(N["V1"]["expectArgsUtf8"])


def sda_with_head(head: bytes, count: int) -> str:
    return base64.b64encode(head + count.to_bytes(4, "little") + V2_SDA[RECEIVER_END + 4 :]).decode()


def sda_with_sender(s: str, count: int = 1) -> str:
    return sda_with_head(borsh_string(s) + V2_SDA[SENDER_END:RECEIVER_END], count)


def sda_with_receiver(s: str, count: int = 1) -> str:
    return sda_with_head(V2_SDA[:SENDER_END] + borsh_string(s), count)


def sda_with_args(args: dict[str, Any]) -> str:
    text = json.dumps(args).encode()
    return base64.b64encode(V2_SDA[:ARGS_AT] + len(text).to_bytes(4, "little") + text + V2_SDA[ARGS_END:]).decode()


def presented(sda: str, accepted: dict[str, Any] = O) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": accepted, "payload": {"signedDelegateAction": sda}}


def choice(**changes: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "required": {"x402Version": 2, "resource": F["resource"], "accepts": [O]},
        "accepted": O,
        "payer": F["payer"],
        "publicKey": F["publicKey"],
        "accessKeyNonce": int(F["accessKeyNonce"]),
        "finalHeight": int(F["finalHeight"]),
    }
    value.update(changes)
    return value


def test_the_sweep_is_the_shared_one_and_the_oracle_reads_the_crate_data() -> None:
    counted: dict[str, dict[str, int]] = {}
    for name, group in GROUPS.items():
        answers = Counter(validate(s) or "ok" for s in group)
        counted[name] = {"total": len(group), **{k: answers[k] for k in COUNTS[name] if k != "total"}}
    assert counted == COUNTS
    # The oracle reads each of the crate's own ids and refuses each of its bad ones, as its tests require.
    assert len(OK_ACCOUNT_IDS) == 24 and len(BAD_ACCOUNT_IDS) == 24
    assert [validate(s) for s in OK_ACCOUNT_IDS] == [None] * 24
    assert [s for s in BAD_ACCOUNT_IDS if validate(s) is None] == []


def test_is_near_account_id_answers_as_validate() -> None:
    assert differences(lambda s: "ok" if is_near_account_id(s) else "refused") == (OK, REFUSED, [])
    for value in (None, 7, ["alice.near"], b"alice.near", {"alice.near": 1}):
        assert not is_near_account_id(value), value


def test_the_delegate_sender_and_receiver_are_read_as_account_ids() -> None:
    # near_carrier and bound read V2's hash under a sender or receiver that is an account id, and refuse anything else
    # as near/sda-malformed; the decoder reads the id as written.
    for where, sda in (("sender", sda_with_sender), ("receiver", sda_with_receiver)):

        def answer(s: str) -> str:
            text = sda(s)
            carried, bound = near_carrier(text), X402_EXACT_NEAR.bound(presented(text))
            if carried == bound == Refusal("near/sda-malformed"):
                return "refused"
            decoded = decode_signed_delegate(base64.b64decode(text))
            if isinstance(decoded, str) or carried != BOUND or bound != BOUND:
                return f"read as {carried!r}, bound {bound!r}"
            read = decoded[0].sender_id if where == "sender" else decoded[0].receiver_id
            return "ok" if read == s else f"read {read!r}"

        assert (where, differences(answer)) == (where, (OK, REFUSED, []))


def test_the_sender_and_receiver_are_read_before_the_count_of_actions() -> None:
    # With a count of two, a sender or receiver that is an account id gives near/actions, and any other is
    # near/sda-malformed: nearcore reads both before the actions.
    for where, sda in (("sender", sda_with_sender), ("receiver", sda_with_receiver)):

        def answer(s: str) -> str:
            got = near_carrier(sda(s, 2))
            if got == Refusal("near/actions"):
                return "ok"
            return "refused" if got == Refusal("near/sda-malformed") else repr(got)

        assert (where, differences(answer)) == (where, (OK, REFUSED, []))


def test_ft_transfer_receiver_id_is_read_as_an_account_id() -> None:
    # bound reads V2's hash from arguments whose receiver_id is an account id, and refuses anything else as
    # near/args-malformed; a receiver_id that is absent or not a string is no account id.
    def answer(s: str) -> str:
        got = X402_EXACT_NEAR.bound(presented(sda_with_args({**V1_ARGS, "receiver_id": s})))
        return "ok" if got == BOUND else "refused" if got == Refusal("near/args-malformed") else repr(got)

    assert differences(answer) == (OK, REFUSED, [])
    no_receiver = {k: v for k, v in V1_ARGS.items() if k != "receiver_id"}
    for args in (no_receiver, {**V1_ARGS, "receiver_id": 7}, {**V1_ARGS, "receiver_id": None}):
        assert near_carrier(sda_with_args(args)) == Refusal("near/args-malformed"), args
        assert X402_EXACT_NEAR.bound(presented(sda_with_args(args))) == Refusal("near/args-malformed"), args


def test_the_option_pay_to_and_asset_are_read_as_account_ids() -> None:
    # read offers an option whose payTo and asset are account ids, and build and bound serve it; any other is
    # near/option-malformed at build and bound, and read has no payable option.
    for field in ("payTo", "asset"):

        def answer(s: str) -> str:
            option = {**O, field: s}
            required = {"x402Version": 2, "resource": F["resource"], "accepts": [option]}
            read = X402_EXACT_NEAR.read(x402_doc(option, F["resource"]))
            built = X402_EXACT_NEAR.build(choice(required=required, accepted=option), H)
            bound = X402_EXACT_NEAR.bound(presented(N["V2"]["expectSignedDelegateAction"], option))
            answers = [built, bound]
            if all(a == Refusal("near/option-malformed") for a in answers):
                return "refused" if read == Refusal("x402/no-payable-option") else repr(read)
            if any(isinstance(a, Refusal) for a in answers) or isinstance(read, Refusal):
                return repr([read, *answers])
            return "ok" if read.offer["options"] == [option] and bound == BOUND else repr(read)

        assert (field, differences(answer)) == (field, (OK, REFUSED, []))


def test_ft_transfer_args_writes_a_pay_to_that_is_an_account_id() -> None:
    def answer(s: str) -> str:
        args = ft_transfer_args(s, O["amount"], H)
        if args == Refusal("near/option-malformed"):
            return "refused"
        return "ok" if isinstance(args, bytes) and json.loads(args)["receiver_id"] == s else repr(args)

    assert differences(answer) == (OK, REFUSED, [])
    # The payTo is read before the hash.
    assert ft_transfer_args("merchant..testnet", O["amount"], "0x12") == Refusal("near/option-malformed")
    assert ft_transfer_args(O["payTo"], O["amount"], "0x12") == Refusal("x402/payload-malformed")


def test_build_reads_a_payer_that_is_an_account_id() -> None:
    def answer(s: str) -> str:
        built = X402_EXACT_NEAR.build(choice(payer=s), H)
        if built == Refusal("x402/option-malformed"):
            return "refused"
        return "ok" if not isinstance(built, Refusal) else repr(built)

    assert differences(answer) == (OK, REFUSED, [])
