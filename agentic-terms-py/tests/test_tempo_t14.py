"""Tempo T14's configurable accounts sign with the 0x05 signature type: 0x05 ‖ rlp([account, config, approvals]).

tempo_t14_configurable.json holds transactions a T14 node included (and one it rejected), recorded on a real node (the
protocol package's lcp/test/fixtures/tempo-t14-configurable.json, copied unchanged); tempo_sender must name the account
the node named, and refuse the 0x05 forms that carry no account to name, as the protocol package's tempoSender does.
"""

import json
from pathlib import Path
from typing import Any

from integraledger_terms._types import Refusal
from integraledger_terms.bindings._rlp import RlpItem, rlp_bytes, rlp_decode, rlp_list
from integraledger_terms.bindings._tempo import tempo_sender

F: dict[str, Any] = json.loads((Path(__file__).parent / "tempo_t14_configurable.json").read_text())
MALFORMED = Refusal("tempo/tx-malformed")


def entry(name: str) -> dict[str, Any]:
    found: dict[str, Any] = next(e for e in F["entries"] if e["id"] == name)
    return found


def raw(hex_text: str) -> bytes:
    return bytes.fromhex(hex_text[2:])


def items_of(wire: bytes) -> list[RlpItem]:
    top = rlp_decode(wire[1:], 8)
    assert top is not None and top.items is not None
    return top.items


def with_signature(wire: bytes, signature: bytes) -> bytes:
    """The 0x76 envelope wire with its sender signature replaced by signature."""
    items = items_of(wire)
    return bytes([0x76]) + rlp_list([i.raw for i in items[:-1]] + [rlp_bytes(signature)])


def configurable(*parts: bytes) -> bytes:
    """A 0x05 signature over the RLP-encoded parts given."""
    return bytes([0x05]) + rlp_list(list(parts))


K1 = entry("k1/transaction")
SIG = items_of(raw(K1["hex"]))[-1].data
PARTS = rlp_decode(SIG[1:], 8)
assert PARTS is not None and PARTS.items is not None
ACCOUNT, CONFIG, APPROVALS = PARTS.items
assert APPROVALS.items is not None
APPROVAL = APPROVALS.items[0]


def test_the_fixtures_control_a_0x05_transaction_the_node_included() -> None:
    assert SIG[0] == 0x05
    assert "0x" + ACCOUNT.data.hex() == K1["account"]


def test_tempo_sender_names_the_account_the_node_named_for_every_transaction_it_included() -> None:
    included = [e for e in F["entries"] if e["kind"] in ("tx", "open") and e["node"] == "included"]
    assert {e["id"] for e in included} >= {
        "control/valid-single-key",
        "k1/transaction",
        "k2of2/transaction",
        "p256/transaction",
        "webauthn/transaction",
        "initial/transaction",
        "k1/session/open",
    }
    for e in included:
        assert tempo_sender(raw(e["hex"])) == e["account"].lower(), e["id"]


def test_re_encoding_names_the_same_account_and_each_form_with_no_account_to_name_is_malformed() -> None:
    wire = raw(K1["hex"])
    assert tempo_sender(with_signature(wire, configurable(ACCOUNT.raw, CONFIG.raw, APPROVALS.raw))) == K1["account"]
    cases: list[tuple[str, bytes]] = [
        ("no approvals", configurable(ACCOUNT.raw, CONFIG.raw, rlp_list([]))),
        ("nine approvals", configurable(ACCOUNT.raw, CONFIG.raw, rlp_list([APPROVAL.raw] * 9))),
        ("an approval of 64 bytes", configurable(ACCOUNT.raw, CONFIG.raw, rlp_list([rlp_bytes(APPROVAL.data[:64])]))),
        ("an approval that is a list", configurable(ACCOUNT.raw, CONFIG.raw, rlp_list([rlp_list([APPROVAL.raw])]))),
        ("a P256 approval one byte short", configurable(ACCOUNT.raw, CONFIG.raw, rlp_list([rlp_bytes(b"\x01" + b"\x11" * 128)]))),
        ("an account of 19 bytes", configurable(rlp_bytes(ACCOUNT.data[:19]), CONFIG.raw, APPROVALS.raw)),
        ("the zero account", configurable(rlp_bytes(bytes(20)), CONFIG.raw, APPROVALS.raw)),
        ("an account that is a list", configurable(rlp_list([ACCOUNT.raw]), CONFIG.raw, APPROVALS.raw)),
        ("a config that is a byte string", configurable(ACCOUNT.raw, rlp_bytes(b"\x01"), APPROVALS.raw)),
        ("two items", configurable(ACCOUNT.raw, CONFIG.raw)),
        ("four items", configurable(ACCOUNT.raw, CONFIG.raw, APPROVALS.raw, rlp_bytes(b""))),
        ("a byte string, not a list", bytes([0x05]) + ACCOUNT.raw),
        ("the type byte alone", bytes([0x05])),
    ]
    for name, signature in cases:
        assert tempo_sender(with_signature(wire, signature)) == MALFORMED, name


def test_a_0x05_signature_naming_an_account_whose_owners_did_not_sign_is_read_as_that_accounts() -> None:
    """The approvals are not verified and the account's stored commitment is not read, as a keychain signature's key is
    not checked against the keychain: the node decides. The node rejected this one; a seller that broadcasts it is
    paid nothing."""
    forged = entry("design/forged-0x05-naming-another-account")
    assert forged["node"] == "rejected"
    assert tempo_sender(raw(forged["hex"])) == forged["account"].lower()
