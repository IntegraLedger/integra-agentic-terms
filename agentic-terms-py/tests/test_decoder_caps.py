"""The decoder caps: decoder-caps.json. The XRPL binary codec, msgpack and ScVal each nest at most as deep as the rows
say, and each row says whether the caps admit its input."""

import base64
from typing import Any

from support import Msgpack, load, msgpack_longer_forms, msgpack_strings, msgpack_value

from integraledger_terms import Refusal
from integraledger_terms.bindings import _algorand, _stellar, _stellar_xdr, _xrpl, _xrpl_codec

V: dict[str, Any] = load("decoder-caps.json")


def test_xrpl_caps() -> None:
    assert _xrpl_codec.MAX_DEPTH == V["xrpl"]["maxDepth"]
    for row in V["xrpl"]["rows"]:
        decoded = _xrpl.decode_blob(row["blob"])
        if row["accept"]:
            assert isinstance(decoded, _xrpl.Blob), row["name"]
        else:
            assert decoded == Refusal("xrpl/blob-malformed"), row["name"]


def test_msgpack_caps() -> None:
    assert _algorand.MAX_DEPTH == V["msgpack"]["maxDepth"]
    for row in V["msgpack"]["rows"]:
        try:
            _algorand.unpack(bytes.fromhex(row["hex"]))
            accepted = True
        except _algorand.Malformed:
            accepted = False
        assert accepted is row["accept"], row["name"]


def msgpack_row(row: dict[str, Any]) -> Msgpack | None:
    return msgpack_value(bytes.fromhex(row["hex"]))


def test_msgpack_string_rows() -> None:
    """The msgpack rows that are one value holding a str with a byte outside ASCII, read with support.msgpack_value. The
    caps judge no string's bytes: the Algorand reader judges each string by the member it fills. So each row is
    admitted, as its accept says, whether or not its strings are UTF-8."""
    rows = [
        row
        for row in V["msgpack"]["rows"]
        if (value := msgpack_row(row)) is not None and any(max(s, default=0) >= 0x80 for s, _ in msgpack_strings(value))
    ]
    assert rows, "decoder-caps.json holds no msgpack row with a string outside ASCII"
    for row in rows:
        assert row["accept"] is True, row["name"]
        _algorand.unpack(bytes.fromhex(row["hex"]))


def test_msgpack_rows_in_longer_forms() -> None:
    """The msgpack rows that are one value written otherwise than in its shortest form with distinct str keys (a map key
    written twice, a key that is not a str, a length, count or integer in a longer format than it needs), read with
    support.msgpack_value. The caps judge no key or format: the Algorand reader reads each as algod and the facilitator
    read it. So each row is admitted, as its accept says."""
    rows = [
        row for row in V["msgpack"]["rows"] if (value := msgpack_row(row)) is not None and msgpack_longer_forms(value)
    ]
    assert rows, "decoder-caps.json holds no msgpack row written in a longer form"
    for row in rows:
        assert row["accept"] is True, row["name"]
        _algorand.unpack(bytes.fromhex(row["hex"]))


def test_scval_caps() -> None:
    """The ScVal rows are one ScVal each, admitted when its vectors and maps nest at most maxDepth levels. The envelope
    rows are read by decode_stellar_tx, which bounds what it reads, the operation and the payer's entry: a row the caps
    admit decodes to the payment, or to the refusal its expect names, and one they refuse is stellar/tx-malformed."""
    assert _stellar_xdr.MAX_DEPTH == V["scval"]["maxDepth"]
    for row in V["scval"]["rows"]:
        r = _stellar_xdr.Reader(base64.b64decode(row["xdr"]))
        try:
            val = _stellar_xdr.sc_val(r)
            accepted = r.remaining == 0 and val.nesting <= _stellar_xdr.MAX_DEPTH
        except _stellar_xdr.Malformed:
            accepted = False
        assert accepted is row["accept"], row["name"]
    for row in V["scval"]["envelopes"]:
        decoded = _stellar.decode_stellar_tx(row["xdr"], "stellar:testnet")
        if not row["accept"]:
            assert decoded == Refusal("stellar/tx-malformed"), row["name"]
        elif "expect" in row:
            assert decoded == Refusal(row["expect"]), row["name"]
        else:
            assert isinstance(decoded, _stellar.Payment), row["name"]


def entry_kinds(envelope: str) -> list[int] | None:
    """The credential kinds of the envelope's authorization entries, or None when its operations are not one
    InvokeHostFunction."""
    try:
        return [e.kind for e in _stellar_xdr.envelope(base64.b64decode(envelope)).invoke.entries]
    except _stellar_xdr.NotOneTransfer:
        return None


def test_scval_envelopes_with_delegates_decode() -> None:
    """The envelope rows holding an authorization entry with delegates (credential kind 3), which decode_stellar_tx
    does not read: no cap bounds delegates (the file's about), so each decodes to the payment."""
    rows = [row for row in V["scval"]["envelopes"] if 3 in (entry_kinds(row["xdr"]) or [])]
    assert rows, "decoder-caps.json holds no envelope row with delegates"
    for row in rows:
        assert row["accept"] is True and "expect" not in row, row["name"]
        assert isinstance(_stellar.decode_stellar_tx(row["xdr"], "stellar:testnet"), _stellar.Payment), row["name"]


def test_scval_envelopes_of_another_operation_are_read_whole() -> None:
    """The envelope rows whose operations are not one InvokeHostFunction: no cap bounds a claim predicate (the file's
    about), so each is read whole and is the refusal its expect names, stellar/not-one-transfer."""
    rows = [row for row in V["scval"]["envelopes"] if entry_kinds(row["xdr"]) is None]
    assert rows, "decoder-caps.json holds no envelope row of another operation"
    for row in rows:
        assert row["accept"] is True and row["expect"] == "stellar/not-one-transfer", row["name"]
        assert _stellar.decode_stellar_tx(row["xdr"], "stellar:testnet") == Refusal(row["expect"]), row["name"]
