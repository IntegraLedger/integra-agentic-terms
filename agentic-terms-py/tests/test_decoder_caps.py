"""The decoder caps: decoder-caps.json. The XRPL binary codec, msgpack and ScVal each nest at most as deep as the rows
say, and each row says whether the caps admit its input."""

import base64
from typing import Any

from support import load

from integraledger_terms import Refusal
from integraledger_terms.bindings import _algorand, _stellar, _stellar_xdr, _xrpl, _xrpl_codec

V: dict[str, Any] = load("decoder-caps.json")


def test_xrpl_caps() -> None:
    assert _xrpl_codec.MAX_DEPTH == V["xrpl"]["maxDepth"]
    assert _xrpl.MAX_BLOB_HEX // 2 == V["xrpl"]["maxFields"]
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


def test_scval_caps() -> None:
    assert _stellar_xdr.MAX_DEPTH == V["scval"]["maxDepth"]
    assert _stellar_xdr.MAX_ELEMENTS == V["scval"]["maxElements"]
    for row in V["scval"]["rows"]:
        r = _stellar_xdr.Reader(base64.b64decode(row["xdr"]))
        try:
            _stellar_xdr.sc_val(r)
            accepted = r.remaining == 0
        except _stellar_xdr.Malformed:
            accepted = False
        assert accepted is row["accept"], row["name"]
    for row in V["scval"]["envelopes"]:
        decoded = _stellar.decode_stellar_tx(row["xdr"], "stellar:testnet")
        if row["accept"]:
            assert isinstance(decoded, _stellar.Payment), row["name"]
        else:
            assert decoded == Refusal("stellar/tx-malformed"), row["name"]
