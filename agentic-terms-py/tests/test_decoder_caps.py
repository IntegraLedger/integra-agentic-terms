"""The decoder caps: decoder-caps.json. The XRPL binary codec, msgpack and ScVal each nest at most as deep as the rows
say, and each row says whether the caps admit its input."""

import base64
import hashlib
import sys
from types import FrameType
from typing import Any

from support import Msgpack, load, msgpack_longer_forms, msgpack_strings, msgpack_value

from integraledger_terms import Refusal
from integraledger_terms.bindings import _algorand, _stellar, _stellar_xdr, _xrpl, _xrpl_codec

V: dict[str, Any] = load("decoder-caps.json")


def xrpl_nesting(blob: str) -> tuple[int, str, list[str]]:
    """A blob's deepest field level, that field's kind (field, object or array; the first at that level), and its
    stray end markers, read over its field headers as the file's about counts them: a top-level field sits at level 1,
    and every other field one level below the objects and arrays open around it. An object or array field opens a
    level; an end marker closes the innermost one when it is that one's own (ObjectEndMarker an object's,
    ArrayEndMarker an array's) and sits at no level; any other end marker is stray: it counts as a field and opens a
    level as its type's fields do. Every other value is read as a leaf."""
    kinds = {_xrpl_codec.OBJECT: "object", _xrpl_codec.ARRAY: "array"}
    r = _xrpl_codec._Reader(bytes.fromhex(blob))
    opened: list[int] = []
    deepest, deepest_kind = 0, ""
    strays = []
    while not r.end():
        type_code, nth = r.field()
        if opened and (type_code, nth) == (opened[-1], 1):
            opened.pop()
            continue
        if type_code in kinds and nth == 1:
            strays.append(_xrpl_codec._key(type_code, nth))
        if len(opened) + 1 > deepest:
            deepest, deepest_kind = len(opened) + 1, kinds.get(type_code, "field")
        if type_code in kinds:
            opened.append(type_code)
        else:
            _xrpl_codec._value(r, type_code, nth, 0)
    assert not opened, "every object and array the blob opens is closed"
    return deepest, deepest_kind, strays


def test_xrpl_caps() -> None:
    """Every XRPL row, every member read: the walk of its field headers gives its depth and its stray end marker, if
    it has one; accept is whether that depth is within maxDepth with no stray marker; decode_blob gives that verdict;
    and a row's hash is SHA-512Half over 54584E00 and its blob (Python's hashlib), the decoded blob's hash where the
    row is accepted. The rows hold a field, an empty object and an empty array at maxDepth and one level past it, and
    each end marker stray."""
    cap = V["xrpl"]["maxDepth"]
    assert _xrpl_codec.MAX_DEPTH == cap
    seen: set[object] = set()
    for row in V["xrpl"]["rows"]:
        label = f"{row['name']}: {row['case']}"
        depth, kind, strays = xrpl_nesting(row["blob"])
        assert (depth, strays) == (row["depth"], [row["stray"]] if "stray" in row else []), label
        assert row["accept"] is (depth <= cap and not strays), label
        decoded = _xrpl.decode_blob(row["blob"])
        if "hash" in row:
            digest = hashlib.sha512(bytes.fromhex("54584E00" + row["blob"])).digest()[:32]
            assert digest.hex().upper() == row["hash"], label
        if row["accept"]:
            assert isinstance(decoded, _xrpl.Blob) and decoded.hash == row.get("hash", decoded.hash), label
        else:
            assert decoded == Refusal("xrpl/blob-malformed"), label
        seen.update(strays or [(kind, depth - cap)])
    wanted: set[object] = {(at, past) for at in ("field", "object", "array") for past in (0, 1)}
    assert wanted | {"ArrayEndMarker", "ObjectEndMarker"} <= seen, seen


def test_xrpl_an_array_at_max_depth_holds_no_member() -> None:
    """An array's member object sits one level below the array (the file's about). So a row whose deepest field is an
    empty Memos array at maxDepth is accepted, and the same blob with one empty Memo object as that array's member, an
    object at maxDepth + 1, is xrpl/blob-malformed, as rippled refuses a field past its limit (rippled 3.4.1,
    src/libxrpl/protocol/STVar.cpp L104-108)."""
    cap = V["xrpl"]["maxDepth"]
    rows = [row for row in V["xrpl"]["rows"] if xrpl_nesting(row["blob"])[:2] == (cap, "array")]
    assert rows, "decoder-caps.json holds no XRPL row whose deepest field is an array at maxDepth"
    for row in rows:
        assert isinstance(_xrpl.decode_blob(row["blob"]), _xrpl.Blob), row["name"]
        data = bytes.fromhex(row["blob"])
        assert data.count(b"\xf9\xf1") == 1, row["name"]
        member = data.replace(b"\xf9\xf1", b"\xf9\xea\xe1\xf1").hex().upper()
        assert xrpl_nesting(member)[:2] == (cap + 1, "object"), row["name"]
        assert _xrpl.decode_blob(member) == Refusal("xrpl/blob-malformed"), row["name"]


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
        assert_verdict(row, _stellar.decode_stellar_tx(row["xdr"], "stellar:testnet"))


def assert_verdict(row: dict[str, Any], decoded: object) -> None:
    """decode_stellar_tx's answer is the envelope row's: stellar/tx-malformed where the caps refuse it, else its expect,
    else the payment."""
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


def one_level_deeper() -> list[tuple[dict[str, Any], bytes, int, bytes]]:
    """The envelope rows that are another row with one level of its nesting added: the deeper row, its bytes, where
    the level sits and the level's bytes, a run of at most 64 bytes whose removal gives the other row (the shortest such
    level, where a row is deeper than more than one)."""
    rows = [(row, base64.b64decode(row["xdr"])) for row in V["scval"]["envelopes"]]
    found = []
    for row, deeper in rows:
        levels = []
        for _, shallower in rows:
            size = len(deeper) - len(shallower)
            if 0 < size <= 64:
                at = next((i for i, (a, b) in enumerate(zip(deeper, shallower)) if a != b), len(shallower))
                if deeper[:at] + deeper[at + size :] == shallower:
                    levels.append((at, deeper[at : at + size]))
        if levels:
            at, level = min(levels, key=lambda found_level: len(found_level[1]))
            found.append((row, deeper, at, level))
    return found


def frames() -> int:
    """How many frames the caller runs under."""
    frame: FrameType | None = sys._getframe()
    count = 0
    while frame is not None:
        count += 1
        frame = frame.f_back
    return count


def test_scval_envelopes_keep_their_verdict_at_the_deepest_nesting_8192_characters_hold() -> None:
    """Each envelope row that is another with one level added, that level repeated until 8,192 characters (6,144 bytes)
    hold no more: the reader takes the bytes whole, and decode_stellar_tx gives the deeper row's verdict, the cap's
    refusal where the nesting is read and the payment or the row's expect where it is not. The reader keeps a stack of
    its own, so each read holds at a recursion limit 50 frames above the test's, far below the nesting."""
    rows = one_level_deeper()
    assert rows, "decoder-caps.json holds no envelope row one level deeper than another"
    for row, deeper, at, level in rows:
        data = deeper[:at] + level * ((6144 - len(deeper)) // len(level)) + deeper[at:]
        text = base64.b64encode(data).decode("ascii")
        assert len(text) <= 8192 < len(base64.b64encode(data + level)), row["name"]
        before = sys.getrecursionlimit()
        sys.setrecursionlimit(frames() + 50)
        try:
            try:
                _stellar_xdr.envelope(data)
            except _stellar_xdr.NotOneTransfer:
                pass
            decoded = _stellar.decode_stellar_tx(text, "stellar:testnet")
        finally:
            sys.setrecursionlimit(before)
        assert_verdict(row, decoded)
