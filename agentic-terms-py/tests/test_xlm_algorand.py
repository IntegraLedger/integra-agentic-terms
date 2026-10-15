"""x402/exact/algorand: the TypeScript gate's B2, B6, B10 and B16 rows, and the buyer half's vector rows. Expected
values are the vector file's; the payer signs with the Ed25519 seed the file names, 01×32."""

import base64
import copy
import hashlib
from typing import Any

import pytest

from integraledger_terms import X402_EXACT_ALGORAND, Refusal
from integraledger_terms.bindings import _algorand
from integraledger_terms.bindings.x402_exact_algorand import AvmUnsigned, check

import ed25519
from breadth import H, Pairing, build_and_sign, plant, x402_doc
from support import hexb, load, msgpack_strings, msgpack_value
from xlm_support import EVM_ACCOUNT, b10, b16

A = load("x402-exact-algorand.json")
F: dict[str, Any] = A["fixed"]
SEED = bytes([1]) * 32


def answer(request: Any) -> Any:
    assert request["kind"] == "algorand-txn", request["kind"]
    return "0x" + ed25519.sign(SEED, hexb(request["bytes"])).hex()


ALGORAND = Pairing(
    binding=X402_EXACT_ALGORAND,
    doc=x402_doc(F["O"], F["resource"]),
    account=f"{F['O']['network']}:{F['payer']}",
    answer=answer,
    inputs={"params": F["params"]},
)


def txid(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def built(option: dict[str, Any]) -> AvmUnsigned:
    doc = x402_doc(option, F["resource"])
    params = {**F["params"], **{k: int(F["params"][k]) for k in ("firstValid", "minFee", "feePerByte")}}
    unsigned = X402_EXACT_ALGORAND.build({"required": doc, "accepted": option, "payer": F["payer"], "params": params}, H)
    assert isinstance(unsigned, AvmUnsigned), unsigned
    return unsigned


def encode_address(public_key: bytes) -> str:
    """Base32 of the 32-byte key and the last 4 bytes of its SHA-512/256, without padding: Algorand's address form."""
    checksum = hashlib.new("sha512_256", public_key).digest()[-4:]
    return base64.b32encode(public_key + checksum).decode("ascii").rstrip("=")


def test_x402_exact_algorand_payer_key_is_the_vector_payer() -> None:
    assert encode_address(ed25519.public_key(SEED)) == F["payer"]

def test_x402_exact_algorand_b6_bytes_to_sign_and_payment_group_are_v2() -> None:
    def inspect(request: Any) -> None:
        assert request["kind"] == "algorand-txn"
        assert hexb(request["bytes"]).hex() == A["V2"]["expectBytesToSign"]
        assert answer(request) == "0x" + F["signature"]

    signed, _ = build_and_sign(ALGORAND, inspect)
    assert signed["payload"] == {
        "paymentIndex": A["V2"]["expectPaymentIndex"],
        "paymentGroup": A["V2"]["expectPaymentGroup"],
    }


def test_x402_exact_algorand_b10_http_link() -> None:
    b10(ALGORAND)


def test_x402_exact_algorand_b16_other_accounts() -> None:
    b16(ALGORAND, [EVM_ACCOUNT, f"algorand:wGHE2Pwdvd7S12BL5FaOP20EGYesN73k:{F['payer']}"])


# ── the buyer half's vector rows ──────────────────────────────────────────────────────────────────────────────────


def test_x402_exact_algorand_v1_standalone_axfer() -> None:
    unsigned = built(F["OStandalone"])
    (txn,) = unsigned._group
    assert txn.fee == 1000 and txn.group is None
    assert txid(txn.raw_id()) == A["V1"]["expectTxid"]
    assert len(txn.encoded()) == A["V1"]["expectEncodedLength"]


def test_x402_exact_algorand_v2_group_id_and_txids() -> None:
    unsigned = built(F["O"])
    pay, transfer = unsigned._group
    assert pay.fee == 2000 and transfer.fee == 0
    assert pay.group is not None and base64.b64encode(pay.group).decode() == A["V2"]["expectGroupId"]
    assert txid(transfer.raw_id()) == A["V2"]["expectPaymentTxid"]
    assert txid(pay.raw_id()) == A["V2"]["expectFeePayerTxid"]
    completed = unsigned.complete(bytes.fromhex(F["signature"]))
    assert isinstance(completed, dict)
    assert completed["payload"]["paymentGroup"] == A["V2"]["expectPaymentGroup"]


def presented(payload: dict[str, Any], option: Any = None) -> dict[str, Any]:
    return {"x402Version": 2, "resource": F["resource"], "accepted": option or F["O"], "payload": payload}


def test_x402_exact_algorand_v3_bound_and_refusals() -> None:
    payload = {"paymentIndex": A["V2"]["expectPaymentIndex"], "paymentGroup": A["V2"]["expectPaymentGroup"]}
    assert X402_EXACT_ALGORAND.bound(presented(payload)) == A["V3"]["expectBound"]
    for row in A["V3"]["refusals"]:
        payload = {"paymentIndex": row["paymentIndex"], "paymentGroup": row["paymentGroup"]}
        expect = row.get("expect", "avm/group-too-large")
        assert X402_EXACT_ALGORAND.bound(presented(payload)) == Refusal(expect), row["case"]


# ── the payment entry, read as the x402 path reads it ────────────────────────────────────────────────────────────
# The x402 reference facilitator decodes a payment entry and submits its own bytes, which algod decodes; the entry is
# read only when both accept it as one signed asset transfer and both read the same transaction. Each member is read
# as its type is read: a byte member from a str or a bin, whatever its bytes; a string member (type, gen) only when
# its bytes are UTF-8; a key only when its bytes spell a member's name. Expected values are lcp's: exactAvm.bound's
# answer and its reader's transaction id for the same bytes, V2's id being the file's expectPaymentTxid.

V2_GROUP, V2_INDEX = A["V2"]["expectPaymentGroup"], A["V2"]["expectPaymentIndex"]
V2_BYTES = base64.b64decode(V2_GROUP[V2_INDEX])
V2_TXID: str = A["V2"]["expectPaymentTxid"]
# V2's payment entry as the file writes it is {sig, txn}, whose last member is txn, a fixmap of 11 members whose last
# is xaid; TXN_HEAD is txn's key and map header, GEN the member "gen": "testnet-v1.0".
TXN_HEAD = bytes.fromhex("a374786e8b")
GEN = bytes.fromhex("a367656eac746573746e65742d76312e30")
MARK = b"\xef\xbb\xbf"
NOT_UTF8_32, NOT_UTF8_64 = bytes([0xFF]) * 32, bytes([0xFE]) * 64
PROGRAM = bytes([0x01, 0x20, 0x01, 0x01])


def msgpack_str(data: bytes) -> bytes:
    """data as one msgpack string: a fixstr up to 31 bytes, else a str 8."""
    return (bytes([0xA0 | len(data)]) if len(data) < 32 else bytes([0xD9, len(data)])) + data


def msgpack_bin(data: bytes) -> bytes:
    return bytes([0xC4, len(data)]) + data


def msgpack_numbers(data: bytes) -> bytes:
    """data as a fixarray of its bytes, each a positive fixint (data is ASCII and shorter than 16 bytes)."""
    assert len(data) < 16 and data.isascii()
    return bytes([0x90 | len(data)]) + data


def key(name: str) -> bytes:
    return msgpack_str(name.encode("ascii"))


def once(data: bytes, old: bytes, new: bytes) -> bytes:
    assert data.count(old) == 1, old.hex()
    return data.replace(old, new)


def with_member(member: bytes) -> bytes:
    """V2's payment entry with one member, its key and value, added to the entry's map."""
    return bytes([V2_BYTES[0] + 1]) + V2_BYTES[1:] + member


def with_txn_member(member: bytes) -> bytes:
    """V2's payment entry with one member, its key and value, added last to the transaction's map."""
    return once(V2_BYTES, TXN_HEAD, b"\xa3txn\x8c") + member


def with_first_txn_member(member: bytes) -> bytes:
    """V2's payment entry with one member, its key and value, added first to the transaction's map."""
    return once(V2_BYTES, TXN_HEAD, b"\xa3txn\x8c" + member)


def bin_member(name: str) -> tuple[bytes, bytes]:
    """V2's payment entry member name, a bin 8: its key and value as the entry writes them, and its bytes."""
    head = key(name) + b"\xc4"
    assert V2_BYTES.count(head) == 1, name
    at = V2_BYTES.index(head) + len(head)
    return V2_BYTES[at - len(head) : at + 1 + V2_BYTES[at]], V2_BYTES[at + 1 : at + 1 + V2_BYTES[at]]


SIG = bin_member("sig")[0]
V2_TXN = V2_BYTES[V2_BYTES.index(TXN_HEAD) + 4 :]
XAID = key("xaid") + b"\xce\x00\x9f\x97\x3d"
assert V2_TXN.endswith(XAID)


def entry_of(*members: bytes) -> bytes:
    """A payment entry: a fixmap of the members, each its key and value, as given."""
    return bytes([0x80 | len(members)]) + b"".join(members)


def bound_of_entry(data: bytes) -> Any:
    group = list(V2_GROUP)
    group[V2_INDEX] = base64.b64encode(data).decode("ascii")
    return X402_EXACT_ALGORAND.bound(presented({"paymentIndex": V2_INDEX, "paymentGroup": group}))


def assert_read(data: bytes, read_as: str | None) -> None:
    """read_signed reads the entry with the transaction id read_as and bound gives H, or, for None, read_signed refuses
    it and bound gives avm/txn-malformed."""
    try:
        read = _algorand.read_signed(data)
        txid = read.txid if isinstance(read, _algorand.SignedRead) else read
    except _algorand.Malformed:
        txid = None
    assert txid == read_as
    assert bound_of_entry(data) == (H if read_as is not None else Refusal("avm/txn-malformed"))


@pytest.mark.parametrize("name", ["sig", "arcv", "gh", "grp", "note", "snd"])
def test_x402_exact_algorand_a_byte_member_written_as_a_string_is_read_as_its_bytes(name: str) -> None:
    """V2's entry with one of its byte members written as a msgpack str of the same bytes: both readers read a byte
    member's bytes whatever they are, so the entry is V2's transaction, with V2's id. Every member but note holds bytes
    that are not UTF-8."""
    written, raw = bin_member(name)
    if name != "note":
        with pytest.raises(UnicodeDecodeError):
            raw.decode("utf-8")
    assert_read(once(V2_BYTES, written, key(name) + msgpack_str(raw)), V2_TXID)


SUBSIG = b"\x82" + key("pk") + msgpack_str(NOT_UTF8_32) + key("s") + msgpack_str(NOT_UTF8_64)
MSIG = b"\x83" + key("v") + b"\x01" + key("thr") + b"\x01" + key("subsig") + b"\x91" + SUBSIG
LSIG = b"\x82" + key("l") + msgpack_str(PROGRAM + b"\xff") + key("arg") + b"\x91" + msgpack_str(b"\xff\xfe")
BYTE_MEMBERS_AS_STRINGS = [
    pytest.param(with_txn_member(key("lx") + msgpack_str(NOT_UTF8_32)), id="the lease"),
    pytest.param(with_txn_member(key("rekey") + msgpack_str(NOT_UTF8_32)), id="the address the account is rekeyed to"),
    pytest.param(with_txn_member(key("asnd") + msgpack_str(NOT_UTF8_32)), id="the asset sender"),
    pytest.param(with_txn_member(key("aclose") + msgpack_str(NOT_UTF8_32)), id="the asset close-to address"),
    pytest.param(with_member(key("sgnr") + msgpack_str(NOT_UTF8_32)), id="the signer"),
    pytest.param(once(V2_BYTES, SIG, key("msig") + MSIG), id="a subsignature's key and signature"),
    pytest.param(once(V2_BYTES, SIG, key("lsig") + LSIG), id="a logic signature's program and argument"),
]


@pytest.mark.parametrize("data", BYTE_MEMBERS_AS_STRINGS)
def test_x402_exact_algorand_other_byte_members_written_as_strings_are_read(data: bytes) -> None:
    """V2's entry with a byte member it does not write added as a msgpack str of bytes that are not UTF-8, or with a
    multisignature or logic signature in place of sig whose byte members are such strs: both readers read the bytes,
    and bound reads H."""
    assert bound_of_entry(data) == H


# Bytes RFC 3629 section 4's syntax refuses: an overlong t, the surrogate U+D800, U+110000 above U+10FFFF, a two-byte
# lead the string's end cuts short, a continuation byte with no lead, and FF.
NOT_UTF8 = ["c1b4", "eda080", "f4908080", "c3", "80", "ff"]


@pytest.mark.parametrize("tail", NOT_UTF8)
def test_x402_exact_algorand_a_genesis_id_that_is_not_utf8_is_refused(tail: str) -> None:
    """gen, a string member, written as testnet-v1. and bytes that are not UTF-8, as a str and as a bin: the facilitator
    reads them as other text than the bytes algod reads, so the two read different transactions."""
    text = b"testnet-v1." + bytes.fromhex(tail)
    assert_read(once(V2_BYTES, GEN, key("gen") + msgpack_str(text)), None)
    assert_read(once(V2_BYTES, GEN, key("gen") + msgpack_bin(text)), None)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(b"testnet-v1.0\xc3\xa9", id="an e with an acute accent last"),
        pytest.param(b"testnet-v1.0\xf0\x9f\x98\x80", id="U+1F600 last"),
        pytest.param(MARK + b"x" * 197, id="the mark and 197 x"),
        pytest.param(MARK + b"x" * 198, id="the mark and 198 x"),
        pytest.param(MARK + b"x" * 250, id="the mark and 250 x"),
        pytest.param(b"x" + MARK + b"x" * 197, id="x, the mark and 197 x"),
    ],
)
def test_x402_exact_algorand_a_genesis_id_that_is_utf8_is_read_as_written(text: bytes) -> None:
    """gen written as UTF-8 holding characters outside ASCII, as a str: both readers read the same bytes, a leading
    byte-order mark being a character at any length, so bound reads H."""
    assert bound_of_entry(once(V2_BYTES, GEN, key("gen") + msgpack_str(text))) == H


@pytest.mark.parametrize(
    ("data", "read_as"),
    [
        pytest.param(once(V2_BYTES, GEN, key("gen") + msgpack_bin(b"testnet-v1.0")), V2_TXID, id="gen as a bin"),
        pytest.param(once(V2_BYTES, key("type") + msgpack_str(b"axfer"), key("type") + msgpack_bin(b"axfer")), V2_TXID,
                     id="type as a bin"),
        pytest.param(once(V2_BYTES, GEN, key("gen") + msgpack_numbers(b"testnet-v1.0")), None,
                     id="gen as an array of its bytes"),
        pytest.param(once(V2_BYTES, key("type") + msgpack_str(b"axfer"), key("type") + msgpack_numbers(b"axfer")), None,
                     id="type as an array of its bytes"),
    ],
)  # fmt: skip
def test_x402_exact_algorand_type_and_gen_are_read_from_a_str_or_a_bin(data: bytes, read_as: str | None) -> None:
    """The string members type and gen written as a bin of V2's bytes are V2's transaction; written as an array of their
    bytes, which algod reads and the facilitator refuses, the entry is refused."""
    assert_read(data, read_as)


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(once(V2_BYTES, key("txn"), msgpack_bin(b"txn")), id="txn as a bin"),
        pytest.param(once(V2_BYTES, key("type"), msgpack_bin(b"type")), id="type as a bin"),
        pytest.param(once(V2_BYTES, key("gen"), b"\xd9\x03gen"), id="gen as a str 8"),
        pytest.param(once(V2_BYTES, key("xaid"), b"\xda\x00\x04xaid"), id="xaid as a str 16"),
    ],
)
def test_x402_exact_algorand_a_key_whose_bytes_spell_a_member_is_read(data: bytes) -> None:
    """A key is read from a str or a bin, in any of their formats, as the member its bytes spell: V2's entry with one
    key so written is V2's transaction."""
    assert_read(data, V2_TXID)


ODD_KEYS = {
    "zz": key("zz"),
    "the empty string": b"\xa0",
    "Type": key("Type"),
    "typ": key("typ"),
    "type and a zero byte": msgpack_bin(b"type\x00"),
    "the mark and type": msgpack_str(MARK + b"type"),
    "an overlong t": msgpack_str(b"\xc1\xb4"),
    "the surrogate U+D800": msgpack_str(b"\xed\xa0\x80"),
    "U+110000": msgpack_str(b"\xf4\x90\x80\x80"),
    "si and a two-byte lead the key's end cuts short": msgpack_str(b"si\xc1"),
    "the integer 1": b"\x01",
    "nil": b"\xc0",
    "true": b"\xc3",
    "a float 64": b"\xcb" + bytes(8),
    "an empty map": b"\x80",
    "txn as an array of its bytes": msgpack_numbers(b"txn"),
}


@pytest.mark.parametrize("odd", ODD_KEYS)
def test_x402_exact_algorand_a_key_that_spells_no_member_is_refused(odd: str) -> None:
    """A member keyed by bytes that are not exactly a member's name (a name algod does not know, the empty string, a
    string that is not UTF-8 and so spells no name) or by a key of another msgpack type, value 5, added to the entry's
    map and to its transaction's: algod refuses it."""
    assert_read(with_member(ODD_KEYS[odd] + b"\x05"), None)
    assert_read(with_txn_member(ODD_KEYS[odd] + b"\x05"), None)


@pytest.mark.parametrize(
    "near",
    [
        pytest.param(key("xai"), id="its first three bytes"),
        pytest.param(key("aid"), id="its last three bytes"),
        pytest.param(key("Xaid"), id="its first letter in capital"),
        pytest.param(key("xaidx"), id="an x after it"),
        pytest.param(msgpack_str(b"xaid\x00"), id="a zero byte after it"),
        pytest.param(msgpack_str(MARK + b"xaid"), id="the mark before it"),
        pytest.param(msgpack_bin(b"xai"), id="its first three bytes as a bin"),
    ],
)
def test_x402_exact_algorand_a_key_near_a_members_name_is_refused(near: bytes) -> None:
    """V2's entry with a member keyed by bytes near xaid's name added to the transaction, its value V2's xaid: a key is
    read only when its bytes spell a member's name exactly, so algod refuses the key, though the facilitator, which
    reads only the members it names, reads the entry as V2's. Written exactly, the key is read."""
    assert_read(with_txn_member(near + XAID[len(key("xaid")) :]), None)
    assert_read(with_txn_member(XAID), V2_TXID)


def test_x402_exact_algorand_a_transaction_keyed_by_an_array_is_refused() -> None:
    """V2's entry with txn's key written as an array of its bytes, which algod reads as txn and the facilitator does
    not read as a key. The fee payer's entry, a payment, keyed so is read by algod as a payment, so it is not-axfer
    before its keys are judged."""
    assert_read(once(V2_BYTES, key("txn"), msgpack_numbers(b"txn")), None)
    fee_payer = base64.b64decode(V2_GROUP[1 - V2_INDEX])
    assert _algorand.read_signed(once(fee_payer, key("txn"), msgpack_numbers(b"txn"))) == "not-axfer"


def test_x402_exact_algorand_a_map_key_the_facilitators_decoder_does_not_take_is_refused() -> None:
    """votekey, another type's member, added as a map, whose keys and values algod reads in turn as its bytes: {0: 0}
    is two zero bytes, the member at zero, so the entry is V2's transaction; {nil: 0} is the same bytes to algod, and
    the facilitator's msgpack decoder refuses a nil map key wherever it sits."""
    assert_read(with_txn_member(key("votekey") + b"\x81\x00\x00"), V2_TXID)
    assert_read(with_txn_member(key("votekey") + b"\x81\xc0\x00"), None)


# The address whose key is the ASCII of its own first 32 characters.
SELF_SPELLED = "JJFEMRKNKJFU4S2KIZKTIUZSJNEVUS2UJFKVUU2KJZCVMVKTGJKVMRC77Q"


def test_x402_exact_algorand_an_address_written_as_its_text_is_read_when_both_readers_read_one_key() -> None:
    """snd written as an address's 58 characters: algod reads their first 32 bytes, the facilitator the key the address
    spells. For SELF_SPELLED the two read one key, so the entry is the transaction whose snd is that key, with its id
    (lcp's reader's id for that entry); for the payer's address they read two keys."""
    self_key = SELF_SPELLED[:32].encode("ascii")
    assert encode_address(self_key) == SELF_SPELLED
    written, _ = bin_member("snd")
    as_key = "XZOAQOY6RAE26OW6GMG3TNS6K7SGOFHWRV6LTKZL57TJB7Z3BM6A"
    assert_read(once(V2_BYTES, written, key("snd") + msgpack_bin(self_key)), as_key)
    assert_read(once(V2_BYTES, written, key("snd") + msgpack_str(SELF_SPELLED.encode("ascii"))), as_key)
    assert_read(once(V2_BYTES, written, key("snd") + msgpack_str(F["payer"].encode("ascii"))), None)


LEASE = key("lx") + msgpack_bin(bytes([7]) * 32)
# A key registration's voting key, a 32-byte member the facilitator does not read: written again shorter, algod keeps
# the bytes the later write does not hold, so votekey stays set, another type's member on an asset transfer.
VOTEKEY = key("votekey") + msgpack_bin(bytes([1]) * 32)
# V2's payment entry whose transaction's map header counts two more members, which follow it.
TWO_MORE = once(V2_BYTES, TXN_HEAD, b"\xa3txn\x8d")


@pytest.mark.parametrize(
    ("data", "read_as"),
    [
        pytest.param(entry_of(SIG, key("txn") + V2_TXN, key("txn") + V2_TXN), V2_TXID, id="txn twice"),
        pytest.param(entry_of(SIG, key("txn") + b"\x81" + XAID, key("txn") + V2_TXN), V2_TXID,
                     id="txn with V2's xaid alone, then V2's txn"),
        pytest.param(entry_of(SIG, key("txn") + b"\x81" + key("fee") + b"\x05", key("txn") + V2_TXN), None,
                     id="txn with fee 5, then V2's txn"),
        pytest.param(entry_of(SIG, key("txn") + b"\x81" + LEASE, key("txn") + V2_TXN), None,
                     id="txn with a lease, then V2's txn"),
        pytest.param(with_first_txn_member(key("xaid") + b"\x05"), V2_TXID, id="xaid 5, then V2's xaid"),
        pytest.param(with_first_txn_member(key("gh") + msgpack_bin(bytes(31))), V2_TXID,
                     id="gh as 31 zero bytes, then V2's gh"),
        pytest.param(with_txn_member(key("gh") + msgpack_bin(bytes(31))), None, id="V2's gh, then 31 zero bytes"),
        pytest.param(with_txn_member(key("gh") + msgpack_bin(bin_member("gh")[1] + b"\x00")), None,
                     id="V2's gh, then V2's gh and a zero byte"),
        pytest.param(TWO_MORE + VOTEKEY + key("votekey") + msgpack_bin(bytes(1)), None,
                     id="votekey as 32 bytes of 01, then one zero byte"),
        pytest.param(TWO_MORE + VOTEKEY + key("votekey") + msgpack_bin(bytes(32)), V2_TXID,
                     id="votekey as 32 bytes of 01, then 32 zero bytes"),
        pytest.param(TWO_MORE + LEASE + key("lx") + b"\xc0", V2_TXID,
                     id="a lease, then lx nil"),
    ],
)  # fmt: skip
def test_x402_exact_algorand_a_repeated_member_is_read_when_both_readers_read_one_transaction(
    data: bytes, read_as: str | None
) -> None:
    """A member written twice: algod decodes each occurrence into the value the earlier left (a struct's members
    merge, a fixed-length byte member has only the bytes written replaced), and the facilitator reads the last alone.
    The entry is read when the two then read one transaction, and refused when they read two."""
    assert_read(data, read_as)


def subsig(fill: int, signed: bool) -> bytes:
    """A subsignature: the key of 32 bytes of fill and, when signed, the signature of 64 bytes of fill."""
    pairs = key("pk") + msgpack_bin(bytes([fill]) * 32)
    if signed:
        return b"\x82" + pairs + key("s") + msgpack_bin(bytes([fill]) * 64)
    return b"\x81" + pairs


def msig_with_lists(*lists: list[bytes]) -> bytes:
    """V2's entry with msig {v: 1, thr: 1} and one subsig member for each list, in order, added to the entry's map."""
    members = key("v") + b"\x01" + key("thr") + b"\x01"
    members += b"".join(key("subsig") + bytes([0x90 | len(items)]) + b"".join(items) for items in lists)
    return with_member(key("msig") + bytes([0x80 | (2 + len(lists))]) + members)


SUB_A, SUB_B, SUB_C, SUB_X, EMPTY = subsig(1, False), subsig(2, False), subsig(3, False), subsig(9, True), b"\x80"


@pytest.mark.parametrize(
    ("data", "read_as"),
    [
        pytest.param(msig_with_lists([SUB_A, SUB_B, SUB_C], [SUB_A, SUB_B, SUB_C]), V2_TXID, id="the same list twice"),
        pytest.param(msig_with_lists([SUB_A], [SUB_X, SUB_B, SUB_C]), V2_TXID, id="a longer list after a shorter"),
        pytest.param(msig_with_lists([SUB_A, SUB_B, SUB_C], [SUB_X]), V2_TXID, id="a shorter list after a longer"),
        pytest.param(msig_with_lists([SUB_A, SUB_B, SUB_C], [SUB_X, EMPTY, EMPTY]), None,
                     id="empty subsignatures where a longer list left two"),
        pytest.param(msig_with_lists([SUB_A, SUB_B, SUB_C], [SUB_X], [SUB_X, EMPTY, EMPTY]), None,
                     id="a list within the capacity a longer list left"),
    ],
)  # fmt: skip
def test_x402_exact_algorand_a_repeated_list_is_read_into_the_array_algod_keeps(
    data: bytes, read_as: str | None
) -> None:
    """A multisignature's subsig written more than once: algod decodes a later list into the array the earlier left, up
    to its capacity, so an element the later list leaves empty keeps what the earlier wrote there; the facilitator
    reads the last list alone. The entry is read when the two then read one multisignature."""
    assert_read(data, read_as)


@pytest.mark.parametrize(
    ("data", "read_as"),
    [
        pytest.param(once(V2_BYTES, key("fv") + b"\xce", key("fv") + b"\xcf\x00\x00\x00\x00"), V2_TXID,
                     id="fv as a uint 64"),
        pytest.param(once(V2_BYTES, key("fv") + b"\xce", key("fv") + b"\xd2"), V2_TXID, id="fv as an int 32"),
        pytest.param(once(V2_BYTES, key("aamt") + b"\xcd", key("aamt") + b"\xd3" + bytes(6)), V2_TXID,
                     id="aamt as an int 64"),
        pytest.param(once(V2_BYTES, XAID, key("xaid") + b"\xcf\x00\x00\x00\x00\x00\x9f\x97\x3d"), V2_TXID,
                     id="xaid as a uint 64"),
        pytest.param(with_txn_member(key("fee") + b"\xff"), None, id="fee -1"),
        pytest.param(with_txn_member(key("fee") + b"\xcb" + bytes(8)), None, id="fee 0 as a float 64"),
        pytest.param(with_txn_member(key("afrz") + b"\x00"), V2_TXID, id="afrz the fixint 0"),
        pytest.param(with_txn_member(key("afrz") + b"\x01"), None, id="afrz the fixint 1"),
        pytest.param(with_txn_member(key("afrz") + b"\xcc\x00"), None, id="afrz 0 as a uint 8"),
        pytest.param(with_member(key("msig") + b"\x81" + key("v") + b"\x00"), V2_TXID, id="msig v the fixint 0"),
        pytest.param(with_member(key("msig") + b"\x81" + key("v") + b"\xcf" + bytes(8)), None,
                     id="msig v 0 as a uint 64"),
        pytest.param(with_member(key("msig") + b"\x81" + key("v") + b"\xcd\x01\x00"), None, id="msig v 256"),
    ],
)  # fmt: skip
def test_x402_exact_algorand_an_integer_is_read_in_the_formats_both_readers_read_alike(
    data: bytes, read_as: str | None
) -> None:
    """An integer member in a format longer than it needs is read as its value. A negative, a float, a bool written as
    the integer 1 or in another format than a fixint, a value past the member's width, and a multisignature version 0
    in a 64-bit format, which the facilitator writes back and algod's encoding leaves out, are refused."""
    assert_read(data, read_as)


def edits_v2s_payment_entry(row: dict[str, Any]) -> bool:
    """Whether the row is V2's group with the payment entry's bytes written otherwise and every other entry V2's."""
    group = row["paymentGroup"]
    if row["paymentIndex"] != V2_INDEX or len(group) != len(V2_GROUP):
        return False
    others = all(entry == v2 for i, (entry, v2) in enumerate(zip(group, V2_GROUP)) if i != V2_INDEX)
    return others and base64.b64decode(group[V2_INDEX]) != V2_BYTES


def test_x402_exact_algorand_v3_entries_written_otherwise_than_v2s() -> None:
    """The V3.refusals rows that are V2's group with the payment entry written otherwise: each entry is one algod or the
    facilitator refuses, or one the two read as different transactions, so bound gives each row's refusal."""
    rows = [row for row in A["V3"]["refusals"] if edits_v2s_payment_entry(row)]
    assert rows, "x402-exact-algorand.json holds no V3.refusals row that writes V2's payment entry otherwise"
    for row in rows:
        payload = {"paymentIndex": row["paymentIndex"], "paymentGroup": row["paymentGroup"]}
        assert X402_EXACT_ALGORAND.bound(presented(payload)) == Refusal(row["expect"]), row["case"]


def strings_not_utf8(row: dict[str, Any]) -> list[tuple[bytes, bytes | None]]:
    """Each msgpack str in the row's payment entry whose bytes are not UTF-8 (RFC 3629), with the key it is the value
    of (None for a str that is a key), read with support.msgpack_value."""
    group, index = row["paymentGroup"], row["paymentIndex"]
    value = msgpack_value(base64.b64decode(group[index])) if 0 <= index < len(group) else None
    out = []
    for text, under in msgpack_strings(value) if value is not None else []:
        try:
            text.decode("utf-8")
        except UnicodeDecodeError:
            out.append((text, under))
    return out


def test_x402_exact_algorand_v3_entries_holding_a_string_that_is_not_utf8() -> None:
    """The V3.refusals rows whose payment entry holds a msgpack str that is not UTF-8. Such a str is judged by the
    member it fills: as a key it spells no member's name, and as the value of the string member type or gen it is
    refused, while a byte member's would be read as its bytes. So each one is a key or the value of type or gen, and
    bound gives each row's refusal."""
    rows = [row for row in A["V3"]["refusals"] if strings_not_utf8(row)]
    assert rows, "x402-exact-algorand.json holds no V3.refusals row whose payment entry holds a str that is not UTF-8"
    for row in rows:
        for text, under in strings_not_utf8(row):
            assert under in (None, b"type", b"gen"), (row["case"], text.hex(), under)
        payload = {"paymentIndex": row["paymentIndex"], "paymentGroup": row["paymentGroup"]}
        assert X402_EXACT_ALGORAND.bound(presented(payload)) == Refusal(row["expect"]), row["case"]


def build_with(genesis_id: str, genesis_hash: str | None = None) -> AvmUnsigned | Refusal:
    """build of fixed.O for the file's payer and suggested parameters, with genesis_id and genesis_hash written in."""
    params = {**F["params"], **{k: int(F["params"][k]) for k in ("firstValid", "minFee", "feePerByte")}}
    params["genesisId"] = genesis_id
    if genesis_hash is not None:
        params["genesisHash"] = genesis_hash
    choice = {"required": x402_doc(F["O"], F["resource"]), "accepted": F["O"], "payer": F["payer"], "params": params}
    unsigned: AvmUnsigned | Refusal = X402_EXACT_ALGORAND.build(choice, H)
    return unsigned


# build writes the suggested parameters' genesis id as each transaction's gen, a msgpack string. Expected values are
# lcp's exactAvm.build, for these genesis ids: one holding a lone surrogate, short or long (RFC 3629 section 3 excludes
# U+D800 to U+DFFF from UTF-8), is avm/option-malformed; any other, characters outside ASCII and a leading byte-order
# mark at any length among them, is written as given, and bound reads H.
REFUSED_GENESIS_IDS = [
    pytest.param("testnet-v1.\ud800", id="a lone high surrogate last"),
    pytest.param("\udc00testnet-v1.0", id="a lone low surrogate first"),
    pytest.param("testnet-v1.0" + "x" * 60 + "\ud83d", id="a lone high surrogate after 72 characters"),
]
WRITTEN_GENESIS_IDS = [
    pytest.param(F["params"]["genesisId"], id="the file's genesis id"),
    pytest.param("testnet-v1.0\u00e9", id="an e with an acute accent last"),
    pytest.param("testnet-v1.0\U0001f600", id="U+1F600 last"),
    pytest.param("\ufeff" + "x" * 197, id="the mark and 197 x"),
    pytest.param("\ufeff" + "x" * 198, id="the mark and 198 x"),
    pytest.param("x\ufeff" + "x" * 197, id="x, the mark and 197 x"),
]


@pytest.mark.parametrize("genesis_id", REFUSED_GENESIS_IDS)
def test_x402_exact_algorand_build_refuses_a_genesis_id_utf8_cannot_encode(genesis_id: str) -> None:
    assert build_with(genesis_id) == Refusal("avm/option-malformed")


@pytest.mark.parametrize("genesis_id", WRITTEN_GENESIS_IDS)
def test_x402_exact_algorand_build_writes_any_other_genesis_id_as_given(genesis_id: str) -> None:
    unsigned = build_with(genesis_id)
    assert isinstance(unsigned, AvmUnsigned), unsigned
    payment = unsigned.complete(bytes.fromhex(F["signature"]))
    assert isinstance(payment, dict)
    for entry in payment["payload"]["paymentGroup"]:
        assert key("gen") + msgpack_str(genesis_id.encode("utf-8")) in base64.b64decode(entry)
    assert X402_EXACT_ALGORAND.bound(presented(payment["payload"])) == H


def test_x402_exact_algorand_build_reads_the_genesis_id_before_the_genesis_hash() -> None:
    """As lcp's exactAvm.build checks the suggested parameters: a genesis id holding a lone surrogate is
    avm/option-malformed under another network's genesis hash too, and a well-formed one under it is
    avm/network-mismatch, the mark and 198 x among them."""
    mainnet = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8="
    assert build_with("testnet-v1.\ud800", mainnet) == Refusal("avm/option-malformed")
    assert build_with("testnet-v1.0", mainnet) == Refusal("avm/network-mismatch")
    assert build_with("\ufeff" + "x" * 198, mainnet) == Refusal("avm/network-mismatch")


def test_x402_exact_algorand_build_refuses_a_payment_entry_carrier_does_not_read() -> None:
    """build reads the payment entry it writes as carrier reads it. Under a genesis hash of 32 zero bytes, which the
    transaction's canonical encoding leaves out, the facilitator computes no transaction id, so build refuses, as lcp's
    exactAvm.build does for the same option and parameters."""
    option = {**F["O"], "network": "algorand:" + "A" * 32}
    params = {**F["params"], **{k: int(F["params"][k]) for k in ("firstValid", "minFee", "feePerByte")}}
    params["genesisHash"] = base64.b64encode(bytes(32)).decode("ascii")
    choice = {"required": x402_doc(option, F["resource"]), "accepted": option, "payer": F["payer"], "params": params}
    assert X402_EXACT_ALGORAND.build(choice, H) == Refusal("avm/option-malformed")


def test_x402_exact_algorand_build_rows() -> None:
    """build.rows: build of fixed.O for the file's payer and parameters with each row's genesis id, and its genesis hash
    where it names one. A refused row gives its code; a built row's group id, payment transaction id and bound are the
    row's. The rows with another network's genesis hash pin the order: the genesis id is read before it."""
    rows = A.get("build", {}).get("rows", [])
    assert rows, "x402-exact-algorand.json holds no build rows"
    for row in rows:
        unsigned = build_with(row["genesisId"], row.get("genesisHash"))
        if "expect" in row:
            assert unsigned == Refusal(row["expect"]), row["case"]
            continue
        assert isinstance(unsigned, AvmUnsigned), row["case"]
        transfer = unsigned._group[unsigned._index]
        assert transfer.group is not None and base64.b64encode(transfer.group).decode() == row["expectGroupId"]
        assert txid(_algorand.sha512_256(unsigned.request["bytes"])) == row["expectPaymentTxid"], row["case"]
        payment = unsigned.complete(bytes.fromhex(F["signature"]))
        assert isinstance(payment, dict)
        assert X402_EXACT_ALGORAND.bound(presented(payment["payload"])) == row["expectBound"], row["case"]


def test_x402_exact_algorand_build_refuses_a_payment_entry_longer_than_carrier_reads() -> None:
    """build reads the payment entry as complete writes it, with a 64-byte signature in place, so it writes no payment
    bound refuses. With the file's fee payer, a genesis id of 5,780 x gives an entry of 8,192 base64 characters, which
    builds and is bound; 5,781 x gives 8,196 and is avm/option-malformed, as lcp's build.rows[4] holds."""
    unsigned = build_with("x" * 5780)
    assert isinstance(unsigned, AvmUnsigned) and len(unsigned._group) == 2
    payment = unsigned.complete(bytes.fromhex(F["signature"]))
    assert isinstance(payment, dict)
    assert len(payment["payload"]["paymentGroup"][unsigned._index]) == 8192
    assert X402_EXACT_ALGORAND.bound(presented(payment["payload"])) == H
    assert build_with("x" * 5781) == Refusal("avm/option-malformed")


def test_x402_exact_algorand_v3_presented_options_are_refused_by_the_read_filter() -> None:
    """V2's payment under each V3.presentedOptions option, whose amount or timeout no build could use: bound holds the
    echoed option to the filter read applies and gives the row's refusal, while read serves no such option and build
    refuses it. Under each options row, bound gives that row's refusal."""
    payload = {"paymentIndex": A["V2"]["expectPaymentIndex"], "paymentGroup": A["V2"]["expectPaymentGroup"]}
    params = {**F["params"], **{k: int(F["params"][k]) for k in ("firstValid", "minFee", "feePerByte")}}
    rows = A["V3"]["presentedOptions"]
    assert rows
    for row in rows:
        accepted = row["accepted"]
        assert X402_EXACT_ALGORAND.bound(presented(payload, accepted)) == Refusal(row["expect"]), row["case"]
        doc = x402_doc(accepted, F["resource"])
        assert X402_EXACT_ALGORAND.read(doc) == Refusal("x402/no-payable-option"), row["case"]
        choice = {"required": doc, "accepted": accepted, "payer": F["payer"], "params": params}
        assert X402_EXACT_ALGORAND.build(choice, H) == Refusal("avm/option-malformed"), row["case"]
    assert A["options"]
    for row in A["options"]:
        assert X402_EXACT_ALGORAND.bound(presented(payload, row["option"])) == Refusal(row["expect"]), row["case"]


def test_x402_exact_algorand_option_filter_rows() -> None:
    for row in A["options"]:
        assert check(row["option"]) == Refusal(row["expect"]), row["case"]
    assert check(copy.deepcopy(F["O"])) is True
