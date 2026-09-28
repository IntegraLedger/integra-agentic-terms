"""The XRP Ledger binary codec's decoding walk over a serialized transaction, and XRPL base58 account addresses.

A field header names its type code and field code. The walk reads each field's value by its type: fixed-width
integers and hashes, amounts (XRP drops, issued and MPT), length-prefixed blobs, account ids and 256-bit vectors,
path sets, issues, bridges, and nested objects and arrays closed by their end markers. A field the XRPL definitions
do not name, or a value an enumeration does not name, makes the input malformed. The fields read are written back
first (an array's members without length prefixes, each followed by an object end marker) and the JSON is read from
what was written. Values come out as JSON in the codec's forms: integers as numbers, hashes and
blobs as upper-case hex, accounts as classic addresses.

The input must be the canonical serialization of what it decodes to (xrpl.org Binary Format): each object's fields in
ascending order of type code and then field code with none repeated, no end marker and nothing after the top-level
object's last field, every nested object and array closed by its end marker, and every array member an object. An
AccountID is 20 bytes, except that a UNLModify's Account is written with length 0. A Vector256's length is a
multiple of 32. An XRP amount has its positive bit set and at most 10^17 drops, except that FeeAmountDelta may be
negative and non-zero. An issued amount is zero written as 0x80 and seven zero bytes, or has a mantissa from 10^15
to 10^16 - 1 and an exponent from -96 to 80. An MPT amount leads with 0x60 and is below 2^63. A path step's type
byte sets only its account, currency and issuer bits, and the first step of a path set sets at least one of them;
a path set with paths ends with its end byte. A bridge's account length bytes are 20. A Number is the encoding of its
own text, as ripple-binary-codec reads and writes it.
"""

import hashlib
import re
from typing import Any

XRPL_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
_XRPL_INDEX = {c: i for i, c in enumerate(XRPL_ALPHABET)}
MAX_DEPTH = 64

# Type codes.
UINT16, UINT32, UINT64, HASH128, HASH256, AMOUNT, BLOB, ACCOUNT = 1, 2, 3, 4, 5, 6, 7, 8
NUMBER, INT32, OBJECT, ARRAY, UINT8, HASH160, PATHSET, VECTOR256 = 9, 10, 14, 15, 16, 17, 18, 19
HASH192, ISSUE, BRIDGE, CURRENCY = 21, 24, 25, 26


def _codes(spec: str) -> frozenset[int]:
    """A set of field codes written as comma-separated numbers and inclusive ranges."""
    out: set[int] = set()
    for part in spec.split(","):
        low, _, high = part.partition("-")
        out.update(range(int(low), int(high or low) + 1))
    return frozenset(out)


# The field codes the XRPL definitions name, per type code.
_KNOWN: dict[int, frozenset[int]] = {
    UINT16: _codes("1-6,16,21,22"),
    UINT32: _codes("1-44,48,50-80"),
    UINT64: _codes("1-13,19-33"),
    HASH128: _codes("1"),
    HASH256: _codes("1-14,16-19,21-29,34-41"),
    AMOUNT: _codes("1-13,16-19,22-34"),
    BLOB: _codes("1-14,16-21,26-46"),
    ACCOUNT: _codes("1-6,8-12,18-31"),
    NUMBER: _codes("1-17"),
    INT32: _codes("1,2"),
    OBJECT: _codes("1-13,15,16,18,19,25-38"),
    ARRAY: _codes("1,3-10,12,13,16,17,21,22,24-31"),
    UINT8: _codes("1-6,16,17,19-22"),
    HASH160: _codes("1-4"),
    PATHSET: _codes("1"),
    VECTOR256: _codes("1-5"),
    HASH192: _codes("1-4"),
    ISSUE: _codes("1-4"),
    BRIDGE: _codes("1"),
    CURRENCY: _codes("1,2"),
}

# The names of the fields the bindings read; every other known field is keyed "<type>:<field>".
_NAMES: dict[tuple[int, int], str] = {
    (UINT16, 2): "TransactionType",
    (UINT32, 2): "Flags",
    (UINT32, 4): "Sequence",
    (UINT32, 14): "DestinationTag",
    (UINT32, 27): "LastLedgerSequence",
    (UINT32, 36): "CancelAfter",
    (UINT32, 39): "SettleDelay",
    (UINT32, 41): "TicketSequence",
    (UINT32, 1): "NetworkID",
    (HASH256, 17): "InvoiceID",
    (HASH256, 22): "Channel",
    (AMOUNT, 1): "Amount",
    (AMOUNT, 2): "Balance",
    (AMOUNT, 8): "Fee",
    (AMOUNT, 9): "SendMax",
    (BLOB, 1): "PublicKey",
    (BLOB, 3): "SigningPubKey",
    (BLOB, 4): "TxnSignature",
    (BLOB, 6): "Signature",
    (BLOB, 12): "MemoType",
    (BLOB, 13): "MemoData",
    (BLOB, 14): "MemoFormat",
    (ACCOUNT, 1): "Account",
    (ACCOUNT, 3): "Destination",
    (OBJECT, 1): "ObjectEndMarker",
    (OBJECT, 10): "Memo",
    (ARRAY, 1): "ArrayEndMarker",
    (ARRAY, 3): "Signers",
    (ARRAY, 9): "Memos",
}

# UInt16 field 2's values.
TRANSACTION_TYPES: dict[int, str] = {
    0: "Payment", 1: "EscrowCreate", 2: "EscrowFinish", 3: "AccountSet", 4: "EscrowCancel", 5: "SetRegularKey",
    7: "OfferCreate", 8: "OfferCancel", 10: "TicketCreate", 12: "SignerListSet", 13: "PaymentChannelCreate",
    14: "PaymentChannelFund", 15: "PaymentChannelClaim", 16: "CheckCreate", 17: "CheckCash", 18: "CheckCancel",
    19: "DepositPreauth", 20: "TrustSet", 21: "AccountDelete", 25: "NFTokenMint", 26: "NFTokenBurn",
    27: "NFTokenCreateOffer", 28: "NFTokenCancelOffer", 29: "NFTokenAcceptOffer", 30: "Clawback", 31: "AMMClawback",
    35: "AMMCreate", 36: "AMMDeposit", 37: "AMMWithdraw", 38: "AMMVote", 39: "AMMBid", 40: "AMMDelete",
    41: "XChainCreateClaimID", 42: "XChainCommit", 43: "XChainClaim", 44: "XChainAccountCreateCommit",
    45: "XChainAddClaimAttestation", 46: "XChainAddAccountCreateAttestation", 47: "XChainModifyBridge",
    48: "XChainCreateBridge", 49: "DIDSet", 50: "DIDDelete", 51: "OracleSet", 52: "OracleDelete",
    53: "LedgerStateFix", 54: "MPTokenIssuanceCreate", 55: "MPTokenIssuanceDestroy", 56: "MPTokenIssuanceSet",
    57: "MPTokenAuthorize", 58: "CredentialCreate", 59: "CredentialAccept", 60: "CredentialDelete",
    61: "NFTokenModify", 62: "PermissionedDomainSet", 63: "PermissionedDomainDelete", 64: "DelegateSet",
    65: "VaultCreate", 66: "VaultSet", 67: "VaultDelete", 68: "VaultDeposit", 69: "VaultWithdraw",
    70: "VaultClawback", 71: "Batch", 74: "LoanBrokerSet", 75: "LoanBrokerDelete", 76: "LoanBrokerCoverDeposit",
    77: "LoanBrokerCoverWithdraw", 78: "LoanBrokerCoverClawback", 80: "LoanSet", 81: "LoanDelete",
    82: "LoanManage", 84: "LoanPay", 85: "ConfidentialMPTConvert", 86: "ConfidentialMPTMergeInbox",
    87: "ConfidentialMPTConvertBack", 88: "ConfidentialMPTSend", 89: "ConfidentialMPTClawback",
    90: "SponsorshipTransfer", 91: "SponsorshipSet", 100: "EnableAmendment", 101: "SetFee", 102: "UNLModify",
}  # fmt: skip
# UInt8 field 3 (TransactionResult), UInt16 field 1 (LedgerEntryType) and UInt32 field 52 (PermissionValue) values.
_RESULTS = _codes("0,100-105,121-152,154-197,199,200")
_LEDGER_ENTRY_TYPES = _codes("55,67,73,78,80,83,84,97,100,102,104,105,111-117,120,121,126-132,136,137,144")
_PERMISSIONS = frozenset({t + 1 for t in TRANSACTION_TYPES} | set(range(65537, 65549)))
# FeeAmountDelta, an Amount field read as a signed XRP amount.
_SIGNED_AMOUNT = (AMOUNT, 34)
_MAX_DROPS = 10**17
# The UInt64 fields written in decimal: MaximumAmount, OutstandingAmount, MPTAmount, LockedAmount and
# ConfidentialOutstandingAmount.
_BASE10_UINT64_CODES = _codes("24-26,29,32")
_NO_ACCOUNT = bytes(19) + b"\x01"


class Malformed(Exception):
    """The bytes are not a serialization the codec reads."""


# A Number's 12 bytes: a signed 64-bit mantissa and a signed 32-bit exponent, big-endian.
_MIN_MANTISSA = 10**18
_MAX_MANTISSA = 10**19 - 1
_MAX_INT64 = 2**63 - 1
_MIN_EXPONENT = -32768
_MAX_EXPONENT = 32768
_ZERO_EXPONENT = -(2**31)
_RANGE_LOG = 18


def _number_text(data: bytes) -> str:
    """A Number's text: "0" for the zero encoding; otherwise the mantissa (times 10 when below 10^18) and exponent,
    as a decimal when the exponent is 0 or from -28 to -8, else as mantissa "e" exponent with trailing zeros moved
    into the exponent."""
    mantissa = int.from_bytes(data[:8], "big", signed=True)
    exponent = int.from_bytes(data[8:], "big", signed=True)
    if mantissa == 0 and exponent == _ZERO_EXPONENT:
        return "0"
    negative = mantissa < 0
    m = -mantissa if negative else mantissa
    if m != 0 and m < _MIN_MANTISSA:
        m *= 10
        exponent -= 1
    sign = "-" if negative else ""
    if exponent != 0 and (exponent < -(_RANGE_LOG + 10) or exponent > -(_RANGE_LOG - 10)):
        while m != 0 and m % 10 == 0 and exponent < _MAX_EXPONENT:
            m //= 10
            exponent += 1
        return f"{sign}{m}e{exponent}"
    raw = "0" * (_RANGE_LOG + 12) + str(m) + "0" * (_RANGE_LOG + 8)
    offset = exponent + _RANGE_LOG + 12 + _RANGE_LOG + 1
    integer = raw[:offset].lstrip("0") or "0"
    fraction = raw[offset:].rstrip("0")
    return f"{sign}{integer}{'.' + fraction if fraction else ''}"


_NUMBER_TEXT = re.compile(r"([-+]?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?")


def _number_bytes(text: str) -> bytes:
    """The 12 bytes a Number's text encodes to: the mantissa brought to 10^18 through 2^63 - 1 by moving digits into
    the exponent, rounding half up on the last digit dropped; zero as mantissa 0 and exponent -2^31. Raises Malformed
    when the exponent leaves -32768 through 32768."""
    match = _NUMBER_TEXT.fullmatch(text)
    if match is None:
        raise Malformed
    sign, integer, fraction, exp = match.groups()
    digits = integer.lstrip("0") or "0"
    exponent = 0
    if fraction:
        digits += fraction
        exponent -= len(fraction)
    if exp:
        exponent += int(exp)
    while len(digits) > 1 and digits.endswith("0"):
        digits = digits[:-1]
        exponent += 1
    m = int(digits)
    negative = sign == "-" and m != 0
    if m == 0:
        return (0).to_bytes(8, "big") + _ZERO_EXPONENT.to_bytes(4, "big", signed=True)
    while m < _MIN_MANTISSA and exponent > _MIN_EXPONENT:
        exponent -= 1
        m *= 10
    last: int | None = None
    while m > _MAX_MANTISSA:
        if exponent >= _MAX_EXPONENT:
            raise Malformed
        exponent += 1
        last = m % 10
        m //= 10
    if exponent < _MIN_EXPONENT or m < _MIN_MANTISSA or exponent > _MAX_EXPONENT:
        raise Malformed
    if m > _MAX_INT64:
        if exponent >= _MAX_EXPONENT:
            raise Malformed
        exponent += 1
        last = m % 10
        m //= 10
    if last is not None and last >= 5:
        m += 1
        if m > _MAX_INT64:
            if exponent >= _MAX_EXPONENT:
                raise Malformed
            last = m % 10
            exponent += 1
            m //= 10
            if last >= 5:
                m += 1
    return (-m if negative else m).to_bytes(8, "big", signed=True) + exponent.to_bytes(4, "big", signed=True)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def end(self) -> bool:
        return self.at >= len(self.data)

    def peek(self) -> int:
        if self.end():
            raise Malformed
        return self.data[self.at]

    def read(self, n: int) -> bytes:
        if n < 0 or self.at + n > len(self.data):
            raise Malformed
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def u8(self) -> int:
        return self.read(1)[0]

    def length(self) -> int:
        """A variable-length prefix: one, two or three bytes."""
        b1 = self.u8()
        if b1 <= 192:
            return b1
        if b1 <= 240:
            return 193 + (b1 - 193) * 256 + self.u8()
        if b1 <= 254:
            b2, b3 = self.u8(), self.u8()
            return 12481 + (b1 - 241) * 65536 + b2 * 256 + b3
        raise Malformed

    def field(self) -> tuple[int, int]:
        """A field header's type code and field code; codes of 16 and above take their own byte."""
        head = self.u8()
        type_code, nth = head >> 4, head & 0x0F
        if type_code == 0:
            type_code = self.u8()
            if type_code < 16:
                raise Malformed
        if nth == 0:
            nth = self.u8()
            if nth < 16:
                raise Malformed
        if nth not in _KNOWN.get(type_code, frozenset()):
            raise Malformed
        return type_code, nth


def _hex(data: bytes) -> str:
    return data.hex().upper()


def b58_encode(data: bytes) -> str:
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = XRPL_ALPHABET[rest] + out
    zeros = len(data) - len(data.lstrip(b"\0"))
    return XRPL_ALPHABET[0] * zeros + out


def b58_decode(text: str, max_bytes: int) -> bytes | None:
    """The bytes of an XRPL-alphabet base58 string of at most max_bytes, or None."""
    if not isinstance(text, str) or text == "" or len(text) > 2 * max_bytes:
        return None
    number = 0
    for c in text:
        v = _XRPL_INDEX.get(c)
        if v is None:
            return None
        number = number * 58 + v
    zeros = len(text) - len(text.lstrip(XRPL_ALPHABET[0]))
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    out = b"\0" * zeros + body
    return out if len(out) <= max_bytes else None


def _checksum(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]


def encode_account(account_id: bytes) -> str:
    """The classic address of a 20-byte AccountID: version 0, the id, and a double-SHA-256 checksum."""
    payload = b"\0" + account_id
    return b58_encode(payload + _checksum(payload))


def account_id_of(address: object) -> bytes | None:
    """The 20-byte AccountID of a classic address, or None when it does not decode or its checksum fails."""
    if not isinstance(address, str) or len(address) > 35:
        return None
    raw = b58_decode(address, 25)
    if raw is None or len(raw) != 25 or raw[0] != 0 or _checksum(raw[:21]) != raw[21:]:
        return None
    return raw[1:21]


def _currency(data: bytes) -> str:
    """A currency code: XRP for all zeros, a three-character code in the standard form, else hex."""
    if data == bytes(20):
        return "XRP"
    if data[:12] == bytes(12) and data[15:] == bytes(5):
        try:
            iso = data[12:15].decode("utf-8")
        except UnicodeDecodeError:
            iso = ""
        if iso != "XRP" and len(iso) == 3 and all(c.isascii() and (c.isalnum() or c in "?!@#$%^&*(){}[]|") for c in iso):
            return iso
    return _hex(data)


def _iou_value(mantissa_bytes: bytes) -> str:
    """An issued amount's value in fixed decimal notation; raises Malformed outside 16 digits and exponents -96 to 80."""
    b1, b2 = mantissa_bytes[0], mantissa_bytes[1]
    sign = "" if b1 & 0x40 else "-"
    exponent = ((b1 & 0x3F) << 2) + (b2 >> 6) - 97
    mantissa = int.from_bytes(bytes([0, b2 & 0x3F]) + mantissa_bytes[2:], "big")
    if mantissa == 0:
        return "0"
    digits = str(mantissa)
    stripped = digits.rstrip("0")
    lead = len(digits) - 1 + exponent
    if len(stripped) > 16 or not -96 <= lead - 15 <= 80:
        raise Malformed
    if lead >= 0:
        whole = (stripped + "0" * (lead + 1))[: lead + 1]
        frac = stripped[lead + 1 :]
        return sign + whole + ("." + frac if frac else "")
    return sign + "0." + "0" * (-lead - 1) + stripped


def _amount(r: _Reader, signed: bool) -> Any:
    """An amount in its canonical form; signed is an XRP amount that may be negative and non-zero."""
    first = r.peek()
    if first & 0x80:
        data = r.read(48)
        mantissa = int.from_bytes(data[:8], "big") & ((1 << 54) - 1)
        exponent = (int.from_bytes(data[:2], "big") >> 6) & 0xFF
        zero = data[:8] == b"\x80" + bytes(7)
        if signed or not (zero or (10**15 <= mantissa < 10**16 and 1 <= exponent <= 177)):
            raise Malformed
        return {"value": _iou_value(data[:8]), "currency": _currency(data[8:28]), "issuer": encode_account(data[28:48])}
    if first & 0x20:
        data = r.read(33)
        drops = int.from_bytes(data[1:9], "big")
        if signed or data[0] != 0x60 or drops >= 1 << 63:
            raise Malformed
        return {"value": str(drops), "mpt_issuance_id": _hex(data[9:33])}
    data = r.read(8)
    drops = int.from_bytes(bytes([data[0] & 0x3F]) + data[1:], "big")
    positive = bool(data[0] & 0x40)
    if drops > _MAX_DROPS or not (positive or (signed and drops != 0)):
        raise Malformed
    return ("" if positive else "-") + str(drops)


def _pathset(r: _Reader) -> list[list[dict[str, str]]]:
    paths: list[list[dict[str, str]]] = []
    ended = False
    while not r.end():
        path: list[dict[str, str]] = []
        while not r.end():
            kind = r.u8()
            if kind & ~0x31 or (kind == 0 and not paths and not path):
                raise Malformed
            hop: dict[str, str] = {}
            if kind & 0x01:
                hop["account"] = encode_account(r.read(20))
            currency = _currency(r.read(20)) if kind & 0x10 else None
            if kind & 0x20:
                hop["issuer"] = encode_account(r.read(20))
            if currency is not None:
                hop["currency"] = currency
            path.append(hop)
            if r.peek() in (0x00, 0xFF):
                break
        paths.append(path)
        if r.u8() == 0x00:
            ended = True
            break
    if paths and not ended:
        raise Malformed
    return paths


def _issue(r: _Reader) -> bytes:
    first = r.read(20)
    if _currency(first) == "XRP":
        return first
    issuer = r.read(20)
    return first + issuer + (r.read(4) if issuer == _NO_ACCOUNT else b"")


def _value(r: _Reader, type_code: int, nth: int, depth: int) -> Any:
    if type_code == UINT8:
        value = r.u8()
        if nth == 3 and value not in _RESULTS:
            raise Malformed
        return value
    if type_code == UINT16:
        value = int.from_bytes(r.read(2), "big")
        if nth == 2:
            name = TRANSACTION_TYPES.get(value)
            if name is None:
                raise Malformed
            return name
        if nth == 1 and value not in _LEDGER_ENTRY_TYPES:
            raise Malformed
        return value
    if type_code == UINT32:
        value = int.from_bytes(r.read(4), "big")
        if nth == 52 and value not in _PERMISSIONS:
            raise Malformed
        return value
    if type_code == UINT64:
        data = r.read(8)
        return str(int.from_bytes(data, "big")) if nth in _BASE10_UINT64_CODES else _hex(data)
    if type_code == INT32:
        return int.from_bytes(r.read(4), "big", signed=True)
    if type_code == NUMBER:
        data = r.read(12)
        text = _number_text(data)
        if _number_bytes(text) != data:
            raise Malformed
        return text
    width = {HASH128: 16, HASH160: 20, HASH192: 24, HASH256: 32, CURRENCY: 20}.get(type_code)
    if width is not None:
        data = r.read(width)
        return _currency(data) if type_code == CURRENCY else _hex(data)
    if type_code == AMOUNT:
        return _amount(r, (type_code, nth) == _SIGNED_AMOUNT)
    if type_code == BLOB:
        return _hex(r.read(r.length()))
    if type_code == ACCOUNT:
        data = r.read(r.length())
        if len(data) == 0:
            data = bytes(20)
        if len(data) != 20:
            raise Malformed
        return encode_account(data)
    if type_code == VECTOR256:
        length = r.length()
        if length % 32:
            raise Malformed
        return [_hex(r.read(32)) for _ in range(length // 32)]
    if type_code == PATHSET:
        return _pathset(r)
    if type_code == ISSUE:
        return _hex(_issue(r))
    if type_code == BRIDGE:
        parts = []
        for _ in range(2):
            if r.u8() != 20:
                raise Malformed
            parts.append(r.read(20))
            parts.append(_issue(r))
        return _hex(b"".join(parts))
    if type_code == OBJECT:
        return _object_json(_normal_object(r, depth + 1), depth + 1)
    if type_code == ARRAY:
        return _array_json(_normal_array(r, depth + 1), depth + 1)
    raise Malformed


def _key(type_code: int, nth: int) -> str:
    return _NAMES.get((type_code, nth), f"{type_code}:{nth}")


_VL_TYPES = (BLOB, ACCOUNT, VECTOR256)


def _header(type_code: int, nth: int) -> bytes:
    if type_code < 16 and nth < 16:
        return bytes([type_code << 4 | nth])
    if type_code < 16:
        return bytes([type_code << 4, nth])
    if nth < 16:
        return bytes([nth, type_code])
    return bytes([0, type_code, nth])


def _length_prefix(n: int) -> bytes:
    if n <= 192:
        return bytes([n])
    if n <= 12480:
        n -= 193
        return bytes([193 + (n >> 8), n & 0xFF])
    n -= 12481
    return bytes([241 + (n >> 16), (n >> 8) & 0xFF, n & 0xFF])


def _content(r: _Reader, type_code: int, nth: int, depth: int, empty_account: bool) -> bytes:
    """A field's value as held after reading: its bytes without a length prefix, and objects and arrays in their
    written-back form. An AccountID is 20 bytes, or empty where empty_account says so."""
    if type_code == OBJECT:
        return _normal_object(r, depth + 1)
    if type_code == ARRAY:
        return _normal_array(r, depth + 1)
    if type_code in _VL_TYPES:
        start = r.at
        _value(r, type_code, nth, depth)
        raw = r.data[start : r.at]
        body = _Reader(raw)
        body.length()
        content = raw[body.at :]
        if type_code == ACCOUNT and len(content) != (0 if empty_account else 20):
            raise Malformed
        return content
    start = r.at
    _value(r, type_code, nth, depth)
    return r.data[start : r.at]


# The field values after which an object's Account is written with length 0: TransactionType UNLModify, and the
# PermissionValue that names it.
_UNL_MODIFY = {(UINT16, 2): (102).to_bytes(2, "big"), (UINT32, 52): (103).to_bytes(4, "big")}


def _normal_object(r: _Reader, depth: int) -> bytes:
    """An object's fields, written back: each field's header, length prefix and value, and an end marker after each
    nested object. The fields ascend by type code and then field code; a nested object ends at its end marker, and
    the top-level object at the end of the bytes."""
    if depth > MAX_DEPTH:
        raise Malformed
    out = bytearray()
    last = 0
    unl_modify = False
    closed = False
    while not r.end():
        type_code, nth = r.field()
        if (type_code, nth) == (OBJECT, 1):
            closed = True
            break
        ordinal = type_code << 16 | nth
        if ordinal <= last:
            raise Malformed
        last = ordinal
        content = _content(r, type_code, nth, depth, unl_modify and (type_code, nth) == (ACCOUNT, 1))
        if _UNL_MODIFY.get((type_code, nth)) == content:
            unl_modify = True
        out += _header(type_code, nth)
        out += _length_prefix(len(content)) + content if type_code in _VL_TYPES else content
        if type_code == OBJECT:
            out.append(0xE1)
    if closed == (depth == 0):
        raise Malformed
    return bytes(out)


def _normal_array(r: _Reader, depth: int) -> bytes:
    """An array's object members up to its end marker, written back: each member's header and value, followed by an
    object end marker; then the array end marker."""
    if depth > MAX_DEPTH:
        raise Malformed
    out = bytearray()
    closed = False
    while not r.end():
        type_code, nth = r.field()
        if (type_code, nth) == (ARRAY, 1):
            closed = True
            break
        if type_code != OBJECT:
            raise Malformed
        out += _header(type_code, nth) + _content(r, type_code, nth, depth, False) + b"\xe1"
    if not closed:
        raise Malformed
    return bytes(out + b"\xf1")


def _object_json(data: bytes, depth: int) -> dict[str, Any]:
    """The JSON of an object's written-back fields."""
    r = _Reader(data)
    out: dict[str, Any] = {}
    while not r.end():
        type_code, nth = r.field()
        if (type_code, nth) == (OBJECT, 1):
            break
        out[_key(type_code, nth)] = _value(r, type_code, nth, depth)
    return out


def _array_json(data: bytes, depth: int) -> list[dict[str, Any]]:
    """The JSON of an array's written-back members: each member's header, then the fields that follow it up to an
    object end marker, as an object under the member's name."""
    r = _Reader(data)
    out: list[dict[str, Any]] = []
    while not r.end():
        type_code, nth = r.field()
        if (type_code, nth) == (ARRAY, 1):
            break
        out.append({_key(type_code, nth): _object_json(_normal_object(r, depth + 1), depth + 1)})
    return out


def decode(data: bytes) -> dict[str, Any]:
    """The JSON of a serialized transaction. Raises Malformed for bytes that are not a canonical serialization."""
    r = _Reader(data)
    return _object_json(_normal_object(r, 0), 0)
