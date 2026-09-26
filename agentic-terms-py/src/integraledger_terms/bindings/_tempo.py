"""Tempo's pieces the MPP pairings read and build: the 0x76 transaction's calls, the TIP-20 transferWithMemo calldata,
the TIP-20 channel reserve's descriptor and ids, and the account keychain's key authorizations."""

from dataclasses import dataclass
from typing import Any

from .._keccak import keccak256
from .._types import Refusal
from ._codec import hex_bytes, to_hex
from ._lcp import is_address, normal_hash
from ._mpp_evm import address_word, uint_word
from ._rlp import RlpItem, rlp_bytes, rlp_decode, rlp_list, rlp_uint, rlp_uint_bytes

TRANSFER_WITH_MEMO_SELECTOR = "0x95777d59"
TRANSFER_WITH_MEMO_TOPIC = "0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"
TIP20_CHANNEL_RESERVE = "0x4d50500000000000000000000000000000000000"
ACCOUNT_KEYCHAIN = "0xaaaaaaaa00000000000000000000000000000000"
OPEN_V2_SELECTOR = "0xedc53b00"
OPEN_V1_SELECTOR = "0xc79ea485"

TEMPO_TX_TYPE = 0x76
MAX_WIRE_BYTES = 65_536
_MAX_WIRE_DEPTH = 8
_MAX_CALLS = 64
MAX_KEY_AUTHORIZATION_BYTES = 8192
_MAX_KEY_AUTHORIZATION_DEPTH = 6
_MAX_SCOPES = 16
_CALLS = 4
_VALID_BEFORE = 8
_FEE_TOKEN = 10
_FEE_PAYER_SIGNATURE = 11
_UINT_FIELDS = (0, 1, 2, 3, 6, 7, 8, 9)


@dataclass(frozen=True, slots=True)
class TempoCall:
    to: str | None
    value: int
    input: bytes


@dataclass(frozen=True, slots=True)
class TempoTx:
    chain_id: int
    calls: list[TempoCall]
    valid_before: int | None


def _is_uint(v: object, bits: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << bits


def _envelope(wire: object) -> list[RlpItem] | Refusal:
    """0x76, then an RLP list of 14 items (13 fields and the sender's signature), or 15 when a key authorization
    precedes the signature. At most 64 KiB, RLP depth 8."""
    if not isinstance(wire, bytes):
        return Refusal("tempo/tx-malformed")
    if len(wire) > MAX_WIRE_BYTES:
        return Refusal("tempo/tx-too-large")
    if len(wire) < 2 or wire[0] != TEMPO_TX_TYPE:
        return Refusal("tempo/tx-malformed")
    top = rlp_decode(wire[1:], _MAX_WIRE_DEPTH)
    if top is None or top.items is None:
        return Refusal("tempo/tx-malformed")
    items = top.items
    if len(items) not in (14, 15):
        return Refusal("tempo/tx-malformed")
    for i in _UINT_FIELDS:
        if rlp_uint(items[i]) is None:
            return Refusal("tempo/tx-malformed")
    for i in (_CALLS, 5, 12):
        if not items[i].is_list:
            return Refusal("tempo/tx-malformed")
    if items[_FEE_TOKEN].is_list:
        return Refusal("tempo/tx-malformed")
    if len(items) == 15 and not items[13].is_list:
        return Refusal("tempo/tx-malformed")
    if items[-1].is_list:
        return Refusal("tempo/tx-malformed")
    return items


def decode_tempo_tx(wire: bytes) -> TempoTx | Refusal:
    """The chain id, the calls and valid_before of a signed 0x76 transaction. Each call is rlp([to, value, input]),
    an empty to read as None; valid_before written empty is None. At most 64 calls."""
    items = _envelope(wire)
    if isinstance(items, Refusal):
        return items
    call_list = items[_CALLS].items or []
    if len(call_list) > _MAX_CALLS:
        return Refusal("tempo/tx-malformed")
    calls: list[TempoCall] = []
    for c in call_list:
        if c.items is None or len(c.items) != 3:
            return Refusal("tempo/tx-malformed")
        to, value, data = c.items
        v = rlp_uint(value)
        if to.is_list or data.is_list or v is None:
            return Refusal("tempo/tx-malformed")
        if len(to.data) not in (0, 20):
            return Refusal("tempo/tx-malformed")
        calls.append(TempoCall(to=None if not to.data else to_hex(to.data), value=v, input=bytes(data.data)))
    valid_before = items[_VALID_BEFORE]
    chain_id = rlp_uint(items[0])
    assert chain_id is not None
    return TempoTx(chain_id, calls, None if not valid_before.data else rlp_uint(valid_before))


def memo_calldata(to: object, amount: object, memo: object) -> str | Refusal:
    """transferWithMemo(to, amount, memo) calldata: the selector, then the three 32-byte words."""
    m = normal_hash(memo)
    if not is_address(to) or not _is_uint(amount, 256) or m is None:
        return Refusal("tempo/tx-malformed")
    assert isinstance(to, str) and isinstance(amount, int)
    return TRANSFER_WITH_MEMO_SELECTOR + address_word(to).hex() + uint_word(amount).hex() + m[2:]


def tempo_channel_id(d: Any) -> str | Refusal:
    """The TIP-20 channel reserve's channel id: keccak256(abi.encode(payer, payee, operator, token, salt,
    authorizedSigner, expiringNonceHash, escrow, chainId))."""
    if not isinstance(d, dict):
        return Refusal("tempo/descriptor-mismatch")
    salt, nonce_hash = normal_hash(d.get("salt")), normal_hash(d.get("expiringNonceHash"))
    for k in ("payer", "payee", "operator", "token", "authorizedSigner", "escrow"):
        if not is_address(d.get(k)):
            return Refusal("tempo/descriptor-mismatch")
    chain_id = d.get("chainId")
    if salt is None or nonce_hash is None or isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        return Refusal("tempo/descriptor-mismatch")
    return to_hex(
        keccak256(
            address_word(d["payer"])
            + address_word(d["payee"])
            + address_word(d["operator"])
            + address_word(d["token"])
            + bytes.fromhex(salt[2:])
            + address_word(d["authorizedSigner"])
            + bytes.fromhex(nonce_hash[2:])
            + address_word(d["escrow"])
            + uint_word(chain_id)
        )
    )


def expiring_nonce_hash(signed_tx: bytes, sender: object) -> str | Refusal:
    """keccak256(0x76 ‖ rlp(every envelope field before the sender's signature) ‖ sender). When a fee payer has
    signed, fee_token is written as 0x80 and the fee payer's signature as 0x00, as the sender signed them."""
    items = _envelope(signed_tx)
    if isinstance(items, Refusal):
        return items
    if not is_address(sender):
        return Refusal("tempo/tx-malformed")
    assert isinstance(sender, str)
    fields = [i.raw for i in items[:-1]]
    fee_payer = items[_FEE_PAYER_SIGNATURE]
    if not (not fee_payer.is_list and fee_payer.raw == b"\x80"):
        fields[_FEE_TOKEN] = b"\x80"
        fields[_FEE_PAYER_SIGNATURE] = b"\x00"
    return to_hex(keccak256(bytes([TEMPO_TX_TYPE]) + rlp_list(fields) + bytes.fromhex(sender[2:])))


def encode_key_authorization(a: Any, signature: str | None = None) -> bytes | Refusal:
    """rlp([chain_id, key_type, key_id, expiry, limits, allowed_calls, witness]); with a signature,
    rlp([that list, signature]). At most 16 limits and 16 scopes, 16 selector rules each and 16 recipients each."""
    bad = Refusal("tempo/key-authorization-malformed")
    if not isinstance(a, dict):
        return bad
    witness = normal_hash(a.get("witness"))
    if not _is_uint(a.get("chainId"), 64) or not _is_uint(a.get("expiry"), 64) or witness is None:
        return bad
    if not is_address(a.get("keyId")) or a.get("keyType") not in (0, 1, 2) or isinstance(a.get("keyType"), bool):
        return bad
    limits_in, calls_in = a.get("limits"), a.get("allowedCalls")
    if not isinstance(limits_in, list) or len(limits_in) > _MAX_SCOPES:
        return bad
    if not isinstance(calls_in, list) or len(calls_in) > _MAX_SCOPES:
        return bad
    limits: list[bytes] = []
    for lim in limits_in:
        if not is_address(lim.get("token")) or not _is_uint(lim.get("limit"), 256) or not _is_uint(lim.get("period"), 64):
            return bad
        limits.append(rlp_list([rlp_bytes(bytes.fromhex(lim["token"][2:])), rlp_uint_bytes(lim["limit"]), rlp_uint_bytes(lim["period"])]))
    scopes: list[bytes] = []
    for s in calls_in:
        rules_in = s.get("selectorRules")
        if not is_address(s.get("target")) or not isinstance(rules_in, list) or len(rules_in) > _MAX_SCOPES:
            return bad
        rules: list[bytes] = []
        for r in rules_in:
            selector = hex_bytes(r.get("selector"))
            recipients = r.get("recipients")
            if selector is None or len(selector) != 4:
                return bad
            if not isinstance(recipients, list) or len(recipients) > _MAX_SCOPES or not all(is_address(x) for x in recipients):
                return bad
            rules.append(rlp_list([rlp_bytes(selector), rlp_list([rlp_bytes(bytes.fromhex(x[2:])) for x in recipients])]))
        scopes.append(rlp_list([rlp_bytes(bytes.fromhex(s["target"][2:])), rlp_list(rules)]))
    authorization = rlp_list(
        [
            rlp_uint_bytes(a["chainId"]),
            rlp_uint_bytes(a["keyType"]),
            rlp_bytes(bytes.fromhex(a["keyId"][2:])),
            rlp_uint_bytes(a["expiry"]),
            rlp_list(limits),
            rlp_list(scopes),
            rlp_bytes(bytes.fromhex(witness[2:])),
        ]
    )
    if len(authorization) > MAX_KEY_AUTHORIZATION_BYTES:
        return bad
    if signature is None:
        return authorization
    sig = hex_bytes(signature)
    if sig is None or len(sig) == 0 or len(sig) > MAX_KEY_AUTHORIZATION_BYTES:
        return bad
    signed = rlp_list([authorization, rlp_bytes(sig)])
    return bad if len(signed) > MAX_KEY_AUTHORIZATION_BYTES else signed


def _within_scopes(item: RlpItem, calls: bool) -> bool:
    """A list of at most 16 entries; for allowed_calls, also at most 16 rules per scope and 16 recipients per rule."""
    if item.items is None:
        return len(item.data) == 0
    if len(item.items) > _MAX_SCOPES:
        return False
    if not calls:
        return True
    for scope in item.items:
        if scope.items is None or len(scope.items) != 2:
            return False
        rules = scope.items[1]
        if rules.items is None or len(rules.items) > _MAX_SCOPES:
            return False
        for rule in rules.items:
            if rule.items is None or len(rule.items) != 2:
                return False
            recipients = rule.items[1]
            if recipients.items is None or len(recipients.items) > _MAX_SCOPES:
                return False
    return True


@dataclass(frozen=True, slots=True)
class KeyAuthorization:
    digest: str
    key_id: str
    witness: str | None


def decode_key_authorization(signed: object) -> KeyAuthorization | Refusal:
    """A signed key authorization: an RLP list of the authorization (3 to 9 items) and a byte-string signature. The
    digest is keccak256 over the authorization's bytes as received; the witness is item 6, 32 bytes, when present."""
    bad = Refusal("tempo/key-authorization-malformed")
    if not isinstance(signed, str) or len(signed) > 2 + 2 * MAX_KEY_AUTHORIZATION_BYTES:
        return bad
    b = hex_bytes(signed)
    if b is None or len(b) > MAX_KEY_AUTHORIZATION_BYTES:
        return bad
    top = rlp_decode(b, _MAX_KEY_AUTHORIZATION_DEPTH)
    if top is None or top.items is None or len(top.items) != 2:
        return bad
    auth, sig = top.items
    if auth.items is None or sig.is_list or not 3 <= len(auth.items) <= 9:
        return bad
    key_id = auth.items[2]
    if key_id.is_list or len(key_id.data) != 20:
        return bad
    if rlp_uint(auth.items[0]) is None or rlp_uint(auth.items[1]) is None:
        return bad
    for i in (4, 5):
        if i < len(auth.items) and not _within_scopes(auth.items[i], i == 5):
            return bad
    witness: str | None = None
    if len(auth.items) > 6:
        w = auth.items[6]
        if w.is_list or len(w.data) not in (0, 32):
            return bad
        if len(w.data) == 32:
            witness = to_hex(w.data)
    return KeyAuthorization(digest=to_hex(keccak256(auth.raw)), key_id=to_hex(key_id.data), witness=witness)
