"""The request checks of every MPP (intent, method) a challenge may name, each naming the pairings the challenge
offers, and the value checks they share: decimal strings, positive integers, RFC 3339 times, strict base64url JSON,
Solana keys, XRPL and Stellar forms, and each method's network names."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .._types import Refusal
from ._bolt11 import FIELD
from ._bolt11 import decode as decode_invoice
from ._codec import b58_decode, b64u_decode, b64u_encode, canonical_or_none, utf16_key
from ._jose import js_length, parse_json, within_depth
from ._lcp import is_address, is_list, is_object, uint256_of
from ._native_usdc import NATIVE_USDC
from ._stacks import is_canonical_principal
from ._svm import TOKEN, TOKEN_2022, built_version
from ._xrpl_codec import account_id_of

Obj = Mapping[str, Any]
PairingCheck = Callable[[Obj, Obj, Obj], "list[str] | Refusal"]

MAX_DECODED = 8192
# A member's value where the member is absent, as no JSON value is.
_ABSENT = object()
# The depth MPP holds a decoded object or an echoed challenge to, as the protocol package's MPP reads hold them.
MAX_JSON_DEPTH = 16
MAX_SAFE_INTEGER = 2**53 - 1
UINT256_LIMIT = 2**256
U64_LIMIT = 2**64

_DECIMAL = re.compile(r"[0-9]{1,78}")
_POSITIVE = re.compile(r"[1-9][0-9]{0,77}")
_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})[Tt]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(?:([Zz])|([+-])([0-9]{2}):([0-9]{2}))"
)
_PERIOD_COUNT = re.compile(r"[1-9][0-9]{0,15}")
_PAYMENT_HASH = re.compile(r"[0-9a-f]{64}")
_CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
_XRPL_AMOUNT = re.compile(r"(?:0|[1-9][0-9]{0,39})(?:\.[0-9]{1,40})?")
_XRPL_ZERO = re.compile(r"[0.]+")
_XRPL_DROPS = re.compile(r"0|[1-9][0-9]{0,19}")
_XRPL_ADDRESS = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
_XRPL_CURRENCY = re.compile(r"(?:[A-Za-z0-9?!@#$%^&*<>(){}\[\]|]{3}|[0-9A-Fa-f]{40})")
_XRPL_MPT = re.compile(r"[0-9A-Fa-f]{48}")
_HEX64 = re.compile(r"[0-9A-Fa-f]{64}")
_STACKS_CHAIN = re.compile(r"(?:0|[1-9][0-9]{0,9})")
_STACKS_NAME = re.compile(r"[a-zA-Z](?:[a-zA-Z0-9]|[-_])*")
_C32_PRINCIPAL = re.compile(r"S[0-9A-HJKMNP-TV-Z]{38,40}")
_EVM_MAX_SPLITS = 10
_MAX_MEMO_BYTES = 566

EVM_CREDENTIAL_TYPES: Mapping[str, str] = {
    "permit2": "mpp/charge/evm/permit2",
    "authorization": "mpp/charge/evm/authorization",
    "transaction": "mpp/charge/evm/transaction",
    "hash": "mpp/charge/evm/hash",
}

# MPP Solana's network names and their CAIP-2 identifiers; localnet has none.
SOLANA_NETWORKS: Mapping[str, str | None] = {
    "mainnet": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "devnet": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    "localnet": None,
}

# MPP XRPL's network names and their CAIP-2 identifiers.
XRPL_NETWORKS: Mapping[str, str] = {"mainnet": "xrpl:0", "testnet": "xrpl:1", "devnet": "xrpl:2"}

# MPP Hedera's chain ids and their CAIP-2 networks.
HEDERA_CHAIN_IDS: Mapping[int, str] = {295: "hedera:mainnet", 296: "hedera:testnet"}

# The profiles usdc's methodDetails.type names, and the pairing each one is.
USDC_PROFILES: Mapping[str, str] = {
    "evm": "mpp/charge/usdc/evm",
    "solana": "mpp/charge/usdc/solana",
    "stacks": "mpp/charge/usdc/stacks",
    "gateway": "mpp/charge/usdc/gateway",
}

# Stripe metadata: at most 50 keys, key names at most 40 characters without square brackets, values at most 500.
STRIPE_METADATA_KEYS = 50
STRIPE_METADATA_KEY_LENGTH = 40
STRIPE_METADATA_VALUE_LENGTH = 500


# ── Values.


def is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def positive_int(value: object) -> int | None:
    """A JSON number holding a safe integer above zero, as an int; None otherwise."""
    if not is_number(value):
        return None
    assert isinstance(value, (int, float))
    if isinstance(value, float) and not value.is_integer():
        return None
    number = int(value)
    return number if 0 < number <= MAX_SAFE_INTEGER else None


def is_decimal(value: object) -> bool:
    """A string of 1 to 78 decimal digits below 2^256."""
    return isinstance(value, str) and _DECIMAL.fullmatch(value) is not None and int(value) < UINT256_LIMIT


def is_u64_positive(value: object) -> bool:
    return isinstance(value, str) and _DECIMAL.fullmatch(value) is not None and 0 < int(value) < U64_LIMIT


def is_drops(value: object) -> bool:
    """A u64 in decimal, as an XRP amount in drops is written: no sign, point or leading zero."""
    return isinstance(value, str) and _XRPL_DROPS.fullmatch(value) is not None and int(value) < U64_LIMIT


def is_key(value: object) -> bool:
    """A Solana key: 32 to 44 base58 characters decoding to 32 bytes."""
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return False
    decoded = b58_decode(value)
    return decoded is not None and len(decoded) == 32


def is_caip2(value: object) -> bool:
    return isinstance(value, str) and _CAIP2.fullmatch(value) is not None


def _civil_days(y: int, m: int, d: int) -> int:
    """Days from 1970-01-01 to the given civil date (proleptic Gregorian)."""
    yy = y - 1 if m <= 2 else y
    era = yy // 400
    yoe = yy - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def unix_of(text: object) -> int | None:
    """An RFC 3339 date-time as unix seconds, the fraction dropped. Seconds 60 and out-of-range fields are None."""
    match = _RFC3339.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        return None
    y, mo, d, hh, mm, ss = (int(match.group(k)) for k in range(1, 7))
    if mo < 1 or mo > 12 or hh > 23 or mm > 59 or ss > 59:
        return None
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    if d < 1 or d > days:
        return None
    offset = 0
    if match.group(7) is None:
        oh, om = int(match.group(9)), int(match.group(10))
        if oh > 23 or om > 59:
            return None
        offset = (-1 if match.group(8) == "-" else 1) * (oh * 3600 + om * 60)
    return _civil_days(y, mo, d) * 86400 + hh * 3600 + mm * 60 + ss - offset



def decode_object(text: object) -> dict[str, Any] | None:
    """The JSON object a strict base64url-nopad value holds: at most 8 KiB, UTF-8, depth 16, serialisable."""
    raw = b64u_decode(text, MAX_DECODED)
    if raw is None:
        return None
    try:
        value = parse_json(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return None
    if not isinstance(value, dict) or not within_depth(value, MAX_JSON_DEPTH):
        return None
    if canonical_or_none(value) is None:
        return None
    return value


def decode_string_map(text: object) -> dict[str, str] | None:
    """A decoded opaque: a flat string-to-string map."""
    value = decode_object(text)
    if value is None or not all(isinstance(v, str) for v in value.values()):
        return None
    return value


# ── Each method's network names.


def solana_network_of(details: Obj, required: bool) -> str | None | Refusal:
    """The CAIP-2 network of MPP Solana's methodDetails.network (absent: mainnet unless required), None for
    localnet."""
    if "network" not in details and not required:
        return SOLANA_NETWORKS["mainnet"]
    n = details.get("network")
    if not isinstance(n, str) or n not in SOLANA_NETWORKS:
        return Refusal("svm/network-malformed")
    return SOLANA_NETWORKS[n]


def xrpl_network_of(details: Obj) -> str | Refusal:
    """The CAIP-2 network of MPP XRPL's methodDetails.network, which has no default."""
    if "network" not in details:
        return Refusal("xrpl/network-missing")
    n = details["network"]
    if not isinstance(n, str) or n not in XRPL_NETWORKS:
        return Refusal("xrpl/network-malformed")
    return XRPL_NETWORKS[n]


def hedera_network_of_chain_id(chain_id: object) -> str | Refusal:
    """The CAIP-2 network of an MPP methodDetails.chainId: 295 and 296 only."""
    if not is_number(chain_id) or chain_id not in HEDERA_CHAIN_IDS:
        return Refusal("hedera/chain-id-unnamed")
    assert isinstance(chain_id, (int, float))
    return HEDERA_CHAIN_IDS[int(chain_id)]


def hedera_session_network_of(details: Obj) -> str | Refusal:
    """The network of an MPP Hedera session's methodDetails.chainId (absent or null: 295)."""
    chain_id = details.get("chainId")
    return hedera_network_of_chain_id(295 if chain_id is None else chain_id)


def stacks_network_of(details: Obj) -> str | None:
    """The CAIP-2 network of a usdc Stacks profile: stacks: and its chainId."""
    p = details.get("stacks")
    chain_id = p.get("chainId") if is_object(p) else None
    return f"stacks:{chain_id}" if isinstance(chain_id, str) and _STACKS_CHAIN.fullmatch(chain_id) else None


# ── charge and session on EVM and Tempo, subscription on Tempo, Lightning.


def _has(o: Obj, key: str) -> bool:
    return key in o


def evm_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if (
        positive_int(d.get("chainId")) is None
        or not is_address(r.get("currency"))
        or not is_address(r.get("recipient"))
        or not is_decimal(r.get("amount"))
    ):
        return Refusal("mpp/request-malformed")
    listed: list[str]
    if not _has(d, "credentialTypes"):
        listed = ["mpp/charge/evm/transaction", "mpp/charge/evm/hash"]
    else:
        types = d["credentialTypes"]
        if not is_list(types) or len(types) == 0:
            return Refusal("mpp/credential-types")
        listed = []
        for t in types:
            p = EVM_CREDENTIAL_TYPES.get(t) if isinstance(t, str) else None
            if p is None:
                return Refusal("mpp/credential-types")
            if p not in listed:
                listed.append(p)
    if _has(d, "splits"):
        splits = d["splits"]
        if not is_list(splits) or not 1 <= len(splits) <= _EVM_MAX_SPLITS:
            return Refusal("mpp/splits-malformed")
        for s in splits:
            if not is_object(s) or not is_address(s.get("recipient")) or not is_decimal(s.get("amount")):
                return Refusal("mpp/splits-malformed")
        listed = [p for p in listed if p == "mpp/charge/evm/permit2"]
    if not listed:
        return Refusal("mpp/credential-types")
    # The Permit2 build writes permit2Address as the verifying contract and externalId into the signed witness; without
    # expires no Permit2 pairing is offered.
    if "mpp/charge/evm/permit2" in listed and "expires" in c:
        if _has(d, "permit2Address") and not is_address(d["permit2Address"]):
            return Refusal("mpp/request-malformed")
        if _has(r, "externalId") and not isinstance(r["externalId"], str):
            return Refusal("mpp/request-malformed")
        # permit2 pays the recipient amount less the splits, which must be above zero (MPP's EVM charge: the splits'
        # sum "MUST be strictly less than amount"); where it is not, permit2 is left out, and a challenge left with no
        # pairing is mpp/input-malformed, the code its build gives.
        split = sum(int(s["amount"]) for s in d["splits"]) if _has(d, "splits") else 0
        if int(r["amount"]) - split <= 0:
            listed = [p for p in listed if p != "mpp/charge/evm/permit2"]
            if not listed:
                return Refusal("mpp/input-malformed")
    return listed


def tempo_charge_pairings(r: Obj, d: Obj, c: Obj, carried: bool = False) -> list[str] | Refusal:
    """charge on tempo (profile mpp/charge/tempo/split-memo, rules 2 to 4): currency and recipient addresses and amount
    a decimal, else mpp/request-malformed; methodDetails.chainId a positive integer, else mpp/chain-id-required, since
    the draft reads an absent one as Moderato; methodDetails.zones present is mpp/zones-not-served, and
    machineTokenEnabled other than absent or false is mpp/machine-token-enabled; a zero amount names no pairing, its
    payment being an off-chain proof that moves nothing; methodDetails.memo present is mpp/carrier-taken. The forms are
    read from supportedModes alone, absent being pull and push: pull names mpp/charge/tempo/split-memo, push
    mpp/charge/tempo/split-memo/push; a list that is not of those two, or is empty, is mpp/request-malformed, as is a
    feePayer that is not a boolean. splits reads as tempo_splits reads them. The split carrying H is the one whose memo
    is the H the challenge's id carries: there is at most one, and it is {recipient, amount: 1, memo: H} with the
    request's own recipient, else mpp/split-not-placed; with carried (a challenge as placed, or echoed) it is required.
    Beside it the seller's own splits number at most nine, else mpp/splits-malformed, and the primary transfer, amount
    less every split and the one that carries H, must be above zero, else mpp/input-malformed."""
    from ._mpp import challenge_id_h

    if not is_address(r.get("currency")) or not is_address(r.get("recipient")) or not is_decimal(r.get("amount")):
        return Refusal("mpp/request-malformed")
    if positive_int(d.get("chainId")) is None:
        return Refusal("mpp/chain-id-required")
    if _has(d, "zones"):
        return Refusal("mpp/zones-not-served")
    if _has(d, "machineTokenEnabled") and d["machineTokenEnabled"] is not False:
        return Refusal("mpp/machine-token-enabled")
    if int(r["amount"]) == 0:
        return []
    if _has(d, "memo"):
        return Refusal("mpp/carrier-taken")
    modes = d.get("supportedModes")
    if _has(d, "supportedModes") and (
        not is_list(modes) or len(modes) == 0 or not all(isinstance(m, str) and m in ("pull", "push") for m in modes)
    ):
        return Refusal("mpp/request-malformed")
    if _has(d, "feePayer") and not isinstance(d["feePayer"], bool):
        return Refusal("mpp/request-malformed")
    splits = tempo_splits(d)
    if isinstance(splits, Refusal):
        return splits
    h = challenge_id_h(c) if isinstance(c.get("id"), str) else None
    carrier = (
        [s for s in splits or [] if s.memo is not None and s.memo.lower() == h.lower()] if isinstance(h, str) else []
    )
    if len(carrier) > 1:
        return Refusal("mpp/split-not-placed")
    placed = carrier[0] if carrier else None
    if placed is not None and (placed.to.lower() != str(r["recipient"]).lower() or placed.amount != 1):
        return Refusal("mpp/split-not-placed")
    if carried and placed is None:
        return Refusal("mpp/split-not-placed")
    own = [s for s in splits or [] if s is not placed]
    if len(own) > _MAX_TEMPO_SPLITS - 1:
        return Refusal("mpp/splits-malformed")
    if int(r["amount"]) - sum((s.amount for s in own), 1) <= 0:
        return Refusal("mpp/input-malformed")
    out: list[str] = []
    if modes is None or "pull" in modes:
        out.append("mpp/charge/tempo/split-memo")
    if modes is None or "push" in modes:
        out.append("mpp/charge/tempo/split-memo/push")
    return out


_MAX_TEMPO_SPLITS = 10
_BYTES32_HEX = re.compile(r"0x[0-9a-fA-F]{64}")


@dataclass(frozen=True, slots=True)
class TempoSplit:
    """A Tempo charge split: the recipient, the amount and, when present, the memo."""

    to: str
    amount: int
    memo: str | None


def tempo_splits(d: Obj) -> list[TempoSplit] | None | Refusal:
    """A Tempo charge's methodDetails.splits, as draft-tempo-charge-00's Split Payments section gives them: absent, or 1
    to 10 entries, each an address recipient, a decimal amount above zero and below 2^256 and, when present, a bytes32
    hex memo; otherwise mpp/splits-malformed."""
    if not _has(d, "splits"):
        return None
    splits = d["splits"]
    if not is_list(splits) or not 1 <= len(splits) <= _MAX_TEMPO_SPLITS:
        return Refusal("mpp/splits-malformed")
    out: list[TempoSplit] = []
    for s in splits:
        if not is_object(s) or not is_address(s.get("recipient")) or not is_decimal(s.get("amount")):
            return Refusal("mpp/splits-malformed")
        amount = int(s["amount"])
        if amount == 0:
            return Refusal("mpp/splits-malformed")
        memo = s.get("memo")
        if _has(s, "memo") and (not isinstance(memo, str) or _BYTES32_HEX.fullmatch(memo) is None):
            return Refusal("mpp/splits-malformed")
        out.append(TempoSplit(s["recipient"], amount, memo if isinstance(memo, str) else None))
    return out


def evm_session_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if _has(d, "channelId") or _has(d, "sessionSnapshot"):
        return Refusal("mpp/channel-named")
    if not is_address(d.get("escrowContract")):
        return Refusal("mpp/escrow-malformed")
    if positive_int(d.get("chainId")) is None:
        return Refusal("mpp/chain-id-required")
    if not is_address(r.get("currency")) or not is_address(r.get("recipient")):
        return Refusal("mpp/request-malformed")
    # The pairing is an opening the seller's settler submits, funded by an authorization or a permit2; an opening funded
    # by a hash, a transaction the buyer's client broadcasts, is no part of it and is not offered. So the challenge names
    # credentialTypes, without hash, since an absent member admits hash (draft-evm-session-00 reads it as ["hash"]).
    types = d.get("credentialTypes")
    if not is_list(types) or len(types) == 0:
        return Refusal("mpp/credential-types")
    if not all(isinstance(t, str) and t in ("permit2", "authorization") for t in types):
        return Refusal("mpp/credential-types")
    # The Permit2 opening signs permit2Contract as the verifying contract.
    if "permit2" in types and _has(d, "permit2Contract") and not is_address(d["permit2Contract"]):
        return Refusal("mpp/request-malformed")
    return ["mpp/session/evm"]


def tempo_session_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if _has(d, "channelId") or _has(d, "sessionSnapshot"):
        return Refusal("mpp/channel-named")
    if _has(d, "sessionProtocol") and d["sessionProtocol"] not in ("v1", "v2"):
        return Refusal("mpp/session-protocol")
    if d.get("sessionProtocol") == "v2" and (not _has(d, "chainId") or not _has(d, "escrowContract")):
        return Refusal("mpp/chain-id-required")
    if _has(d, "chainId") and positive_int(d["chainId"]) is None:
        return Refusal("mpp/chain-id-required")
    if not is_address(d.get("escrowContract")):
        return Refusal("mpp/escrow-malformed")
    if _has(d, "operator") and not is_address(d["operator"]):
        return Refusal("mpp/request-malformed")
    if not is_address(r.get("currency")) or not is_address(r.get("recipient")):
        return Refusal("mpp/request-malformed")
    return ["mpp/session/tempo"]


def subscription_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    """subscription on tempo: an access key with an address and a key type Tempo defines; subscriptionExpires an RFC
    3339 date-time from 1970, the key authorization's uint64 expiry; chainId a positive safe integer; currency and
    recipient addresses and amount a decimal; and a period of 1 to 10^16 - 1 days or weeks that is below 2^64 seconds,
    the key authorization's uint64 period. Else mpp/request-malformed."""
    key = d.get("accessKey")
    if not is_object(key) or not is_address(key.get("accessKeyAddress")):
        return Refusal("mpp/access-key-malformed")
    if key.get("keyType") not in ("p256", "secp256k1", "webAuthn") or not isinstance(key.get("keyType"), str):
        return Refusal("mpp/access-key-malformed")
    until = unix_of(r["subscriptionExpires"]) if isinstance(r.get("subscriptionExpires"), str) else None
    if until is None or until < 0:
        return Refusal("mpp/request-malformed")
    if positive_int(d.get("chainId")) is None:
        return Refusal("mpp/chain-id-required")
    if not is_address(r.get("currency")) or not is_address(r.get("recipient")) or not is_decimal(r.get("amount")):
        return Refusal("mpp/request-malformed")
    if r.get("periodUnit") not in ("day", "week") or not isinstance(r.get("periodUnit"), str):
        return Refusal("mpp/request-malformed")
    count = r.get("periodCount")
    if not isinstance(count, str) or _PERIOD_COUNT.fullmatch(count) is None:
        return Refusal("mpp/request-malformed")
    if subscription_period(r) >= 2**64:
        return Refusal("mpp/request-malformed")
    return ["mpp/subscription/tempo"]


def subscription_period(r: Obj) -> int:
    """A Tempo subscription request's period in seconds: periodCount days or weeks, as periodUnit names."""
    return int(r["periodCount"]) * (604_800 if r.get("periodUnit") == "week" else 86_400)


# MPP Lightning's network names and the BOLT11 currency of each.
LN_CURRENCIES: Mapping[str, str] = {"mainnet": "bc", "signet": "tbs", "regtest": "bcrt"}


def lightning_pairings(pairing: str, carried: bool = False) -> PairingCheck:
    """Lightning: the payment hash as 64 lower-case hex digits, in methodDetails (charge) or in request (session); the
    request without a description; and methodDetails.network, when present, a network MPP Lightning defines, else
    ln/currency-network. The invoice (methodDetails.invoice, or the session's depositInvoice), when present, is a string
    that decodes as BOLT11 with one h field (else mpp/carrier-not-challenge, the code its comparison with H gives) and no
    d field (ln/description-inline), whose payment hash is the request's (ln/payment-hash-mismatch), whose currency is
    the one network names, when it names one (ln/currency-network), and whose expiry is no earlier than expires, when
    the challenge carries one (ln/expires-after-invoice). The seller's node writes the invoice after the hash, so
    pairings_of takes a challenge without it; with carried, the check of a placed challenge, one without it that passes
    the checks that do not read the invoice is ln/invoice-malformed. amount and currency are not read."""
    charge = pairing == "mpp/charge/lightning"

    def check(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
        h = d.get("paymentHash") if charge else r.get("paymentHash")
        if not isinstance(h, str) or _PAYMENT_HASH.fullmatch(h) is None:
            return Refusal("ln/payment-hash-required")
        holder, key = (d, "invoice") if charge else (r, "depositInvoice")
        if _has(holder, key) and not isinstance(holder[key], str):
            return Refusal("mpp/request-malformed")
        network = d.get("network")
        currency = LN_CURRENCIES.get(network) if isinstance(network, str) else None
        if not _has(holder, key):
            if _has(r, "description"):
                return Refusal("ln/description-present")
            if _has(d, "network") and currency is None:
                return Refusal("ln/currency-network")
            return Refusal("ln/invoice-malformed") if carried else [pairing]
        b = decode_invoice(holder[key])
        if isinstance(b, Refusal):
            return b
        if b.tags.count(FIELD["h"]) != 1:
            return Refusal("mpp/carrier-not-challenge")
        if FIELD["d"] in b.tags:
            return Refusal("ln/description-inline")
        if _has(r, "description"):
            return Refusal("ln/description-present")
        if b.payment_hash.hex() != h:
            return Refusal("ln/payment-hash-mismatch")
        if _has(d, "network") and currency != b.currency:
            return Refusal("ln/currency-network")
        expires = unix_of(c["expires"]) if "expires" in c else None
        if expires is not None and expires > b.timestamp + b.expiry:
            return Refusal("ln/expires-after-invoice")
        return [pairing]

    return check


# ── charge and session on Hedera, Solana, Stellar, XRPL and NEAR Intents.


def is_external_id(r: Obj) -> bool:
    """A charge request's externalId as NEAR Intents carries it: absent or a string."""
    return "externalId" not in r or isinstance(r["externalId"], str)


def is_solana_external_id(r: Obj) -> bool:
    """MPP Solana's externalId, which the payer signs as a memo: absent, or a string of at most 566 bytes."""
    if "externalId" not in r:
        return True
    ext = r["externalId"]
    return isinstance(ext, str) and len(ext.encode("utf-8")) <= _MAX_MEMO_BYTES


def is_xrpl_invoice_id(d: Obj) -> bool:
    """MPP XRPL's methodDetails.invoiceId: absent, or 64 hex digits."""
    if "invoiceId" not in d:
        return True
    inv = d["invoiceId"]
    return isinstance(inv, str) and _HEX64.fullmatch(inv) is not None


def solana_charge_pairings(r: Obj, d: Obj, c: Obj | None = None) -> list[str] | Refusal:
    network = solana_network_of(d, False)
    if isinstance(network, Refusal):
        return network
    currency = r.get("currency")
    if not is_u64_positive(r.get("amount")) or not (currency == "sol" or is_key(currency)) or not is_key(r.get("recipient")):
        return Refusal("mpp/request-malformed")
    if not is_solana_external_id(r):
        return Refusal("mpp/request-malformed")
    if _has(d, "feePayer") and not isinstance(d["feePayer"], bool):
        return Refusal("mpp/request-malformed")
    if d.get("feePayer") is True and not is_key(d.get("feePayerKey")):
        return Refusal("mpp/request-malformed")
    # What build reads of methodDetails in place of its own inputs, in the form it builds with: no splits and no
    # confidential transfer, which it does not build; a transactionVersions that admits a version (built_version:
    # absent, or a non-empty array of the integers 0 and 1); a recentBlockhash that is a string is a key; and, for a
    # mint, a decimals that is a number is an integer from 0 to 255, and a tokenProgram that is a string is Token or
    # Token-2022.
    if _has(d, "splits") or d.get("confidential") is True:
        return Refusal("svm/input-malformed")
    if built_version(d) is None:
        return Refusal("svm/input-malformed")
    if isinstance(d.get("recentBlockhash"), str) and not is_key(d["recentBlockhash"]):
        return Refusal("svm/input-malformed")
    if currency != "sol":
        decimals = d.get("decimals")
        if is_number(decimals) and not _is_byte(decimals):
            return Refusal("svm/input-malformed")
        program = d.get("tokenProgram")
        if isinstance(program, str) and program not in (TOKEN, TOKEN_2022):
            return Refusal("svm/input-malformed")
    # A challenge whose methodDetails.feePayer is true names mpp/charge/solana: the stock client refuses to broadcast
    # under it from @solana/mpp 0.6.0 (src/client/Charge.ts:79-83 at 0.7.0). Any other names
    # mpp/charge/solana/unsponsored, whose payer can broadcast.
    return ["mpp/charge/solana"] if d.get("feePayer") is True else ["mpp/charge/solana/unsponsored"]


def _is_byte(value: object) -> bool:
    """An integer from 0 to 255, as a JSON number reads: 8 and 8.0 alike."""
    return (isinstance(value, int) or (isinstance(value, float) and value.is_integer())) and 0 <= value <= 255


def is_xrpl_address(value: object) -> bool:
    return isinstance(value, str) and _XRPL_ADDRESS.fullmatch(value) is not None


# An XRPL asset as a charge request's currency names it: XRP, an issued currency, or an MPT.
XrplCurrency = str | dict[str, str]


def _issued_or_mpt(value: object) -> XrplCurrency | None:
    """An issued currency {currency, issuer} or an MPT {mpt_issuance_id}, each part held to its form, exactly those
    members."""
    if not is_object(value):
        return None
    keys = ",".join(sorted(value.keys(), key=utf16_key))
    if keys == "currency,issuer":
        cur, issuer = value.get("currency"), value.get("issuer")
        ok = isinstance(cur, str) and _XRPL_CURRENCY.fullmatch(cur) is not None and cur != "XRP"
        return {"currency": cur, "issuer": issuer} if ok and is_xrpl_address(issuer) else None  # type: ignore[dict-item]
    mpt = value.get("mpt_issuance_id")
    ok = keys == "mpt_issuance_id" and isinstance(mpt, str) and _XRPL_MPT.fullmatch(mpt) is not None
    return {"mpt_issuance_id": mpt} if ok else None  # type: ignore[dict-item]


def xrpl_currency_of(value: object) -> XrplCurrency | None:
    """A charge request's currency, a string as MPP's XRPL schema has it (xrpl-mpp-sdk 0.1.0-beta.4,
    dist/chunk-L6LVAN2P.js:17-90, currency: z.string()), in the forms its parseCurrency reads
    (dist/chunk-JQG7ATQA.js:170-183): "XRP"; a JSON text of an issued currency {currency, issuer} or an MPT
    {mpt_issuance_id}; or CUR:issuer, one colon. Each part is held to its form. None for any other value, an object
    among them, which the stock schema refuses."""
    if not isinstance(value, str):
        return None
    if value == "XRP":
        return "XRP"
    if value.startswith("{"):
        return _issued_or_mpt(parse_json(value))
    parts = value.split(":")
    return _issued_or_mpt({"currency": parts[0], "issuer": parts[1]}) if len(parts) == 2 else None


def is_xrpl_memos(d: Obj) -> bool:
    """A charge request's methodDetails.memos, as MPP's XRPL schema has it (dist/chunk-L6LVAN2P.js:17-90): absent, or
    an array of objects whose only members are the optional strings type, format and data."""
    if "memos" not in d:
        return True
    memos = d["memos"]
    return is_list(memos) and all(
        is_object(m) and all(k in ("type", "format", "data") and isinstance(v, str) for k, v in m.items()) for m in memos
    )


def _is_uint32(value: object) -> bool:
    if not is_number(value):
        return False
    assert isinstance(value, (int, float))
    return (not isinstance(value, float) or value.is_integer()) and 0 <= value <= 0xFFFFFFFF


def xrpl_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    network = xrpl_network_of(d)
    if isinstance(network, Refusal):
        return network
    amount = r.get("amount")
    currency = xrpl_currency_of(r.get("currency"))
    if (
        not is_xrpl_address(r.get("recipient"))
        or currency is None
        or not isinstance(amount, str)
        or _XRPL_AMOUNT.fullmatch(amount) is None
        or _XRPL_ZERO.fullmatch(amount) is not None
        or (currency == "XRP" and not is_u64_positive(amount))
    ):
        return Refusal("mpp/request-malformed")
    if not is_xrpl_invoice_id(d):
        return Refusal("mpp/request-malformed")
    for k in ("destinationTag", "sourceTag"):
        if _has(d, k) and not _is_uint32(d[k]):
            return Refusal("mpp/request-malformed")
    # The stock schema's memos, which build writes.
    if not is_xrpl_memos(d):
        return Refusal("mpp/request-malformed")
    return ["mpp/charge/xrpl"]


def near_intents_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    """methodDetails.originNetwork CAIP-2, which network() returns, and externalId, where H rides, absent or a string.
    No other request member is read."""
    if not is_caip2(d.get("originNetwork")) or not is_external_id(r):
        return Refusal("mpp/request-malformed")
    return ["mpp/charge/nearintents"]


def hedera_session_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if _has(d, "channelId"):
        return Refusal("mpp/channel-named")
    network = hedera_session_network_of(d)
    if isinstance(network, Refusal):
        return network
    if not is_address(r.get("currency")) or not is_address(r.get("recipient")) or not is_address(d.get("escrowContract")):
        return Refusal("mpp/request-malformed")
    return ["mpp/session/hedera/stock"]


def solana_session_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if _has(d, "channelId"):
        return Refusal("mpp/channel-named")
    network = solana_network_of(d, True)
    if isinstance(network, Refusal):
        return network
    signer = d.get("voucherSigner")
    if (
        not is_key(d.get("channelProgram"))
        or not is_key(r.get("currency"))
        or not is_key(r.get("recipient"))
        or not is_key(d.get("recentBlockhash"))
        or not is_decimal(d.get("recentSlot"))
        or not (
            not _has(d, "voucherSigner")
            or signer == "client"
            or (signer == "operator" and is_key(d.get("operator")))
        )
    ):
        return Refusal("svm/input-malformed")
    return ["mpp/session/solana"]


def xrpl_session_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    """session on xrpl: channelId absent or ""; network named; currency absent or "XRP"; a classic recipient whose
    checksum holds, as the channel id build derives reads it; amount a u64 in drops, written in decimal with no sign,
    point or leading zero. It names both XRPL sessions, which no member of the challenge tells apart: the in-band
    opening the protocol package's client writes, and the stock client's session, which opens its channel out of
    band."""
    if r.get("channelId") is not None:
        named = r["channelId"] != ""
    else:
        named = _has(d, "channelId") and d["channelId"] != ""
    if named:
        return Refusal("mpp/channel-named")
    network = xrpl_network_of(d)
    if isinstance(network, Refusal):
        return network
    if _has(r, "currency") and r["currency"] != "XRP":
        return Refusal("xrpl/currency-not-xrp")
    if not is_xrpl_address(r.get("recipient")) or account_id_of(r["recipient"]) is None or not is_drops(r.get("amount")):
        return Refusal("mpp/request-malformed")
    return ["mpp/session/xrpl", "mpp/session/xrpl/stock"]


# ── card, stripe and usdc.


def stripe_metadata_valid(m: object, present: bool, extra: int = 0) -> Refusal | None:
    """A Stripe metadata map as Stripe bounds it, with extra more keys to come; absent is valid."""
    if not present:
        return None
    if not is_object(m):
        return Refusal("mpp/metadata-malformed")
    if len(m) + extra > STRIPE_METADATA_KEYS:
        return Refusal("mpp/metadata-malformed")
    for k, v in m.items():
        if not 0 < js_length(k) <= STRIPE_METADATA_KEY_LENGTH or "[" in k or "]" in k:
            return Refusal("mpp/metadata-malformed")
        if not isinstance(v, str) or js_length(v) > STRIPE_METADATA_VALUE_LENGTH:
            return Refusal("mpp/metadata-malformed")
    return None


def card_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    """charge on card: externalId, the member that carries H, absent or a string."""
    if _has(r, "externalId") and not isinstance(r["externalId"], str):
        return Refusal("mpp/request-malformed")
    return ["mpp/charge/card"]


def stripe_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    """charge on stripe: methodDetails.metadata, which holds the member that carries H, within Stripe's bounds."""
    refused = stripe_metadata_valid(d.get("metadata"), _has(d, "metadata"))
    return refused if refused is not None else ["mpp/charge/stripe"]


def stripe_subscription_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    refused = stripe_metadata_valid(d.get("metadata"), _has(d, "metadata"))
    return refused if refused is not None else ["mpp/subscription/stripe"]


def usdc_profile(d: Obj) -> tuple[str, Obj] | Refusal:
    """The active usdc profile: methodDetails.type names one profile, and methodDetails holds exactly that one
    profile's details object."""
    kind = d.get("type")
    if not isinstance(kind, str) or kind not in USDC_PROFILES:
        return Refusal("mpp/usdc-profile")
    details = d.get(kind)
    if not is_object(details):
        return Refusal("mpp/usdc-profile")
    for other in USDC_PROFILES:
        if other != kind and _has(d, other):
            return Refusal("mpp/usdc-profile")
    return kind, details


def _only_type(types: object, only: str) -> bool:
    """A profile's credentialTypes: absent, which implies the one type v00 of the usdc draft admits, or exactly a list
    holding that type alone (draft-usdc-charge-00 at tempoxyz/mpp-specs 1f0574a, lines 298 and 414)."""
    return types is _ABSENT or (isinstance(types, list) and len(types) == 1 and types[0] == only)


def usdc_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    """charge on usdc: the active profile, amount a positive integer string, recipient a string, and what each
    profile's build reads: EVM chainId and addresses, with decimals 6 (else mpp/request-malformed) and credentialTypes
    absent or ["authorization"], the Gateway profile's absent or ["transfer"] (else mpp/credential-types), as v00 of the
    draft requires (draft-usdc-charge-00 at tempoxyz/mpp-specs 1f0574a, lines 297-298 and 414), and an EVM currency that
    is the native USDC Circle publishes for its chainId (NATIVE_USDC; lines 300-301), else mpp/usdc-not-native, a chain
    the table lacks included; the Solana charge's checks on the Solana details, whose network is
    required, and on externalId, its carrier; Stacks chainId, the token contract, and recipient as a Stacks node writes a
    principal (is_canonical_principal), the spelling the read compares with. The Gateway build reads recipient
    and the request's hash, and none of the Gateway details. No other profile reads externalId. The EVM and Gateway
    derivations hash the request as received, so on those profiles it is in its RFC 8785 form (mpp/request-not-jcs)."""
    profile = usdc_profile(d)
    if isinstance(profile, Refusal):
        return profile
    kind, p = profile
    amount = r.get("amount")
    if not isinstance(amount, str) or _POSITIVE.fullmatch(amount) is None or not isinstance(r.get("recipient"), str):
        return Refusal("mpp/request-malformed")
    if kind == "evm":
        chain_id = positive_int(p.get("chainId"))
        currency = r.get("currency")
        if chain_id is None or not is_address(currency) or not is_address(r.get("recipient")):
            return Refusal("mpp/request-malformed")
        decimals = p.get("decimals")
        if isinstance(decimals, bool) or decimals != 6:
            return Refusal("mpp/request-malformed")
        if not _only_type(p.get("credentialTypes", _ABSENT), "authorization"):
            return Refusal("mpp/credential-types")
        assert isinstance(currency, str)
        if NATIVE_USDC.get(chain_id) != currency.lower():
            return Refusal("mpp/usdc-not-native")
        return ["mpp/charge/usdc/evm"] if is_jcs_request(c["request"], r) else Refusal("mpp/request-not-jcs")
    if kind == "solana":
        network = solana_network_of(p, True)
        if isinstance(network, Refusal):
            return network
        solana = solana_charge_pairings(r, p)
        return solana if isinstance(solana, Refusal) else ["mpp/charge/usdc/solana"]
    if kind == "stacks":
        chain_id = p.get("chainId")
        if not isinstance(chain_id, str) or _STACKS_CHAIN.fullmatch(chain_id) is None or int(chain_id) > 0xFFFFFFFF:
            return Refusal("mpp/request-malformed")
        address = p.get("contractAddress")
        if not isinstance(address, str) or _C32_PRINCIPAL.fullmatch(address) is None:
            return Refusal("mpp/request-malformed")
        name = p.get("contractName")
        if not isinstance(name, str) or js_length(name) > 128 or _STACKS_NAME.fullmatch(name) is None:
            return Refusal("mpp/request-malformed")
        if not is_canonical_principal(r.get("recipient")):
            return Refusal("mpp/request-malformed")
        return ["mpp/charge/usdc/stacks"]
    if not _only_type(p.get("credentialTypes", _ABSENT), "transfer"):
        return Refusal("mpp/credential-types")
    return ["mpp/charge/usdc/gateway"] if is_jcs_request(c["request"], r) else Refusal("mpp/request-not-jcs")


def is_jcs_request(request_param: object, parsed: object) -> bool:
    """True when a challenge's request parameter is the base64url, without padding, of the UTF-8 of the RFC 8785 form
    of parsed, its own parse: the bytes usdc's request hash covers."""
    text = canonical_or_none(parsed)
    return text is not None and b64u_encode(text.encode("utf-8")) == request_param


# Each (intent, method) MPP serves, and the check that names its pairings.
PAIRING_CHECKS: Mapping[str, PairingCheck] = {
    "charge/evm": evm_charge_pairings,
    "charge/tempo": tempo_charge_pairings,
    "session/evm": evm_session_pairings,
    "session/tempo": tempo_session_pairings,
    "subscription/tempo": subscription_pairings,
    "charge/lightning": lightning_pairings("mpp/charge/lightning"),
    "session/lightning": lightning_pairings("mpp/session/lightning"),
    "charge/solana": solana_charge_pairings,
    "charge/xrpl": xrpl_charge_pairings,
    "charge/nearintents": near_intents_charge_pairings,
    "session/hedera": hedera_session_pairings,
    "session/solana": solana_session_pairings,
    "session/xrpl": xrpl_session_pairings,
    "charge/card": card_charge_pairings,
    "charge/stripe": stripe_charge_pairings,
    "subscription/stripe": stripe_subscription_pairings,
    "charge/usdc": usdc_charge_pairings,
}

# The checks of a placed challenge, with the carrier the seller writes after place required where pairings_of takes a
# challenge without it: the Lightning invoice.
CARRIED_PAIRING_CHECKS: Mapping[str, PairingCheck] = {
    **PAIRING_CHECKS,
    "charge/tempo": lambda r, d, c: tempo_charge_pairings(r, d, c, carried=True),
    "charge/lightning": lightning_pairings("mpp/charge/lightning", carried=True),
    "session/lightning": lightning_pairings("mpp/session/lightning", carried=True),
}
