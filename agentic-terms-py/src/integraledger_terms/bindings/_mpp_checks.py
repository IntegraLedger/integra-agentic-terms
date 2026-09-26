"""The request checks of every MPP (intent, method) a challenge may name, each naming the pairings the challenge
offers, and the value checks they share: decimal strings, positive integers, RFC 3339 times, strict base64url JSON,
Solana keys, XRPL and Stellar forms, and each method's network names."""

import re
from collections.abc import Callable, Mapping
from typing import Any

from .._types import Refusal
from ._codec import b58_decode, b64u_decode, canonical_or_none
from ._jose import parse_json
from ._lcp import is_address, is_list, is_object

Obj = Mapping[str, Any]
PairingCheck = Callable[[Obj, Obj, Obj], "list[str] | Refusal"]

MAX_DECODED = 8192
MAX_JSON_DEPTH = 16
MAX_SAFE_INTEGER = 2**53 - 1
UINT256_LIMIT = 2**256
U64_LIMIT = 2**64
INT64_LIMIT = 2**63

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
_XRPL_ADDRESS = re.compile(r"r[1-9A-HJ-NP-Za-km-z]{24,34}")
_XRPL_CURRENCY = re.compile(r"(?:[A-Za-z0-9?!@#$%^&*<>(){}\[\]|]{3}|[0-9A-Fa-f]{40})")
_XRPL_MPT = re.compile(r"[0-9A-Fa-f]{48}")
_HEX64 = re.compile(r"[0-9A-Fa-f]{64}")
_STELLAR_ACCOUNT = re.compile(r"G[A-Z2-7]{55}")
_STELLAR_MUXED = re.compile(r"M[A-Z2-7]{68}")
_STELLAR_CONTRACT = re.compile(r"C[A-Z2-7]{55}")
_STACKS_CHAIN = re.compile(r"(?:0|[1-9][0-9]{0,9})")
_STACKS_NAME = re.compile(r"[a-zA-Z](?:[a-zA-Z0-9]|[-_])*")
_C32_PRINCIPAL = re.compile(r"S[0-9A-HJKMNP-TV-Z]{38,40}")
_HEDERA_ENTITY = re.compile(r"(0|[1-9][0-9]{0,18})\.(0|[1-9][0-9]{0,18})\.(0|[1-9][0-9]{0,18})")
_HEDERA_AMOUNT = re.compile(r"(0|[1-9][0-9]{0,18})")
_HEDERA_MAX_SPLITS = 9
_EVM_MAX_SPLITS = 10
_MAX_MEMO_BYTES = 566
_NEAR_MAX_STRING = 256

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
# The networks a Hedera charge with no chainId may be read on, as the protocol package's Hedera networks.
_HEDERA_DEFAULTS = ("hedera:mainnet", "hedera:testnet", "hedera:previewnet", "hedera:devnet")

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


def utf16_length(text: str) -> int:
    """The length of text in UTF-16 code units."""
    return len(text) + sum(1 for c in text if ord(c) > 0xFFFF)


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



def _depth(value: object, d: int) -> int:
    """The nesting depth of objects and arrays, counting from d, stopping once past MAX_JSON_DEPTH."""
    if d > MAX_JSON_DEPTH or not isinstance(value, (dict, list)):
        return d
    deepest = d + 1
    for item in value.values() if isinstance(value, dict) else value:
        deepest = max(deepest, _depth(item, d + 1))
    return deepest


def decode_object(text: object) -> dict[str, Any] | None:
    """The JSON object a strict base64url-nopad value holds: at most 8 KiB, UTF-8, depth 16, serialisable."""
    raw = b64u_decode(text, MAX_DECODED)
    if raw is None:
        return None
    try:
        value = parse_json(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return None
    if not isinstance(value, dict) or _depth(value, 0) > MAX_JSON_DEPTH:
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


def hedera_charge_network(request: Obj, default: str | None = None) -> str | Refusal:
    """The CAIP-2 network of an MPP Hedera charge: methodDetails.chainId 295 or 296, or, when it names none, the
    default network given."""
    md = request.get("methodDetails")
    if not is_object(md) or "chainId" not in md:
        return default if default in _HEDERA_DEFAULTS else Refusal("hedera/chain-id-unnamed")
    return hedera_network_of_chain_id(md["chainId"])


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
    if _has(d, "permit2Address") and not is_address(d["permit2Address"]):
        return Refusal("mpp/request-malformed")
    if _has(r, "externalId") and not isinstance(r["externalId"], str):
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
            if (
                not is_object(s)
                or not is_address(s.get("recipient"))
                or not is_decimal(s.get("amount"))
                or int(s["amount"]) == 0
            ):
                return Refusal("mpp/splits-malformed")
        listed = [p for p in listed if p == "mpp/charge/evm/permit2"]
    return Refusal("mpp/credential-types") if not listed else listed


def tempo_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if not is_address(r.get("currency")) or not is_address(r.get("recipient")) or not is_decimal(r.get("amount")):
        return Refusal("mpp/request-malformed")
    if _has(d, "chainId") and positive_int(d["chainId"]) is None:
        return Refusal("mpp/request-malformed")
    if _has(d, "memo"):
        return Refusal("mpp/carrier-taken")
    pull = push = True
    if _has(d, "supportedModes"):
        modes = d["supportedModes"]
        if not is_list(modes) or not all(m in ("pull", "push") and isinstance(m, str) for m in modes):
            return Refusal("mpp/request-malformed")
        pull = "pull" in modes
        push = "push" in modes
    if d.get("feePayer") is True:
        push = False
    out: list[str] = []
    if pull:
        out.append("mpp/charge/tempo/memo")
    if push:
        out.append("mpp/charge/tempo/push")
    return out if out else Refusal("mpp/modes-pull-only")


def evm_session_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if _has(d, "channelId") or _has(d, "sessionSnapshot"):
        return Refusal("mpp/channel-named")
    if not is_address(d.get("escrowContract")):
        return Refusal("mpp/escrow-malformed")
    if positive_int(d.get("chainId")) is None:
        return Refusal("mpp/chain-id-required")
    if not is_address(r.get("currency")) or not is_address(r.get("recipient")):
        return Refusal("mpp/request-malformed")
    if _has(d, "permit2Contract") and not is_address(d["permit2Contract"]):
        return Refusal("mpp/request-malformed")
    if _has(d, "credentialTypes"):
        types = d["credentialTypes"]
        if not is_list(types) or len(types) == 0:
            return Refusal("mpp/credential-types")
        if not all(isinstance(t, str) and t in ("permit2", "authorization", "hash") for t in types):
            return Refusal("mpp/credential-types")
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
    key = d.get("accessKey")
    if not is_object(key) or not is_address(key.get("accessKeyAddress")):
        return Refusal("mpp/access-key-malformed")
    if key.get("keyType") not in ("p256", "secp256k1", "webAuthn") or not isinstance(key.get("keyType"), str):
        return Refusal("mpp/access-key-malformed")
    if not isinstance(r.get("subscriptionExpires"), str) or unix_of(r["subscriptionExpires"]) is None:
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
    return ["mpp/subscription/tempo"]


def lightning_pairings(pairing: str) -> PairingCheck:
    """Lightning: amount in satoshis and currency "sat"; the payment hash as 64 lower-case hex digits, in
    methodDetails (charge) or in request (session). The invoice may be absent."""
    charge = pairing == "mpp/charge/lightning"

    def check(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
        if not is_decimal(r.get("amount")) or r.get("currency") != "sat":
            return Refusal("mpp/request-malformed")
        h = d.get("paymentHash") if charge else r.get("paymentHash")
        if not isinstance(h, str) or _PAYMENT_HASH.fullmatch(h) is None:
            return Refusal("ln/payment-hash-required")
        holder, key = (d, "invoice") if charge else (r, "depositInvoice")
        if _has(holder, key) and not isinstance(holder[key], str):
            return Refusal("mpp/request-malformed")
        return [pairing]

    return check


# ── charge and session on Hedera, Solana, Stellar, XRPL and NEAR Intents.


def _hedera_amount(value: object) -> int | None:
    """A positive decimal below 2^63."""
    if not isinstance(value, str) or _HEDERA_AMOUNT.fullmatch(value) is None:
        return None
    number = int(value)
    return number if 0 < number < INT64_LIMIT else None


def _hedera_entity(value: object) -> bool:
    return isinstance(value, str) and _HEDERA_ENTITY.fullmatch(value) is not None


def hedera_charge_legs(request: Obj) -> tuple[str, int, list[tuple[str, int]]] | Refusal:
    """The currency, the amount and the transfer legs of an MPP Hedera charge: the recipient's remainder and each
    split, every account distinct."""
    amount = _hedera_amount(request.get("amount"))
    currency, recipient = request.get("currency"), request.get("recipient")
    if amount is None or not _hedera_entity(currency) or not _hedera_entity(recipient):
        return Refusal("hedera/option-malformed")
    assert isinstance(currency, str) and isinstance(recipient, str)
    splits = request.get("splits")
    splits = [] if splits is None else splits
    if not is_list(splits) or len(splits) > _HEDERA_MAX_SPLITS:
        return Refusal("hedera/option-malformed")
    legs: list[tuple[str, int]] = []
    split_total = 0
    for sp in splits:
        a = _hedera_amount(sp.get("amount")) if is_object(sp) else None
        if not is_object(sp) or not _hedera_entity(sp.get("recipient")) or a is None:
            return Refusal("hedera/option-malformed")
        legs.append((sp["recipient"], a))
        split_total += a
    if split_total >= amount:
        return Refusal("hedera/option-malformed")
    every = [(recipient, amount - split_total), *legs]
    if len({account for account, _ in every}) != len(every):
        return Refusal("hedera/option-malformed")
    return currency, amount, every


def hedera_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    legs = hedera_charge_legs(r)
    if isinstance(legs, Refusal):
        return legs
    md = r.get("methodDetails")
    if _has(r, "methodDetails") and not is_object(md):
        return Refusal("mpp/request-malformed")
    if is_object(md) and _has(md, "chainId"):
        n = hedera_network_of_chain_id(md["chainId"])
        if isinstance(n, Refusal):
            return n
    return ["mpp/charge/hedera"]


def solana_charge_pairings(r: Obj, d: Obj, c: Obj | None = None) -> list[str] | Refusal:
    network = solana_network_of(d, False)
    if isinstance(network, Refusal):
        return network
    currency = r.get("currency")
    if not is_u64_positive(r.get("amount")) or not (currency == "sol" or is_key(currency)) or not is_key(r.get("recipient")):
        return Refusal("mpp/request-malformed")
    if _has(r, "externalId"):
        ext = r["externalId"]
        if not isinstance(ext, str) or len(ext.encode("utf-8")) > _MAX_MEMO_BYTES:
            return Refusal("mpp/request-malformed")
    if _has(d, "feePayer") and not isinstance(d["feePayer"], bool):
        return Refusal("mpp/request-malformed")
    if d.get("feePayer") is True and not is_key(d.get("feePayerKey")):
        return Refusal("mpp/request-malformed")
    return ["mpp/charge/solana"]


def stellar_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if d.get("network") not in ("stellar:pubnet", "stellar:testnet") or not isinstance(d.get("network"), str):
        return Refusal("stellar/option-malformed")
    to, currency = r.get("recipient"), r.get("currency")
    if (
        not is_decimal(r.get("amount"))
        or not isinstance(currency, str)
        or _STELLAR_CONTRACT.fullmatch(currency) is None
        or not isinstance(to, str)
        or not (_STELLAR_ACCOUNT.fullmatch(to) or _STELLAR_MUXED.fullmatch(to))
    ):
        return Refusal("stellar/option-malformed")
    if _has(d, "feePayer") and not isinstance(d["feePayer"], bool):
        return Refusal("stellar/option-malformed")
    return ["mpp/charge/stellar"]


def is_xrpl_address(value: object) -> bool:
    return isinstance(value, str) and _XRPL_ADDRESS.fullmatch(value) is not None


def is_xrpl_currency(value: object) -> bool:
    """XRP, an issued currency {currency, issuer}, or an MPT {mpt_issuance_id}."""
    if value == "XRP" and isinstance(value, str):
        return True
    if not is_object(value):
        return False
    keys = ",".join(sorted(value.keys(), key=lambda k: k.encode("utf-16-be", "surrogatepass")))
    if keys == "currency,issuer":
        cur = value.get("currency")
        return (
            isinstance(cur, str)
            and _XRPL_CURRENCY.fullmatch(cur) is not None
            and cur != "XRP"
            and is_xrpl_address(value.get("issuer"))
        )
    mpt = value.get("mpt_issuance_id")
    return keys == "mpt_issuance_id" and isinstance(mpt, str) and _XRPL_MPT.fullmatch(mpt) is not None


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
    if (
        not is_xrpl_address(r.get("recipient"))
        or not is_xrpl_currency(r.get("currency"))
        or not isinstance(amount, str)
        or _XRPL_AMOUNT.fullmatch(amount) is None
        or _XRPL_ZERO.fullmatch(amount) is not None
        or (r.get("currency") == "XRP" and not is_u64_positive(amount))
    ):
        return Refusal("mpp/request-malformed")
    if _has(d, "invoiceId"):
        inv = d["invoiceId"]
        if not isinstance(inv, str) or _HEX64.fullmatch(inv) is None:
            return Refusal("mpp/request-malformed")
    for k in ("destinationTag", "sourceTag"):
        if _has(d, k) and not _is_uint32(d[k]):
            return Refusal("mpp/request-malformed")
    return ["mpp/charge/xrpl"]


def near_intents_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    if _has(d, "credentialTypes"):
        types = d["credentialTypes"]
        if not (is_list(types) and len(types) == 1 and types[0] == "hash" and isinstance(types[0], str)):
            return Refusal("mpp/credential-types")
    strings = [r.get("currency"), r.get("recipient"), d.get("destinationAsset"), d.get("destinationRecipient"), d.get("refundTo")]
    memo = d.get("depositMemo")
    if (
        not is_decimal(r.get("amount"))
        or not is_decimal(d.get("amountOut"))
        or not is_decimal(d.get("minAmountIn"))
        or not all(isinstance(s, str) and 0 < utf16_length(s) <= _NEAR_MAX_STRING for s in strings)
        or not is_caip2(d.get("originNetwork"))
        or not is_caip2(d.get("destinationNetwork"))
        or (_has(r, "externalId") and not isinstance(r["externalId"], str))
        or (_has(d, "depositMemo") and memo is not None and not isinstance(memo, str))
    ):
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
    return ["mpp/session/hedera"]


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
    if not is_xrpl_address(r.get("recipient")):
        return Refusal("mpp/request-malformed")
    return ["mpp/session/xrpl"]


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
        if not 0 < utf16_length(k) <= STRIPE_METADATA_KEY_LENGTH or "[" in k or "]" in k:
            return Refusal("mpp/metadata-malformed")
        if not isinstance(v, str) or utf16_length(v) > STRIPE_METADATA_VALUE_LENGTH:
            return Refusal("mpp/metadata-malformed")
    return None


def _charge_shape(r: Obj) -> Refusal | None:
    """The charge intent's shared members: amount a decimal string, currency a string, externalId absent or a
    string."""
    currency = r.get("currency")
    if not is_decimal(r.get("amount")) or not isinstance(currency, str) or currency == "":
        return Refusal("mpp/request-malformed")
    if _has(r, "externalId") and not isinstance(r["externalId"], str):
        return Refusal("mpp/request-malformed")
    return None


def card_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    refused = _charge_shape(r)
    return refused if refused is not None else ["mpp/charge/card"]


def stripe_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    refused = _charge_shape(r) or stripe_metadata_valid(d.get("metadata"), _has(d, "metadata"))
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


def _only(types: object, allowed: str) -> bool:
    return is_list(types) and len(types) > 0 and all(t == allowed and isinstance(t, str) for t in types)


def usdc_charge_pairings(r: Obj, d: Obj, c: Obj) -> list[str] | Refusal:
    profile = usdc_profile(d)
    if isinstance(profile, Refusal):
        return profile
    kind, p = profile
    amount = r.get("amount")
    if not isinstance(amount, str) or _POSITIVE.fullmatch(amount) is None or not isinstance(r.get("recipient"), str):
        return Refusal("mpp/request-malformed")
    if _has(r, "externalId") and not isinstance(r["externalId"], str):
        return Refusal("mpp/request-malformed")
    if kind == "evm":
        if positive_int(p.get("chainId")) is None or not is_address(r.get("currency")) or not is_address(r.get("recipient")):
            return Refusal("mpp/request-malformed")
        if _has(p, "credentialTypes") and not _only(p["credentialTypes"], "authorization"):
            return Refusal("mpp/credential-types")
        return ["mpp/charge/usdc/evm"]
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
        if not isinstance(name, str) or utf16_length(name) > 128 or _STACKS_NAME.fullmatch(name) is None:
            return Refusal("mpp/request-malformed")
        return ["mpp/charge/usdc/stacks"]
    sources = p.get("acceptedSources")
    if not is_list(sources) or not 1 <= len(sources) <= 32:
        return Refusal("mpp/request-malformed")
    if not all(is_caip2(s) for s in sources):
        return Refusal("mpp/request-malformed")
    if not is_caip2(p.get("destinationNetwork")):
        return Refusal("mpp/request-malformed")
    if not is_decimal(p.get("maxFee")):
        return Refusal("mpp/request-malformed")
    if _has(p, "credentialTypes") and not _only(p["credentialTypes"], "transfer"):
        return Refusal("mpp/credential-types")
    return ["mpp/charge/usdc/gateway"]


# Each (intent, method) MPP serves, and the check that names its pairings.
PAIRING_CHECKS: Mapping[str, PairingCheck] = {
    "charge/evm": evm_charge_pairings,
    "charge/tempo": tempo_charge_pairings,
    "session/evm": evm_session_pairings,
    "session/tempo": tempo_session_pairings,
    "subscription/tempo": subscription_pairings,
    "charge/lightning": lightning_pairings("mpp/charge/lightning"),
    "session/lightning": lightning_pairings("mpp/session/lightning"),
    "charge/hedera": hedera_charge_pairings,
    "charge/solana": solana_charge_pairings,
    "charge/stellar": stellar_charge_pairings,
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
