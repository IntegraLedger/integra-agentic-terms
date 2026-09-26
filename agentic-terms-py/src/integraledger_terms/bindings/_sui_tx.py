"""Sui's TransactionData in BCS, as the @mysten/sui 2.31.3 schema defines it, with its transforms: addresses as
0x and 64 lower-case hex digits, object digests as base58 of exactly 32 bytes, type tags as their string forms, and
TransactionExpiration's Epoch as a double. A transaction reads only when writing its parse back gives its bytes."""

import hashlib
import re
from typing import Any

from ._bcs import (
    BOOL,
    BYTE_VECTOR,
    STRING,
    U16,
    U32,
    U64,
    BcsError,
    Enum,
    FixedBytes,
    Lazy,
    Map,
    Struct,
    Transform,
    Tuple,
    Type,
    Vector,
    option,
)
from ._codec import b58_decode, b58_encode

_ADDRESS_HEX = re.compile(r"(0x|0X)?[a-fA-F0-9]+")
_HEX_PAIR = re.compile(r"[0-9a-fA-F]{2}")
# JavaScript's . matches every code unit but the four line terminators.
_DOT = r"[^\n\r  ]"
_VECTOR = re.compile(rf"vector<({_DOT}+)>\Z")
_STRUCT = re.compile(rf"([^:]+)::([^:]+)::([^<]+)(<({_DOT}+)>)?")
# JavaScript's String.prototype.trim: WhiteSpace and LineTerminator.
_JS_SPACE = "\t\n\v\f\r                  　﻿"
_PRIMITIVES = ("address", "bool", "u8", "u16", "u32", "u64", "u128", "u256", "signer")
_DIGEST_PREFIX = b"TransactionData::"


def _normalize_address(value: str) -> str:
    address = value.lower()
    if address.startswith("0x"):
        address = address[2:]
    return "0x" + address.rjust(64, "0")


def _is_valid_address(value: str) -> bool:
    if _ADDRESS_HEX.fullmatch(value) is None or len(value) % 2 != 0:
        return False
    digits = value[2:] if value[:2] in ("0x", "0X") else value
    return len(digits) // 2 == 32


def _from_hex(text: str) -> bytes:
    digits = text[2:] if text.startswith("0x") else text
    padded = digits if len(digits) % 2 == 0 else "0" + digits
    pairs = _HEX_PAIR.findall(padded)
    if len(pairs) != len(padded) // 2:
        raise BcsError("invalid hex")
    return bytes(int(p, 16) for p in pairs)


def _address_validate(value: Any) -> None:
    address = value if isinstance(value, str) else value.hex() if isinstance(value, bytes) else ""
    if not address or not _is_valid_address(_normalize_address(address)):
        raise BcsError("invalid address")


ADDRESS = Transform(
    FixedBytes(32),
    output=lambda b: _normalize_address(b.hex()),
    input=lambda v: _from_hex(_normalize_address(v)) if isinstance(v, str) else v,
    validate=_address_validate,
)


def _digest_validate(value: Any) -> None:
    raw = b58_decode(value)
    if raw is None or len(raw) != 32:
        raise BcsError("ObjectDigest must be 32 bytes")


def _digest_input(value: Any) -> bytes:
    raw = b58_decode(value)
    if raw is None:
        raise BcsError("invalid base58")
    return raw


OBJECT_DIGEST = Transform(BYTE_VECTOR, output=b58_encode, input=_digest_input, validate=_digest_validate)


def _unsafe_u64_output(value: str) -> float:
    return float(int(value))


UNSAFE_U64 = Transform(U64, output=_unsafe_u64_output)

SUI_OBJECT_REF = Struct([("objectId", ADDRESS), ("version", U64), ("digest", OBJECT_DIGEST)])
SHARED_OBJECT_REF = Struct([("objectId", ADDRESS), ("initialSharedVersion", U64), ("mutable", BOOL)])
OBJECT_ARG = Enum([("ImmOrOwnedObject", SUI_OBJECT_REF), ("SharedObject", SHARED_OBJECT_REF), ("Receiving", SUI_OBJECT_REF)])
OWNER = Enum(
    [
        ("AddressOwner", ADDRESS),
        ("ObjectOwner", ADDRESS),
        ("Shared", Struct([("initialSharedVersion", U64)])),
        ("Immutable", None),
        ("ConsensusAddressOwner", Struct([("startVersion", U64), ("owner", ADDRESS)])),
    ]
)
RESERVATION = Enum([("MaxAmountU64", U64)])


# ── type tags


def _js_trim(text: str) -> str:
    return text.strip(_JS_SPACE)


def _split_generic_parameters(text: str) -> list[str]:
    tok: list[str] = []
    word = ""
    nested = 0
    for c in text:
        if c == "<":
            nested += 1
        if c == ">":
            nested -= 1
        if nested == 0 and c == ",":
            tok.append(_js_trim(word))
            word = ""
            continue
        word += c
    tok.append(_js_trim(word))
    return tok


def parse_type_tag(text: str, normalize_address: bool = False) -> dict[str, Any]:
    """A type tag from its string form, as @mysten/sui's TypeTagSerializer.parseFromStr reads it."""
    if text in _PRIMITIVES:
        return {text: True}
    vector = _VECTOR.match(text)
    if vector is not None:
        return {"vector": parse_type_tag(vector.group(1), normalize_address)}
    struct = _STRUCT.match(text)
    if struct is not None:
        address = _normalize_address(struct.group(1)) if normalize_address else struct.group(1)
        params = struct.group(5)
        return {
            "struct": {
                "address": address,
                "module": struct.group(2),
                "name": struct.group(3),
                "typeParams": [] if params is None else [parse_type_tag(t, normalize_address) for t in _split_generic_parameters(params)],
            }
        }
    raise BcsError("unexpected token in a type tag")


def type_tag_string(tag: dict[str, Any]) -> str:
    """The string form of a type tag, as @mysten/sui's TypeTagSerializer.tagToString writes it."""
    for primitive in ("bool", "u8", "u16", "u32", "u64", "u128", "u256", "address", "signer"):
        if primitive in tag:
            return primitive
    if "vector" in tag:
        return f"vector<{type_tag_string(tag['vector'])}>"
    if "struct" in tag:
        s = tag["struct"]
        params = ", ".join(type_tag_string(p) for p in s["typeParams"])
        return f"{s['address']}::{s['module']}::{s['name']}" + (f"<{params}>" if params else "")
    raise BcsError("invalid type tag")


INNER_TYPE_TAG: Type = Enum(
    [
        ("bool", None),
        ("u8", None),
        ("u64", None),
        ("u128", None),
        ("address", None),
        ("signer", None),
        ("vector", Lazy(lambda: INNER_TYPE_TAG)),
        ("struct", Lazy(lambda: STRUCT_TAG)),
        ("u16", None),
        ("u32", None),
        ("u256", None),
    ]
)
STRUCT_TAG: Type = Struct([("address", ADDRESS), ("module", STRING), ("name", STRING), ("typeParams", Vector(INNER_TYPE_TAG))])
TYPE_TAG = Transform(
    INNER_TYPE_TAG,
    output=type_tag_string,
    input=lambda v: parse_type_tag(v, True) if isinstance(v, str) else v,
)

# ── programmable transactions

WITHDRAWAL_TYPE = Enum([("Balance", Lazy(lambda: TYPE_TAG))])
WITHDRAW_FROM = Enum(
    [("Sender", None), ("Sponsor", None), ("SenderAllowance", Struct([("funder", ADDRESS), ("allowance", ADDRESS)]))]
)
FUNDS_WITHDRAWAL = Struct([("reservation", RESERVATION), ("typeArg", WITHDRAWAL_TYPE), ("withdrawFrom", WITHDRAW_FROM)])
CALL_ARG = Enum([("Pure", Struct([("bytes", BYTE_VECTOR)])), ("Object", OBJECT_ARG), ("FundsWithdrawal", FUNDS_WITHDRAWAL)])
ARGUMENT = Enum([("GasCoin", None), ("Input", U16), ("Result", U16), ("NestedResult", Tuple([U16, U16]))])
PROGRAMMABLE_MOVE_CALL = Struct(
    [
        ("package", ADDRESS),
        ("module", STRING),
        ("function", STRING),
        ("typeArguments", Vector(TYPE_TAG)),
        ("arguments", Vector(ARGUMENT)),
    ]
)
COMMAND = Enum(
    [
        ("MoveCall", PROGRAMMABLE_MOVE_CALL),
        ("TransferObjects", Struct([("objects", Vector(ARGUMENT)), ("address", ARGUMENT)])),
        ("SplitCoins", Struct([("coin", ARGUMENT), ("amounts", Vector(ARGUMENT))])),
        ("MergeCoins", Struct([("destination", ARGUMENT), ("sources", Vector(ARGUMENT))])),
        ("Publish", Struct([("modules", Vector(BYTE_VECTOR)), ("dependencies", Vector(ADDRESS))])),
        ("MakeMoveVec", Struct([("type", option(TYPE_TAG)), ("elements", Vector(ARGUMENT))])),
        (
            "Upgrade",
            Struct(
                [
                    ("modules", Vector(BYTE_VECTOR)),
                    ("dependencies", Vector(ADDRESS)),
                    ("package", ADDRESS),
                    ("ticket", ARGUMENT),
                ]
            ),
        ),
    ]
)
PROGRAMMABLE_TRANSACTION = Struct([("inputs", Vector(CALL_ARG)), ("commands", Vector(COMMAND))])

# ── expiration


def _proposers_not_empty(value: Any) -> Any:
    if len(value) == 0:
        raise BcsError("Allowed proposers must not be empty")
    return value


def _proposers_increasing(value: Any) -> Any:
    _proposers_not_empty(value)
    for i in range(1, len(value)):
        if value[i] <= value[i - 1]:
            raise BcsError("Allowed proposers must be strictly increasing")
    return value


_EPOCH_BOUNDS = [
    ("minEpoch", option(U64)),
    ("maxEpoch", option(U64)),
    ("minTimestamp", option(U64)),
    ("maxTimestamp", option(U64)),
    ("chain", OBJECT_DIGEST),
    ("nonce", U32),
]
VALID_DURING = Struct(_EPOCH_BOUNDS)
ALLOWED_PROPOSERS = Struct(
    [("epoch", U64), ("proposers", Transform(Vector(U32), output=_proposers_not_empty, input=_proposers_increasing))]
)
VALIDITY = Struct([*_EPOCH_BOUNDS, ("allowedProposers", option(ALLOWED_PROPOSERS))])
TRANSACTION_EXPIRATION = Enum([("None", None), ("Epoch", UNSAFE_U64), ("ValidDuring", VALID_DURING), ("Validity", VALIDITY)])

# ── objects, for the genesis kind

MOVE_OBJECT_TYPE = Enum(
    [("Other", STRUCT_TAG), ("GasCoin", None), ("StakedSui", None), ("Coin", TYPE_TAG), ("AccumulatorBalanceWrapper", None)]
)
TYPE_ORIGIN = Struct([("moduleName", STRING), ("datatypeName", STRING), ("package", ADDRESS)])
UPGRADE_INFO = Struct([("upgradedId", ADDRESS), ("upgradedVersion", U64)])
MOVE_PACKAGE = Struct(
    [
        ("id", ADDRESS),
        ("version", U64),
        ("moduleMap", Map(STRING, BYTE_VECTOR)),
        ("typeOriginTable", Vector(TYPE_ORIGIN)),
        ("linkageTable", Map(ADDRESS, UPGRADE_INFO)),
    ]
)
MOVE_OBJECT = Struct([("type", MOVE_OBJECT_TYPE), ("hasPublicTransfer", BOOL), ("version", U64), ("contents", BYTE_VECTOR)])
DATA = Enum([("Move", MOVE_OBJECT), ("Package", MOVE_PACKAGE)])

# ── system transaction kinds

CHANGE_EPOCH = Struct(
    [
        ("epoch", U64),
        ("protocolVersion", U64),
        ("storageCharge", U64),
        ("computationCharge", U64),
        ("storageRebate", U64),
        ("nonRefundableStorageFee", U64),
        ("epochStartTimestampMs", U64),
        ("systemPackages", Vector(Tuple([U64, Vector(BYTE_VECTOR), Vector(ADDRESS)]))),
    ]
)
GENESIS_OBJECT = Enum([("RawObject", Struct([("data", DATA), ("owner", OWNER)]))])
GENESIS_TRANSACTION = Struct([("objects", Vector(GENESIS_OBJECT))])
CONSENSUS_COMMIT_PROLOGUE = Struct([("epoch", U64), ("round", U64), ("commitTimestampMs", U64)])
CONSENSUS_COMMIT_PROLOGUE_V2 = Struct(
    [("epoch", U64), ("round", U64), ("commitTimestampMs", U64), ("consensusCommitDigest", OBJECT_DIGEST)]
)
VERSION_ASSIGNMENTS = Enum(
    [
        ("CancelledTransactions", Vector(Tuple([OBJECT_DIGEST, Vector(Tuple([ADDRESS, U64]))]))),
        ("CancelledTransactionsV2", Vector(Tuple([OBJECT_DIGEST, Vector(Tuple([Tuple([ADDRESS, U64]), U64]))]))),
    ]
)
_PROLOGUE_V3 = [
    ("epoch", U64),
    ("round", U64),
    ("subDagIndex", option(U64)),
    ("commitTimestampMs", U64),
    ("consensusCommitDigest", OBJECT_DIGEST),
    ("consensusDeterminedVersionAssignments", VERSION_ASSIGNMENTS),
]
CONSENSUS_COMMIT_PROLOGUE_V3 = Struct(_PROLOGUE_V3)
CONSENSUS_COMMIT_PROLOGUE_V4 = Struct([*_PROLOGUE_V3, ("additionalStateDigest", OBJECT_DIGEST)])
ACTIVE_JWK = Struct(
    [
        ("jwkId", Struct([("iss", STRING), ("kid", STRING)])),
        ("jwk", Struct([("kty", STRING), ("e", STRING), ("n", STRING), ("alg", STRING)])),
        ("epoch", U64),
    ]
)
AUTHENTICATOR_STATE_UPDATE = Struct(
    [("epoch", U64), ("round", U64), ("newActiveJwks", Vector(ACTIVE_JWK)), ("authenticatorObjInitialSharedVersion", U64)]
)
RANDOMNESS_STATE_UPDATE = Struct(
    [("epoch", U64), ("randomnessRound", U64), ("randomBytes", BYTE_VECTOR), ("randomnessObjInitialSharedVersion", U64)]
)
AUTHENTICATOR_STATE_EXPIRE = Struct([("minEpoch", U64), ("authenticatorObjInitialSharedVersion", U64)])
EXECUTION_TIME_OBSERVATION_KEY = Enum(
    [
        (
            "MoveEntryPoint",
            Struct([("package", ADDRESS), ("module", STRING), ("function", STRING), ("typeArguments", Vector(TYPE_TAG))]),
        ),
        ("TransferObjects", None),
        ("SplitCoins", None),
        ("MergeCoins", None),
        ("Publish", None),
        ("MakeMoveVec", None),
        ("Upgrade", None),
    ]
)
STORED_EXECUTION_TIME_OBSERVATIONS = Enum(
    [
        (
            "V1",
            Vector(
                Tuple(
                    [
                        EXECUTION_TIME_OBSERVATION_KEY,
                        Vector(Tuple([BYTE_VECTOR, Struct([("secs", U64), ("nanos", U32)])])),
                    ]
                )
            ),
        )
    ]
)
END_OF_EPOCH_TRANSACTION_KIND = Enum(
    [
        ("ChangeEpoch", CHANGE_EPOCH),
        ("AuthenticatorStateCreate", None),
        ("AuthenticatorStateExpire", AUTHENTICATOR_STATE_EXPIRE),
        ("RandomnessStateCreate", None),
        ("DenyListStateCreate", None),
        ("BridgeStateCreate", OBJECT_DIGEST),
        ("BridgeCommitteeInit", U64),
        ("StoreExecutionTimeObservations", STORED_EXECUTION_TIME_OBSERVATIONS),
        ("AccumulatorRootCreate", None),
        ("CoinRegistryCreate", None),
        ("DisplayRegistryCreate", None),
        ("AddressAliasStateCreate", None),
        ("WriteAccumulatorStorageCost", Struct([("storageCost", U64)])),
        ("ForwardingAddressRegistryCreate", None),
    ]
)
TRANSACTION_KIND = Enum(
    [
        ("ProgrammableTransaction", PROGRAMMABLE_TRANSACTION),
        ("ChangeEpoch", CHANGE_EPOCH),
        ("Genesis", GENESIS_TRANSACTION),
        ("ConsensusCommitPrologue", CONSENSUS_COMMIT_PROLOGUE),
        ("AuthenticatorStateUpdate", AUTHENTICATOR_STATE_UPDATE),
        ("EndOfEpochTransaction", Vector(END_OF_EPOCH_TRANSACTION_KIND)),
        ("RandomnessStateUpdate", RANDOMNESS_STATE_UPDATE),
        ("ConsensusCommitPrologueV2", CONSENSUS_COMMIT_PROLOGUE_V2),
        ("ConsensusCommitPrologueV3", CONSENSUS_COMMIT_PROLOGUE_V3),
        ("ConsensusCommitPrologueV4", CONSENSUS_COMMIT_PROLOGUE_V4),
        ("ProgrammableSystemTransaction", PROGRAMMABLE_TRANSACTION),
    ]
)
GAS_DATA = Struct([("payment", Vector(SUI_OBJECT_REF)), ("owner", ADDRESS), ("price", U64), ("budget", U64)])
TRANSACTION_DATA_V1 = Struct(
    [("kind", TRANSACTION_KIND), ("sender", ADDRESS), ("gasData", GAS_DATA), ("expiration", TRANSACTION_EXPIRATION)]
)
TRANSACTION_DATA = Enum([("V1", TRANSACTION_DATA_V1)])


def parse_transaction_data(data: bytes) -> Any:
    """The parsed TransactionData, when writing it back gives exactly these bytes; raises BcsError otherwise."""
    try:
        parsed = TRANSACTION_DATA.parse(data)
        written = TRANSACTION_DATA.serialize(parsed)
    except Exception as e:
        raise BcsError(type(e).__name__) from e
    if written != data:
        raise BcsError("not canonical")
    return parsed


def command_arguments(command: dict[str, Any]) -> list[Any]:
    """Every argument a command names."""
    kind = command["$kind"]
    c = command[kind]
    if kind == "MoveCall":
        return list(c["arguments"])
    if kind == "TransferObjects":
        return [*c["objects"], c["address"]]
    if kind == "SplitCoins":
        return [c["coin"], *c["amounts"]]
    if kind == "MergeCoins":
        return [c["destination"], *c["sources"]]
    if kind == "MakeMoveVec":
        return list(c["elements"])
    if kind == "Upgrade":
        return [c["ticket"]]
    return []


def sui_digest(data: bytes) -> str:
    """Base58 of Blake2b-256 over "TransactionData::" followed by the bytes."""
    return b58_encode(hashlib.blake2b(_DIGEST_PREFIX + data, digest_size=32).digest())
