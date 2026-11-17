"""The buyer half of the pairing spend-permissions/eip155, an account's approval of a Spend Permission whose salt is H,
as the sale's agreement and never a charge (lcp profile spend-permissions-eip155.md): read, build, bound and
broadcaster.

The resource server's 402 body offers the permission without its account, salt being H; the account adds itself and
either signs the permission as EIP-712 typed data in the SpendPermissionManager's domain or calls the manager's approve
with it, and returns the whole permission with its signature or its transaction in the Spend-Permission header. The
permission's hash is the manager's getHash. Nothing here fetches, signs or reads a chain.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal

from .._core import AtrHash, hash_equals
from .._keccak import keccak256
from .._types import Act, Advertised, AgreementData, Broadcaster, Coverage, Json, Refusal
from ._codec import js_json
from ._evm import address_word, bytes_of, hex_of, uint_word
from ._jose import js_length, json_bytes
from ._lcp import MAX_LINK_CHARS, chain_id_of, is_address, is_https_link, is_list, is_object, is_other_scheme_link, normal_hash

ID = "spend-permissions/eip155"

# The bounds the profile sets: the 402 body and the header's value, each as JSON's UTF-8 bytes, and a signature's bytes.
MAX_HEADER_BYTES = 65_536
MAX_SIGNATURE_BYTES = 8192

Route = Literal["signature", "transaction"]
ROUTES: tuple[Route, ...] = ("signature", "transaction")

# The codes a refused return is answered with, in the 402 body's error member.
ERRORS = (
    "spend-permissions/not-bound",
    "spend-permissions/signature-invalid",
    "spend-permissions/not-approved",
    "spend-permissions/revoked",
    "spend-permissions/ended",
    "spend-permissions/header-malformed",
    "spend-permissions/route-not-accepted",
    "spend-permissions/account-is-spender",
)

_MEMBERS = ("spender", "token", "allowance", "period", "start", "end", "salt", "extraData")
_OFFER = ("network", "manager", "permission", "accepts", "legalContext")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,77}")
_UINT48 = (1 << 48) - 1
_UINT160 = (1 << 160) - 1
_UINT256 = (1 << 256) - 1
_ZERO_ADDRESS = "0x" + "00" * 20

# The manager's SpendPermission type (SpendPermissionManager.sol :92-94), and its EIP-712 domain's name and version.
_TYPE = "SpendPermission(address account,address spender,address token,uint160 allowance,uint48 period,uint48 start,uint48 end,uint256 salt,bytes extraData)"
SPEND_PERMISSION_TYPEHASH = hex_of(keccak256(_TYPE.encode()))
DOMAIN_NAME = "Spend Permission Manager"
DOMAIN_VERSION = "1"
_DOMAIN_TYPEHASH = keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
_TUPLE = "(address,address,address,uint160,uint48,uint48,uint48,uint256,bytes)"
APPROVE_SELECTOR = hex_of(keccak256(f"approve({_TUPLE})".encode())[:4])
SPEND_PERMISSION_FIELDS: tuple[tuple[str, str], ...] = (
    ("account", "address"),
    ("spender", "address"),
    ("token", "address"),
    ("allowance", "uint160"),
    ("period", "uint48"),
    ("start", "uint48"),
    ("end", "uint48"),
    ("salt", "uint256"),
    ("extraData", "bytes"),
)


@dataclass(frozen=True, slots=True)
class Permission:
    """A permission read: addresses lowercase, integers as ints, extraData as bytes; account None where it has none."""

    account: str | None
    spender: str
    token: str
    allowance: int
    period: int
    start: int
    end: int
    salt: int
    extra_data: bytes


def _decimal_of(value: object, limit: int) -> int | None:
    """A decimal string with no sign and no leading zero, at most limit, as an int; None for anything else."""
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        return None
    n = int(value)
    return n if n <= limit else None


def permission_of(value: object, with_account: bool) -> Permission | None:
    """A permission in the exchange's wire form, with account where with_account is true and without it otherwise, and
    no other member; None for anything else."""
    if not is_object(value):
        return None
    names = ("account", *_MEMBERS) if with_account else _MEMBERS
    if set(value.keys()) != set(names):
        return None
    account, spender, token = value.get("account"), value["spender"], value["token"]
    if (with_account and not is_address(account)) or not is_address(spender) or not is_address(token):
        return None
    allowance = _decimal_of(value["allowance"], _UINT160)
    period = _decimal_of(value["period"], _UINT48)
    start = _decimal_of(value["start"], _UINT48)
    end = _decimal_of(value["end"], _UINT48)
    salt = _decimal_of(value["salt"], _UINT256)
    extra = bytes_of(value["extraData"])
    if allowance is None or period is None or start is None or end is None or salt is None or extra is None:
        return None
    return Permission(
        account.lower() if with_account and isinstance(account, str) else None,
        spender.lower(),
        token.lower(),
        allowance,
        period,
        start,
        end,
        salt,
        extra,
    )


def wire_permission(p: Permission) -> dict[str, str]:
    """The permission in the exchange's wire form, account first where it has one."""
    out = {} if p.account is None else {"account": p.account}
    return {
        **out,
        "spender": p.spender,
        "token": p.token,
        "allowance": str(p.allowance),
        "period": str(p.period),
        "start": str(p.start),
        "end": str(p.end),
        "salt": str(p.salt),
        "extraData": hex_of(p.extra_data),
    }


def manager_refuses(p: Permission) -> bool:
    """Whether the manager refuses the permission, so every approval of it reverts (_approve, :630-653): a zero token or
    spender, a zero period or allowance, or a start not before end."""
    return p.token == _ZERO_ADDRESS or p.spender == _ZERO_ADDRESS or p.period == 0 or p.allowance == 0 or p.start >= p.end


def salt_hash(p: Permission) -> AtrHash:
    """The salt as a 32-byte hash, the way H is written."""
    return hex_of(uint_word(p.salt))


def _account(p: Permission) -> str:
    assert p.account is not None
    return p.account


def hash_of(p: Permission, chain_id: int, manager: str) -> str:
    """The permission's hash, as the manager's getHash computes it on chain_id at manager (:561-578): the EIP-712 digest
    the account signs."""
    struct = keccak256(
        bytes.fromhex(SPEND_PERMISSION_TYPEHASH[2:])
        + address_word(_account(p))
        + address_word(p.spender)
        + address_word(p.token)
        + uint_word(p.allowance)
        + uint_word(p.period)
        + uint_word(p.start)
        + uint_word(p.end)
        + uint_word(p.salt)
        + keccak256(p.extra_data)
    )
    domain = keccak256(
        _DOMAIN_TYPEHASH
        + keccak256(DOMAIN_NAME.encode())
        + keccak256(DOMAIN_VERSION.encode())
        + uint_word(chain_id)
        + address_word(manager)
    )
    return hex_of(keccak256(b"\x19\x01" + domain + struct))


def permission_call(selector: str, p: Permission) -> str:
    """A call of the manager whose one argument is the permission: the selector, the tuple's offset, its nine head
    words, then extraData's length and its bytes padded with zeros to a word."""
    pad = (32 - len(p.extra_data) % 32) % 32
    data = (
        bytes.fromhex(selector[2:])
        + uint_word(32)
        + address_word(_account(p))
        + address_word(p.spender)
        + address_word(p.token)
        + uint_word(p.allowance)
        + uint_word(p.period)
        + uint_word(p.start)
        + uint_word(p.end)
        + uint_word(p.salt)
        + uint_word(9 * 32)
        + uint_word(len(p.extra_data))
        + p.extra_data
        + bytes(pad)
    )
    return hex_of(data)


@dataclass(frozen=True, slots=True)
class Offer:
    """The offer read whole: its network and chain id, the manager lowercase, the permission, the routes, H and the
    link."""

    network: str
    chain_id: int
    manager: str
    permission: Permission
    accepts: tuple[Route, ...]
    h: AtrHash
    link: str


def _routes_of(value: object) -> tuple[Route, ...] | None:
    """A non-empty array of distinct routes, or None."""
    if not is_list(value) or not 0 < len(value) <= len(ROUTES) or not all(r in ROUTES for r in value):
        return None
    return tuple(value) if len(set(value)) == len(value) else None


def offer_of(value: object) -> Offer | Refusal:
    """The offer as the profile's rule 3 states it, meeting the manager's refusals and with salt = H: its legalContext
    decoding with an https link of at most 2048 UTF-16 code units, and no other member."""
    if not is_object(value) or "refused" in value:
        return Refusal("spend-permissions/option-malformed")
    if "legalContext" not in value:
        return Refusal("spend-permissions/legal-context-malformed")
    if set(value.keys()) != set(_OFFER):
        return Refusal("spend-permissions/option-malformed")
    lc = value["legalContext"]
    if not is_object(lc) or any(k not in ("type", "value", "legalContextUrl") for k in lc):
        return Refusal("spend-permissions/legal-context-malformed")
    url = lc.get("legalContextUrl")
    if is_other_scheme_link(url):
        return Refusal("spend-permissions/link-not-https")
    h = normal_hash(lc.get("value"))
    if lc.get("type") != "sha256" or h is None or not isinstance(url, str) or js_length(url) > MAX_LINK_CHARS:
        return Refusal("spend-permissions/legal-context-malformed")
    if not is_https_link(url):
        return Refusal("spend-permissions/legal-context-malformed")
    chain_id = chain_id_of(value["network"])
    permission = permission_of(value["permission"], False)
    accepts = _routes_of(value["accepts"])
    manager = value["manager"]
    if chain_id is None or not is_address(manager) or permission is None or accepts is None:
        return Refusal("spend-permissions/option-malformed")
    if manager_refuses(permission):
        return Refusal("spend-permissions/option-malformed")
    if not hash_equals(salt_hash(permission), h):
        return Refusal("spend-permissions/not-bound")
    return Offer(value["network"], chain_id, manager.lower(), permission, accepts, h, url)


def wire_offer(o: Offer) -> dict[str, Any]:
    """The offer in its wire form."""
    return {
        "network": o.network,
        "manager": o.manager,
        "permission": wire_permission(o.permission),
        "accepts": list(o.accepts),
        "legalContext": {"type": "sha256", "value": o.h, "legalContextUrl": o.link},
    }


@dataclass(frozen=True, slots=True)
class ReturnRead:
    """A return read: the network and its chain id, the manager lowercase, the whole permission, the route, and the
    signature's or the transaction's hex, lowercase."""

    network: str
    chain_id: int
    manager: str
    permission: Permission
    route: Route
    signature: str | None = None
    transaction: str | None = None


def return_of(value: object) -> ReturnRead | Literal["signature"] | None:
    """A return as the profile's rule 8 states it: network, manager, the whole permission, and exactly one of signature
    (1 to 8192 bytes of hex) and transaction (a 32-byte hash), and no other member. None where its shape is not that;
    "signature" where only its signature is malformed."""
    if not is_object(value):
        return None
    keys = set(value.keys())
    route: Route | None = (
        "signature"
        if "signature" in keys and "transaction" not in keys
        else "transaction"
        if "transaction" in keys and "signature" not in keys
        else None
    )
    if route is None or keys != {"network", "manager", "permission", route}:
        return None
    chain_id = chain_id_of(value["network"])
    manager = value["manager"]
    if chain_id is None or not is_address(manager):
        return None
    permission = permission_of(value["permission"], True)
    if permission is None:
        return None
    if route == "transaction":
        t = normal_hash(value["transaction"])
        return None if t is None else ReturnRead(value["network"], chain_id, manager.lower(), permission, route, transaction=t)
    s = bytes_of(value["signature"], MAX_SIGNATURE_BYTES)
    if s is None or len(s) == 0:
        return "signature"
    return ReturnRead(value["network"], chain_id, manager.lower(), permission, route, signature=hex_of(s))


def read_return(presented: object) -> ReturnRead | Refusal:
    """A return, or the refusal its shape earns: signature-invalid where only its signature is malformed."""
    if is_object(presented) and "refused" in presented:
        return Refusal("spend-permissions/header-malformed")
    r = return_of(presented)
    if r == "signature":
        return Refusal("spend-permissions/signature-invalid")
    return Refusal("spend-permissions/header-malformed") if r is None else r


def wire_return(r: ReturnRead) -> dict[str, Any]:
    """The return in its wire form, as the Spend-Permission header carries it."""
    base: dict[str, Any] = {"network": r.network, "manager": r.manager, "permission": wire_permission(r.permission)}
    return {**base, "signature": r.signature} if r.route == "signature" else {**base, "transaction": r.transaction}


def presented_return(presented: object) -> dict[str, Any] | Refusal:
    """The return as the Spend-Permission header carries it, whose JSON is at most 65,536 bytes; else the refusal the
    header gives it (header-malformed, or signature-invalid for a malformed signature)."""
    r = read_return(presented)
    if isinstance(r, Refusal):
        return r
    wire = wire_return(r)
    return Refusal("spend-permissions/header-malformed") if len(js_json(wire).encode("utf-8")) > MAX_HEADER_BYTES else wire


@dataclass(frozen=True, slots=True)
class SpendPermissionUnsigned:
    """What build gives the account: the whole permission, its hash, the typed data it signs on "signature", and the
    manager's approve call it makes on "transaction"."""

    permission: dict[str, str]
    hash: str
    typed_data: dict[str, Any]
    approve: dict[str, str]


# The agreement this pairing's act is, as @integraledger/lcp's registry states it: an approval that moves nothing,
# offered as an agreement only.
AGREEMENT = AgreementData(floor="0", only=True)


@dataclass(frozen=True, slots=True)
class SpendPermissionsEip155:
    id: str = ID
    coverage: Coverage = "full"
    agreement: AgreementData | None = AGREEMENT

    def read(self, doc: Json) -> Advertised | Refusal:
        """H and the link from the offer's legalContext, and the offer, which must meet the manager's refusals and
        carry salt = H (not-bound). A body over 65,536 bytes as JSON, holding a member but spendPermission and error, or
        whose error is not one of the exchange's codes, is option-malformed."""
        if not is_object(doc) or "refused" in doc:
            return Refusal("spend-permissions/option-malformed")
        size = json_bytes(doc)
        if size is None or size > MAX_HEADER_BYTES:
            return Refusal("spend-permissions/option-malformed")
        if any(k not in ("spendPermission", "error") for k in doc):
            return Refusal("spend-permissions/option-malformed")
        if "error" in doc and doc["error"] not in ERRORS:
            return Refusal("spend-permissions/option-malformed")
        o = offer_of(doc.get("spendPermission"))
        if isinstance(o, Refusal):
            return o
        return Advertised(h=o.h, link=o.link, offer=wire_offer(o))

    def build(self, choice: Json, h: AtrHash, act: Act | None = None) -> SpendPermissionUnsigned | Refusal:
        """What the account signs or calls, with H in salt: the offer must carry salt = H and legalContext.value = H,
        H being the hash of the ATR fetched (not-bound); account an address (choice-malformed) that is not spender
        (account-is-spender). The act changes nothing: the pairing's one act is the agreement."""
        if not is_object(choice):
            return Refusal("spend-permissions/choice-malformed")
        o = offer_of(choice.get("offer"))
        if isinstance(o, Refusal):
            return o
        nh = normal_hash(h)
        if nh is None or not hash_equals(o.h, nh) or not hash_equals(salt_hash(o.permission), nh):
            return Refusal("spend-permissions/not-bound")
        account = choice.get("account")
        if not is_address(account):
            return Refusal("spend-permissions/choice-malformed")
        if account.lower() == o.permission.spender:
            return Refusal("spend-permissions/account-is-spender")
        p = replace(o.permission, account=account.lower())
        return SpendPermissionUnsigned(
            permission=wire_permission(p),
            hash=hash_of(p, o.chain_id, o.manager),
            typed_data={
                "domain": {"name": DOMAIN_NAME, "version": DOMAIN_VERSION, "chainId": o.chain_id, "verifyingContract": o.manager},
                "types": {"SpendPermission": [{"name": n, "type": t} for n, t in SPEND_PERMISSION_FIELDS]},
                "primaryType": "SpendPermission",
                "message": {
                    "account": p.account,
                    "spender": p.spender,
                    "token": p.token,
                    "allowance": p.allowance,
                    "period": p.period,
                    "start": p.start,
                    "end": p.end,
                    "salt": p.salt,
                    "extraData": hex_of(p.extra_data),
                },
            },
            approve={"to": o.manager, "data": permission_call(APPROVE_SELECTOR, p)},
        )

    def bound(self, presented: Json, given: Mapping[str, Any] | None = None) -> AtrHash | Refusal:
        """H as the return carries it, the permission's salt as a 32-byte hash; given H, a salt that is not it is
        not-bound. A return of another shape is refused as its header is."""
        r = read_return(presented)
        if isinstance(r, Refusal):
            return r
        h = salt_hash(r.permission)
        given_h = given.get("h") if is_object(given) else None
        if given is not None and not (isinstance(given_h, str) and hash_equals(h, given_h)):
            return Refusal("spend-permissions/not-bound")
        return h

    def broadcaster(self, presented: Json) -> Broadcaster | Refusal:
        """On "signature" the payee, which submits the approval as spender; on "transaction" the payer, whose account
        has already made it."""
        r = read_return(presented)
        if isinstance(r, Refusal):
            return r
        return "payee" if r.route == "signature" else "payer"
