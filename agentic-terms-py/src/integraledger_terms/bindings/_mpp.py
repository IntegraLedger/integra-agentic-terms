"""What every MPP pairing's buyer half shares: the challenge id derived from the ATR hash, the challenge checked as
issued or as placed and the pairings it offers, the buyer's reading of the challenge list, the network a challenge
pays on, the echoed challenge of a credential, the challenge hash and MPP's attribution memo."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._keccak import keccak256
from .._types import Advertised, Refusal
from ._codec import b64u_decode, b64u_encode, to_hex
from ._evm import ZERO_ADDRESS
from ._jose import js_length, within_depth
from ._lcp import (
    agreement_fault,
    from_lcp_string,
    is_address,
    is_https_link,
    is_list,
    is_object,
    is_other_scheme_link,
    is_well_formed,
    normal_hash,
)
from ._mpp_checks import (
    CARRIED_PAIRING_CHECKS,
    MAX_JSON_DEPTH,
    PAIRING_CHECKS,
    decode_object,
    decode_string_map,
    hedera_charge_network,
    hedera_session_network_of,
    positive_int,
    solana_network_of,
    stacks_network_of,
    unix_of,
    usdc_profile,
    xrpl_network_of,
)

MAX_CHALLENGES = 32
MAX_CREDENTIAL = 65_536
MAX_LINK = 2048
LCP_KEYS = ("legalContext", "legalContextUrl", "legalContextAgreementUrl")
TEMPO_DEFAULT_CHAIN = 42431
TEMPO_V1_DEFAULT_CHAIN = 4217

_POSITION = re.compile(r"0|[1-9][0-9]?")
_DID_PKH = re.compile(r"did:pkh:eip155:[1-9][0-9]{0,15}:(0x[0-9a-fA-F]{40})")
_HEX_DIGITS = re.compile(r"0x[0-9a-fA-F]*")
_MPP_TAG = keccak256(b"mpp")[:4]


# ── The attribution memo and the challenge hash.


def attribution_memo(realm: str, challenge_id: str, client_id: str | None = None) -> str:
    """MPP's 32-byte attribution memo: keccak256("mpp")[0..3], 0x01, keccak256(realm)[0..9], keccak256(clientId)[0..9]
    or ten zero bytes, then keccak256(challengeId)[0..6], each over the string's UTF-8."""
    out = bytearray(32)
    out[0:4] = _MPP_TAG
    out[4] = 0x01
    out[5:15] = keccak256(str(realm).encode("utf-8"))[:10]
    if client_id is not None:
        out[15:25] = keccak256(str(client_id).encode("utf-8"))[:10]
    out[25:32] = keccak256(str(challenge_id).encode("utf-8"))[:7]
    return to_hex(bytes(out))


def check_attribution(memo: object, realm: str, challenge_id: str) -> bool | Refusal:
    """A memo's tag, version, server id for realm and nonce for challenge_id. The client id is not read."""
    m = normal_hash(memo)
    if m is None:
        return Refusal("mpp/attribution-malformed")
    got = bytes.fromhex(m[2:])
    expect = bytes.fromhex(attribution_memo(realm, challenge_id)[2:])
    if got[:15] != expect[:15] or got[25:] != expect[25:]:
        return Refusal("mpp/attribution-mismatch")
    return True


def challenge_id_h(c: object) -> AtrHash | Refusal:
    """H from a challenge's id in the form its intent and method take: the bare base64url of H for a Tempo
    subscription challenge, and challenge_id's form with a position for every other challenge. Any other id is
    mpp/id-not-ours."""
    if not is_object(c) or not isinstance(c.get("id"), str):
        return Refusal("mpp/id-not-ours")
    subscription = c.get("intent") == "subscription" and c.get("method") == "tempo"
    if ("." in c["id"]) == subscription:
        return Refusal("mpp/id-not-ours")
    return challenge_h(c["id"])


def challenge_hash(challenge_id: str, realm: str) -> str:
    """keccak256(UTF-8(id) ‖ UTF-8(realm)), lower-case: Solidity's abi.encodePacked(string, string)."""
    return to_hex(keccak256((str(challenge_id) + str(realm)).encode("utf-8")))


# ── The id.


def challenge_id(h: AtrHash, index: int) -> str | Refusal:
    """base64url, without padding, of H's 32 bytes, then "." and the challenge's position (0 to 31)."""
    b = normal_hash(h)
    if b is None or isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < MAX_CHALLENGES:
        return Refusal("mpp/challenge-malformed")
    return f"{b64u_encode(bytes.fromhex(b[2:]))}.{index}"


def challenge_h(id_: object) -> AtrHash | Refusal:
    """H from an id challenge_id wrote, or from the bare base64url of H; anything else is mpp/id-not-ours."""
    if not isinstance(id_, str):
        return Refusal("mpp/id-not-ours")
    body, dot, position = id_.partition(".")
    if dot and (_POSITION.fullmatch(position) is None or int(position) >= MAX_CHALLENGES):
        return Refusal("mpp/id-not-ours")
    if len(body) != 43:
        return Refusal("mpp/id-not-ours")
    raw = b64u_decode(body, 32)
    if raw is None or len(raw) != 32:
        return Refusal("mpp/id-not-ours")
    return to_hex(raw)


# ── The challenge, checked.


def is_challenge_shape(c: object) -> bool:
    if not is_object(c):
        return False
    for k in ("realm", "method", "intent", "request"):
        if not isinstance(c.get(k), str):
            return False
    for k in ("id", "expires", "digest", "description", "header", "opaque"):
        if k in c and not isinstance(c[k], str):
            return False
    return True


@dataclass(frozen=True, slots=True)
class Checked:
    """A challenge as check_challenge has checked it. expires is unix seconds; None when the challenge carries none,
    and then pairings holds none that needs it."""

    challenge: Mapping[str, Any]
    intent: str
    method: str
    request: dict[str, Any]
    details: Mapping[str, Any]
    expires: int | None
    pairings: tuple[str, ...]


# The pairings that need the challenge's expires: each one's build writes it into what the payer signs (the EIP-3009
# validBefore, the Permit2 deadline, the Tempo transaction's validBefore, the Stellar entry's expiration ledger, the
# session opening's deadline), or, on NEAR Intents and the XRP Ledger charge, the method's draft requires it. Without
# expires a challenge offers none of them.
NEEDS_EXPIRES = frozenset(
    {
        "mpp/charge/evm/authorization",
        "mpp/charge/evm/permit2",
        "mpp/charge/tempo/memo",
        "mpp/charge/tempo/push",
        "mpp/charge/usdc/evm",
        "mpp/charge/stellar",
        "mpp/charge/nearintents",
        "mpp/charge/xrpl",
        "mpp/session/evm",
        "mpp/session/tempo",
    }
)


def expires_of(checked: Checked) -> int | Refusal:
    """Unix seconds of a checked challenge's expires, for a build whose pairing writes it; none is
    mpp/expires-required, as pairings_of gives it."""
    return Refusal("mpp/expires-required") if checked.expires is None else checked.expires


def check_challenge(c: object, placed: bool, carried: bool = False) -> Checked | Refusal:
    """The checks of pairings_of. With placed, opaque may carry the LCP members the seller's placement writes. With
    carried, the carrier the seller writes after placement, which pairings_of takes absent (the Lightning invoice), is
    required. A realm with no UTF-8 form, which the attribution memo and the challenge hash cannot take, is
    mpp/challenge-malformed."""
    if not is_challenge_shape(c):
        return Refusal("mpp/challenge-malformed")
    assert is_object(c)
    if not is_well_formed(c["realm"]):
        return Refusal("mpp/challenge-malformed")
    check = (CARRIED_PAIRING_CHECKS if carried else PAIRING_CHECKS).get(f"{c['intent']}/{c['method']}")
    if check is None:
        return Refusal("mpp/not-this-pairing")
    expires = unix_of(c["expires"]) if "expires" in c else None
    if "expires" in c and expires is None:
        return Refusal("mpp/expires-required")
    request = decode_object(c["request"])
    if request is None:
        return Refusal("mpp/request-malformed")
    if "opaque" in c:
        present = decode_string_map(c["opaque"])
        if present is None:
            return Refusal("mpp/opaque-malformed")
        if not placed and any(k in present for k in LCP_KEYS):
            return Refusal("mpp/carrier-taken")
    md = request.get("methodDetails")
    if "methodDetails" in request and not is_object(md):
        return Refusal("mpp/request-malformed")
    details: Mapping[str, Any] = md if is_object(md) else {}
    named = check(request, details, c)
    if isinstance(named, Refusal):
        return named
    pairings = named if expires is not None else [p for p in named if p not in NEEDS_EXPIRES]
    if not pairings and named:
        return Refusal("mpp/expires-required")
    return Checked(c, c["intent"], c["method"], request, details, expires, tuple(pairings))


def pairings_of(c: object) -> tuple[str, ...] | Refusal:
    """A challenge checked as issued (no LCP member in opaque), and its pairings in the order they are offered. A
    Tempo charge whose amount is 0 names none: MPP pays it with a proof credential, which moves no money. An expires
    that is present must be an RFC 3339 date-time, else mpp/expires-required. Without expires, the pairings whose build
    writes it into what the payer signs, and the NEAR Intents and XRP Ledger charges, whose drafts require it, are left
    out, and a challenge left with no pairing is mpp/expires-required. These checks are each pairing's one filter: they
    include every check its build and bound make on the challenge alone, and those take only a challenge
    pairings_of_placed names for the pairing, refusing any other with the code these checks give it
    (mpp/not-this-pairing where they name only other pairings)."""
    checked = check_challenge(c, False)
    return checked if isinstance(checked, Refusal) else checked.pairings


def checked_for(c: object, pairing: str) -> Checked | Refusal:
    """A challenge as placed, held to pairing's filter: pairings_of's checks over it, with the LCP members the seller's
    placement writes allowed in opaque and the Lightning invoice required, and pairing among the pairings they name. A
    challenge they refuse gives their refusal, and one that does not offer pairing (another intent, method, credential
    type, mode or usdc profile, or no expires where pairing needs it) is mpp/not-this-pairing. Each pairing's build
    takes the chosen challenge through this one step, and its bound the echoed one (echoed_for), so none of them takes a
    challenge pairings_of would not name for that pairing."""
    checked = check_challenge(c, True, True)
    if isinstance(checked, Refusal):
        return checked
    return checked if pairing in checked.pairings else Refusal("mpp/not-this-pairing")


# ── The buyer's reading.


def is_link(value: object) -> bool:
    """True for an https link of at most 2048 UTF-16 code units."""
    return isinstance(value, str) and js_length(value) <= MAX_LINK and is_https_link(value)


def read(doc: object) -> Advertised | Refusal:
    """The challenges whose opaque carries an LCP hash and an https link and whose id derives from that hash, in
    document order, as offer {"challenges"}. agreement is their https agreement URL when one is present. With no
    challenge read, a link of another scheme in any such challenge is mpp/link-not-https, else any other failing link
    is mpp/legal-context-malformed."""
    if not is_list(doc) or len(doc) > MAX_CHALLENGES:
        return Refusal("mpp/challenge-malformed")
    h: AtrHash | None = None
    link: str | None = None
    agreement: str | None = None
    challenges: list[Any] = []
    not_https = False
    malformed_link = False
    for c in doc:
        if not is_challenge_shape(c) or "opaque" not in c:
            continue
        present = decode_string_map(c["opaque"])
        if present is None:
            continue
        lc = from_lcp_string(present["legalContext"]) if "legalContext" in present else None
        url = present.get("legalContextUrl")
        if lc is None:
            continue
        from_id = challenge_id_h(c)
        if isinstance(from_id, Refusal) or not hash_equals(from_id, lc):
            continue
        if not is_link(url):
            if is_other_scheme_link(url):
                not_https = True
            else:
                malformed_link = True
            continue
        assert isinstance(url, str)
        if h is not None and not hash_equals(h, lc):
            return Refusal("mpp/legal-context-conflict")
        if link is not None and link != url:
            return Refusal("mpp/legal-context-conflict")
        if "legalContextAgreementUrl" in present:
            a = present["legalContextAgreementUrl"]
            if not is_link(a):
                return Refusal(f"mpp/{agreement_fault(a).fault}")
            if agreement is not None and agreement != a:
                return Refusal("mpp/legal-context-conflict")
            agreement = a
        h = lc
        link = url
        challenges.append(c)
    if h is None or link is None:
        if not_https:
            return Refusal("mpp/link-not-https")
        return Refusal("mpp/legal-context-malformed" if malformed_link else "mpp/no-legal-context")
    return Advertised(h=h, link=link, offer={"challenges": challenges}, agreement=agreement)


# ── The network.


def chain_of(c: "Checked | EchoedChallenge") -> int:
    """The chain an EVM or Tempo charge challenge pays on: its methodDetails.chainId, or Tempo's default where it names
    none. The filter has read chainId as a positive safe integer where it is present."""
    chain_id = positive_int(c.details.get("chainId"))
    return TEMPO_DEFAULT_CHAIN if chain_id is None else chain_id


@dataclass(frozen=True, slots=True)
class Params:
    """The chain, escrow and protocol version an EVM or Tempo session or subscription challenge names."""

    method: str
    intent: str
    chain_id: int
    network: str
    escrow: str
    version: str
    request: dict[str, Any]
    details: Mapping[str, Any]


def params_of(c: object) -> Params | Refusal:
    """The chain, escrow and protocol version an EVM or Tempo session or subscription challenge names, read without
    the offer checks. A methodDetails that is present and not an object is mpp/request-malformed. On a Tempo session,
    sessionProtocol is absent, v1 or v2, else mpp/session-protocol, and a missing chainId reads as Tempo's default chain
    on v1 only: a v2 session without chainId or escrowContract is mpp/chain-id-required, the codes pairings_of gives."""
    if not is_object(c) or not isinstance(c.get("request"), str):
        return Refusal("mpp/credential-malformed")
    method, intent = c.get("method"), c.get("intent")
    if not ((intent == "session" and method in ("evm", "tempo")) or (intent == "subscription" and method == "tempo")):
        return Refusal("mpp/not-this-pairing")
    request = decode_object(c["request"])
    if request is None:
        return Refusal("mpp/request-malformed")
    md = request.get("methodDetails")
    if "methodDetails" in request and not is_object(md):
        return Refusal("mpp/request-malformed")
    details: Mapping[str, Any] = md if is_object(md) else {}
    tempo_session = method == "tempo" and intent == "session"
    protocol = details.get("sessionProtocol")
    if tempo_session and "sessionProtocol" in details and protocol not in ("v1", "v2"):
        return Refusal("mpp/session-protocol")
    if tempo_session and protocol == "v2" and ("chainId" not in details or "escrowContract" not in details):
        return Refusal("mpp/chain-id-required")
    chain_id = positive_int(details.get("chainId"))
    if chain_id is None and tempo_session and protocol != "v2" and "chainId" not in details:
        chain_id = TEMPO_V1_DEFAULT_CHAIN
    if chain_id is None:
        return Refusal("mpp/chain-id-required")
    escrow = details.get("escrowContract")
    if intent == "session" and not is_address(escrow):
        return Refusal("mpp/escrow-malformed")
    return Params(
        method=str(method),
        intent=str(intent),
        chain_id=chain_id,
        network=f"eip155:{chain_id}",
        escrow=escrow if isinstance(escrow, str) and is_address(escrow) else ZERO_ADDRESS,
        version="v2" if protocol == "v2" else "v1",
        request=request,
        details=details,
    )


def session_network(c: object) -> str | Refusal:
    """The CAIP-2 network of an EVM or Tempo session or subscription challenge."""
    p = params_of(c)
    return p if isinstance(p, Refusal) else p.network


def network(challenge: object) -> str | Refusal:
    """The CAIP-2 network a challenge pays on, read from its method, intent and methodDetails as each method defines
    it, with that method's default where it names one. A method whose challenge names no network is refused."""
    c = check_challenge(challenge, True)
    if isinstance(c, Refusal):
        return c
    d = c.details
    key = f"{c.intent}/{c.method}"
    if key in ("charge/evm", "charge/tempo"):
        return f"eip155:{chain_of(c)}"
    if key in ("session/evm", "session/tempo", "subscription/tempo"):
        return session_network(challenge)
    if key in ("charge/solana", "session/solana"):
        n = solana_network_of(d, c.intent == "session")
        return Refusal("svm/network-undeclared") if n is None else n
    if key in ("charge/xrpl", "session/xrpl"):
        return xrpl_network_of(d)
    if key == "charge/hedera":
        return hedera_charge_network(c.request)
    if key == "session/hedera":
        return hedera_session_network_of(d)
    if key == "charge/stellar":
        return str(d["network"])
    if key == "charge/nearintents":
        return str(d["originNetwork"])
    if key == "charge/usdc":
        profile = usdc_profile(d)
        if isinstance(profile, Refusal):
            return profile
        kind, details = profile
        if kind == "evm":
            return f"eip155:{positive_int(details.get('chainId'))}"
        if kind == "stacks":
            return stacks_network_of(d) or Refusal("mpp/request-malformed")
        if kind == "solana":
            n = solana_network_of(details, True)
            return Refusal("svm/network-undeclared") if n is None else n
        return Refusal("mpp/network-unnamed")
    return Refusal("mpp/network-unnamed")


# ── The echoed challenge.


def _json_within(value: object, limit: int) -> bool:
    """True when value is JSON data of at most limit bytes as JSON, counted as MPP counts it, nested at most 16 arrays
    and objects, the outermost counting 1, whatever the innermost holds. The depth is read first, without recursion,
    so the byte count never walks deeper than 16 levels."""
    if not within_depth(value, MAX_JSON_DEPTH):
        return False
    budget = limit

    def walk(x: object) -> bool:
        nonlocal budget
        if isinstance(x, str):
            budget -= js_length(x) + 2
        elif x is None or isinstance(x, (bool, int, float)):
            budget -= 8
        elif is_list(x):
            budget -= 2
            for y in x:
                if not walk(y):
                    return False
        elif is_object(x):
            budget -= 2
            for k, y in x.items():
                if not isinstance(k, str):
                    return False
                budget -= js_length(k) + 3
                if not walk(y):
                    return False
        else:
            return False
        return budget >= 0

    return walk(value)


def credential_of(c: object) -> Mapping[str, Any] | Refusal:
    """A credential's shape: an echoed challenge with an id, an optional string source, and a payload object. A
    credential that carries a refused member, the member refusals use, is mpp/credential-malformed."""
    if not is_object(c) or "refused" in c or not is_object(c.get("challenge")) or not is_object(c.get("payload")):
        return Refusal("mpp/credential-malformed")
    if not is_challenge_shape(c["challenge"]) or not isinstance(c["challenge"].get("id"), str):
        return Refusal("mpp/credential-malformed")
    if "source" in c and not isinstance(c["source"], str):
        return Refusal("mpp/credential-malformed")
    return c


@dataclass(frozen=True, slots=True)
class Bound:
    h: AtrHash
    request: dict[str, Any]


def challenge_bound(c: object) -> Bound | Refusal:
    """H from an echoed challenge: its id derives from H in the form its intent and method take, its opaque names H,
    and its request decodes. A realm with no UTF-8 form is mpp/challenge-malformed."""
    shaped = credential_of(c)
    if isinstance(shaped, Refusal):
        return shaped
    if not _json_within(shaped, MAX_CREDENTIAL):
        return Refusal("mpp/credential-malformed")
    challenge = shaped["challenge"]
    if not is_well_formed(challenge["realm"]):
        return Refusal("mpp/challenge-malformed")
    h = challenge_id_h(challenge)
    if isinstance(h, Refusal):
        return h
    if "opaque" not in challenge:
        return Refusal("mpp/opaque-not-this-hash")
    present = decode_string_map(challenge["opaque"])
    if present is None:
        return Refusal("mpp/opaque-malformed")
    lc = from_lcp_string(present["legalContext"]) if "legalContext" in present else None
    if lc is None or not hash_equals(lc, h):
        return Refusal("mpp/opaque-not-this-hash")
    request = decode_object(challenge["request"])
    if request is None:
        return Refusal("mpp/request-malformed")
    return Bound(h, request)


@dataclass(frozen=True, slots=True)
class EchoedChallenge:
    """An echoed challenge as a credential presents it, held to its pairing's filter (checked_for): the request
    decoded, and each pairing reads the request members its own read keys or derivation use. details is methodDetails,
    empty when the request has none. expires is unix seconds; None when the challenge carries none; and
    mpp/expires-required, the code pairings_of gives, when it carries one that does not read as a date."""

    challenge: Mapping[str, Any]
    request: dict[str, Any]
    details: Mapping[str, Any]
    expires: int | None | Refusal


@dataclass(frozen=True, slots=True)
class Echoed:
    h: AtrHash
    checked: EchoedChallenge
    payload: Mapping[str, Any]


def echoed_of(challenge: Mapping[str, Any], request: dict[str, Any]) -> EchoedChallenge | Refusal:
    """The EchoedChallenge of a challenge and its decoded request. A methodDetails that is present and not an object
    is mpp/request-malformed, the code pairings_of gives it; it is never read as empty."""
    md = request.get("methodDetails")
    if "methodDetails" in request and not is_object(md):
        return Refusal("mpp/request-malformed")
    details: Mapping[str, Any] = md if is_object(md) else {}
    expires: int | Refusal | None = None
    if "expires" in challenge:
        at = unix_of(challenge["expires"])
        expires = Refusal("mpp/expires-required") if at is None else at
    return EchoedChallenge(challenge, request, details, expires)


def echoed_for(c: object, pairing: str) -> Echoed | Refusal:
    """The echoed challenge of a credential for pairing: H from challenge_bound, the challenge's intent and method,
    which must be pairing's, and the challenge held to pairing's filter (checked_for), whose refusal it gives."""
    b = challenge_bound(c)
    if isinstance(b, Refusal):
        return b
    assert is_object(c)
    challenge = c["challenge"]
    _, intent, method = pairing.split("/")[:3]
    if challenge["intent"] != intent or challenge["method"] != method:
        return Refusal("mpp/not-this-pairing")
    held = checked_for(challenge, pairing)
    if isinstance(held, Refusal):
        return held
    echoed = echoed_of(challenge, b.request)
    if isinstance(echoed, Refusal):
        return echoed
    return Echoed(b.h, echoed, c["payload"])


def request_address(e: EchoedChallenge, key: str) -> str | Refusal:
    """The request member key as an address, else mpp/request-malformed."""
    v = e.request.get(key)
    return v if isinstance(v, str) and is_address(v) else Refusal("mpp/request-malformed")


def chosen_for(challenge: object, h: object, pairing: str) -> Checked | Refusal:
    """The buyer's chosen challenge for pairing, held to its filter (checked_for), whose id derives from h."""
    if not is_challenge_shape(challenge) or not isinstance(challenge.get("id") if is_object(challenge) else None, str):
        return Refusal("mpp/input-malformed")
    checked = checked_for(challenge, pairing)
    if isinstance(checked, Refusal):
        return checked
    assert is_object(challenge)
    from_id = challenge_id_h(challenge)
    if isinstance(from_id, Refusal) or not isinstance(h, str) or not hash_equals(from_id, h):
        return Refusal("mpp/id-not-ours")
    return checked


def offer_for(choice: object, h: object, pairing: str) -> Checked | Refusal:
    """The checked challenge a build answers: it is held to pairing's filter (checked_for), its id carries h, and from
    is an address."""
    if not is_object(choice) or not is_object(choice.get("challenge")):
        return Refusal("mpp/input-malformed")
    checked = checked_for(choice["challenge"], pairing)
    if isinstance(checked, Refusal):
        return checked
    from_id = challenge_id_h(choice["challenge"])
    if isinstance(from_id, Refusal) or not isinstance(h, str) or not hash_equals(from_id, h):
        return Refusal("mpp/id-not-ours")
    if not is_address(choice.get("from")):
        return Refusal("mpp/input-malformed")
    return checked


# ── Helpers the pairings share.


def did_pkh_address(source: object) -> str | None:
    """The address of a did:pkh:eip155:<chain>:<address> source, lower-case, or None."""
    match = _DID_PKH.fullmatch(source) if isinstance(source, str) else None
    return match.group(1).lower() if match is not None else None


def is_hex_bytes(value: object, low: int, high: int) -> bool:
    """0x and an even number of hex digits, from low to high bytes."""
    if not isinstance(value, str) or len(value) % 2 != 0 or len(value) > 2 + 2 * high:
        return False
    return _HEX_DIGITS.fullmatch(value) is not None and (len(value) - 2) // 2 >= low


def same_bytes(a: object, b: object) -> bool:
    """Equal byte strings written as 0x hex in either case."""
    return (
        isinstance(a, str)
        and isinstance(b, str)
        and _HEX_DIGITS.fullmatch(a) is not None
        and _HEX_DIGITS.fullmatch(b) is not None
        and len(a) % 2 == 0
        and a.lower() == b.lower()
    )


def text(value: object) -> str:
    """value when it is a string, else the empty string."""
    return value if isinstance(value, str) else ""


@dataclass(frozen=True, slots=True)
class MppUnsigned:
    """What an MPP build gives: the request handed to the signer, and the completion of the signer's answer into
    the credential."""

    request: dict[str, Any]
    complete: Callable[[Any], dict[str, Any] | Refusal]
