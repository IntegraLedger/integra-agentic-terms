"""The buyer half of MPP's usdc method on its EVM and Gateway profiles. On EVM the payer signs an EIP-3009
authorization whose nonce, and on Gateway a burn intent whose TransferSpec salt, is usdc's derivation over the
challenge id, which carries the ATR hash."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._keccak import keccak256
from .._types import Advertised, Refusal
from ._codec import b58_encode, b64u_decode, canonical_or_none, to_hex
from ._jose import UNPARSED, parse_json
from ._lcp import is_address, is_object, normal_hash
from ._mpp import Checked, MppUnsigned, chosen_for, credential_of, echoed_for, is_hex_bytes, read, same_bytes, text
from ._mpp_checks import MAX_DECODED, positive_int
from ._mpp_evm import eip3009_typed_data

EVM = "mpp/charge/usdc/evm"
GATEWAY = "mpp/charge/usdc/gateway"

MAX_SIGNATURE = 8192
GATEWAY_FORMAT = "circle-gateway-v1"
_UINT = re.compile(r"[0-9]{1,78}")
_BYTES32 = re.compile(r"0x[0-9a-fA-F]{64}")
_MAX_SAFE_INTEGER = 2**53 - 1

SALT_KEYS = (
    "id",
    "realm",
    "requestHash",
    "sourceNetwork",
    "destinationNetwork",
    "sourceDepositor",
    "sourceSigner",
    "recipient",
    "destinationRecipient",
    "amount",
    "maxFee",
)



def usdc_request_hash(request_param: object) -> str | Refusal:
    """keccak256 of the challenge's request parameter's decoded bytes, 0x and lower-case hex. The bytes must be the
    RFC 8785 form of their own parse, else mpp/request-not-jcs; they are hashed as received."""
    raw = b64u_decode(request_param, MAX_DECODED)
    if raw is None:
        return Refusal("mpp/request-malformed")
    try:
        text_ = raw.decode("utf-8")
    except UnicodeDecodeError:
        return Refusal("mpp/request-malformed")
    parsed = parse_json(text_)
    if parsed is UNPARSED:
        return Refusal("mpp/request-malformed")
    if canonical_or_none(parsed) != text_:
        return Refusal("mpp/request-not-jcs")
    return to_hex(keccak256(raw))


def _keccak_jcs(v: Mapping[str, str]) -> str | Refusal:
    """keccak256 of the UTF-8 of the RFC 8785 form of v."""
    t = canonical_or_none(v)
    return Refusal("mpp/challenge-malformed") if t is None else to_hex(keccak256(t.encode("utf-8")))


def usdc_nonce(id_: str, realm: str, request_hash: str) -> str | Refusal:
    """usdc's EIP-3009 nonce: keccak256 of the JCS of {id, method: "usdc", realm, intent: "charge", requestHash}."""
    rh = normal_hash(request_hash)
    if rh is None:
        return Refusal("mpp/request-malformed")
    return _keccak_jcs({"id": str(id_), "method": "usdc", "realm": str(realm), "intent": "charge", "requestHash": rh})


def usdc_gateway_salt(i: object) -> str | Refusal:
    """usdc's Gateway salt: keccak256 of the JCS of the inputs with method "usdc", intent "charge", type "gateway"."""
    if not is_object(i):
        return Refusal("mpp/input-malformed")
    out: dict[str, str] = {"method": "usdc", "intent": "charge", "type": "gateway"}
    for k in SALT_KEYS:
        v = i.get(k)
        if not isinstance(v, str):
            return Refusal("mpp/input-malformed")
        out[k] = v
    return _keccak_jcs(out)


def _profile_of(c: Checked) -> Mapping[str, Any]:
    p = c.details.get(str(c.details.get("type")))
    return p if is_object(p) else {}


# ── mpp/charge/usdc/evm.


def _evm_build(choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    if not is_object(choice):
        return Refusal("mpp/input-malformed")
    o = chosen_for(choice.get("challenge"), h, EVM)
    if isinstance(o, Refusal):
        return o
    td = choice.get("tokenDomain")
    if (
        not is_object(td)
        or not isinstance(td.get("name"), str)
        or td["name"] == ""
        or not isinstance(td.get("version"), str)
        or td["version"] == ""
    ):
        return Refusal("mpp/input-malformed")
    from_ = choice.get("from")
    if not is_address(from_):
        return Refusal("mpp/input-malformed")
    challenge = dict(choice["challenge"])
    request_hash = usdc_request_hash(challenge["request"])
    if isinstance(request_hash, Refusal):
        return request_hash
    nonce = usdc_nonce(challenge["id"], challenge["realm"], request_hash)
    if isinstance(nonce, Refusal):
        return nonce
    chain_id = positive_int(_profile_of(o).get("chainId"))
    valid_before = o.expires
    to, value = text(o.request.get("recipient")), text(o.request.get("amount"))
    typed_data = eip3009_typed_data(
        network=f"eip155:{chain_id}",
        asset=text(o.request.get("currency")),
        name=td["name"],
        version=td["version"],
        from_=str(from_),
        to=to,
        value=value,
        valid_after=0,
        valid_before=valid_before,
        nonce=nonce,
    )
    if isinstance(typed_data, Refusal):
        return typed_data
    source = f"did:pkh:eip155:{chain_id}:{from_}"

    def complete(signature: Any) -> dict[str, Any] | Refusal:
        if not is_hex_bytes(signature, 65, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        return {
            "challenge": challenge,
            "source": source,
            "payload": {
                "type": "authorization",
                "from": from_,
                "to": to,
                "value": value,
                "validAfter": "0",
                "validBefore": str(valid_before),
                "nonce": nonce,
                "signature": signature,
            },
        }

    return MppUnsigned({"kind": "eip712", "typedData": typed_data}, complete)


def _evm_bound(presented: Any) -> AtrHash | Refusal:
    """H from the echoed challenge, once the authorization's nonce equals usdc_nonce over it, by bytes."""
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    e = echoed_for(c, EVM)
    if isinstance(e, Refusal):
        return e
    if e.payload.get("type") != "authorization":
        return Refusal("mpp/credential-type")
    if normal_hash(e.payload.get("nonce")) is None:
        return Refusal("mpp/credential-malformed")
    request_hash = usdc_request_hash(c["challenge"]["request"])
    if isinstance(request_hash, Refusal):
        return request_hash
    nonce = usdc_nonce(c["challenge"]["id"], c["challenge"]["realm"], request_hash)
    if isinstance(nonce, Refusal):
        return nonce
    if not same_bytes(e.payload["nonce"], nonce):
        return Refusal("mpp/nonce-not-usdc-derivation")
    return e.h


@dataclass(frozen=True, slots=True)
class MppChargeUsdcEvm:
    id: str = EVM
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _evm_build(choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _evm_bound(presented)


# ── mpp/charge/usdc/gateway.


def gateway_account(network: str, word: object) -> str | None:
    """CAIP-10 of a TransferSpec bytes32 account on network: on eip155:* the last 20 bytes as 0x lower-case hex, the
    first 12 being zero; on solana:* base58 of the 32 bytes. Anything else is None."""
    if not isinstance(word, str) or _BYTES32.fullmatch(word) is None:
        return None
    b = bytes.fromhex(word[2:])
    if network.startswith("eip155:"):
        if any(b[:12]):
            return None
        return f"{network}:0x{word[26:].lower()}"
    if network.startswith("solana:"):
        return f"{network}:{b58_encode(b)}"
    return None


def _decimal_of(v: object) -> str | None:
    """A Gateway uint256 as a decimal string without leading zeros, from a decimal string or a safe integer."""
    if isinstance(v, str) and _UINT.fullmatch(v) is not None:
        return str(int(v))
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if isinstance(v, float) and not v.is_integer():
            return None
        n = int(v)
        return str(n) if 0 <= n <= _MAX_SAFE_INTEGER else None
    return None


def _gateway_build(choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
    """The chosen challenge's values of the salt's preimage, as data: the buyer's Gateway client adds its own values,
    computes usdc_gateway_salt and sets the result as spec.salt before signing. complete wraps the signed burn intent."""
    if not is_object(choice):
        return Refusal("mpp/input-malformed")
    o = chosen_for(choice.get("challenge"), h, GATEWAY)
    if isinstance(o, Refusal):
        return o
    challenge = dict(choice["challenge"])
    request_hash = usdc_request_hash(challenge["request"])
    if isinstance(request_hash, Refusal):
        return request_hash
    preimage = {
        "id": challenge["id"],
        "realm": challenge["realm"],
        "requestHash": request_hash,
        "recipient": text(o.request.get("recipient")),
    }

    def complete(c: Any) -> dict[str, Any] | Refusal:
        if not is_object(c) or not is_object(c.get("burnIntent")) or not is_hex_bytes(c.get("signature"), 1, MAX_SIGNATURE):
            return Refusal("mpp/credential-malformed")
        for k in ("source", "sourceNetwork", "destinationNetwork", "maxFee"):
            if not isinstance(c.get(k), str) or c[k] == "":
                return Refusal("mpp/credential-malformed")
        return {
            "challenge": challenge,
            "source": c["source"],
            "payload": {
                "type": "transfer",
                "sourceNetwork": c["sourceNetwork"],
                "destinationNetwork": c["destinationNetwork"],
                "maxFee": c["maxFee"],
                "authorization": {
                    "format": GATEWAY_FORMAT,
                    "transfer": {"burnIntent": c["burnIntent"], "signature": c["signature"]},
                },
            },
        }

    return MppUnsigned({"kind": "gateway-burn-intent", "preimage": preimage}, complete)


def _gateway_bound(presented: Any) -> AtrHash | Refusal:
    """H from the echoed challenge, once the signed burn intent's TransferSpec salt equals usdc_gateway_salt over the
    challenge and the credential's own values, by bytes. No signature is verified and no value is compared."""
    c = credential_of(presented)
    if isinstance(c, Refusal):
        return c
    e = echoed_for(c, GATEWAY)
    if isinstance(e, Refusal):
        return e
    p = e.payload
    if p.get("type") != "transfer":
        return Refusal("mpp/credential-type")
    source, source_network, destination_network = c.get("source"), p.get("sourceNetwork"), p.get("destinationNetwork")
    if not isinstance(source, str) or not isinstance(source_network, str) or not isinstance(destination_network, str):
        return Refusal("mpp/credential-malformed")
    a = p.get("authorization")
    if not is_object(a) or ("format" in a and a["format"] != GATEWAY_FORMAT):
        return Refusal("mpp/gateway-unread")
    transfer = a.get("transfer")
    if not is_object(transfer) or "burnIntentSet" in transfer or not isinstance(transfer.get("signature"), str):
        return Refusal("mpp/gateway-unread")
    intent = transfer.get("burnIntent")
    spec = intent.get("spec") if is_object(intent) else None
    if not is_object(intent) or not is_object(spec):
        return Refusal("mpp/gateway-unread")
    salt = spec.get("salt")
    amount = _decimal_of(spec.get("value"))
    max_fee = _decimal_of(intent.get("maxFee"))
    source_signer = gateway_account(source_network, spec.get("sourceSigner"))
    destination_recipient = gateway_account(destination_network, spec.get("destinationRecipient"))
    if (
        not isinstance(salt, str)
        or _BYTES32.fullmatch(salt) is None
        or amount is None
        or max_fee is None
        or source_signer is None
        or destination_recipient is None
    ):
        return Refusal("mpp/gateway-unread")
    request_hash = usdc_request_hash(c["challenge"]["request"])
    if isinstance(request_hash, Refusal):
        return request_hash
    expected = usdc_gateway_salt(
        {
            "id": c["challenge"]["id"],
            "realm": c["challenge"]["realm"],
            "requestHash": request_hash,
            "sourceNetwork": source_network,
            "destinationNetwork": destination_network,
            "sourceDepositor": source,
            "sourceSigner": source_signer,
            "recipient": text(e.checked.request.get("recipient")),
            "destinationRecipient": destination_recipient,
            "amount": amount,
            "maxFee": max_fee,
        }
    )
    if isinstance(expected, Refusal):
        return expected
    return e.h if same_bytes(salt, expected) else Refusal("mpp/salt-not-usdc-derivation")


@dataclass(frozen=True, slots=True)
class MppChargeUsdcGateway:
    id: str = GATEWAY
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> MppUnsigned | Refusal:
        return _gateway_build(choice, h)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        return _gateway_bound(presented)
