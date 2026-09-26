"""The buyer half of the x402 EVM pairings beside x402/exact/eip155/eip3009: read, build with complete, and bound.

- exact over Permit2 and upto over Permit2: H is the Permit2 nonce the payer signs.
- exact over ERC-7710: at the unsigned level H is read from the echoed legalContext; at the salt level, through
  MetaMask's reference DelegationManager, H is the signed salt of the permission context's leaf delegation.
- auth-capture on the commerce-payments escrow: H is the payment's salt when unbound, its saltNonce when bound, and the
  signed nonce commits to it through the escrow's PaymentInfo.

Nothing here fetches, hashes an ATR or signs.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._evm import (
    ESCROW_V1_0,
    ESCROW_V1_1,
    EXACT_PERMIT2_PROXY,
    MAX_CONTEXT_BYTES,
    UPTO_PERMIT2_PROXY,
    ZERO_ADDRESS,
    Escrow,
    PaymentInfo,
    Witness,
    as_hash,
    bind_salt,
    bytes_of,
    decode_permission_context,
    eip3009_typed_data,
    is_reference_manager,
    payment_hash,
    permit2_typed_data,
)
from ._lcp import chain_id_of, is_address, is_list, is_object, legal_context_info, normal_hash, safe_int, uint256_of
from ._x402 import LEGAL_CONTEXT, MAX_OPTIONS, MAX_SIGNATURE_BYTES, is_offered, is_v2, payment_with, read_for

EXACT_EIP3009 = "x402/exact/eip155/eip3009"
EXACT_PERMIT2 = "x402/exact/eip155/permit2"
EXACT_ERC7710 = "x402/exact/eip155/erc7710"
EXACT_ERC7710_SALT = "x402/exact/eip155/erc7710-salt"
UPTO_PERMIT2 = "x402/upto/eip155/permit2"
AUTH_CAPTURE_EIP3009 = "x402/auth-capture/eip155/eip3009"
AUTH_CAPTURE_PERMIT2 = "x402/auth-capture/eip155/permit2"

MIN_SIGNED_BYTES = 65
MAX_MEMBER = 256
_NONCE_DECIMAL = re.compile(r"[0-9]{1,78}")
_NONCE_HEX = re.compile(r"0x[0-9a-fA-F]{64}")
_HEX_BODY = re.compile(r"0x[0-9a-fA-F]*")
_AUTH_CAPTURE_REQUIRED = (
    "captureAuthorizer",
    "captureDeadline",
    "refundDeadline",
    "feeRecipient",
    "minFeeBps",
    "maxFeeBps",
    "name",
    "version",
)
_WITNESS_EXACT = ({"name": "to", "type": "address"}, {"name": "validAfter", "type": "uint256"})
_WITNESS_UPTO = (
    {"name": "to", "type": "address"},
    {"name": "facilitator", "type": "address"},
    {"name": "validAfter", "type": "uint256"},
)

# A member absent from a JSON object, as distinct from one present with the value null.
_ABSENT: Any = object()


def _member(obj: Mapping[str, Any] | None, key: str) -> Any:
    return obj.get(key, _ABSENT) if obj is not None else _ABSENT


def _scheme_of(pairing: str) -> str:
    return pairing.split("/")[1]


def _option_id_of(pairing: str) -> str:
    """The option-level pairing: both ERC-7710 levels share the erc7710 option."""
    return EXACT_ERC7710 if pairing == EXACT_ERC7710_SALT else pairing


def _extra_of(option: Mapping[str, Any]) -> Mapping[str, Any] | None | Literal[False]:
    """The option's extra: None when absent, False when present and not an object."""
    extra = _member(option, "extra")
    if extra is _ABSENT:
        return None
    return extra if is_object(extra) else False


def _eip3009_of(option: Mapping[str, Any]) -> str | None:
    """The EIP-3009 exact filter: the slice pairing's id for an option it can pay, or None."""
    if option.get("scheme") != "exact" or chain_id_of(option.get("network")) is None:
        return None
    extra = _extra_of(option)
    if extra is False:
        return None
    method = _member(extra, "assetTransferMethod")
    if method is not _ABSENT and method != "eip3009":
        return None
    flow = _member(extra, "paymentFlow")
    if flow is not _ABSENT and flow not in ("authorization", "upfront"):
        return None
    return EXACT_EIP3009


def _deployment_of(extra: Mapping[str, Any]) -> Escrow | None:
    """The escrow deployment an auth-capture option names: absent or v1.1's escrow gives v1.1, v1.0's gives v1.0."""
    named = _member(extra, "authCaptureEscrow")
    if named is _ABSENT:
        return ESCROW_V1_1
    if not isinstance(named, str):
        return None
    for deployment in (ESCROW_V1_1, ESCROW_V1_0):
        if named.lower() == deployment.escrow.lower():
            return deployment
    return None


def _places(option: Mapping[str, Any]) -> bool:
    return chain_id_of(option.get("network")) is not None and is_address(option.get("asset")) and is_address(
        option.get("payTo")
    )


def option_filter(option: object) -> str | Refusal | None:
    """The pairing an option names, a refusal naming what is wrong with an option of a scheme these pairings carry, or
    None for any other option."""
    if not is_object(option):
        return None
    extra = _extra_of(option)
    if extra is False:
        return None
    scheme = option.get("scheme")
    if scheme == "exact":
        method = _member(extra, "assetTransferMethod")
        if method is _ABSENT or method == "eip3009":
            return _eip3009_of(option)
        if not _places(option):
            return None
        flow = _member(extra, "paymentFlow")
        if flow is not _ABSENT and flow not in ("authorization", "upfront"):
            return None
        if method == "permit2":
            return EXACT_PERMIT2
        if method == "erc7710":
            return EXACT_ERC7710
        return None
    if scheme == "upto":
        if not _places(option):
            return None
        if not is_address(_member(extra, "facilitatorAddress")):
            return Refusal("x402/facilitator-missing")
        return UPTO_PERMIT2
    if scheme == "auth-capture":
        if not _places(option):
            return None
        if extra is None or any(_member(extra, k) is _ABSENT for k in _AUTH_CAPTURE_REQUIRED):
            return Refusal("x402/option-malformed")
        if _deployment_of(extra) is None:
            return Refusal("x402/escrow-not-canonical")
        flow = _member(extra, "paymentFlow")
        if flow is not _ABSENT and flow not in ("escrow", "authorization"):
            return Refusal("x402/flow-not-carried")
        if extra.get("autoCapture") is True:
            return Refusal("x402/flow-not-carried")
        method = _member(extra, "assetTransferMethod")
        if method is _ABSENT or method == "eip3009":
            return AUTH_CAPTURE_EIP3009
        if method == "permit2":
            return AUTH_CAPTURE_PERMIT2
        return None
    return None


def pairing_of(option: object) -> str | None:
    """The x402 EVM pairing an option names, or None."""
    named = option_filter(option)
    return named if isinstance(named, str) else None


def pairing_of_payment(presented: object) -> str | None:
    """The pairing that serves a presented payment: pairing_of its accepted, except that an erc7710 payment whose
    delegation manager is MetaMask's reference DelegationManager, on a chain where it is deployed, is the salt level."""
    if not is_object(presented) or not is_object(presented.get("accepted")):
        return None
    accepted = presented["accepted"]
    named = pairing_of(accepted)
    if named != EXACT_ERC7710:
        return named
    payload = presented.get("payload")
    manager = payload.get("delegationManager") if is_object(payload) else None
    return EXACT_ERC7710_SALT if is_reference_manager(manager, accepted.get("network")) else EXACT_ERC7710


def _non_empty(value: object) -> bool:
    return isinstance(value, str) and value != ""


def _payable(pairing: str, option: Mapping[str, Any]) -> bool:
    """An option build can use: its amount and time bound, and for auth-capture the token's EIP-712 name and
    version."""
    timeout = safe_int(option.get("maxTimeoutSeconds"))
    if uint256_of(option.get("amount")) is None or timeout is None or timeout <= 0:
        return False
    if _scheme_of(pairing) != "auth-capture":
        return True
    extra = option.get("extra")
    return is_object(extra) and _non_empty(extra.get("name")) and _non_empty(extra.get("version"))


@dataclass(frozen=True, slots=True)
class _Choice:
    required: Mapping[str, Any]
    accepted: Mapping[str, Any]
    payer: str
    chain_id: int
    deadline: int
    h: AtrHash


def _choice_of(pairing: str, choice: object, h: object) -> _Choice | Refusal:
    """The checks every build makes on the choice, giving the chain id, the now + maxTimeoutSeconds bound and H."""
    if not is_object(choice):
        return Refusal("x402/option-malformed")
    required, accepted = choice.get("required"), choice.get("accepted")
    if not is_v2(required):
        return Refusal("x402/not-v2")
    assert is_object(required)
    accepts = required.get("accepts")
    if not is_list(accepts) or len(accepts) > MAX_OPTIONS:
        return Refusal("x402/option-malformed")
    if not is_offered(accepts, accepted):
        return Refusal("x402/option-not-in-document")
    named = option_filter(accepted)
    if isinstance(named, Refusal):
        return named
    if named != _option_id_of(pairing):
        return Refusal("x402/option-not-this-pairing")
    assert is_object(accepted)
    if not _payable(pairing, accepted):
        return Refusal("x402/option-malformed")
    payer, now = choice.get("from"), safe_int(choice.get("now"))
    if not is_address(payer) or now is None or now < 0:
        return Refusal("x402/option-malformed")
    nonce = normal_hash(h)
    if nonce is None:
        return Refusal("x402/payload-malformed")
    chain_id = chain_id_of(accepted["network"])
    assert chain_id is not None
    timeout = safe_int(accepted["maxTimeoutSeconds"])
    assert timeout is not None
    return _Choice(required, accepted, payer, chain_id, now + timeout, nonce)


def _is_signature(value: object, min_bytes: int) -> bool:
    """0x and an even number of hex digits, from min_bytes to 8 KiB."""
    if not isinstance(value, str) or len(value) % 2 != 0 or _HEX_BODY.fullmatch(value) is None:
        return False
    return min_bytes <= (len(value) - 2) // 2 <= MAX_SIGNATURE_BYTES


def _strings(obj: object, keys: tuple[str, ...]) -> Mapping[str, Any] | None:
    """The object when each named member is a string of at most 256 characters, or None."""
    if not is_object(obj):
        return None
    for key in keys:
        value = obj.get(key)
        if not isinstance(value, str) or len(value) > MAX_MEMBER:
            return None
    return obj


def _nonce_as_hash(nonce: str) -> AtrHash | None:
    """A Permit2 nonce as decimal digits or 0x + 64 hex, below 2^256, as 32 big-endian bytes."""
    if _NONCE_HEX.fullmatch(nonce) is not None:
        return normal_hash(nonce)
    if _NONCE_DECIMAL.fullmatch(nonce) is None:
        return None
    value = int(nonce)
    return None if value >= 2**256 else "0x" + format(value, "064x")


def _presented_as(pairing: str, presented: object) -> tuple[Mapping[str, Any], Mapping[str, Any]] | Refusal:
    """A presented payment whose accepted names the pairing, with its payload as an object."""
    if not is_v2(presented):
        return Refusal("x402/not-v2")
    assert is_object(presented)
    accepted = presented.get("accepted")
    if not is_object(accepted):
        return Refusal("x402/payload-malformed")
    named = option_filter(accepted)
    if isinstance(named, Refusal):
        return named if accepted.get("scheme") == _scheme_of(pairing) else Refusal("x402/option-not-this-pairing")
    if named != _option_id_of(pairing):
        return Refusal("x402/option-not-this-pairing")
    payload = presented.get("payload")
    if not is_object(payload):
        return Refusal("x402/payload-malformed")
    return presented, payload


@dataclass(frozen=True, slots=True)
class Unsigned:
    """What a build asks the buyer's signer for, and how the answer completes the payment."""

    request: dict[str, Any]
    _complete: Callable[[Any], dict[str, Any] | Refusal]

    def complete(self, answer: Any) -> dict[str, Any] | Refusal:
        return self._complete(answer)


def _signed(required: Mapping[str, Any], accepted: Mapping[str, Any], payload: dict[str, Any]) -> Callable[
    [Any], dict[str, Any] | Refusal
]:
    """complete for a single EIP-712 signature: the payload with the signature first."""

    def complete(signature: Any) -> dict[str, Any] | Refusal:
        if not _is_signature(signature, MIN_SIGNED_BYTES):
            return Refusal("x402/signature-malformed")
        return payment_with(required, accepted, {"signature": signature, **_copy(payload)})

    return complete


def _copy(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_copy(v) for v in value]
    return value


# exact and upto over Permit2.


def _permit2_build(pairing: str, choice: Json, h: AtrHash) -> Unsigned | Refusal:
    c = _choice_of(pairing, choice, h)
    if isinstance(c, Refusal):
        return c
    accepted = c.accepted
    upto = pairing == UPTO_PERMIT2
    spender = UPTO_PERMIT2_PROXY if upto else EXACT_PERMIT2_PROXY
    witness: dict[str, str] = (
        {"to": accepted["payTo"], "facilitator": accepted["extra"]["facilitatorAddress"], "validAfter": "0"}
        if upto
        else {"to": accepted["payTo"], "validAfter": "0"}
    )
    amount = uint256_of(accepted["amount"])
    assert amount is not None
    typed_data = permit2_typed_data(
        chain_id=c.chain_id,
        permitted={"token": accepted["asset"], "amount": amount},
        spender=spender,
        nonce=as_hash(c.h),
        deadline=c.deadline,
        witness=Witness("Witness", _WITNESS_UPTO if upto else _WITNESS_EXACT, witness),
    )
    if isinstance(typed_data, Refusal):
        return typed_data
    authorization = {
        "permitted": {"token": accepted["asset"], "amount": accepted["amount"]},
        "from": c.payer,
        "spender": spender,
        "nonce": c.h if upto else str(as_hash(c.h)),
        "deadline": str(c.deadline),
        "witness": witness,
    }
    return Unsigned(
        {"kind": "eip712", "typedData": typed_data},
        _signed(c.required, accepted, {"permit2Authorization": authorization}),
    )


def _permit2_bound(pairing: str, presented: object) -> AtrHash | Refusal:
    """H from the Permit2 authorization's nonce, once the spender is the scheme's proxy."""
    got = _presented_as(pairing, presented)
    if isinstance(got, Refusal):
        return got
    _, payload = got
    if not _is_signature(payload.get("signature"), 1):
        return Refusal("x402/signature-malformed")
    a = _strings(payload.get("permit2Authorization"), ("from", "spender", "nonce", "deadline"))
    permitted = _strings(a.get("permitted") if a is not None else None, ("token", "amount"))
    witness = _strings(a.get("witness") if a is not None else None, ("to",))
    if a is None or permitted is None or witness is None:
        return Refusal("x402/payload-malformed")
    proxy = UPTO_PERMIT2_PROXY if pairing == UPTO_PERMIT2 else EXACT_PERMIT2_PROXY
    if a["spender"].lower() != proxy.lower():
        return Refusal("x402/spender-not-proxy")
    if pairing == UPTO_PERMIT2 and _strings(witness, ("facilitator",)) is None:
        return Refusal("x402/payload-malformed")
    h = _nonce_as_hash(a["nonce"])
    return h if h is not None else Refusal("x402/nonce-malformed")


# exact over ERC-7710: the unsigned level and the salt level.


def _erc7710_build(choice: Json, h: AtrHash) -> Unsigned | Refusal:
    c = _choice_of(EXACT_ERC7710, choice, h)
    if isinstance(c, Refusal):
        return c
    accepted = c.accepted
    amount = uint256_of(accepted["amount"])
    assert amount is not None
    request = {
        "kind": "erc7710",
        "chainId": c.chain_id,
        "token": accepted["asset"],
        "payTo": accepted["payTo"],
        "amount": amount,
        "salt": c.h,
    }

    def complete(d: Any) -> dict[str, Any] | Refusal:
        if not is_object(d) or not is_address(d.get("delegationManager")) or not is_address(d.get("delegator")):
            return Refusal("x402/payload-malformed")
        if bytes_of(d.get("permissionContext"), MAX_CONTEXT_BYTES) is None:
            return Refusal("x402/permission-context-malformed")
        payload = {
            "delegationManager": d["delegationManager"],
            "permissionContext": d["permissionContext"],
            "delegator": d["delegator"],
        }
        return payment_with(c.required, accepted, payload)

    return Unsigned(request, complete)


def _erc7710_presented(pairing: str, presented: object) -> tuple[Mapping[str, Any], Mapping[str, Any]] | Refusal:
    """The presented payment and its ERC-7710 payload."""
    got = _presented_as(pairing, presented)
    if isinstance(got, Refusal):
        return got
    p, payload = got
    ctx = payload.get("permissionContext")
    if (
        _strings(payload, ("delegationManager", "delegator")) is None
        or not isinstance(ctx, str)
        or len(ctx) > 2 + 2 * MAX_CONTEXT_BYTES
    ):
        return Refusal("x402/payload-malformed")
    return p, payload


def _erc7710_bound(presented: object) -> AtrHash | Refusal:
    """The unsigned level: H from the echoed extensions.legalContext.info."""
    got = _erc7710_presented(EXACT_ERC7710, presented)
    if isinstance(got, Refusal):
        return got
    extensions = got[0].get("extensions")
    lc = extensions.get(LEGAL_CONTEXT) if is_object(extensions) else None
    decoded = legal_context_info(lc.get("info") if is_object(lc) else None)
    return decoded[0] if decoded is not None else Refusal("x402/no-legal-context")


def _erc7710_salt_bound(presented: object) -> AtrHash | Refusal:
    """The salt level: H is the signed salt of the permission context's leaf delegation."""
    got = _erc7710_presented(EXACT_ERC7710_SALT, presented)
    if isinstance(got, Refusal):
        return got
    p, payload = got
    if not is_reference_manager(payload["delegationManager"], p["accepted"].get("network")):
        return Refusal("x402/manager-not-reference")
    delegations = decode_permission_context(payload["permissionContext"])
    if isinstance(delegations, Refusal):
        return Refusal("x402/permission-context-malformed")
    if not delegations:
        return Refusal("x402/delegation-empty")
    return delegations[0].salt


# auth-capture on the commerce-payments escrow.


def _uint_member(value: object) -> int | None:
    """A non-negative safe integer, or its decimal string, as an int."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = safe_int(value)
        return number if number is not None and number >= 0 else None
    return uint256_of(value)


@dataclass(frozen=True, slots=True)
class _Terms:
    chain_id: int
    deployment: Escrow
    bound: bool
    receiver_authorizer: str
    policy: str
    operator: str
    receiver: str
    token: str
    max_amount: int
    authorization_expiry: int
    refund_expiry: int
    min_fee_bps: int
    max_fee_bps: int
    fee_receiver: str

    def info(self, payer: str, salt: str, pre_approval_expiry: int) -> PaymentInfo:
        return PaymentInfo(
            operator=self.operator,
            payer=payer,
            receiver=self.receiver,
            token=self.token,
            max_amount=self.max_amount,
            pre_approval_expiry=pre_approval_expiry,
            authorization_expiry=self.authorization_expiry,
            refund_expiry=self.refund_expiry,
            min_fee_bps=self.min_fee_bps,
            max_fee_bps=self.max_fee_bps,
            fee_receiver=self.fee_receiver,
            salt=salt,
        )


def _auth_capture_terms(option: Mapping[str, Any]) -> _Terms | Refusal:
    """The escrow terms an auth-capture option fixes, or x402/option-malformed."""
    extra = option["extra"]
    deployment = _deployment_of(extra)
    assert deployment is not None

    def address(key: str, fallback: str | None = None) -> str | None:
        value = extra.get(key)
        value = fallback if value is None else value
        return value if is_address(value) else None

    operator = address("captureAuthorizer")
    fee_receiver = address("feeRecipient")
    receiver_authorizer = address("receiverAuthorizer", ZERO_ADDRESS)
    policy = address("policy", ZERO_ADDRESS)
    authorization_expiry = _uint_member(extra.get("captureDeadline"))
    refund_expiry = _uint_member(extra.get("refundDeadline"))
    min_fee_bps = _uint_member(extra.get("minFeeBps"))
    max_fee_bps = _uint_member(extra.get("maxFeeBps"))
    max_amount = uint256_of(option.get("amount"))
    if operator is None or fee_receiver is None or receiver_authorizer is None or policy is None:
        return Refusal("x402/option-malformed")
    if authorization_expiry is None or refund_expiry is None or max_amount is None:
        return Refusal("x402/option-malformed")
    if min_fee_bps is None or max_fee_bps is None or min_fee_bps > 65535 or max_fee_bps > 65535:
        return Refusal("x402/option-malformed")
    chain_id = chain_id_of(option.get("network"))
    assert chain_id is not None
    return _Terms(
        chain_id=chain_id,
        deployment=deployment,
        bound=receiver_authorizer.lower() != ZERO_ADDRESS or policy.lower() != ZERO_ADDRESS,
        receiver_authorizer=receiver_authorizer,
        policy=policy,
        operator=operator,
        receiver=option["payTo"],
        token=option["asset"],
        max_amount=max_amount,
        authorization_expiry=authorization_expiry,
        refund_expiry=refund_expiry,
        min_fee_bps=min_fee_bps,
        max_fee_bps=max_fee_bps,
        fee_receiver=fee_receiver,
    )


def _auth_capture_build(pairing: str, choice: Json, h: AtrHash) -> Unsigned | Refusal:
    c = _choice_of(pairing, choice, h)
    if isinstance(c, Refusal):
        return c
    accepted = c.accepted
    t = _auth_capture_terms(accepted)
    if isinstance(t, Refusal):
        return t
    salt = bind_salt(t.receiver_authorizer, t.policy, c.h) if t.bound else c.h
    if isinstance(salt, Refusal):
        return Refusal("x402/option-malformed")
    signature_nonce = payment_hash(t.chain_id, t.deployment.escrow, t.info(ZERO_ADDRESS, salt, c.deadline))
    if isinstance(signature_nonce, Refusal):
        return Refusal("x402/option-malformed")
    salts = {"salt": salt, "saltNonce": c.h} if t.bound else {"salt": salt}
    if pairing == AUTH_CAPTURE_EIP3009:
        typed_data = eip3009_typed_data(
            "ReceiveWithAuthorization",
            network=accepted["network"],
            asset=accepted["asset"],
            name=accepted["extra"]["name"],
            version=accepted["extra"]["version"],
            from_=c.payer,
            to=t.deployment.eip3009_collector,
            value=accepted["amount"],
            valid_after=0,
            valid_before=c.deadline,
            nonce=signature_nonce,
        )
        if isinstance(typed_data, Refusal):
            return typed_data
        authorization = {
            "from": c.payer,
            "to": t.deployment.eip3009_collector,
            "value": accepted["amount"],
            "validAfter": "0",
            "validBefore": str(c.deadline),
            "nonce": signature_nonce,
        }
        payload: dict[str, Any] = {"authorization": authorization, **salts}
    else:
        amount = uint256_of(accepted["amount"])
        assert amount is not None
        typed_data = permit2_typed_data(
            chain_id=t.chain_id,
            permitted={"token": accepted["asset"], "amount": amount},
            spender=t.deployment.permit2_collector,
            nonce=as_hash(signature_nonce),
            deadline=c.deadline,
        )
        if isinstance(typed_data, Refusal):
            return typed_data
        permit2_authorization = {
            "permitted": {"token": accepted["asset"], "amount": accepted["amount"]},
            "from": c.payer,
            "spender": t.deployment.permit2_collector,
            "nonce": str(as_hash(signature_nonce)),
            "deadline": str(c.deadline),
        }
        payload = {"permit2Authorization": permit2_authorization, **salts}
    return Unsigned({"kind": "eip712", "typedData": typed_data}, _signed(c.required, accepted, payload))


def _salt_of(value: object) -> AtrHash | None:
    """0x and 64 hex digits, zero-padded to the full width, lower-case."""
    return normal_hash(value) if isinstance(value, str) and _NONCE_HEX.fullmatch(value) is not None else None


def _auth_capture_bound(pairing: str, presented: object) -> AtrHash | Refusal:
    """H (the salt when unbound, the saltNonce when bound, whose commitment must be the salt), once the signed nonce
    is the signatureNonce rebuilt with payer zero."""
    got = _presented_as(pairing, presented)
    if isinstance(got, Refusal):
        return got
    p, payload = got
    if not _is_signature(payload.get("signature"), 1):
        return Refusal("x402/signature-malformed")
    t = _auth_capture_terms(p["accepted"])
    if isinstance(t, Refusal):
        return t
    salt = _salt_of(payload.get("salt"))
    if salt is None:
        return Refusal("x402/salt-malformed")
    h = salt
    if t.bound:
        salt_nonce = _salt_of(payload.get("saltNonce"))
        if salt_nonce is None:
            return Refusal("x402/salt-malformed")
        commitment = bind_salt(t.receiver_authorizer, t.policy, salt_nonce)
        if isinstance(commitment, Refusal) or commitment != salt:
            return Refusal("x402/salt-not-bound")
        h = salt_nonce
    if pairing == AUTH_CAPTURE_EIP3009:
        a = _strings(payload.get("authorization"), ("from", "to", "value", "validAfter", "validBefore", "nonce"))
        if a is None:
            return Refusal("x402/payload-malformed")
        payer, signed, expiry = a["from"], normal_hash(a["nonce"]), uint256_of(a["validBefore"])
    else:
        a = _strings(payload.get("permit2Authorization"), ("from", "spender", "nonce", "deadline"))
        if a is None:
            return Refusal("x402/payload-malformed")
        payer, signed, expiry = a["from"], _nonce_as_hash(a["nonce"]), uint256_of(a["deadline"])
    if not is_address(payer) or expiry is None or expiry >= 1 << 48:
        return Refusal("x402/payload-malformed")
    if signed is None:
        return Refusal("x402/nonce-not-payment")
    signature_nonce = payment_hash(t.chain_id, t.deployment.escrow, t.info(ZERO_ADDRESS, salt, expiry))
    if isinstance(signature_nonce, Refusal) or signature_nonce != signed:
        return Refusal("x402/nonce-not-payment")
    return h


# The bindings.


def _reads(pairing: str) -> Callable[[Mapping[str, Any]], bool | Refusal | None]:
    """The filter at read: the option names the pairing's option-level id."""

    def check(option: Mapping[str, Any]) -> bool | None:
        return True if pairing_of(option) == _option_id_of(pairing) else None

    return check


@dataclass(frozen=True, slots=True)
class X402EvmBinding:
    """One x402 EVM pairing's buyer half. public_proof is the pairing's pattern.publicProof."""

    id: str
    public_proof: bool

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when the legal context names one, and the options this pairing can pay, in
        document order."""
        return read_for(_reads(self.id))(doc)

    def build(self, choice: Json, h: AtrHash) -> Unsigned | Refusal:
        """What the buyer's signer is handed for the chosen option with H in its place, and how its answer completes
        the payment."""
        if self.id in (EXACT_PERMIT2, UPTO_PERMIT2):
            return _permit2_build(self.id, choice, h)
        if self.id in (EXACT_ERC7710, EXACT_ERC7710_SALT):
            return _erc7710_build(choice, h)
        return _auth_capture_build(self.id, choice, h)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash inside what the payer signed or, at ERC-7710's unsigned level, the hash the payment echoed. No
        signature is verified here."""
        if self.id in (EXACT_PERMIT2, UPTO_PERMIT2):
            return _permit2_bound(self.id, presented)
        if self.id == EXACT_ERC7710:
            return _erc7710_bound(presented)
        if self.id == EXACT_ERC7710_SALT:
            return _erc7710_salt_bound(presented)
        return _auth_capture_bound(self.id, presented)


X402_EXACT_EIP155_PERMIT2 = X402EvmBinding(EXACT_PERMIT2, public_proof=True)
X402_UPTO_EIP155_PERMIT2 = X402EvmBinding(UPTO_PERMIT2, public_proof=True)
X402_EXACT_EIP155_ERC7710 = X402EvmBinding(EXACT_ERC7710, public_proof=False)
X402_EXACT_EIP155_ERC7710_SALT = X402EvmBinding(EXACT_ERC7710_SALT, public_proof=True)
X402_AUTH_CAPTURE_EIP155_EIP3009 = X402EvmBinding(AUTH_CAPTURE_EIP3009, public_proof=True)
X402_AUTH_CAPTURE_EIP155_PERMIT2 = X402EvmBinding(AUTH_CAPTURE_PERMIT2, public_proof=True)
