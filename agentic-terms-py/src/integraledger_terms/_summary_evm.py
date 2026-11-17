"""The approval summaries of the EVM requests (terms' profile buyer-gate.md, rule 13): Permit2's
PermitWitnessTransferFrom, through x402's Permit2 proxies and MPP's charge; a transaction calling an ERC-20 transfer;
Tempo's key authorization; x402's auth-capture token authorization on the commerce-payments escrow; and x402's
batch-settlement opening on EVM. Each reads only what the request handed to the signer signs, and answers None for a
request of another form, so a request a summary cannot read has no summary; a member signed only by its hash is shown
only once the hash, recomputed over what the request carries, is the signed value."""

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from ._keccak import keccak256
from ._types import Payee, Summary, Validity
from .bindings._batch_evm import (
    BATCH_SETTLEMENT,
    DOMAIN_NAME,
    DOMAIN_VERSION,
    ERC3009_DEPOSIT_COLLECTOR,
    PERMIT2_DEPOSIT_COLLECTOR,
    batch_channel_id,
    erc3009_deposit_nonce,
)
from .bindings._evm import ESCROW_V1_0, ESCROW_V1_1, EXACT_PERMIT2_PROXY, PERMIT2, UPTO_PERMIT2_PROXY, Escrow, PaymentInfo, payment_hash
from .bindings._tempo import TRANSFER_WITH_MEMO_SELECTOR, encode_key_authorization

if TYPE_CHECKING:
    from ._summary import Opened

_DECIMAL = re.compile(r"[0-9]{1,78}")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
# transfer(address,uint256)'s selector, then the recipient's word, 12 zero bytes and 20, then the amount's word.
_TRANSFER = re.compile(r"0xa9059cbb0{24}([0-9a-fA-F]{40})([0-9a-fA-F]{64})")

_PERMIT_WITNESS_TRANSFER_FROM = (
    ("permitted", "TokenPermissions"),
    ("spender", "address"),
    ("nonce", "uint256"),
    ("deadline", "uint256"),
)
_TOKEN_PERMISSIONS = (("token", "address"), ("amount", "uint256"))
# x402's exact proxy's witness, Witness(address to,uint256 validAfter).
_EXACT_WITNESS = (("to", "address"), ("validAfter", "uint256"))
# x402's upto proxy's witness, Witness(address to,address facilitator,uint256 validAfter).
_UPTO_WITNESS = (("to", "address"), ("facilitator", "address"), ("validAfter", "uint256"))
# MPP's charge witness, PaymentWitness(bytes32 challengeHash,string externalId).
_PAYMENT_WITNESS = (("challengeHash", "bytes32"), ("externalId", "string"))


def _decimal(v: object) -> str | None:
    """A non-negative integer as a decimal string: an int (a bool is none) or a decimal string; else None."""
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v) if v >= 0 else None
    return v if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


def _address(v: object) -> str | None:
    """A 20-byte address as 0x and 40 hex digits, as the request writes it; else None."""
    return v if isinstance(v, str) and _ADDRESS.fullmatch(v) is not None else None


def _same(a: str, b: str) -> bool:
    """Whether two addresses name one account, compared without their letters' case."""
    return a.lower() == b.lower()


def _type_is(members: object, fields: Sequence[tuple[str, str]]) -> bool:
    """Whether an EIP-712 struct type's members are exactly fields, each (name, type), in that order."""
    if not isinstance(members, list) or len(members) != len(fields):
        return False
    return all(
        isinstance(m, Mapping) and len(m) == 2 and m.get("name") == name and m.get("type") == kind
        for m, (name, kind) in zip(members, fields, strict=True)
    )


def _permit_witness(
    request: Mapping[str, Any], witness_type: str, witness: Sequence[tuple[str, str]]
) -> tuple[str, str, str, Mapping[str, Any], str, str] | None:
    """A PermitWitnessTransferFrom to Permit2 under the witness type witness_type of members witness: the permitted
    token and amount, the spender, the witness, the deadline and the chain; None where the request is of another form."""
    typed = request.get("typedData")
    if request.get("kind") != "eip712" or not isinstance(typed, Mapping):
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if typed.get("primaryType") != "PermitWitnessTransferFrom" or not isinstance(types, Mapping):
        return None
    if not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    if not _type_is(types.get("PermitWitnessTransferFrom"), (*_PERMIT_WITNESS_TRANSFER_FROM, ("witness", witness_type))):
        return None
    if not _type_is(types.get("TokenPermissions"), _TOKEN_PERMISSIONS) or not _type_is(types.get(witness_type), witness):
        return None
    contract, spender = _address(d.get("verifyingContract")), _address(m.get("spender"))
    if contract is None or not _same(contract, PERMIT2) or spender is None:
        return None
    p, w = m.get("permitted"), m.get("witness")
    if not isinstance(p, Mapping) or not isinstance(w, Mapping):
        return None
    token, amount = _address(p.get("token")), _decimal(p.get("amount"))
    deadline, chain = _decimal(m.get("deadline")), _decimal(d.get("chainId"))
    if token is None or amount is None or deadline is None or chain is None:
        return None
    return token, amount, spender, w, deadline, chain


def exact_permit2(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/eip155/permit2: the amount and the one payee's part are m.permitted.amount, the payee m.witness.to,
    the asset m.permitted.token, the network eip155: and d.chainId, and the validity m.witness.validAfter to
    m.deadline, in seconds. The proxy pays only the witness's to, so the spender must be x402's exact proxy."""
    s = _permit_witness(request, "Witness", _EXACT_WITNESS)
    if s is None:
        return None
    token, amount, spender, w, deadline, chain = s
    to, after = _address(w.get("to")), _decimal(w.get("validAfter"))
    if not _same(spender, EXACT_PERMIT2_PROXY) or to is None or after is None:
        return None
    return Summary(
        amount=amount,
        payees=(Payee(account=to, amount=amount),),
        asset=token,
        network=f"eip155:{chain}",
        validity=Validity(not_before=after, not_after=deadline, unit="seconds"),
        atr=b"",
    )


def upto_permit2(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/upto/eip155/permit2: the maximum and the one payee's part are m.permitted.amount, the payee m.witness.to,
    the operator m.witness.facilitator, who settles the charge, the asset m.permitted.token, the network eip155: and
    d.chainId, and the validity m.witness.validAfter to m.deadline, in seconds. The proxy pays only the witness's to,
    so the spender must be x402's upto proxy."""
    s = _permit_witness(request, "Witness", _UPTO_WITNESS)
    if s is None:
        return None
    token, amount, spender, w, deadline, chain = s
    to, facilitator, after = _address(w.get("to")), _address(w.get("facilitator")), _decimal(w.get("validAfter"))
    if not _same(spender, UPTO_PERMIT2_PROXY) or to is None or facilitator is None or after is None:
        return None
    return Summary(
        maximum=amount,
        payees=(Payee(account=to, amount=amount),),
        operator=facilitator,
        asset=token,
        network=f"eip155:{chain}",
        validity=Validity(not_before=after, not_after=deadline, unit="seconds"),
        atr=b"",
    )


def mpp_permit2(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """mpp/charge/evm/permit2: the permit signs no recipient, so the payee is m.spender, the one account the signature
    lets move the amount, to any account; the amount and its part are m.permitted.amount, the asset m.permitted.token,
    the network eip155: and d.chainId, and the validity none to m.deadline, in seconds."""
    s = _permit_witness(request, "PaymentWitness", _PAYMENT_WITNESS)
    if s is None:
        return None
    token, amount, spender, _w, deadline, chain = s
    return Summary(
        amount=amount,
        payees=(Payee(account=spender, amount=amount),),
        asset=token,
        network=f"eip155:{chain}",
        validity=Validity(not_before=None, not_after=deadline, unit="seconds"),
        atr=b"",
    )


def erc20_transfer(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """mpp/charge/evm/hash and mpp/charge/evm/transaction: a call of to and data alone, data an ERC-20
    transfer(address,uint256) and nothing else. The amount and the one payee's part are the transfer's amount, the
    payee its recipient, as the call data writes it, the asset call.to, the network eip155: and chainId; a transaction
    signs no end, so the validity is none to none."""
    call = request.get("call")
    # A call of any other member, a value among them, moves what this summary does not read.
    if request.get("kind") != "evm-call" or not isinstance(call, Mapping) or sorted(call) != ["data", "to"]:
        return None
    chain, asset, data = _decimal(request.get("chainId")), _address(call.get("to")), call.get("data")
    words = _TRANSFER.fullmatch(data) if isinstance(data, str) else None
    if chain is None or asset is None or words is None:
        return None
    amount = str(int(words.group(2), 16))
    return Summary(
        amount=amount,
        payees=(Payee(account=f"0x{words.group(1)}", amount=amount),),
        asset=asset,
        network=f"eip155:{chain}",
        validity=Validity(not_before=None, not_after=None, unit="seconds"),
        atr=b"",
    )


def key_authorization(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """mpp/subscription/tempo: the root key signs digest, the keccak-256 of the RLP of authorization, which lets the
    key keyId spend under its limits and call only its allowed calls until its expiry; a digest that is not that hash
    gives no summary. Read only where the key may spend one token and call only that token's transferWithMemo to named
    recipients: the limit is the limit per period and each payee's part, its period the period, the payees every
    recipient of the selector rules, the asset the limit's token, the network eip155: and chainId, and the end and the
    validity's end the expiry, an expiry of 0 signing none; the grant is {keyId, limits, allowedCalls}."""
    a, digest = request.get("authorization"), request.get("digest")
    if request.get("kind") != "tempo-key-authorization" or not isinstance(a, dict) or not isinstance(digest, str):
        return None
    encoded = encode_key_authorization(a)
    if not isinstance(encoded, bytes) or "0x" + keccak256(encoded).hex() != digest.lower():
        return None
    chain, key_id, expiry = _decimal(a.get("chainId")), _address(a.get("keyId")), _decimal(a.get("expiry"))
    limits, allowed = a.get("limits"), a.get("allowedCalls")
    if chain is None or key_id is None or expiry is None:
        return None
    if not isinstance(limits, list) or len(limits) != 1 or not isinstance(limits[0], Mapping):
        return None
    token, limit, period = _address(limits[0].get("token")), _decimal(limits[0].get("limit")), _decimal(limits[0].get("period"))
    if token is None or limit is None or period is None:
        return None
    if not isinstance(allowed, list) or not allowed:
        return None
    recipients: list[str] = []
    calls: list[Any] = []
    for call in allowed:
        target = _address(call.get("target")) if isinstance(call, Mapping) else None
        rules = call.get("selectorRules") if isinstance(call, Mapping) else None
        if target is None or not _same(target, token) or not isinstance(rules, list) or not rules:
            return None
        shown: list[Any] = []
        for rule in rules:
            selector = rule.get("selector") if isinstance(rule, Mapping) else None
            named = rule.get("recipients") if isinstance(rule, Mapping) else None
            if not isinstance(selector, str) or selector.lower() != TRANSFER_WITH_MEMO_SELECTOR:
                return None
            if not isinstance(named, list) or not named:
                return None
            accounts = [x for x in map(_address, named) if x is not None]
            if len(accounts) != len(named):
                return None
            for x in accounts:
                if not any(_same(x, y) for y in recipients):
                    recipients.append(x)
            shown.append({"selector": selector, "recipients": accounts})
        calls.append({"target": target, "selectorRules": shown})
    end = None if int(expiry) == 0 else expiry
    return Summary(
        payees=tuple(Payee(account=x, amount=limit) for x in recipients),
        period=period,
        limit_per_period=limit,
        end=end,
        grant={"keyId": key_id, "limits": [{"token": token, "limit": limit, "period": period}], "allowedCalls": calls},
        asset=token,
        network=f"eip155:{chain}",
        validity=Validity(not_before=None, not_after=end, unit="seconds"),
        atr=b"",
    )


# ── x402 auth-capture on the commerce-payments escrow.

_ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
_HASH32 = re.compile(r"0x[0-9a-fA-F]{64}")
_RECEIVE_WITH_AUTHORIZATION = (
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
)
_PERMIT_TRANSFER_FROM = _PERMIT_WITNESS_TRANSFER_FROM


def _escrowed(request: Mapping[str, Any]) -> tuple[PaymentInfo, Escrow] | None:
    """The request's paymentInfo, as payment_hash takes it, with the escrow deployment its escrow names, where the
    payer is the zero address, as the collectors hash it; else None."""
    p, escrow = request.get("paymentInfo"), _address(request.get("escrow"))
    if not isinstance(p, Mapping) or escrow is None:
        return None
    deployment = next((d for d in (ESCROW_V1_1, ESCROW_V1_0) if _same(d.escrow, escrow)), None)
    addresses = [_address(p.get(k)) for k in ("operator", "payer", "receiver", "token", "feeReceiver")]
    uints = [_decimal(p.get(k)) for k in ("maxAmount", "preApprovalExpiry", "authorizationExpiry", "refundExpiry", "minFeeBps", "maxFeeBps")]
    salt = p.get("salt")
    if deployment is None or any(a is None for a in addresses) or any(u is None for u in uints):
        return None
    if not isinstance(salt, str) or _HASH32.fullmatch(salt) is None:
        return None
    operator, payer, receiver, token, fee_receiver = (str(a) for a in addresses)
    max_amount, pre_approval, authorization, refund, min_fee, max_fee = (int(str(u)) for u in uints)
    if not _same(payer, _ZERO_ADDRESS) or min_fee >= 65536 or max_fee >= 65536:
        return None
    info = PaymentInfo(operator, payer, receiver, token, max_amount, pre_approval, authorization, refund, min_fee, max_fee, fee_receiver, salt)  # fmt: skip
    return info, deployment


def _nonces_to(nonce: object, chain: str, deployment: Escrow, info: PaymentInfo) -> bool:
    """Whether nonce, a bytes32 as hex or a uint256, is payment_hash(chain, escrow, info)."""
    digest = payment_hash(int(chain), deployment.escrow, info)
    if not isinstance(digest, str):
        return False
    if isinstance(nonce, str) and _HASH32.fullmatch(nonce) is not None:
        return int(nonce, 16) == int(digest, 16)
    n = _decimal(nonce)
    return n is not None and int(n) == int(digest, 16)


def _auth_capture(info: PaymentInfo, value: str, chain: str, not_before: str | None, not_after: str) -> Summary:
    """The summary of an authorization of value of info.token on chain, from not_before to not_after."""
    return Summary(
        maximum=value,
        payees=(Payee(account=info.receiver, amount=value),),
        operator=info.operator,
        authorization_expiry=str(info.authorization_expiry),
        refund_expiry=str(info.refund_expiry),
        asset=info.token,
        network=f"eip155:{chain}",
        validity=Validity(not_before=not_before, not_after=not_after, unit="seconds"),
        atr=b"",
    )


def auth_capture_eip3009(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/auth-capture/eip155/eip3009: a ReceiveWithAuthorization of m.value to the EIP-3009 collector of the
    deployment whose escrow is escrow, in the domain of paymentInfo.token, whose m.nonce is payment_hash(d.chainId,
    escrow, paymentInfo). The maximum and the one payee's part are m.value, which the operator captures for the payee up
    to; the payee paymentInfo.receiver; the operator paymentInfo.operator; the authorization's and the refund's expiries
    paymentInfo.authorizationExpiry and paymentInfo.refundExpiry; the asset d.verifyingContract; the network eip155: and
    d.chainId; and the validity m.validAfter to m.validBefore."""
    typed = request.get("typedData")
    if request.get("kind") != "eip712" or not isinstance(typed, Mapping) or typed.get("primaryType") != "ReceiveWithAuthorization":
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if not isinstance(types, Mapping) or not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    if not _type_is(types.get("ReceiveWithAuthorization"), _RECEIVE_WITH_AUTHORIZATION):
        return None
    e = _escrowed(request)
    value, after, before = (_decimal(m.get(k)) for k in ("value", "validAfter", "validBefore"))
    chain = _decimal(d.get("chainId"))
    to, token = _address(m.get("to")), _address(d.get("verifyingContract"))
    if e is None or value is None or after is None or before is None or chain is None:
        return None
    info, deployment = e
    if to is None or not _same(to, deployment.eip3009_collector) or token is None or not _same(token, info.token):
        return None
    if not _nonces_to(m.get("nonce"), chain, deployment, info):
        return None
    return _auth_capture(info, value, chain, after, before)


def auth_capture_permit2(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/auth-capture/eip155/permit2: a Permit2 PermitTransferFrom of m.permitted.amount of paymentInfo.token whose
    spender is the Permit2 collector of the deployment whose escrow is escrow, and whose m.nonce is
    payment_hash(d.chainId, escrow, paymentInfo). Its members are those of the EIP-3009 form, the maximum being
    m.permitted.amount, the asset m.permitted.token, and the validity none to m.deadline."""
    typed = request.get("typedData")
    if request.get("kind") != "eip712" or not isinstance(typed, Mapping) or typed.get("primaryType") != "PermitTransferFrom":
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if not isinstance(types, Mapping) or not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    if not _type_is(types.get("PermitTransferFrom"), _PERMIT_TRANSFER_FROM) or not _type_is(types.get("TokenPermissions"), _TOKEN_PERMISSIONS):
        return None
    e = _escrowed(request)
    contract, spender, p = _address(d.get("verifyingContract")), _address(m.get("spender")), m.get("permitted")
    if e is None or contract is None or not _same(contract, PERMIT2) or not isinstance(p, Mapping):
        return None
    info, deployment = e
    if spender is None or not _same(spender, deployment.permit2_collector):
        return None
    token, amount = _address(p.get("token")), _decimal(p.get("amount"))
    deadline, chain = _decimal(m.get("deadline")), _decimal(d.get("chainId"))
    if token is None or amount is None or deadline is None or chain is None:
        return None
    if not _same(token, info.token) or not _nonces_to(m.get("nonce"), chain, deployment, info):
        return None
    return _auth_capture(info, amount, chain, None, deadline)


# ── x402 batch-settlement's opening on EVM.

_VOUCHER = (("channelId", "bytes32"), ("maxClaimableAmount", "uint128"))
_DEPOSIT_WITNESS = (("channelId", "bytes32"),)
_CONFIG_ADDRESSES = ("payer", "payerAuthorizer", "receiver", "receiverAuthorizer", "token")


def _hash32(v: object) -> str | None:
    return v if isinstance(v, str) and _HASH32.fullmatch(v) is not None else None


def _config(v: object) -> dict[str, Any] | None:
    """The request's config, its seven members as batch_channel_id reads them; else None."""
    if not isinstance(v, Mapping):
        return None
    addresses = {k: _address(v.get(k)) for k in _CONFIG_ADDRESSES}
    delay, salt = _decimal(v.get("withdrawDelay")), _hash32(v.get("salt"))
    if any(a is None for a in addresses.values()) or delay is None or salt is None or int(delay) > 2**53 - 1:
        return None
    return {**addresses, "withdrawDelay": int(delay), "salt": salt}


def _voucher(request: object) -> tuple[str, str, str] | None:
    """The voucher, Voucher(bytes32 channelId, uint128 maxClaimableAmount) under the channel contract's domain: its
    chain, channel id and maxClaimableAmount."""
    typed = request.get("typedData") if isinstance(request, Mapping) else None
    if not isinstance(request, Mapping) or request.get("kind") != "eip712" or not isinstance(typed, Mapping):
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if typed.get("primaryType") != "Voucher" or not isinstance(types, Mapping) or not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    contract = _address(d.get("verifyingContract"))
    if not _type_is(types.get("Voucher"), _VOUCHER) or d.get("name") != DOMAIN_NAME or d.get("version") != DOMAIN_VERSION:
        return None
    if contract is None or not _same(contract, BATCH_SETTLEMENT):
        return None
    chain, channel_id, max_claimable = _decimal(d.get("chainId")), _hash32(m.get("channelId")), _decimal(m.get("maxClaimableAmount"))
    return None if chain is None or channel_id is None or max_claimable is None else (chain, channel_id, max_claimable)


def _deposit(request: object, c: Mapping[str, Any], channel_id: str, chain: str, auth_salt: object) -> tuple[str, Validity] | None:
    """The deposit into channel channel_id of c on chain: an ERC-3009 ReceiveWithAuthorization from the payer to x402's
    ERC-3009 deposit collector, in the token's domain, whose nonce is erc3009_deposit_nonce(channel_id, auth_salt); or a
    Permit2 permit of the token to x402's Permit2 deposit collector whose DepositWitness names channel_id. Its amount
    and validity."""
    typed = request.get("typedData") if isinstance(request, Mapping) else None
    if not isinstance(request, Mapping) or request.get("kind") != "eip712" or not isinstance(typed, Mapping):
        return None
    if typed.get("primaryType") == "ReceiveWithAuthorization":
        types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
        if not isinstance(types, Mapping) or not isinstance(m, Mapping) or not isinstance(d, Mapping):
            return None
        if not _type_is(types.get("ReceiveWithAuthorization"), _RECEIVE_WITH_AUTHORIZATION):
            return None
        sender, to, token = _address(m.get("from")), _address(m.get("to")), _address(d.get("verifyingContract"))
        salt = _hash32(auth_salt)
        nonce = None if salt is None else erc3009_deposit_nonce(channel_id, salt)
        value, after, before = (_decimal(m.get(k)) for k in ("value", "validAfter", "validBefore"))
        signed = m.get("nonce")
        if sender is None or to is None or token is None or not isinstance(nonce, str) or not isinstance(signed, str):
            return None
        if not _same(sender, c["payer"]) or not _same(to, ERC3009_DEPOSIT_COLLECTOR) or not _same(token, c["token"]):
            return None
        if _decimal(d.get("chainId")) != chain or signed.lower() != nonce.lower():
            return None
        if value is None or after is None or before is None:
            return None
        return value, Validity(not_before=after, not_after=before, unit="seconds")
    s = _permit_witness(request, "DepositWitness", _DEPOSIT_WITNESS)
    if s is None:
        return None
    token, amount, spender, w, deadline, permit_chain = s
    witnessed = _hash32(w.get("channelId"))
    if witnessed is None or witnessed.lower() != channel_id.lower() or permit_chain != chain:
        return None
    if not _same(spender, PERMIT2_DEPOSIT_COLLECTOR) or not _same(token, c["token"]):
        return None
    return amount, Validity(not_before=None, not_after=deadline, unit="seconds")


def batch_evm_opening(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/batch-settlement/eip155, the opening: the amount and the one payee's part are the voucher's
    maxClaimableAmount, the payee config.receiver; the deposit the deposit authorization's amount; who may close
    config.receiver and config.receiverAuthorizer, by a refund at any time, and config.payer and, where it is not the
    zero address, config.payerAuthorizer, by a withdrawal once config.withdrawDelay has passed; the asset config.token;
    the network eip155: and the requests' chain id; and the validity the deposit authorization's. The voucher's
    channelId must be batch_channel_id(chainId, config) and the deposit must commit to it."""
    requests = request.get("requests")
    if request.get("kind") != "batch" or not isinstance(requests, list) or len(requests) != 2:
        return None
    c, v = _config(request.get("config")), _voucher(requests[1])
    if c is None or v is None:
        return None
    chain, channel_id, max_claimable = v
    computed = batch_channel_id(int(chain), c)
    if not isinstance(computed, str) or computed.lower() != channel_id.lower():
        return None
    deposit = _deposit(requests[0], c, computed, chain, request.get("authSalt"))
    if deposit is None:
        return None
    value, validity = deposit
    closers = tuple(a for a in (c["receiver"], c["receiverAuthorizer"], c["payer"], c["payerAuthorizer"]) if not _same(a, _ZERO_ADDRESS))
    return Summary(
        amount=max_claimable,
        payees=(Payee(account=c["receiver"], amount=max_claimable),),
        deposit=value,
        closable_by=closers,
        asset=c["token"],
        network=f"eip155:{chain}",
        validity=validity,
        atr=b"",
    )
