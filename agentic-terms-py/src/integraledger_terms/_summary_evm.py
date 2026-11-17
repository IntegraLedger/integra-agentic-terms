"""The approval summaries of the EVM requests (terms' profile buyer-gate.md, rule 13): Permit2's
PermitWitnessTransferFrom, through x402's Permit2 proxies and MPP's charge; a transaction calling an ERC-20 transfer;
and Tempo's key authorization. Each reads only what the request handed to the signer signs, and answers None for a
request of another form, so a request a summary cannot read has no summary."""

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from ._keccak import keccak256
from ._types import Payee, Summary, Validity
from .bindings._evm import EXACT_PERMIT2_PROXY, PERMIT2, UPTO_PERMIT2_PROXY
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
