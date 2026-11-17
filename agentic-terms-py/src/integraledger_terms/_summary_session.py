"""MPP's payment channels on EVM networks and on Tempo (terms' profile buyer-gate.md, rule 13): an EVM session's opening
funded by a Permit2 transfer or an EIP-3009 authorization to the escrow, and the voucher that follows a session's
opening. The voucher signs only the
channel id and a cumulative amount; the channel id is a hash over the payer, the payee, the token, the salt, the
authorized signer, the escrow and the chain (on the TIP-20 channel reserve also the operator and the opening
transaction's expiring nonce hash). So the voucher is shown with the payees, asset and network of the opening the gate
hands its summary, and only once the channel id recomputed from that opening, with the signer's account as the payer,
is the one the voucher signs; a voucher of another channel, or one shown without the opening or the account, has no
summary."""

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ._summary_evm import _permit_witness, _type_is
from ._summary_tempo import open_of, tempo_open
from ._types import Payee, Summary, Validity
from .bindings._tempo import expiring_nonce_hash, tempo_channel_id
from .bindings.mpp_session import evm_channel_id, evm_session_authorization_nonce

if TYPE_CHECKING:
    from ._summary import Opened

# The escrow's witness, ChannelOpenWitness(address payee,bytes32 salt,address authorizedSigner).
_CHANNEL_OPEN_WITNESS = (("payee", "address"), ("salt", "bytes32"), ("authorizedSigner", "address"))
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_HASH32 = re.compile(r"0x[0-9a-fA-F]{64}")
_DECIMAL = re.compile(r"[0-9]{1,78}")
# A signed Tempo transaction as 0x hex, at most the protocol package's 64 KiB.
_SIGNED_TX = re.compile(r"0x(?:[0-9a-fA-F]{2}){1,65536}")
_ZERO = "0x" + "0" * 40


def _decimal(v: object) -> str | None:
    """A non-negative integer as a decimal string: an int (a bool is none) or a decimal string; else None."""
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v) if v >= 0 else None
    return v if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


def _address(v: object) -> str | None:
    return v if isinstance(v, str) and _ADDRESS.fullmatch(v) is not None else None


# EIP-3009's ReceiveWithAuthorization members, in order.
_RECEIVE_WITH_AUTHORIZATION = (
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
)


@dataclass(frozen=True, slots=True)
class _EvmOpening:
    """An EVM session's opening: the channel's payee, token, salt and authorized signer, the escrow, the deposit and
    its window."""

    payee: str
    token: str
    salt: str
    authorized_signer: str
    escrow: str
    deposit: str
    chain: str
    not_before: str | None
    not_after: str


def _evm_opening(request: Mapping[str, Any]) -> _EvmOpening | None:
    """An EVM session's opening, as the escrow opens the channel from it: a Permit2 PermitWitnessTransferFrom of the
    deposit whose spender is the escrow and whose witness ChannelOpenWitness names the payee, the salt and the
    authorized signer (openWithPermit2); or an EIP-3009 ReceiveWithAuthorization of the deposit to the escrow, m.to, in
    the token's domain, whose nonce is evm_session_authorization_nonce over m.from, the payee, the token, the salt and
    the authorized signer the request's opening names, recomputed and held equal to m.nonce (openWithAuthorization
    recomputes it so); else None."""
    permit = _permit_witness(request, "ChannelOpenWitness", _CHANNEL_OPEN_WITNESS)
    return _authorization_opening(request) if permit is None else _permit_opening(permit)


def _permit_opening(permit: tuple[str, str, str, Mapping[str, Any], str, str]) -> _EvmOpening | None:
    """The Permit2 opening: its witness's payee, salt and authorized signer, the spender as the escrow."""
    token, amount, spender, w, deadline, chain = permit
    payee, signer, salt = _address(w.get("payee")), _address(w.get("authorizedSigner")), w.get("salt")
    if payee is None or signer is None or not isinstance(salt, str) or _HASH32.fullmatch(salt) is None:
        return None
    return _EvmOpening(payee, token, salt, signer, spender, amount, chain, None, deadline)


def _authorization_opening(request: Mapping[str, Any]) -> _EvmOpening | None:
    """The EIP-3009 opening: the request's opening names the payee, salt and authorized signer, held to m.nonce."""
    typed, opening = request.get("typedData"), request.get("opening")
    if request.get("kind") != "eip712" or not isinstance(typed, Mapping) or not isinstance(opening, Mapping):
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if typed.get("primaryType") != "ReceiveWithAuthorization" or not isinstance(types, Mapping):
        return None
    if not isinstance(m, Mapping) or not isinstance(d, Mapping) or not _type_is(types.get("ReceiveWithAuthorization"), _RECEIVE_WITH_AUTHORIZATION):
        return None
    from_, escrow, token = _address(m.get("from")), _address(m.get("to")), _address(d.get("verifyingContract"))
    payee, signer, salt = _address(opening.get("payee")), _address(opening.get("authorizedSigner")), opening.get("salt")
    deposit, after, before, chain = (_decimal(x) for x in (m.get("value"), m.get("validAfter"), m.get("validBefore"), d.get("chainId")))
    if from_ is None or escrow is None or token is None or payee is None or signer is None:
        return None
    if not isinstance(salt, str) or _HASH32.fullmatch(salt) is None or deposit is None or after is None or before is None or chain is None:
        return None
    nonce, signed = evm_session_authorization_nonce(from_, payee, token, salt, signer), m.get("nonce")
    if not isinstance(nonce, str) or not isinstance(signed, str) or nonce.lower() != signed.lower():
        return None
    return _EvmOpening(payee, token, salt, signer, escrow, deposit, chain, after, before)


def evm_session_open(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """An EVM session's opening (_evm_opening): the deposit moves from the payer to the escrow, and the channel's payee
    may draw on it with vouchers, which are signed apart, so the summary names no amount. The one payee is the
    channel's payee, with the deposit; the asset the token; the network eip155: and d.chainId; the validity the
    funding's, none or m.validAfter to m.deadline or m.validBefore, in seconds. deposit is the deposit, and grant
    {escrow, authorizedSigner}: the contract that holds the deposit, and the key the opening names to sign the
    channel's vouchers."""
    o = _evm_opening(request)
    if o is None:
        return None
    return Summary(
        payees=(Payee(account=o.payee, amount=o.deposit),),
        asset=o.token,
        network=f"eip155:{o.chain}",
        validity=Validity(not_before=o.not_before, not_after=o.not_after, unit="seconds"),
        deposit=o.deposit,
        grant={"escrow": o.escrow, "authorizedSigner": o.authorized_signer},
        atr=b"",
    )


@dataclass(frozen=True, slots=True)
class _Channel:
    """The channel an opening opens for a payer: its voucher domain's name and amount width, the escrow, the chain and
    the id."""

    name: str
    width: str
    escrow: str
    chain_id: int
    id: str


def _channel_of(opened: "Opened", payer: str) -> _Channel | None:
    """The channel the opening opened opens for payer, recomputed as the protocol package's channel ids give it: a
    Tempo open on the earlier escrow, or an EVM session's opening of either funding, by evm_channel_id; a Tempo open on
    the TIP-20 channel reserve by tempo_channel_id, over the expiring nonce hash of the signed transaction the signer
    answered, under payer. None for any other opening."""
    r = opened.request
    if r.get("kind") == "tempo-call":
        call = r.get("call")
        chain = _decimal(r.get("chainId"))
        escrow = _address(call.get("to")) if isinstance(call, Mapping) else None
        data = call.get("data") if isinstance(call, Mapping) else None
        found = open_of(data) if isinstance(data, str) else None
        if chain is None or int(chain) > 2**53 - 1 or escrow is None or found is None:
            return None
        chain_id = int(chain)
        if found.version == "v1":
            id_ = evm_channel_id(payer, found.payee, found.token, found.salt, found.authorized_signer, escrow, chain_id)
            return _Channel("Tempo Stream Channel", "uint128", escrow, chain_id, id_) if isinstance(id_, str) else None
        signed = opened.signature
        if not isinstance(signed, str) or _SIGNED_TX.fullmatch(signed) is None:
            return None
        nonce_hash = expiring_nonce_hash(bytes.fromhex(signed[2:]), payer)
        if not isinstance(nonce_hash, str):
            return None
        descriptor = {
            "payer": payer,
            "payee": found.payee,
            "operator": found.operator or _ZERO,
            "token": found.token,
            "salt": found.salt,
            "authorizedSigner": found.authorized_signer,
            "expiringNonceHash": nonce_hash,
            "escrow": escrow,
            "chainId": chain_id,
        }
        id_ = tempo_channel_id(descriptor)
        return _Channel("TIP20 Channel Reserve", "uint96", escrow, chain_id, id_) if isinstance(id_, str) else None
    o = _evm_opening(r)
    if o is None or int(o.chain) > 2**53 - 1:
        return None
    id_ = evm_channel_id(payer, o.payee, o.token, o.salt, o.authorized_signer, o.escrow, int(o.chain))
    return _Channel("EVM Payment Channel", "uint128", o.escrow, int(o.chain), id_) if isinstance(id_, str) else None


def _payer_of(account: str | None) -> str | None:
    """The address of an eip155 CAIP-10 account; else None."""
    parts = account.split(":") if isinstance(account, str) else []
    return parts[2] if len(parts) == 3 and parts[0] == "eip155" and _address(parts[2]) is not None else None


def session_voucher(
    request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None, account: str | None = None
) -> Summary | None:
    """The voucher after a session's opening: Voucher(bytes32 channelId, uint128 cumulativeAmount) (uint96 on the
    TIP-20 channel reserve) under the domain {name, version "1", chainId, verifyingContract} of the opened channel's
    escrow, whose m.channelId is the channel opened opens for the signer's account. The amount and the one payee's part
    are m.cumulativeAmount, what the payee may claim from the channel in all; the payee, the asset, the network and the
    validity are the opening's, as its summary shows them: the voucher signs none of them, and pays only from the deposit
    that opening moves; the operator is the opening's, where it shows one."""
    payer = _payer_of(account)
    typed = request.get("typedData")
    if opened is None or payer is None or request.get("kind") != "eip712" or not isinstance(typed, Mapping):
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if typed.get("primaryType") != "Voucher" or not isinstance(types, Mapping):
        return None
    if not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    c = _channel_of(opened, payer)
    if c is None:
        return None
    members = types.get("Voucher")
    expected = [{"name": "channelId", "type": "bytes32"}, {"name": "cumulativeAmount", "type": c.width}]
    if not isinstance(members, list) or [dict(x) if isinstance(x, Mapping) else x for x in members] != expected:
        return None
    contract = _address(d.get("verifyingContract"))
    if d.get("name") != c.name or d.get("version") != "1" or _decimal(d.get("chainId")) != str(c.chain_id):
        return None
    if contract is None or contract.lower() != c.escrow.lower():
        return None
    channel, amount = m.get("channelId"), _decimal(m.get("cumulativeAmount"))
    if not isinstance(channel, str) or _HASH32.fullmatch(channel) is None or channel.lower() != c.id.lower():
        return None
    if amount is None or int(amount) >= 1 << (96 if c.width == "uint96" else 128):
        return None
    facts = opened.summary
    if len(facts.payees) != 1:
        return None
    return Summary(
        amount=amount,
        payees=(Payee(account=facts.payees[0].account, amount=amount),),
        asset=facts.asset,
        network=facts.network,
        validity=facts.validity,
        operator=facts.operator,
        atr=b"",
    )


def tempo_session(
    request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None, account: str | None = None
) -> Summary | None:
    """mpp/session/tempo: its opening, a tempo-call, or the voucher that follows it."""
    return tempo_open(request, network, opened) or session_voucher(request, network, opened, account)


def evm_session(
    request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None, account: str | None = None
) -> Summary | None:
    """mpp/session/evm: its opening, or the voucher that follows it."""
    return evm_session_open(request, network, opened) or session_voucher(request, network, opened, account)
