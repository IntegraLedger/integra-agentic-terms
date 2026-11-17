"""The approval summaries of the NEAR, Tron and TON requests, which hand the signer only a hash (terms' profile
buyer-gate.md, rule 13), as summary/near-delegate.ts, tron-txid.ts and ton-w5.ts read them in the TypeScript package.
Each request carries the bytes its hash is taken over; the summary reads them with the pairing's binding, which reads
them as the protocol package's nearRequest, tronRequest and tvmRequest do, holds the hash that read gives equal to the
request's, and shows the transfer they sign. Each reads the request as the gate hands it to the signer, every byte
string as 0x and lowercase hex, and answers None for a request it cannot read, so the gate declines it
summary-missing."""

import re
from collections.abc import Mapping
from typing import Any

from ._types import Inputs, Payee, Refusal, Summary, Validity
from .bindings._codec import hex_bytes
from .bindings.x402_exact_near import near_request
from .bindings.x402_exact_tron_lcp_trc20_memo import tron_request
from .bindings.x402_exact_tvm import MAX_ATTACHED_ABOVE_FORWARD, tvm_request

# A CAIP-2 network id, as the summary's network names one.
_CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
# A decimal string of at most 78 digits, as the pairing's piece reads a decimal input.
_DECIMAL = re.compile(r"[0-9]{1,78}")


def _network_in(namespace: str, network: object) -> str | None:
    """network where it is a CAIP-2 id in namespace, else None."""
    if isinstance(network, str) and _CAIP2.fullmatch(network) is not None and network.startswith(f"{namespace}:"):
        return network
    return None


def _one_payee(amount: str, payee: str, asset: str, network: str, validity: Validity) -> Summary:
    return Summary(
        amount=amount,
        payees=(Payee(account=payee, amount=amount),),
        asset=asset,
        network=network,
        validity=validity,
        atr=b"",
    )


def near_delegate(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """near-delegate: the amount and the one payee's part are the ft_transfer arguments' amount, the payee their
    receiver_id, the asset the delegate action's receiver, the token contract, the network the signer's account's (the
    request names none), and the validity none to max_block_height, in blocks. The function call attaches 1 yoctoNEAR,
    as NEP-141's ft_transfer requires; a call attaching another deposit, which would move NEAR to the contract, has no
    summary."""
    if request.get("kind") != "near-delegate":
        return None
    handed, delegate_action = hex_bytes(request.get("hash")), hex_bytes(request.get("delegateAction"))
    net = _network_in("near", network)
    if handed is None or delegate_action is None or net is None:
        return None
    r = near_request(delegate_action)
    if isinstance(r, Refusal) or r.hash != handed or r.deposit != 1:
        return None
    until = str(r.max_block_height)
    return _one_payee(r.amount, r.pay_to, r.asset, net, Validity(not_before=None, not_after=until, unit="block"))


def near_start(inputs: Inputs) -> int | None:
    """The height the caller gave the build, finalHeight, a decimal string as the pairing's piece reads it, from which
    max_block_height was counted."""
    v = inputs.get("finalHeight")
    return int(v) if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


def tron_txid(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """tron-txid: the amount and the one payee's part are the transfer's value, the payee its recipient and the asset
    the contract, each address in base58check, the network the signer's account's (the request names none), and the
    validity none to expiration, in seconds, its milliseconds rounded up."""
    if request.get("kind") != "tron-txid":
        return None
    handed, raw_bytes = hex_bytes(request.get("txid")), hex_bytes(request.get("rawBytes"))
    net = _network_in("tron", network)
    if handed is None or raw_bytes is None or net is None:
        return None
    r = tron_request(raw_bytes)
    if isinstance(r, Refusal) or r.txid != handed:
        return None
    until = str(-(-r.raw.expiration // 1000))
    return _one_payee(r.amount, r.pay_to, r.asset, net, Validity(not_before=None, not_after=until, unit="seconds"))


def ton_w5(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """ton-w5: the amount and the one payee's part are the transfer's amount, the payee its destination, the asset the
    message's destination, the payer's Jetton wallet, each address raw (the request names no Jetton master), the
    network the signer's account's (the request names none), and the validity none to valid_until, in seconds. The
    message attaches at most MAX_ATTACHED_ABOVE_FORWARD nanotons, the stock settler's cap, which pays the transfer's
    fees; a forward TON amount above zero, a second asset paid to the payee, an extra currency, a state init or a
    custom payload gives no summary."""
    if request.get("kind") != "ton-w5":
        return None
    handed, signed_boc = hex_bytes(request.get("hash")), request.get("signedBoc")
    net = _network_in("tvm", network)
    if handed is None or not isinstance(signed_boc, str) or net is None:
        return None
    r = tvm_request(signed_boc, net)
    if isinstance(r, Refusal) or r.hash != handed:
        return None
    if r.forward_ton_amount != "0" or r.attach_nanotons > MAX_ATTACHED_ABOVE_FORWARD:
        return None
    if r.extra is not None or r.state_init is not None or r.custom_payload is not None:
        return None
    validity = Validity(not_before=None, not_after=str(r.valid_until), unit="seconds")
    return _one_payee(r.amount, r.pay_to, r.jetton_wallet, net, validity)
