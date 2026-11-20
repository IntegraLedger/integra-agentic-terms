"""The approval summaries of the Casper, Starknet, Concordium, Polkadot, Aptos, Cardano and Sui requests (terms' profile
buyer-gate.md, rule 13), each read from the request as the signer is handed it, every byte string as 0x and lowercase
hex, and answering None for a request it cannot read, so the gate declines it summary-missing."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from ._types import Payee, Summary, Validity
from .bindings._jose import js_length
from .bindings.x402_exact_polkadot_lcp_assets_remark import decode_profile_call
from .bindings.x402_exact_starknet import SELECTOR_TRANSFER, felt_value

if TYPE_CHECKING:
    # The registry in _summary imports these functions; the type is only named here.
    from ._summary import Opened

_DECIMAL = re.compile(r"[0-9]{1,78}")


def _decimal(v: object) -> str | None:
    """A non-negative integer as a decimal string: an int (a bool is none) or a decimal string; else None."""
    if isinstance(v, int) and not isinstance(v, bool):
        return str(v) if v >= 0 else None
    return v if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else None


def _type_is(members: object, fields: Sequence[tuple[str, str]]) -> bool:
    """Whether a typed-data struct type's members are exactly fields, each (name, type), in that order."""
    if not isinstance(members, list) or len(members) != len(fields):
        return False
    return all(
        isinstance(m, Mapping) and len(m) == 2 and m.get("name") == name and m.get("type") == type_
        for m, (name, type_) in zip(members, fields)
    )


def _typed(request: Mapping[str, Any], kind: str, primary: str) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]] | None:
    """The types, message and domain of a request of kind whose typed data's primary type is primary; else None."""
    typed = request.get("typedData")
    if request.get("kind") != kind or not isinstance(typed, Mapping) or typed.get("primaryType") != primary:
        return None
    types, m, d = typed.get("types"), typed.get("message"), typed.get("domain")
    if not isinstance(types, Mapping) or not isinstance(m, Mapping) or not isinstance(d, Mapping):
        return None
    return types, m, d


# ── casper-eip712: CEP-3009's TransferWithAuthorization, which the payer's key signs as typed data. Only what the typed
# data signs is read, and only under CEP-3009's own types, so a member the types do not sign is never shown.

# CEP-3009's domain: the token's name and version, the chain's name, and the token's contract package hash.
_CASPER_DOMAIN = (("name", "string"), ("version", "string"), ("chain_name", "string"), ("contract_package_hash", "bytes32"))
_CASPER_TRANSFER = (
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
)
# The chain's name as the domain signs it: the network's CAIP-2 id.
_CASPER_NETWORK = re.compile(r"casper:[a-z0-9-]{1,64}")
_CASPER_PACKAGE = re.compile(r"[0-9a-fA-F]{64}")
# A Casper key as CEP-3009 signs an address: a tag byte, 00 an account hash or 01 a package hash, and 32 bytes.
_CASPER_ADDRESS = re.compile(r"0[01][0-9a-fA-F]{64}")


def casper_transfer_with_authorization(
    request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None
) -> Summary | None:
    """x402/exact/casper: the amount and the one payee's part are m.value, the payee m.to, the asset
    d.contract_package_hash, the network d.chain_name, and the validity m.validAfter to m.validBefore, in seconds."""
    typed = _typed(request, "casper-eip712", "TransferWithAuthorization")
    if typed is None:
        return None
    types, m, d = typed
    if not _type_is(types.get("EIP712Domain"), _CASPER_DOMAIN) or not _type_is(types.get("TransferWithAuthorization"), _CASPER_TRANSFER):
        return None
    chain, asset, to = d.get("chain_name"), d.get("contract_package_hash"), m.get("to")
    value, after, before = _decimal(m.get("value")), _decimal(m.get("validAfter")), _decimal(m.get("validBefore"))
    if not isinstance(chain, str) or _CASPER_NETWORK.fullmatch(chain) is None:
        return None
    if not isinstance(asset, str) or _CASPER_PACKAGE.fullmatch(asset) is None:
        return None
    if not isinstance(to, str) or _CASPER_ADDRESS.fullmatch(to) is None or value is None or after is None or before is None:
        return None
    return Summary(
        amount=value,
        payees=(Payee(account=to, amount=value),),
        asset=asset,
        network=chain,
        validity=Validity(not_before=after, not_after=before, unit="seconds"),
        atr=b"",
    )


# ── starknet-snip12: SNIP-9's OutsideExecution under SNIP-12's revision 1, which the payer's account key signs. Only
# what the typed data signs is read, under SNIP-9's own types, and only where its calls are one ERC-20
# transfer(recipient, amount) and nothing else, the call the build writes; any other call, or a second one, has none.

_STARKNET_DOMAIN = (("name", "shortstring"), ("version", "shortstring"), ("chainId", "shortstring"), ("revision", "shortstring"))
_OUTSIDE_EXECUTION = (
    ("Caller", "ContractAddress"),
    ("Nonce", "felt"),
    ("Execute After", "u128"),
    ("Execute Before", "u128"),
    ("Calls", "Call*"),
)
_CALL = (("To", "ContractAddress"), ("Selector", "selector"), ("Calldata", "felt*"))
_U128 = 1 << 128
_TRANSFER = int(SELECTOR_TRANSFER, 16)


def _u128(v: object) -> str | None:
    """A u128 as SNIP-12 takes it, a decimal or a felt, as a decimal string; else None."""
    n = int(v) if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else felt_value(v)
    return str(n) if n is not None and n < _U128 else None


def _short_string(v: object) -> str | None:
    """A short string's felt as its ASCII text, each character printable; else None."""
    n = felt_value(v)
    if n is None or n == 0:
        return None
    out = ""
    while n > 0:
        c = n & 0xFF
        if c < 0x21 or c > 0x7E:
            return None
        out = chr(c) + out
        n >>= 8
    return out


def starknet_transfer(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/starknet: the one call's transfer, c being m.Calls[0]: the amount and the one payee's part are its u256
    amount, c.Calldata[1] and [2] as its low and high halves; the payee c.Calldata[0], the asset c.To, the network
    starknet: and d.chainId's short string, and the validity m["Execute After"] to m["Execute Before"], in seconds."""
    typed = _typed(request, "starknet-snip12", "OutsideExecution")
    if typed is None:
        return None
    types, m, d = typed
    if not _type_is(types.get("StarknetDomain"), _STARKNET_DOMAIN) or not _type_is(types.get("OutsideExecution"), _OUTSIDE_EXECUTION):
        return None
    if not _type_is(types.get("Call"), _CALL):
        return None
    calls = m.get("Calls")
    if not isinstance(calls, list) or len(calls) != 1 or not isinstance(calls[0], Mapping):
        return None
    c = calls[0]
    data = c.get("Calldata")
    if felt_value(c.get("Selector")) != _TRANSFER or not isinstance(data, list) or len(data) != 3:
        return None
    to, low, high = data
    lo, hi, asset = felt_value(low), felt_value(high), c.get("To")
    chain, after, before = _short_string(d.get("chainId")), _u128(m.get("Execute After")), _u128(m.get("Execute Before"))
    if felt_value(to) is None or felt_value(asset) is None or lo is None or hi is None or lo >= _U128 or hi >= _U128:
        return None
    if chain is None or after is None or before is None:
        return None
    assert isinstance(to, str) and isinstance(asset, str)
    amount = str(lo + (hi << 128))
    return Summary(
        amount=amount,
        payees=(Payee(account=to, amount=amount),),
        asset=asset,
        network=f"starknet:{chain}",
        validity=Validity(not_before=after, not_after=before, unit="seconds"),
        atr=b"",
    )


# ── ccd-transfer: the one transfer the payer's wallet assembles and signs as a sponsored Concordium transaction, whose
# members the request names: the receiver, the asset, the amount, the memo and the expiry. The sponsor pays the
# transaction's energy and moves nothing, so it is not shown.

_CCD_NETWORK = re.compile(r"ccd:[0-9a-f]{32}")
# An account address in Concordium's base58check form, as the request writes it.
_CCD_ACCOUNT = re.compile(r"[1-9A-HJ-NP-Za-km-z]{1,64}")
# CCD, in any case, or a protocol-level token's id.
_CCD_TOKEN = re.compile(r"[\x21-\x7e]{1,128}")


def ccd_transfer(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/ccd: the amount and the one payee's part are amount, the payee toAddress, the asset asset, the
    network network, and the validity none to expiresBy, in seconds."""
    if request.get("kind") != "ccd-transfer":
        return None
    chain, to, asset = request.get("network"), request.get("toAddress"), request.get("asset")
    amount = _decimal(request.get("amount"))
    expires = request.get("expiresBy")
    until = _decimal(expires) if isinstance(expires, int) else None
    if not isinstance(chain, str) or _CCD_NETWORK.fullmatch(chain) is None:
        return None
    if not isinstance(to, str) or _CCD_ACCOUNT.fullmatch(to) is None:
        return None
    if not isinstance(asset, str) or _CCD_TOKEN.fullmatch(asset) is None or amount is None or until is None:
        return None
    return Summary(
        amount=amount,
        payees=(Payee(account=to, amount=amount),),
        asset=asset,
        network=chain,
        validity=Validity(not_before=None, not_after=until, unit="seconds"),
        atr=b"",
    )


# ── substrate-call: the call the payer's signer wraps in a signed extrinsic, read only where the profile's call
# decoder reads it as the profile's call, exactly: batch_all([transfer_keep_alive(assetId, Id(dest), amount),
# remark_with_event(remark)]); any other call has none. The era and the nonce are the extrinsic's, which the signer
# writes, so the call signs no end.

_POLKADOT_NETWORK = re.compile(r"polkadot:[0-9a-f]{32}")
# The call as the signer is handed it: 0x and lowercase hex.
_HEX = re.compile(r"0x(?:[0-9a-f]{2})*")


def substrate_transfer(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/polkadot/lcp-assets-remark: the amount and the one payee's part are the transfer's amount, the payee
    its dest, the 32-byte account as 0x and lowercase hex, the asset its assetId in decimal, the network network, and
    the validity 0 to maxEraPeriod, in blocks from the era's birth (the block whose hash the extrinsic signs, at or
    before the block it is signed at): the call signs no era, which the signer's extrinsic adds, of at most the
    maxEraPeriod the gate hands it; none to none where the request carries no maxEraPeriod."""
    chain, call = request.get("network"), request.get("call")
    if request.get("kind") != "substrate-call" or not isinstance(chain, str) or _POLKADOT_NETWORK.fullmatch(chain) is None:
        return None
    if not isinstance(call, str) or _HEX.fullmatch(call) is None:
        return None
    ok, era = _latest_in(request, "maxEraPeriod")
    if not ok:
        return None
    decoded = decode_profile_call(bytes.fromhex(call[2:]))
    if not isinstance(decoded, tuple):
        return None
    asset_id, dest, value, _ = decoded
    amount = str(value)
    return Summary(
        amount=amount,
        payees=(Payee(account="0x" + dest.hex(), amount=amount),),
        asset=str(asset_id),
        network=chain,
        validity=Validity(not_before=None if era is None else "0", not_after=era, unit="block"),
        atr=b"",
    )


# ── aptos-transaction, cardano-transaction and sui-transaction: the requests whose transaction the payer's wallet
# builds itself from the option the request carries, as x402's scheme for the chain has the client do. The request
# hands the wallet accepted, the exact option to pay, beside what carries H; the summary reads accepted as the request
# holds it. The transaction's expiry is the wallet's to set: the gate hands it the latest it may sign
# (maxExpirationTimestampSecs, maxTtl, maxEpoch), which the summary shows as the validity's end, and a request without
# one signs no end.

# The longest account or asset text read, in UTF-16 code units: Sui's coin type bound, the longest of the three chains'.
_MAX_TEXT = 4096


def _text(v: object) -> bool:
    return isinstance(v, str) and 0 < js_length(v) <= _MAX_TEXT


def _latest_in(request: Mapping[str, Any], member: str) -> tuple[bool, str | None]:
    """The latest deadline a request carries in member: (True, a decimal string), (True, None) where it carries none,
    and (False, None) where member holds anything else."""
    if member not in request:
        return True, None
    v = request[member]
    return (True, v) if isinstance(v, str) and _DECIMAL.fullmatch(v) is not None else (False, None)


def _wallet_built(request: Mapping[str, Any], kind: str, network: re.Pattern[str], unit: str, member: str) -> Summary | None:
    """An exact option as a request of kind carries it in accepted, on a network network matches: the amount and the
    one payee's part are accepted.amount, the payee accepted.payTo, the asset accepted.asset, the network
    accepted.network, and the validity none to the latest deadline the request carries in member, in unit, or none to
    none where it carries none."""
    a = request.get("accepted")
    if request.get("kind") != kind or not isinstance(a, Mapping):
        return None
    ok, not_after = _latest_in(request, member)
    if not ok:
        return None
    amount, chain, pay_to, asset = _decimal(a.get("amount")), a.get("network"), a.get("payTo"), a.get("asset")
    if a.get("scheme") != "exact" or amount is None or not isinstance(chain, str) or network.fullmatch(chain) is None:
        return None
    if not _text(pay_to) or not _text(asset):
        return None
    assert isinstance(pay_to, str) and isinstance(asset, str)
    return Summary(
        amount=amount,
        payees=(Payee(account=pay_to, amount=amount),),
        asset=asset,
        network=chain,
        validity=Validity(not_before=None, not_after=not_after, unit=unit),
        atr=b"",
    )


_APTOS_NETWORK = re.compile(r"aptos:[1-9][0-9]{0,2}")
# A Cardano network named in the cardano namespace or by its CIP-34 alias, as the protocol package reads it.
_CARDANO_NETWORK = re.compile(r"cardano:(?:mainnet|preprod|preview)|cip34:(?:1-764824073|0-1|0-2)")
_SUI_NETWORK = re.compile(r"sui:(?:mainnet|testnet|devnet)")


def aptos_transaction(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/aptos: accepted's members; the validity none to maxExpirationTimestampSecs, in seconds."""
    return _wallet_built(request, "aptos-transaction", _APTOS_NETWORK, "seconds", "maxExpirationTimestampSecs")


def cardano_transaction(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/cardano: accepted's members, on a network named in the cardano namespace or by its CIP-34 alias; the
    validity none to maxTtl, in slots."""
    return _wallet_built(request, "cardano-transaction", _CARDANO_NETWORK, "slot", "maxTtl")


def cardano_lock(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/cardano/lock, as the protocol package's reference names the payee: on a script lock
    (accepted.extra.assetTransferMethod "script") the address method's members, its payee payTo, the contract the
    seller defines; on a Masumi lock ("masumi") the same members but the payee, the seller accepted.extra.terms names
    in sellerAddress, with the amount, and the grant {escrow}, payTo, the escrow every seller of a deployment shares,
    which holds the deposit."""
    a = request.get("accepted")
    extra = a.get("extra") if isinstance(a, Mapping) else None
    if not isinstance(extra, Mapping):
        return None
    if extra.get("assetTransferMethod") == "script":
        return cardano_transaction(request, network, opened)
    if extra.get("assetTransferMethod") != "masumi":
        return None
    terms = extra.get("terms")
    seller = terms.get("sellerAddress") if isinstance(terms, Mapping) else None
    shown = cardano_transaction(request, network, opened)
    if shown is None or not isinstance(seller, str) or not _text(seller):
        return None
    escrow, amount = shown.payees[0].account, shown.payees[0].amount
    return replace(shown, payees=(Payee(account=seller, amount=amount),), grant={"escrow": escrow})


def sui_transaction(request: Mapping[str, Any], network: str | None = None, opened: "Opened | None" = None) -> Summary | None:
    """x402/exact/sui: accepted's members, where the request asks a transaction bounded by epoch; the validity none to
    maxEpoch, in epochs."""
    if request.get("expiration") != "epoch-bounded":
        return None
    return _wallet_built(request, "sui-transaction", _SUI_NETWORK, "epoch", "maxEpoch")
