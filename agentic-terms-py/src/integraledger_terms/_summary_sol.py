"""The approval summaries of the Solana, XRP Ledger, Algorand, Stacks and Hedera requests (terms' profile buyer-gate.md,
rule 13), the batch of x402's batch-settlement opening on Solana among them, as summary/solana-message.ts, xrpl-tx.ts,
algorand-txn.ts, stacks-contract-call.ts and hedera-body.ts read them in the TypeScript package. Each reads the request
as the gate hands it to the signer, every byte string as 0x and lowercase hex, and answers None for a request it cannot
read, so the gate declines it summary-missing."""

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ._types import Payee, Summary, Validity
from .bindings import _svm
from .bindings._algorand import sha512_256
from .bindings._codec import b58_encode, hex_bytes
from .bindings._hedera_proto import _fields_of, decode_hedera_tx, len_field
from .bindings._xrpl import channel_id

MAX_SAFE_INTEGER = 2**53 - 1

# A CAIP-2 network id, as the summary's network names one.
_CAIP2 = re.compile(r"[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,77}")


def _network_in(namespace: str, network: object) -> str | None:
    """network where it is a CAIP-2 id in namespace, else None."""
    if isinstance(network, str) and _CAIP2.fullmatch(network) is not None and network.startswith(f"{namespace}:"):
        return network
    return None


def _uint_le(b: bytes, at: int, length: int) -> int:
    """An unsigned little-endian integer of length bytes at at."""
    return int.from_bytes(b[at : at + length], "little")


def _is_safe_index(v: object) -> bool:
    """A non-negative safe integer: an int, not a bool."""
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_SAFE_INTEGER


# ── Solana: solana-message, solana-session-open and the batch-settlement opening ──────────────────────────────────────

# The version byte of a version-1 message (SIMD-0385).
_V1 = 0x81
# The rail's own life bounds a Solana message: no height is signed, so both ends are none.
_BLOCKS = Validity(not_before=None, not_after=None, unit="block")
# How the summary names native SOL, which a System transfer moves: the MPP solana method's own currency name.
_SOL = "sol"


def _unsigned_wire(message: bytes) -> bytes | None:
    """The message as an unsigned wire transaction, one zero signature slot per required signer, as the Solana
    transaction format lays one out: before a legacy or v0 message with their compact-u16 count, after a version-1
    message."""
    if len(message) < 2:
        return None
    v1 = message[0] == _V1
    required = message[1] if message[0] & 0x80 else message[0]
    if required == 0 or required > 0x7F:
        return None
    if v1:
        return message + bytes(64 * required)
    return bytes([required]) + bytes(64 * required) + message


@dataclass(frozen=True, slots=True)
class _Transfer:
    """A transfer the message signs: the destination, the amount and what moves, a mint or SOL."""

    to: str
    amount: int
    asset: str


@dataclass(frozen=True, slots=True)
class _Open:
    """A payment-channels open the message signs."""

    payee: str
    mint: str
    # The key the channel's vouchers are signed with, the open's fifth account.
    signer: str
    # The channel's account, the open's sixth.
    channel: str
    deposit: int
    recipients: tuple[tuple[str, int], ...]


def _read_message(message: bytes) -> tuple[list[_Transfer], list[_Open]] | None:
    """What the message signs, by its instructions, read with the protocol package's transaction decoder; None where
    one of them is not one the summary can state."""
    wire = _unsigned_wire(message)
    if wire is None:
        return None
    tx = _svm.decode_svm_tx(wire)
    if not isinstance(tx, _svm.SvmTx):
        return None
    keys = [b58_encode(k) for k in tx.keys]
    transfers: list[_Transfer] = []
    opens: list[_Open] = []
    for ix in tx.instructions:
        # An account loaded from an address table is not in the message: the summary cannot name it.
        if ix.program >= len(keys) or any(a >= len(keys) for a in ix.accounts):
            return None
        program = keys[ix.program]
        d = ix.data

        def at(i: int) -> str:
            return keys[ix.accounts[i]]

        if program in (_svm.COMPUTE_BUDGET, _svm.MEMO_V3, _svm.MEMO_V4):
            continue
        if program in (_svm.TOKEN, _svm.TOKEN_2022):
            # TransferChecked: 12, amount u64, decimals u8; accounts source, mint, destination, authority.
            if len(d) != 10 or d[0] != 12 or len(ix.accounts) != 4:
                return None
            transfers.append(_Transfer(to=at(2), amount=_uint_le(d, 1, 8), asset=at(1)))
        elif program == _svm.SYSTEM:
            # transfer: 2 as u32, lamports u64; accounts from, to. Every other System instruction, a durable nonce's
            # AdvanceNonceAccount among them, is not one the summary states.
            if len(d) != 12 or _uint_le(d, 0, 4) != 2 or len(ix.accounts) != 2:
                return None
            transfers.append(_Transfer(to=at(1), amount=_uint_le(d, 4, 8), asset=_SOL))
        elif program == _svm.PAYMENT_CHANNELS:
            # open: 1, salt u64, deposit u64, gracePeriod u32, openSlot u64, then a u32 count of (recipient, bps u16).
            if len(d) < 33 or d[0] != 1 or len(ix.accounts) != 14:
                return None
            count = _uint_le(d, 29, 4)
            if len(d) != 33 + 34 * count:
                return None
            recipients = tuple(
                (b58_encode(d[33 + 34 * i : 65 + 34 * i]), _uint_le(d, 65 + 34 * i, 2)) for i in range(count)
            )
            opens.append(
                _Open(payee=at(2), mint=at(3), signer=at(4), channel=at(5), deposit=_uint_le(d, 9, 8), recipients=recipients)
            )
        else:
            return None
    return transfers, opens


def _shares(open_: _Open, total: int) -> tuple[Payee, ...] | None:
    """Each payee's part of total: each recipient of the distribution its bps of total, rounded down, and the channel's
    payee the rest where the distribution's bps sum to less than 10,000, as the payment-channels program pays the
    remainder to the payee; the payee alone, with the whole, where the distribution names no recipient. A recipient of
    0 bps, or bps that sum past 10,000, which the program's open refuses, gives none."""
    if not open_.recipients:
        return (Payee(account=open_.payee, amount=str(total)),)
    bps = sum(b for _, b in open_.recipients)
    if any(b == 0 for _, b in open_.recipients) or bps > 10_000:
        return None
    parts = [(r, total * b // 10_000) for r, b in open_.recipients]
    if bps < 10_000:
        parts.append((open_.payee, total - sum(a for _, a in parts)))
    return tuple(Payee(account=r, amount=str(a)) for r, a in parts)


def solana_transfer(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """A message of token or SOL transfers and their compute budget and memos: the amount is their sum, each transfer's
    destination a payee with its amount, all of one asset, its mint or sol. A message names no cluster, so its network
    is the signer's account's."""
    net = _network_in("solana", network)
    message = hex_bytes(request.get("message"))
    if request.get("kind") != "solana-message" or message is None or net is None:
        return None
    read = _read_message(message)
    if read is None or read[1] or not read[0]:
        return None
    transfers = read[0]
    asset = transfers[0].asset
    if any(t.asset != asset for t in transfers):
        return None
    return Summary(
        amount=str(sum(t.amount for t in transfers)),
        payees=tuple(Payee(account=t.to, amount=str(t.amount)) for t in transfers),
        asset=asset,
        network=net,
        validity=_BLOCKS,
        atr=b"",
    )


def _open_of(message: object) -> _Open | None:
    """The one payment-channels open of a message that signs nothing else but its compute budget and memos."""
    data = hex_bytes(message)
    read = None if data is None else _read_message(data)
    return None if read is None or read[0] or len(read[1]) != 1 else read[1][0]


def solana_upto_open(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """A one-request channel's open (upto): the deposit escrows the maximum the payee may charge, split by the
    distribution, or the channel's payee's whole where it names none; the asset is its mint."""
    net = _network_in("solana", network)
    if request.get("kind") != "solana-message" or net is None:
        return None
    open_ = _open_of(request.get("message"))
    payees = None if open_ is None else _shares(open_, open_.deposit)
    if open_ is None or payees is None:
        return None
    deposit = str(open_.deposit)
    return Summary(maximum=deposit, payees=payees, deposit=deposit, asset=open_.mint, network=net, validity=_BLOCKS, atr=b"")


def solana_session_open(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """A session's open (solana-session-open): the deposit, split by the distribution, or the channel's payee's whole
    where it names none; the asset is its mint. The vouchers that later charge it are signed apart."""
    net = _network_in("solana", network)
    if request.get("kind") != "solana-session-open" or net is None:
        return None
    open_ = _open_of(request.get("message"))
    payees = None if open_ is None else _shares(open_, open_.deposit)
    if open_ is None or payees is None:
        return None
    return Summary(payees=payees, deposit=str(open_.deposit), asset=open_.mint, network=net, validity=_BLOCKS, atr=b"")


def solana_batch_opening(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """x402/batch-settlement/solana's opening, a batch of the open message, then the first voucher, for the open's
    authorized signer, over the channel the open opens and with no expiry, as x402's scheme writes every voucher
    (scheme_batch_settlement_svm.md: expiresAt "MUST be 0"): the amount and each payee's part are the voucher's amount,
    split by the open's distribution; the deposit the open's; the asset its mint. A voucher of another channel or
    signer, or with an expiry, gives none. The voucher's 50 bytes are 56 01, the channel id, the amount as a u64 and
    the expiry as an i64."""
    net = _network_in("solana", network)
    requests = request.get("requests")
    if request.get("kind") != "batch" or not isinstance(requests, list) or len(requests) != 2 or net is None:
        return None
    tx, voucher = requests
    if not isinstance(tx, Mapping) or not isinstance(voucher, Mapping):
        return None
    if tx.get("kind") != "solana-message" or voucher.get("kind") != "ed25519-raw":
        return None
    open_ = _open_of(tx.get("message"))
    v = hex_bytes(voucher.get("message"))
    if open_ is None or v is None or len(v) != 50 or v[:2] != b"\x56\x01":
        return None
    if b58_encode(v[2:34]) != open_.channel or voucher.get("signer") != open_.signer or _uint_le(v, 42, 8) != 0:
        return None
    amount = _uint_le(v, 34, 8)
    payees = _shares(open_, amount)
    if payees is None:
        return None
    return Summary(
        amount=str(amount), payees=payees, deposit=str(open_.deposit), asset=open_.mint, network=net, validity=_BLOCKS, atr=b""
    )


# ── XRP Ledger: xrpl-tx and xrpl-session-open ───────────────────────────────────────────────────────────────────────

# XRP in drops, as a Payment's Amount writes it: a decimal string.
_DROPS = re.compile(r"0|[1-9][0-9]{0,18}")
# The members every transaction carries that grant nothing beyond what the summary states: identity, fee, memo.
_COMMON = frozenset(
    {"TransactionType", "Flags", "Account", "Fee", "Sequence", "LastLedgerSequence", "NetworkID", "Memos", "SourceTag"}
)
# Seconds from the Unix epoch to the XRP Ledger's, 2000-01-01T00:00:00Z, which CancelAfter counts from.
_RIPPLE_EPOCH = 946_684_800
# The claim's prefix, CLM\0.
_CLM = b"CLM\x00"


def _is_u32(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 0xFFFFFFFF


def _xrpl_frame(tx: Mapping[str, Any], network: str | None, allowed: frozenset[str]) -> tuple[str, Validity] | None:
    """The members both forms read: the network (NetworkID, else the signer's account's), the validity
    (LastLedgerSequence, ledgers), and Flags, which must be 0, so no flag widens what moves."""
    if not all(k in _COMMON or k in allowed for k in tx):
        return None
    if "Flags" in tx and not (_is_u32(tx["Flags"]) and tx["Flags"] == 0):
        return None
    if not isinstance(tx.get("Account"), str) or not _is_u32(tx.get("LastLedgerSequence")):
        return None
    if "NetworkID" in tx and not _is_u32(tx["NetworkID"]):
        return None
    net = f"xrpl:{tx['NetworkID']}" if "NetworkID" in tx else _network_in("xrpl", network)
    if net is None:
        return None
    return net, Validity(not_before=None, not_after=str(tx["LastLedgerSequence"]), unit="ledger")


_PAYMENT = frozenset({"Destination", "Amount", "DestinationTag", "InvoiceID", "TicketSequence"})
_CHANNEL_CREATE = frozenset({"Destination", "Amount", "SettleDelay", "PublicKey", "CancelAfter"})


def xrpl_payment(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """xrpl-tx, a Payment of XRP: the amount and the one payee's part are Amount, in drops, the payee Destination;
    InvoiceID and DestinationTag grant nothing more. An issued currency's Amount is a decimal value with no base unit,
    and is not summarised. A transaction names its network only by NetworkID, which a network whose id is at most 1024
    refuses, so without one its network is the signer's account's."""
    tx = request.get("txJson")
    if request.get("kind") != "xrpl-tx" or not isinstance(tx, Mapping) or tx.get("TransactionType") != "Payment":
        return None
    frame = _xrpl_frame(tx, network, _PAYMENT)
    amount, to = tx.get("Amount"), tx.get("Destination")
    if frame is None or not isinstance(amount, str) or _DROPS.fullmatch(amount) is None or not isinstance(to, str):
        return None
    return Summary(amount=amount, payees=(Payee(account=to, amount=amount),), asset="XRP", network=frame[0], validity=frame[1], atr=b"")


def xrpl_session_open(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """xrpl-session-open: the PaymentChannelCreate's Amount is the deposit, in drops, and its Destination the payee;
    the first claim's bytes, CLM\\0, the channel the create makes and drops as a big-endian u64, are the amount the
    payee may redeem at once. The destination may close the channel at any time and the source once SettleDelay has
    passed (XRP Ledger, PaymentChannelClaim), so both may close it; CancelAfter, where set, is when it ends."""
    tx, claim = request.get("txJson"), request.get("claim")
    if request.get("kind") != "xrpl-session-open" or not isinstance(tx, Mapping) or not isinstance(claim, Mapping):
        return None
    if tx.get("TransactionType") != "PaymentChannelCreate":
        return None
    frame = _xrpl_frame(tx, network, _CHANNEL_CREATE)
    deposit, to, cancel_after = tx.get("Amount"), tx.get("Destination"), tx.get("CancelAfter")
    data = hex_bytes(claim.get("bytes"))
    if frame is None or not isinstance(deposit, str) or _DROPS.fullmatch(deposit) is None or not isinstance(to, str):
        return None
    if not _is_u32(tx.get("Sequence")) or ("CancelAfter" in tx and not _is_u32(cancel_after)):
        return None
    if data is None or len(data) != 44 or data[:4] != _CLM:
        return None
    account = tx["Account"]
    channel = channel_id(account, to, tx["Sequence"])
    if not isinstance(channel, str) or data[4:36].hex().upper() != channel.upper():
        return None
    drops = str(int.from_bytes(data[36:44], "big"))
    return Summary(
        amount=drops,
        payees=(Payee(account=to, amount=drops),),
        end=str(cancel_after + _RIPPLE_EPOCH) if isinstance(cancel_after, int) else None,
        deposit=deposit,
        closable_by=(account, to),
        asset="XRP",
        network=frame[0],
        validity=frame[1],
        atr=b"",
    )


# ── Algorand: algorand-txn ──────────────────────────────────────────────────────────────────────────────────────────

# The members of an asset transfer the summary reads, or that grant nothing beyond it.
_AXFER_MEMBERS = frozenset({"aamt", "arcv", "fee", "fv", "gen", "gh", "grp", "lv", "lx", "note", "snd", "type", "xaid"})


class _Unread(Exception):
    """The bytes are not one flat map of the formats the reader reads."""


def _flat_map(b: bytes) -> dict[str, int | str | bytes] | None:
    """One flat msgpack map of string keys to unsigned integers, strings and byte strings (the formats the msgpack
    specification names: fixmap, map 16; fixstr, str 8, str 16; positive fixint, uint 8 to 64; bin 8, bin 16), the
    whole input; None for anything else."""
    at = 0

    def take(n: int) -> bytes:
        nonlocal at
        if at + n > len(b):
            raise _Unread
        out = b[at : at + n]
        at += n
        return out

    def uint(n: int) -> int:
        return int.from_bytes(take(n), "big")

    def value() -> int | str | bytes:
        t = uint(1)
        if t <= 0x7F:
            return t
        if 0xA0 <= t <= 0xBF:
            return take(t & 0x1F).decode("utf-8")
        if t in (0xD9, 0xDA):
            return take(uint(1 if t == 0xD9 else 2)).decode("utf-8")
        if t in (0xCC, 0xCD, 0xCE, 0xCF):
            return uint(1 << (t - 0xCC))
        if t in (0xC4, 0xC5):
            return take(uint(1 if t == 0xC4 else 2))
        raise _Unread

    try:
        t = uint(1)
        count = t & 0x0F if 0x80 <= t <= 0x8F else uint(2) if t == 0xDE else -1
        if count < 0:
            return None
        out: dict[str, int | str | bytes] = {}
        for _ in range(count):
            k = value()
            if not isinstance(k, str) or k in out:
                return None
            out[k] = value()
        return out if at == len(b) else None
    except (_Unread, UnicodeDecodeError):
        return None


def _algorand_address(key: object) -> str | None:
    """An Algorand address's text: base32 (RFC 4648, section 6, unpadded) of the 32-byte key and the last 4 bytes of
    its SHA-512/256."""
    if not isinstance(key, bytes) or len(key) != 32:
        return None
    return base64.b32encode(key + sha512_256(key)[-4:]).decode("ascii").rstrip("=")


def algorand_transfer(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """algorand-txn, the bytes it signs, TX and the transaction's msgpack map (the Algorand transaction format), an
    asset transfer (type axfer): the amount and the one payee's part are aamt (absent, 0), the payee arcv, the asset
    xaid as its decimal id, the network algorand: and the first 32 characters of gh in URL-safe base64, as the protocol
    package names an Algorand network, and the validity fv to lv, in rounds. A member that hands over the account
    (rekey), closes out its holding (aclose) or claws back another's (asnd), or one the reader does not know, gives no
    summary."""
    data = hex_bytes(request.get("bytes"))
    if request.get("kind") != "algorand-txn" or data is None or data[:2] != b"TX":
        return None
    m = _flat_map(data[2:])
    if m is None or not all(k in _AXFER_MEMBERS for k in m) or m.get("type") != "axfer":
        return None
    amount, asset, fv, lv, gh = m.get("aamt", 0), m.get("xaid"), m.get("fv", 0), m.get("lv"), m.get("gh")
    payee = _algorand_address(m.get("arcv"))
    if not isinstance(amount, int) or not isinstance(asset, int) or not isinstance(fv, int) or not isinstance(lv, int):
        return None
    if not isinstance(gh, bytes) or len(gh) != 32 or payee is None:
        return None
    net = "algorand:" + base64.urlsafe_b64encode(gh).decode("ascii")[:32]
    return Summary(
        amount=str(amount),
        payees=(Payee(account=payee, amount=str(amount)),),
        asset=str(asset),
        network=net,
        validity=Validity(not_before=str(fv), not_after=str(lv), unit="round"),
        atr=b"",
    )


# ── Stacks: stacks-contract-call ────────────────────────────────────────────────────────────────────────────────────


def stacks_transfer(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """stacks-contract-call, the SIP-010 transfer(amount, sender, recipient, memo) the wallet builds and signs on the
    token contract contract, with one SentEq post-condition in mode deny, so the call moves exactly amount of the token
    from the sender and nothing else: the amount and the one payee's part are args.amount, the payee args.recipient,
    the asset contract, the network stacks: and chainId. A Stacks transaction signs no expiry, so its validity is none
    to none, and the gate holds it to the profile's rule for a form that signs no end."""
    if request.get("kind") != "stacks-contract-call" or request.get("functionName") != "transfer":
        return None
    if request.get("postCondition") != "SentEq" or request.get("postConditionMode") != "deny":
        return None
    args, chain, contract = request.get("args"), request.get("chainId"), request.get("contract")
    if not isinstance(args, Mapping) or not _is_safe_index(chain) or not isinstance(contract, str):
        return None
    amount, recipient = args.get("amount"), args.get("recipient")
    if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None or not isinstance(recipient, str):
        return None
    return Summary(
        amount=amount,
        payees=(Payee(account=recipient, amount=amount),),
        asset=contract,
        network=f"stacks:{chain}",
        validity=Validity(not_before=None, not_after=None, unit="seconds"),
        atr=b"",
    )


# ── Hedera: hedera-body and hedera-executor ─────────────────────────────────────────────────────────────────────────

# How the protocol package names HBAR as an x402 asset: the entity id 0.0.0.
_HBAR = "0.0.0"
# The TransactionBody fields a crypto transfer's body may hold beside its transfer, none granting more than the summary
# states: transactionID (1), nodeAccountID (2), transactionFee (3), transactionValidDuration (4), memo (6) and
# cryptoTransfer (14) (Hedera's transaction_body.proto).
_BODY_FIELDS = frozenset({1, 2, 3, 4, 6, 14})


def hedera_transfer(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """hedera-body, the TransactionBody bytes the payer signs, a crypto transfer, read with the protocol package's own
    transaction decoder: the payees are the rows it credits, each with its credit, and the amount their sum, all of one
    asset, HBAR (0.0.0) or one token; the validity from the transaction id's valid start to that plus
    transactionValidDuration, in seconds. A body names no ledger, so its network is the signer's account's."""
    net = _network_in("hedera", network)
    body_bytes = hex_bytes(request.get("bodyBytes"))
    if request.get("kind") != "hedera-body" or body_bytes is None or net is None:
        return None
    fields = _fields_of(body_bytes)
    if fields is None or not all(f.n in _BODY_FIELDS for f in fields):
        return None
    # A Transaction {5: SignedTransaction {1: the body}}, the wire form the decoder reads, with no signature.
    decoded = decode_hedera_tx(len_field(5, len_field(1, body_bytes)))
    if not isinstance(decoded, list) or len(decoded) != 1:
        return None
    body = decoded[0]
    t = body.transfer
    if t is None:
        return None
    lists = ([(_HBAR, t.hbar)] if t.hbar else []) + list(t.tokens)
    if len(lists) != 1:
        return None
    asset, rows = lists[0]
    payees = tuple(Payee(account=row.account, amount=str(row.amount)) for row in rows if row.amount > 0)
    if not payees:
        return None
    end = body.tx_id.seconds + body.valid_duration + (1 if body.tx_id.nanos > 0 else 0)
    return Summary(
        amount=str(sum(row.amount for row in rows if row.amount > 0)),
        payees=payees,
        asset=asset,
        network=net,
        validity=Validity(not_before=str(body.tx_id.seconds), not_after=str(end), unit="seconds"),
        atr=b"",
    )


def hedera_executor(request: Mapping[str, Any], network: str | None = None, opened: object = None) -> Summary | None:
    """hedera-executor, what the buyer's executor tooling is asked to authorize, as the request names it: the amount and
    the one payee's part are amount, the payee payTo, the asset asset, the network network, the validity none to
    validBefore, in seconds; the grant is the authorization the executor tooling is asked for, {executors, asset,
    payTo, amount}."""
    if request.get("kind") != "hedera-executor":
        return None
    executors, asset, pay_to, amount, valid_before = (
        request.get(k) for k in ("executors", "asset", "payTo", "amount", "validBefore")
    )
    net = _network_in("hedera", request.get("network"))
    if net is None or not isinstance(asset, str) or not isinstance(pay_to, str):
        return None
    if not isinstance(amount, str) or _DECIMAL.fullmatch(amount) is None or not _is_safe_index(valid_before):
        return None
    if not isinstance(executors, list) or not all(isinstance(e, str) for e in executors):
        return None
    return Summary(
        amount=amount,
        payees=(Payee(account=pay_to, amount=amount),),
        asset=asset,
        network=net,
        validity=Validity(not_before=None, not_after=str(valid_before), unit="seconds"),
        grant={"executors": list(executors), "asset": asset, "payTo": pay_to, "amount": amount},
        atr=b"",
    )
