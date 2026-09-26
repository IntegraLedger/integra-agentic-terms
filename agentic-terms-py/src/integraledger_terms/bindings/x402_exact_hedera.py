"""The buyer halves of x402/exact/hedera (the ATR hash as the LCP string in the signed body's memo) and
x402/exact/hedera/transfer-executor (the hash advertised in the challenge only): read, build with complete, and bound.
Nothing here fetches, hashes or signs."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Json, Refusal
from ._hedera_proto import (
    INT64_LIMIT,
    UINT64_LIMIT,
    account_amount,
    complete_with,
    decode_hedera_tx,
    entity,
    from_base64,
    len_field,
    tx_id_field,
    v_field,
    write_body,
)
from ._lcp import from_lcp_string, from_legal_context, is_object, normal_hash, safe_int, to_lcp_string
from ._x402 import chosen, payment_with, presented_with, read_for

EXACT = "x402/exact/hedera"
EXECUTOR = "x402/exact/hedera/transfer-executor"

HEDERA_NETWORKS = ("hedera:mainnet", "hedera:testnet", "hedera:previewnet", "hedera:devnet")
MAX_EXECUTORS = 16
MAX_AUTHORIZATION_HEX = 8192

_ENTITY = re.compile(r"(0|[1-9][0-9]{0,18})\.(0|[1-9][0-9]{0,18})\.(0|[1-9][0-9]{0,18})")
_DECIMAL = re.compile(r"0|[1-9][0-9]{0,18}")
_HEX_BYTES = re.compile(r"0x(?:[0-9a-fA-F]{2})*")


def is_entity(value: object) -> bool:
    return isinstance(value, str) and _ENTITY.fullmatch(value) is not None


def is_hedera_network(value: object) -> bool:
    return isinstance(value, str) and value in HEDERA_NETWORKS


def amount_of(value: object) -> int | None:
    """A positive decimal below 2^63, or None."""
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        return None
    v = int(value)
    return v if 0 < v < INT64_LIMIT else None


def _big(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _whole(value: object) -> int | None:
    """An integer given as an int or an integral float, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _method_of(o: Mapping[str, Any]) -> object:
    extra = o.get("extra")
    return extra.get("assetTransferMethod") if is_object(extra) else None


def _on_hedera(o: object) -> bool:
    """exact on a hedera: network."""
    if not is_object(o) or o.get("scheme") != "exact":
        return False
    network = o.get("network")
    return isinstance(network, str) and network.startswith("hedera:")


def _servable(o: Mapping[str, Any]) -> bool:
    """Everything but the transfer method: network, asset, payee, amount and timeout."""
    timeout = safe_int(o.get("maxTimeoutSeconds"))
    return (
        is_hedera_network(o.get("network"))
        and ("extra" not in o or is_object(o.get("extra")))
        and is_entity(o.get("asset"))
        and is_entity(o.get("payTo"))
        and amount_of(o.get("amount")) is not None
        and timeout is not None
        and timeout > 0
    )


def check_exact(o: Mapping[str, Any]) -> bool | Refusal | None:
    """True for a cryptoTransfer option (or no method) this pairing serves; None for another pairing's option."""
    if not _on_hedera(o):
        return None
    method = _method_of(o)
    if method == "transferExecutor":
        return None
    if method is not None and method != "cryptoTransfer":
        return Refusal("hedera/option-malformed")
    extra = o.get("extra")
    if not _servable(o) or not is_entity(extra.get("feePayer") if is_object(extra) else None):
        return Refusal("hedera/option-malformed")
    return True


def executors_of(o: Mapping[str, Any]) -> list[str] | None:
    extra = o.get("extra")
    listed = extra.get("executors") if is_object(extra) else None
    if not isinstance(listed, list) or not 0 < len(listed) <= MAX_EXECUTORS or not all(is_entity(e) for e in listed):
        return None
    return list(listed)


def check_executor(o: Mapping[str, Any]) -> bool | Refusal | None:
    """True for a transferExecutor option with a non-empty list of executors; None for another pairing's option."""
    if not _on_hedera(o):
        return None
    method = _method_of(o)
    if method != "transferExecutor":
        return None if method is None or method == "cryptoTransfer" else Refusal("hedera/option-malformed")
    return True if _servable(o) and executors_of(o) is not None else Refusal("hedera/option-malformed")


# ── x402/exact/hedera ─────────────────────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class HederaUnsigned:
    """The body the payer signs, and how its signature completes the wire transaction."""

    request: dict[str, Any]

    def complete(self, s: object) -> str | Refusal:
        """The signed Transaction, base64, from {publicKey, signature, type} with the key and signature as bytes."""
        body = self.request["bodyBytes"]
        assert isinstance(body, bytes)
        return complete_with(body, s)


def _valid_build_inputs(c: Mapping[str, Any]) -> bool:
    vs = c.get("validStart")
    if not is_entity(c.get("payer")) or not is_entity(c.get("node")) or not is_object(vs):
        return False
    seconds, nanos, max_fee = vs.get("seconds"), _whole(vs.get("nanos")), c.get("maxFee")
    if not isinstance(seconds, int) or not _big(seconds) or not 0 <= seconds < INT64_LIMIT:
        return False
    if nanos is None or not 0 <= nanos <= 999_999_999:
        return False
    if not isinstance(max_fee, int) or not _big(max_fee) or not 0 <= max_fee < UINT64_LIMIT:
        return False
    if "decimals" in c:
        decimals = _whole(c.get("decimals"))
        if decimals is None or not 0 <= decimals <= 0xFFFFFFFF:
            return False
    return True


@dataclass(frozen=True, slots=True)
class X402ExactHedera:
    id: str = EXACT
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the options this pairing pays, in document order."""
        return read_for(check_exact)(doc)

    def build(self, c: Json, h: AtrHash) -> HederaUnsigned | Refusal:
        """The TransactionBody the payer signs: the fee payer's transaction id, the hash's LCP string as the memo, and
        the payer's debit and the payee's credit of the option's amount, in HBAR or the option's token."""
        if not is_object(c):
            return Refusal("hedera/option-malformed")
        ok = chosen(c.get("required"), c.get("accepted"), check_exact)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        if not _valid_build_inputs(c):
            return Refusal("hedera/option-malformed")
        nh = normal_hash(h)
        if nh is None:
            return Refusal("x402/payload-malformed")
        a = c["accepted"]
        payer, pay_to, asset = c["payer"], a["payTo"], a["asset"]
        amount = amount_of(a["amount"])
        assert amount is not None
        if asset == "0.0.0":
            rows = len_field(1, account_amount(payer, -amount)) + len_field(1, account_amount(pay_to, amount))
            transfer = len_field(1, rows)
        else:
            decimals = _whole(c.get("decimals")) if "decimals" in c else None
            token_list = (
                len_field(1, entity(asset))
                + len_field(2, account_amount(payer, -amount))
                + len_field(2, account_amount(pay_to, amount))
                + (b"" if decimals is None else len_field(4, v_field(1, decimals)))
            )
            transfer = len_field(2, token_list)
        vs = c["validStart"]
        tx_id = tx_id_field(vs["seconds"], _whole(vs["nanos"]) or 0, a["extra"]["feePayer"])
        body = write_body(tx_id, c["node"], c["maxFee"], to_lcp_string(nh), transfer)
        return HederaUnsigned(request={"kind": "hedera-body", "bodyBytes": body})

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash inside what the payer signed: the body memo, in LCP string form. Transfers, amounts, the fee payer
        and the payer are not read, and no signature is verified here."""
        p = presented_with(presented, check_exact)
        if isinstance(p, Refusal):
            return p
        wire = from_base64(p[1].get("transaction"))
        if wire is None:
            return Refusal("hedera/tx-malformed")
        decoded = decode_hedera_tx(wire)
        if isinstance(decoded, Refusal):
            return decoded
        memo = decoded[0].memo
        if memo == "":
            return Refusal("hedera/no-memo")
        h = from_lcp_string(memo)
        return h if h is not None else Refusal("hedera/memo-not-lcp")


# ── x402/exact/hedera/transfer-executor ─────────────────────────────────────────────────────────────────────────────


def _executor_payload(payload: object) -> dict[str, str] | Refusal:
    if not is_object(payload):
        return Refusal("hedera/executor-malformed")
    payer, executor, authorization = payload.get("payer"), payload.get("executor"), payload.get("authorization")
    if (
        not is_entity(payer)
        or not is_entity(executor)
        or not isinstance(authorization, str)
        or len(authorization) > MAX_AUTHORIZATION_HEX + 2
        or _HEX_BYTES.fullmatch(authorization) is None
    ):
        return Refusal("hedera/executor-malformed")
    assert isinstance(payer, str) and isinstance(executor, str)
    return {"payer": payer, "executor": executor, "authorization": authorization}


@dataclass(frozen=True, slots=True)
class ExecutorUnsigned:
    """What the buyer's wallet or executor tooling needs to obtain an authorization, and how that authorization
    completes the payment. Nothing here carries the hash."""

    request: dict[str, Any]
    _required: Mapping[str, Any]
    _accepted: Mapping[str, Any]

    def complete(self, a: object) -> dict[str, Any] | Refusal:
        """The payment {x402Version, resource, accepted, payload: {payer, executor, authorization}, extensions}."""
        payload = _executor_payload(a)
        if isinstance(payload, Refusal):
            return payload
        executors: Sequence[str] = self.request["executors"]
        if payload["executor"] not in executors:
            return Refusal("hedera/executor-not-offered")
        return payment_with(self._required, self._accepted, payload)


@dataclass(frozen=True, slots=True)
class X402ExactHederaExecutor:
    id: str = EXECUTOR
    public_proof: bool = False

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, the agreement URL when named, and the options this pairing pays, in document order."""
        return read_for(check_executor)(doc)

    def build(self, c: Json, h: AtrHash) -> ExecutorUnsigned | Refusal:
        """The request {kind hedera-executor, network, executors, asset, payTo, amount, validBefore}, validBefore being
        now plus the option's maxTimeoutSeconds."""
        if not is_object(c):
            return Refusal("hedera/option-malformed")
        required, accepted = c.get("required"), c.get("accepted")
        ok = chosen(required, accepted, check_executor)
        if ok is not True:
            return ok if isinstance(ok, Refusal) else Refusal("x402/option-not-this-pairing")
        now = safe_int(c.get("now"))
        if now is None or now < 0:
            return Refusal("hedera/option-malformed")
        if normal_hash(h) is None:
            return Refusal("x402/payload-malformed")
        assert is_object(required) and is_object(accepted)
        executors = executors_of(accepted)
        timeout = safe_int(accepted.get("maxTimeoutSeconds"))
        assert executors is not None and timeout is not None
        request = {
            "kind": "hedera-executor",
            "network": accepted["network"],
            "executors": executors,
            "asset": accepted["asset"],
            "payTo": accepted["payTo"],
            "amount": accepted["amount"],
            "validBefore": now + timeout,
        }
        return ExecutorUnsigned(request=request, _required=required, _accepted=accepted)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """The hash from the echoed, unsigned extensions.legalContext. Nothing the payer signed carries it."""
        p = presented_with(presented, check_executor)
        if isinstance(p, Refusal):
            return p
        payload = _executor_payload(p[1])
        if isinstance(payload, Refusal):
            return payload
        extensions = p[2]
        lc = extensions.get("legalContext") if is_object(extensions) else None
        decoded = from_legal_context({"legalContext": lc.get("info")}) if is_object(lc) else None
        return Refusal("hedera/no-legal-context") if decoded is None else decoded[0]
