"""The buyer half of the pairings mpp/charge/solana and mpp/charge/usdc/solana: read, build with complete, and bound.

The ATR hash in LCP string form is the request's externalId, which the payer signs as the one Memo instruction of the
transaction whose data parses as an LCP string. Other Memo instructions, such as split labels, are not read. Nothing
here fetches, hashes an ATR or signs.
"""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash, hash_equals
from .._types import Advertised, Json, Refusal
from ._lcp import from_lcp_string, is_list, is_object, to_lcp_string
from ._mpp import Checked, MppUnsigned, chosen_for, credential_of, echoed_for, read
from ._mpp_checks import usdc_profile
from ._svm import (
    MEMO_V3,
    MEMO_V4,
    SvmBuildInput,
    SvmTx,
    build_sol_message,
    build_svm_message,
    decode_svm_tx,
    integer_of,
    key_bytes,
    signed_wire,
    to_base64,
    wire_of,
)

SOLANA_ID = "mpp/charge/solana"
USDC_SOLANA_ID = "mpp/charge/usdc/solana"
MAX_BUNDLE = 8
_MEMO_V3_KEY = key_bytes(MEMO_V3)
_MEMO_V4_KEY = key_bytes(MEMO_V4)
_ABSENT = object()


@dataclass(frozen=True, slots=True)
class Carrier:
    h: AtrHash
    memo: str


def mpp_svm_carrier(tx: SvmTx) -> Carrier | Refusal:
    """The one top-level Memo instruction (v3 or v4) whose UTF-8 data parses as an LCP string, and its hash. Memo
    instructions whose data is not an LCP string are not read. None is svm/no-carrier; more than one svm/memo-count."""
    found: list[Carrier] = []
    for ix in tx.instructions:
        program = tx.keys[ix.program] if ix.program < len(tx.keys) else None
        if program != _MEMO_V3_KEY and program != _MEMO_V4_KEY:
            continue
        try:
            memo = ix.data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        h = from_lcp_string(memo)
        if h is not None:
            found.append(Carrier(h, memo))
    if not found:
        return Refusal("svm/no-carrier")
    if len(found) > 1:
        return Refusal("svm/memo-count")
    return found[0]


def _presented_tx(payload: Mapping[str, Any], transaction_only: bool) -> SvmTx | Refusal:
    """The signed transaction a credential presents: the one of transaction, the last of a bundle, or a fetched one.
    Under transaction_only, any type but transaction is mpp/credential-type."""
    kind = payload.get("type")
    text: Any
    if kind == "transaction":
        text = payload.get("transaction")
    elif transaction_only:
        return Refusal("mpp/credential-type")
    elif kind == "bundle":
        items = payload.get("transactions")
        if not is_list(items) or len(items) > MAX_BUNDLE:
            return Refusal("svm/tx-malformed")
        if len(items) == 0:
            return Refusal("svm/bundle-empty")
        text = items[-1]
    elif kind == "signature":
        text = payload.get("transaction", _ABSENT)
        if text is _ABSENT:
            return Refusal("svm/read-first")
    else:
        return Refusal("mpp/credential-type")
    wire = wire_of(text)
    return wire if isinstance(wire, Refusal) else decode_svm_tx(wire)


@dataclass(frozen=True, slots=True)
class MppChargeSolana:
    """A Solana charge pairing: MPP's solana method, or usdc's Solana profile, whose details are
    methodDetails.solana and whose only credential is type=transaction."""

    id: str
    details: Callable[[Checked], Mapping[str, Any]]
    transaction_only: bool
    public_proof: bool = True

    def read(self, doc: Json) -> Advertised | Refusal:
        """H, the link, and the challenges that carry them, in document order."""
        return read(doc)

    def build(self, choice: Json, h: AtrHash) -> MppUnsigned | Refusal:
        """The message for the payer to sign: the request's transfer (a token TransferChecked, or a System transfer
        for sol) with the memo the request's externalId carries, which must be this H's LCP string. Splits and
        confidential transfers are not built."""
        if not is_object(choice):
            return Refusal("svm/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, self.id)
        if isinstance(checked, Refusal):
            return checked
        r = checked.request
        d = self.details(checked)
        memo = to_lcp_string(h)
        if r.get("externalId") != memo:
            return Refusal("svm/carrier-mismatch")
        if "splits" in d or d.get("confidential") is True:
            return Refusal("svm/input-malformed")
        payer: Any = choice.get("payer")
        if key_bytes(payer) is None:
            return Refusal("svm/input-malformed")
        fee_payer: Any = d.get("feePayerKey") if d.get("feePayer") is True else payer
        blockhash: Any = d.get("recentBlockhash")
        if not isinstance(blockhash, str):
            blockhash = choice.get("recentBlockhash")
        if not isinstance(blockhash, str):
            return Refusal("svm/input-malformed")
        limit = choice.get("computeUnitLimit")
        price = choice.get("computeUnitPrice")
        limit = 40_000 if limit is None else integer_of(limit)
        price = 1 if price is None else price
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 <= limit <= 0xFFFFFFFF:
            return Refusal("svm/input-malformed")
        if not isinstance(price, int) or isinstance(price, bool) or not 0 <= price < 1 << 64:
            return Refusal("svm/input-malformed")
        amount = int(r["amount"])
        message: bytes | Refusal
        if r.get("currency") == "sol":
            message = build_sol_message(fee_payer, payer, r["recipient"], amount, blockhash, memo, limit, price)
        else:
            decimals = d["decimals"] if _is_number(d.get("decimals")) else choice.get("decimals")
            token_program = d["tokenProgram"] if isinstance(d.get("tokenProgram"), str) else choice.get("tokenProgram")
            if not _is_number(decimals) or not isinstance(token_program, str):
                return Refusal("svm/input-malformed")
            message = build_svm_message(
                SvmBuildInput(
                    fee_payer=fee_payer,
                    payer=payer,
                    mint=r["currency"],
                    token_program=token_program,
                    decimals=integer_of(decimals),
                    pay_to=r["recipient"],
                    amount=amount,
                    recent_blockhash=blockhash,
                    memo=memo,
                    compute_unit_limit=limit,
                    compute_unit_price=price,
                )
            )
        if isinstance(message, Refusal):
            return message
        signed_message = message
        challenge = choice["challenge"]

        def complete(signature: Any) -> dict[str, Any] | Refusal:
            wire = signed_wire(signed_message, payer, signature)
            if isinstance(wire, Refusal):
                return wire
            return {"challenge": challenge, "payload": {"type": "transaction", "transaction": to_base64(wire)}}

        return MppUnsigned({"kind": "solana-message", "message": signed_message}, complete)

    def bound(self, presented: Json) -> AtrHash | Refusal:
        """H from the echoed challenge, once the signed LCP memo equals the request's externalId and names that H.
        No signature is verified here."""
        credential = credential_of(presented)
        if isinstance(credential, Refusal):
            return credential
        e = echoed_for(credential, self.id)
        if isinstance(e, Refusal):
            return e
        tx = _presented_tx(e.payload, self.transaction_only)
        if isinstance(tx, Refusal):
            return tx
        carrier = mpp_svm_carrier(tx)
        if isinstance(carrier, Refusal):
            return carrier
        if carrier.memo != e.checked.request.get("externalId"):
            return Refusal("svm/carrier-mismatch")
        if not hash_equals(carrier.h, e.h):
            return Refusal("mpp/carrier-not-challenge")
        return e.h


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _usdc_details(c: Checked) -> Mapping[str, Any]:
    profile = usdc_profile(c.details)
    return {} if isinstance(profile, Refusal) else profile[1]


MPP_CHARGE_SOLANA = MppChargeSolana(SOLANA_ID, lambda c: c.details, transaction_only=False)
MPP_CHARGE_USDC_SOLANA = MppChargeSolana(USDC_SOLANA_ID, _usdc_details, transaction_only=True)
