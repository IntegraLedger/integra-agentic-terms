"""The buyer half of mpp/charge/usdc/stacks: a SIP-010 transfer whose memo argument is (some H), the ATR hash's 32
bytes, signed by the buyer's Stacks wallet. Nothing here fetches or signs."""

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Refusal
from . import _stacks
from ._lcp import is_object, normal_hash
from ._mpp import chosen_for, credential_of, echoed_for, read

ID = "mpp/charge/usdc/stacks"

MAX_STACKS_TX = 16_384
STACKS_FORMAT = "stacks_transaction_v1"
MEMO_PREFIX = bytes.fromhex("0a0200000020")
_C32_PRINCIPAL = re.compile(r"S[0-9A-HJKMNP-TV-Z]{38,40}")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _strict_base64(text: str) -> bytes | None:
    """Padded base64 whose padding bits are zero, or None."""
    if _BASE64.fullmatch(text) is None:
        return None
    try:
        data = base64.b64decode(text, validate=True)
    except binascii.Error:
        return None
    return data if base64.b64encode(data).decode("ascii") == text else None


@dataclass(frozen=True, slots=True)
class StacksUnsigned:
    """The contract call the wallet builds and signs, and how its signed bytes complete the credential."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]
    _source: str

    def complete(self, serialized: object) -> dict[str, Any] | Refusal:
        if not isinstance(serialized, bytes) or len(serialized) == 0 or len(serialized) > MAX_STACKS_TX:
            return Refusal("mpp/credential-malformed")
        payload = {
            "type": "transaction",
            "transaction": base64.b64encode(serialized).decode("ascii"),
            "transactionFormat": STACKS_FORMAT,
        }
        return {"challenge": dict(self._challenge), "source": self._source, "payload": payload}


@dataclass(frozen=True, slots=True)
class MppChargeUsdcStacks:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> StacksUnsigned | Refusal:
        """The SIP-010 transfer (amount, sender, recipient, (some H)) on the profile's token contract, one SentEq
        post-condition, post-condition mode Deny and anchor mode OnChainOnly."""
        if not is_object(choice):
            return Refusal("mpp/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        sender = choice.get("from")
        if not isinstance(sender, str) or _C32_PRINCIPAL.fullmatch(sender) is None:
            return Refusal("mpp/input-malformed")
        profile = checked.details.get(str(checked.details.get("type")))
        p: Mapping[str, Any] = profile if is_object(profile) else {}
        memo = normal_hash(h)
        assert memo is not None
        request = {
            "kind": "stacks-contract-call",
            "contract": f"{_text(p.get('contractAddress'))}.{_text(p.get('contractName'))}",
            "functionName": "transfer",
            "args": {
                "amount": _text(checked.request.get("amount")),
                "sender": sender,
                "recipient": _text(checked.request.get("recipient")),
                "memo": memo,
            },
            "postCondition": "SentEq",
            "postConditionMode": "deny",
            "anchorMode": "onChainOnly",
        }
        source = f"stacks:{_text(p.get('chainId'))}:{sender}"
        return StacksUnsigned(request=request, _challenge=choice["challenge"], _source=source)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """H from the echoed challenge, once its transaction decodes and calls transfer with (some H) as its fourth
        argument. Nothing but that argument is read, and no signature is verified here."""
        shaped = credential_of(presented)
        if isinstance(shaped, Refusal):
            return shaped
        e = echoed_for(presented, ID)
        if isinstance(e, Refusal):
            return e
        if e.payload.get("type") != "transaction":
            return Refusal("mpp/credential-type")
        if "transactionFormat" in e.payload and e.payload["transactionFormat"] != STACKS_FORMAT:
            return Refusal("mpp/stacks-tx-malformed")
        text = e.payload.get("transaction")
        if not isinstance(text, str) or len(text) > -(-MAX_STACKS_TX // 3) * 4:
            return Refusal("mpp/stacks-tx-malformed")
        wire = _strict_base64(text)
        if wire is None or len(wire) == 0 or len(wire) > MAX_STACKS_TX:
            return Refusal("mpp/stacks-tx-malformed")
        try:
            call = _stacks.contract_call(wire)
        except _stacks.Malformed:
            return Refusal("mpp/stacks-tx-malformed")
        if call is None or call.function != "transfer":
            return Refusal("mpp/stacks-memo-not-h")
        if call.fourth != MEMO_PREFIX + bytes.fromhex(e.h[2:]):
            return Refusal("mpp/stacks-memo-not-h")
        return e.h
