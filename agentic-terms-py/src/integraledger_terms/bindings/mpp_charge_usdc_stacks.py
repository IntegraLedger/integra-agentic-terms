"""The buyer half of mpp/charge/usdc/stacks: a SIP-010 transfer whose memo argument is (some H), the ATR hash's 32
bytes, signed by the buyer's Stacks wallet. Nothing here fetches or signs."""

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._core import AtrHash
from .._types import Advertised, Broadcaster, Refusal
from . import _stacks
from ._codec import b64_decode
from ._lcp import is_object, normal_hash
from ._mpp import by_type, chosen_for, credential_of, echoed_for, measured, mpp_broadcaster, read

ID = "mpp/charge/usdc/stacks"

# The size bound of a usdc Stacks transaction, which bound and the build's complete share: 1 to 16,384 bytes, else
# mpp/stacks-tx-malformed.
MAX_STACKS_TX = 16_384
# Stacks mainnet's chain id, CHAIN_ID_MAINNET (stacks-core 4.0.5, stacks-common/src/libcommon.rs:58).
STACKS_MAINNET_CHAIN = 1
STACKS_FORMAT = "stacks_transaction_v1"
MEMO_PREFIX = bytes.fromhex("0a0200000020")
_C32_PRINCIPAL = re.compile(r"S[0-9A-HJKMNP-TV-Z]{38,40}")


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _profile(details: Mapping[str, Any]) -> Mapping[str, Any]:
    """The challenge's profile: methodDetails' member that its type names."""
    profile = details.get(str(details.get("type")))
    return profile if is_object(profile) else {}


def _chain_id(profile: Mapping[str, Any]) -> int:
    """The profile's chainId as a number: the pairing's filter has read it as decimal digits, 0 to 4294967295."""
    return int(_text(profile.get("chainId")) or "0")


def _on_network(tx: _stacks.Transaction, chain_id: int) -> bool:
    """True when a node of the challenge's network takes the transaction: its chain id is the challenge's chainId, and
    its version is that network's, 0x00 on mainnet and 0x80 on any other. stacks-core 4.0.5 refuses a transaction of
    another chain id, then one of version 0x00 on a node that is not mainnet's and one of version 0x80 on mainnet's
    (stackslib/src/chainstate/stacks/db/transactions/processing/validation.rs:49-79), and a mainnet node's chain id is
    CHAIN_ID_MAINNET, 1, and no other (stackslib/src/config/mod.rs:1844-1857). Under the CAIP-2 convention stacks:1 is
    Stacks mainnet, so a challenge's chainId 1 is read as mainnet, version 0x00."""
    return tx.chain_id == chain_id and tx.version == (0x00 if chain_id == STACKS_MAINNET_CHAIN else 0x80)


@dataclass(frozen=True, slots=True)
class StacksUnsigned:
    """The contract call the wallet builds and signs, and how its signed bytes complete the credential."""

    request: dict[str, Any]
    _challenge: Mapping[str, Any]
    _source: str
    _chain_id: int

    def complete(self, serialized: object) -> dict[str, Any] | Refusal:
        """The credential of the signed transaction's bytes, read in bound's order: a value that is not bytes is
        mpp/credential-malformed; then the credential measured (measured), as bound measures it before it reads the
        payment; then bytes that are empty, over 16,384 bytes or that a Stacks node does not decode are
        mpp/stacks-tx-malformed; and a transaction a node of the challenge's network does not take (_on_network) is
        stacks/chain-mismatch."""
        if not isinstance(serialized, bytes):
            return Refusal("mpp/credential-malformed")
        payload = {
            "type": "transaction",
            "transaction": base64.b64encode(serialized).decode("ascii"),
            "transactionFormat": STACKS_FORMAT,
        }
        credential = measured({"challenge": dict(self._challenge), "source": self._source, "payload": payload})
        if isinstance(credential, Refusal):
            return credential
        if len(serialized) == 0 or len(serialized) > MAX_STACKS_TX:
            return Refusal("mpp/stacks-tx-malformed")
        try:
            tx = _stacks.transaction(serialized)
        except _stacks.Malformed:
            return Refusal("mpp/stacks-tx-malformed")
        if not _on_network(tx, self._chain_id):
            return Refusal("stacks/chain-mismatch")
        return credential


@dataclass(frozen=True, slots=True)
class MppChargeUsdcStacks:
    id: str = ID
    public_proof: bool = True

    def read(self, doc: Any) -> Advertised | Refusal:
        return read(doc)

    def build(self, choice: Any, h: AtrHash) -> StacksUnsigned | Refusal:
        """The SIP-010 transfer (amount, sender, recipient, (some H)) on the profile's token contract, one SentEq
        post-condition, post-condition mode Deny and anchor mode OnChainOnly, for the profile's chainId."""
        if not is_object(choice):
            return Refusal("mpp/input-malformed")
        checked = chosen_for(choice.get("challenge"), h, ID)
        if isinstance(checked, Refusal):
            return checked
        sender = choice.get("from")
        if not isinstance(sender, str) or _C32_PRINCIPAL.fullmatch(sender) is None:
            return Refusal("mpp/input-malformed")
        p = _profile(checked.details)
        chain_id = _chain_id(p)
        memo = normal_hash(h)
        assert memo is not None
        request = {
            "kind": "stacks-contract-call",
            "chainId": chain_id,
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
        return StacksUnsigned(request=request, _challenge=choice["challenge"], _source=source, _chain_id=chain_id)

    def bound(self, presented: Any) -> AtrHash | Refusal:
        """H from the echoed challenge, once its transaction is one a Stacks node decodes and serializes back to the
        same bytes (stacks-core 4.0.5), with no Clarity value nested more than 16 levels and a principal as any
        recipient, one a node of the challenge's network takes (_on_network, else stacks/chain-mismatch), and calls
        transfer with (some H) as its fourth argument. Nothing but that argument is read for H, and
        no signature is verified here."""
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
        wire = b64_decode(text)
        if wire is None or len(wire) == 0 or len(wire) > MAX_STACKS_TX:
            return Refusal("mpp/stacks-tx-malformed")
        try:
            tx = _stacks.transaction(wire)
        except _stacks.Malformed:
            return Refusal("mpp/stacks-tx-malformed")
        if not _on_network(tx, _chain_id(_profile(e.checked.details))):
            return Refusal("stacks/chain-mismatch")
        call = tx.call
        if call is None or call.function != "transfer" or len(call.args) < 4:
            return Refusal("mpp/stacks-memo-not-h")
        if call.args[3] != MEMO_PREFIX + bytes.fromhex(e.h[2:]):
            return Refusal("mpp/stacks-memo-not-h")
        return e.h

    def broadcaster(self, presented: Any) -> Broadcaster | Refusal:
        """The payee broadcasts a credential of type transaction: the seller's server sponsors and broadcasts the Stacks
        transaction the payer signed. A credential of any other type gets mpp/credential-type, as bound refuses it."""
        return mpp_broadcaster(presented, by_type({"transaction": "payee"}))
