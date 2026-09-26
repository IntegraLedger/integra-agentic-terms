"""The buyer pieces for MPP's channel pairings. A session is signed in two steps: the funding (a token authorization,
an open call the signer broadcasts, or a signed Tempo transaction), then the first voucher, whose channel id depends on
the funding. A subscription is one step: the root key signs the key authorization's digest."""

import re
from collections.abc import Mapping
from typing import Any

from .._types import Advertised, Chosen, Inputs, Json, Refusal, Signature, Step
from ..bindings.mpp_session import SESSION_EVM, SESSION_TEMPO, SUBSCRIPTION
from ._mpp import MppChargePiece, mpp_choose

_EVM_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
_CREDENTIAL_TYPE = re.compile(r"authorization|permit2|hash")
_OPTIONAL: Mapping[str, re.Pattern[str] | None] = {
    "authorizedSigner": _EVM_ADDRESS,
    "credentialType": _CREDENTIAL_TYPE,
    "tokenDomain": None,
}


def optional_inputs(inputs: Inputs, ns: str, spec: Mapping[str, re.Pattern[str] | None]) -> dict[str, Any] | Refusal:
    """The optional inputs present, each matching its pattern (None: an object), or the refusal naming the first
    malformed one."""
    out: dict[str, Any] = {}
    for key, kind in spec.items():
        if key not in inputs:
            continue
        value = inputs[key]
        ok = isinstance(value, Mapping) if kind is None else isinstance(value, str) and kind.fullmatch(value) is not None
        if not ok:
            return Refusal(f"{ns}/input-missing")
        out[key] = value
    return out


class MppSessionPiece(MppChargePiece):
    """The first challenge offering the pairing on the account's chain, with deposit and the optional
    authorizedSigner, credentialType and tokenDomain inputs; the funding request, then the voucher."""

    def __init__(self, pairing: str) -> None:
        super().__init__(pairing, {"deposit": "decimal"})
        self._session_choose = mpp_choose(pairing, {"deposit": "decimal"})

    def choose(self, read: Advertised, account: str, inputs: Inputs, now: int, ref: str, doc: Json) -> Chosen | Refusal:
        chosen = self._session_choose(read, account, inputs, now, ref, doc)
        if isinstance(chosen, Refusal):
            return chosen
        given = optional_inputs(inputs, "mpp", _OPTIONAL)
        if isinstance(given, Refusal):
            return given
        return Chosen(pairing=chosen.pairing, choice={**chosen.choice, **given}, ref=chosen.ref)

    def request(self, unsigned: Any) -> dict[str, Any] | Refusal:
        """The funding request, exactly as built."""
        return dict(unsigned.funding)

    def complete(self, unsigned: Any, signature: Signature, chosen: Chosen) -> dict[str, Any] | Step | Refusal:
        """With the funding answer alone, the next request: the voucher over the channel the funding opens. With the
        list [funded, voucherSignature], the credential."""
        if isinstance(signature, str):
            voucher = unsigned.voucher(signature)
            if isinstance(voucher, Refusal):
                return voucher
            return Step(next={"kind": "eip712", "typedData": voucher})
        if not isinstance(signature, list) or len(signature) != 2:
            return Refusal("mpp/credential-malformed")
        funded, voucher_signature = signature
        if not isinstance(funded, str) or not isinstance(voucher_signature, str):
            return Refusal("mpp/credential-malformed")
        out: dict[str, Any] | Refusal = unsigned.complete(funded, voucher_signature)
        return out


SESSION_EVM_PIECE = MppSessionPiece(SESSION_EVM)
SESSION_TEMPO_PIECE = MppSessionPiece(SESSION_TEMPO)
SUBSCRIPTION_PIECE = MppChargePiece(SUBSCRIPTION, {})
