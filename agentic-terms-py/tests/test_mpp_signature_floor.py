"""The signature an MPP completion takes: 1 to 8192 bytes as 0x hex, as the protocol package's complete takes it (each
EIP-712 signature, the session's voucher signature, the subscription's root signature and an in-channel voucher). The
signer's answer is replaced by a signature of the given length; the rest of each payment is the vector file's."""

import copy
from collections.abc import Callable
from typing import Any

import pytest

from integraledger_terms import MPP_SESSION_EVM, Confirmed, Declined, Finished, Next, Refusal, _gate, confirm, finish
from integraledger_terms.bindings._channel import BatchUnsigned

from breadth import ABC, H, Pairing, offered, run
from support import load, serving
from test_mpp_evm import AUTHORIZATION, PERMIT2
from test_mpp_session import AUTHORIZATION_INPUTS, EF, SUB_P, EvmAnswer, TempoAnswer, evm_pairing, tempo_pairing
from test_mpp_usdc import EVM_P

SIGNED = ("eip712", "tempo-key-authorization")
EVM_NOW: int = load("mpp-charge-evm-authorization.json")["fixed"]["now"]
SESSION_NOW: int = EF["now"]


def signature_of(size: int) -> str:
    return "0x" + "01" * size


def answering(p: Pairing, size: int) -> Callable[[Any], Any]:
    """p's answers, with every signature the payer makes replaced by one of size bytes."""

    def answer(request: Any) -> Any:
        return signature_of(size) if request["kind"] in SIGNED else p.answer(request)

    return answer


def finished(p: Pairing, size: int) -> Finished | Declined:
    """confirm over abc, then finish with each answer until the payment is complete or declined."""
    confirmed = run(lambda c: confirm(p.doc, offered(p.binding), p.account, c, p.inputs), serving(ABC))
    assert isinstance(confirmed, Confirmed), confirmed
    answer = answering(p, size)
    chosen = copy.deepcopy(confirmed.chosen)
    answers = [answer(confirmed.request)]
    done = finish(ABC, chosen, answers[0], p.binding)
    while isinstance(done, Next):
        answers.append(answer(done.next))
        done = finish(ABC, chosen, list(answers), p.binding)
    assert isinstance(done, (Finished, Declined)), done
    return done


def carries(signed: dict[str, Any], size: int) -> bool:
    """The payload carries the signature of size bytes: as each member named signature or voucherSignature, or, for a
    key authorization, at the end of the signed authorization's encoding."""
    p = signed["payload"]
    if p.get("type") == "keyAuthorization":
        return isinstance(p["signature"], str) and p["signature"].endswith(signature_of(size)[2:])
    found = [p[k] for k in ("signature", "voucherSignature") if k in p]
    return bool(found) and set(found) == {signature_of(size)}


# The largest signature each payment binds: 8192 bytes, except the subscription's root signature, which the signed key
# authorization carries and whose read bounds the authorization (the protocol package's bound gives
# tempo/key-authorization-malformed for an 8192-byte root signature, and H for 65 bytes).
CASES: list[tuple[str, Callable[[], Pairing], int, int]] = [
    ("mpp/charge/evm/authorization", lambda: AUTHORIZATION, EVM_NOW, 8192),
    ("mpp/charge/evm/permit2", lambda: PERMIT2, EVM_NOW, 8192),
    ("mpp/charge/usdc/evm", lambda: EVM_P, EVM_NOW, 8192),
    (
        "mpp/session/evm, hash",
        lambda: evm_pairing({"deposit": EF["deposit"], "credentialType": "hash"}, EvmAnswer()),
        SESSION_NOW,
        8192,
    ),
    ("mpp/session/evm, authorization", lambda: evm_pairing(AUTHORIZATION_INPUTS, EvmAnswer()), SESSION_NOW, 8192),
    ("mpp/session/tempo", lambda: tempo_pairing(TempoAnswer()), SESSION_NOW, 8192),
    ("mpp/subscription/tempo", lambda: SUB_P, SESSION_NOW, 65),
]


@pytest.mark.parametrize(("name", "pairing", "now", "largest"), CASES, ids=[c[0] for c in CASES])
def test_a_completion_takes_a_signature_of_1_to_8192_bytes(
    name: str, pairing: Callable[[], Pairing], now: int, largest: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_gate, "_now", lambda: now)
    for size in (1, largest):
        done = finished(pairing(), size)
        assert isinstance(done, Finished) and done.h == H, (size, done)
        assert carries(done.signed, size), size
    for size in (0, 8193):
        declined = finished(pairing(), size)
        assert isinstance(declined, Declined), (size, declined)


def test_an_in_channel_voucher_takes_a_signature_of_1_to_8192_bytes() -> None:
    opening = next(r for r in load("mpp-session-evm.json")["buyer"]["rows"] if r["name"] == "B6")["input"]["presented"]
    w = {"challenge": opening["challenge"], "opening": opening, "cumulativeAmount": 0, "action": "voucher"}
    unsigned = MPP_SESSION_EVM.build_within(w, H)  # type: ignore[attr-defined]
    assert isinstance(unsigned, BatchUnsigned), unsigned
    for size in (1, 8192):
        out = unsigned.complete([signature_of(size)])
        assert isinstance(out, dict) and out["payload"]["signature"] == signature_of(size)
    for size in (0, 8193):
        assert unsigned.complete([signature_of(size)]) == Refusal("mpp/credential-malformed")
