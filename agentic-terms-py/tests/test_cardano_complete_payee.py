"""x402/exact/cardano's complete gives the payment only where the protocol package's reference reads it for the option
the payment accepted: the option's payTo is its payee, a non-empty string (the protocol package's x402 payee rule), so
over an option whose payTo is absent, empty or not a string, which the option filter serves, complete refuses what the
wallet signed, x402/signed-not-bound. The option, the document and the wallet's transaction are
x402-exact-cardano.json's fixed.O and V2, the transaction whose body commits to V1's auxiliary data."""

from typing import Any

import pytest

from integraledger_terms import X402_EXACT_CARDANO, Refusal

from breadth import x402_doc
from support import load

ADA = load("x402-exact-cardano.json")
F: dict[str, Any] = ADA["fixed"]
SIGNED = {"transaction": ADA["V2"]["transactionBase64"], "nonce": F["nonce"]}
_ABSENT = object()


def completed(option: dict[str, Any]) -> Any:
    required = x402_doc(option, F["resource"], link=F["link"])
    u = X402_EXACT_CARDANO.build({"required": required, "accepted": option}, F["H"])
    assert not isinstance(u, Refusal), u
    return u.complete(SIGNED)


def test_the_files_option_completes() -> None:
    assert not isinstance(completed(F["O"]), Refusal)


@pytest.mark.parametrize("pay_to", [_ABSENT, "", 5], ids=["absent", "empty", "a number"])
def test_an_option_whose_pay_to_is_no_payee_is_not_completed(pay_to: object) -> None:
    option = {k: v for k, v in F["O"].items() if k != "payTo"}
    if pay_to is not _ABSENT:
        option["payTo"] = pay_to
    assert completed(option) == Refusal("x402/signed-not-bound")
