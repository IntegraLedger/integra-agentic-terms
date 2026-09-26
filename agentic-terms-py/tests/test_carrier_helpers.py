"""The carrier helpers answer x402/payload-malformed for a value that is not a 32-byte hash, the code each pairing's
build gives for the same input. Expected values are the lcp tests' for auxiliaryData, ftTransferArgs, snNonce and
lcpComment."""

from typing import Any

from integraledger_terms import Refusal
from integraledger_terms.bindings.x402_exact_cardano import auxiliary_data
from integraledger_terms.bindings.x402_exact_near import ft_transfer_args
from integraledger_terms.bindings.x402_exact_starknet import sn_nonce
from integraledger_terms.bindings.x402_exact_tvm import lcp_comment

H = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
BAD: list[Any] = ["0x12", H[2:]]


def test_carrier_helpers_refuse_a_value_that_is_not_a_hash() -> None:
    for bad in BAD:
        assert auxiliary_data(bad) == Refusal("x402/payload-malformed"), bad
        assert ft_transfer_args("payee.near", "1", bad) == Refusal("x402/payload-malformed"), bad
        assert sn_nonce(bad) == Refusal("x402/payload-malformed"), bad
        assert lcp_comment(bad) == Refusal("x402/payload-malformed"), bad
