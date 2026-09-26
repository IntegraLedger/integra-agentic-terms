/**
 * The buyer piece for `x402/exact/stellar`: the Soroban authorization preimage for the buyer's simulated `transfer`,
 * signed by the payer as `stellar-auth`, and the payment whose `payload.transaction` is the signed transaction's XDR.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs } from "../types.js";
import { inputsOf } from "./common.js";
import { railPiece, signature64 } from "./x402-rail.js";

const PAIRING = "x402/exact/stellar";

function inputs(_accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  return inputsOf(given, PAIRING, { simulatedXdr: "string", currentLedger: "uint" });
}

export const x402ExactStellar = railPiece({
  pairing: PAIRING,
  namespace: "stellar",
  address: /^G[A-Z2-7]{55}$/,
  payer: null,
  now: false,
  inputs,
  revive: (c) => c,
  answer: signature64,
  payload: (transaction) => ({ transaction }),
});
