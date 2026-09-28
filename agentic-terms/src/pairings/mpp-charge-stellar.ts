/**
 * The buyer piece for `mpp/charge/stellar`: the Soroban authorization preimage for the buyer's simulated `transfer` to
 * the request's muxed recipient, signed by the payer as `stellar-auth`; the credential is the build's own. The
 * simulated transaction and the current ledger are the buyer's reads.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { Inputs } from "../types.js";
import { inputsOf } from "./common.js";
import { completeWith, mppRailPiece, signature64, STELLAR_ACCOUNT } from "./mpp-rails.js";

const PAIRING = "mpp/charge/stellar";

function inputs(_request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  return inputsOf(given, PAIRING, { simulatedXdr: "string", currentLedger: "uint" });
}

export const mppChargeStellar = mppRailPiece({
  pairing: PAIRING,
  namespace: "stellar",
  address: STELLAR_ACCOUNT,
  payer: "payer",
  now: true,
  inputs,
  revive: (c) => c,
  complete: completeWith(signature64),
});
