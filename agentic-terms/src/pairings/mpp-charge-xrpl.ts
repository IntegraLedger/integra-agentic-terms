/**
 * The buyer piece for `mpp/charge/xrpl`: the Payment whose `InvoiceID` is the request's `methodDetails.invoiceId`,
 * handed to the wallet as `xrpl-tx`. The wallet's signed blob, as `0x` hex, completes the build's own credential.
 * `Fee`, `Sequence` and `LastLedgerSequence` are the buyer's reads.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { Inputs, Signature } from "../types.js";
import { inputsOf, refuse } from "./common.js";
import { completeWith, hexDigits, mppRailPiece, XRPL_ADDRESS } from "./mpp-rails.js";

const PAIRING = "mpp/charge/xrpl";

function inputs(_request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  return inputsOf(given, PAIRING, { fee: "decimal", sequence: "uint", lastLedgerSequence: "uint" });
}

/** The signed blob's hex digits, from `0x` hex. */
function blob(signature: Signature): string | Refusal {
  return hexDigits(signature) ?? refuse("mpp/credential-malformed");
}

export const mppChargeXrpl = mppRailPiece({
  pairing: PAIRING,
  namespace: "xrpl",
  address: XRPL_ADDRESS,
  payer: "account",
  now: false,
  inputs,
  revive: (c) => c,
  complete: completeWith(blob),
});
