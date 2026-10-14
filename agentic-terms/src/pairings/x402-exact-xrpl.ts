/**
 * The buyer piece for `x402/exact/xrpl`: the Payment whose `InvoiceID` is the SHA-256 of the option's
 * `extra.invoiceId`, handed to the wallet as `xrpl-tx`. The wallet's signed blob, as hex digits without `0x`, completes
 * the payment.
 * `Fee`, `Sequence` (or `TicketSequence`) and `LastLedgerSequence` are the buyer's reads.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs, Signature } from "../types.js";
import { inputsOf, refuse } from "./common.js";
import { railPiece } from "./x402-rail.js";

const PAIRING = "x402/exact/xrpl";

function inputs(accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  const ticket = accepted.extra?.["assetTransferMethod"] === "ticketSequence";
  return inputsOf(given, PAIRING, {
    fee: "decimal",
    ...(ticket ? { ticketSequence: "uint" as const } : { sequence: "uint" as const }),
    lastLedgerSequence: "uint",
  });
}

/** The signed blob as given: the build's `complete` reads it as hex digits without `0x`. */
function blob(signature: Signature): string | Refusal {
  return typeof signature === "string" ? signature : refuse("x402/signature-malformed");
}

export const x402ExactXrpl = railPiece({
  pairing: PAIRING,
  namespace: "xrpl",
  address: /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/,
  payer: "account",
  now: false,
  inputs,
  revive: (c) => c,
  answer: blob,
});
