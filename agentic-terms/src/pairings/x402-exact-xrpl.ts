/**
 * The buyer piece for `x402/exact/xrpl`: the Payment whose `InvoiceID` is the SHA-256 of the option's
 * `extra.invoiceId`, handed to the wallet as `xrpl-tx`. The wallet's signed blob, as `0x` hex, completes the payment.
 * `Fee`, `Sequence` (or `TicketSequence`) and `LastLedgerSequence` are the buyer's reads.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs, Signature } from "../types.js";
import { inputsOf, refuse } from "./common.js";
import { railPiece } from "./x402-rail.js";

const PAIRING = "x402/exact/xrpl";
const BLOB = /^0x((?:[0-9a-fA-F]{2})+)$/;

function inputs(accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  const ticket = accepted.extra?.["assetTransferMethod"] === "ticketSequence";
  return inputsOf(given, PAIRING, {
    fee: "decimal",
    ...(ticket ? { ticketSequence: "uint" as const } : { sequence: "uint" as const }),
    lastLedgerSequence: "uint",
  });
}

/** The signed blob's hex digits, from `0x` hex. */
function blob(signature: Signature): string | Refusal {
  const m = typeof signature === "string" ? BLOB.exec(signature) : null;
  return m === null ? refuse("x402/signature-malformed") : m[1]!;
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
