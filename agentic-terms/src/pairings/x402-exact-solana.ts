/**
 * The buyer piece for `x402/exact/solana`: the v0 message whose one memo is the option's `extra.memo`, signed by the
 * payer as `solana-message`. The recent blockhash is the option's `extra.recentBlockhash` when it names one, else the
 * buyer's; the mint's decimals and token program are the buyer's reads.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs } from "../types.js";
import { bigintOf, inputsOf, isRefusal, refuse } from "./common.js";
import { railPiece, signature64 } from "./x402-rail.js";

const PAIRING = "x402/exact/solana";
/** A Solana address: base58 of 32 bytes. */
export const SOLANA_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

/** `computeUnitPrice` as the build's bigint, where the choice carries one. */
export function withUnitPrice(c: Record<string, unknown>): Record<string, unknown> | Refusal {
  if (c["computeUnitPrice"] === undefined) return c;
  const price = bigintOf(c["computeUnitPrice"]);
  return price === undefined ? refuse("x402/choice-malformed") : { ...c, computeUnitPrice: price };
}

function inputs(accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  const offered: unknown = accepted.extra?.["recentBlockhash"];
  const fromOffer = typeof offered === "string" && offered !== "";
  const read = inputsOf(given, PAIRING, {
    decimals: "uint",
    tokenProgram: "string",
    ...(fromOffer ? {} : { recentBlockhash: "string" as const }),
    computeUnitLimit: "optional-uint",
    computeUnitPrice: "optional-decimal",
  });
  if (isRefusal(read)) return read;
  return fromOffer ? { ...read, recentBlockhash: offered } : read;
}

export const x402ExactSolana = railPiece({
  pairing: PAIRING,
  namespace: "solana",
  address: SOLANA_ADDRESS,
  payer: "payer",
  now: false,
  inputs,
  revive: withUnitPrice,
  answer: signature64,
});
