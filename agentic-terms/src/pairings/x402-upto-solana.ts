/**
 * The buyer piece for `x402/upto/solana`: the `open` message of a one-request payment channel whose one memo is the
 * option's `extra.memo`, signed by the payer as `solana-message`. The channel's `nonce` is the buyer's when given, else
 * a random u64; the open slot, recent blockhash and the mint's token program are the buyer's reads.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs } from "../types.js";
import { bigintOf, inputsOf, isRefusal, refuse } from "./common.js";
import { SOLANA_ADDRESS, withUnitPrice } from "./x402-exact-solana.js";
import { railPiece, signature64 } from "./x402-rail.js";

const PAIRING = "x402/upto/solana";
const U64_LIMIT = 1n << 64n;

/** A u64 from the platform's CSPRNG, in decimal. */
function randomU64(): string {
  return crypto.getRandomValues(new BigUint64Array(1))[0]!.toString();
}

function inputs(_accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  const read = inputsOf(given, PAIRING, {
    nonce: "optional-decimal",
    openSlot: "decimal",
    tokenProgram: "string",
    recentBlockhash: "string",
    computeUnitLimit: "optional-uint",
    computeUnitPrice: "optional-decimal",
  });
  if (isRefusal(read)) return read;
  const nonce = read["nonce"] ?? randomU64();
  if (bigintOf(nonce)! >= U64_LIMIT || bigintOf(read["openSlot"])! >= U64_LIMIT) return refuse("x402/input-missing");
  return { ...read, nonce };
}

function revive(c: Record<string, unknown>): Record<string, unknown> | Refusal {
  const nonce = bigintOf(c["nonce"]);
  const openSlot = bigintOf(c["openSlot"]);
  if (nonce === undefined || openSlot === undefined) return refuse("x402/choice-malformed");
  return withUnitPrice({ ...c, nonce, openSlot });
}

export const x402UptoSolana = railPiece({
  pairing: PAIRING,
  namespace: "solana",
  address: SOLANA_ADDRESS,
  payer: "payer",
  now: true,
  inputs,
  revive,
  answer: signature64,
});
