/**
 * The buyer piece for `x402/exact/stellar/precondition`, the agreement on Stellar, never a charge: the buyer's
 * simulated `transfer(buyer, payTo, amount)` with the authorization entry's expiration set and one signed-payload
 * precondition of H and the entry's nonce, handed to the signer as `stellar-precondition`, its `preimage` (whose
 * SHA-256 the buyer's key signs) and its 40-byte `payload` (which the key signs raw). The signer answers
 * `{entry, payload}`, each a 64-byte Ed25519 signature as `0x` hex; the payment's `payload.transaction` is the envelope
 * with both written. `simulatedXdr` and `currentLedger` are the buyer's reads.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs, Signature } from "../types.js";
import { bytesOf, inputsOf, isObject, refuse } from "./common.js";
import { railPiece } from "./x402-rail.js";

const PAIRING = "x402/exact/stellar/precondition";

function inputs(_accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  return inputsOf(given, PAIRING, { simulatedXdr: "string", currentLedger: "uint" });
}

/** `{entry, payload}`, each a 64-byte signature as `0x` hex, as the bytes the build's `complete` takes. */
function answer(signature: Signature): { entry: Uint8Array; payload: Uint8Array } | Refusal {
  if (!isObject(signature)) return refuse("x402/signature-malformed");
  const entry = bytesOf(signature["entry"], 64);
  const payload = bytesOf(signature["payload"], 64);
  return entry === undefined || payload === undefined ? refuse("x402/signature-malformed") : { entry, payload };
}

export const x402ExactStellarPrecondition = railPiece({
  pairing: PAIRING,
  namespace: "stellar",
  address: /^G[A-Z2-7]{55}$/,
  payer: "payer",
  now: false,
  inputs,
  revive: (c) => c,
  answer,
});
