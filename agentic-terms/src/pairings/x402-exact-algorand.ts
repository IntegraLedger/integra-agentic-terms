/**
 * The buyer piece for `x402/exact/algorand`: the asset transfer whose note is the hash's LCP string, signed by the payer
 * as `algorand-txn`. `params` is the buyer's read of algod's transaction parameters.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { Inputs } from "../types.js";
import { bigintOf, inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { railPiece, signature64 } from "./x402-rail.js";

const PAIRING = "x402/exact/algorand";

function inputs(_accepted: PaymentRequirements, given: Inputs): Record<string, Json> | Refusal {
  const read = inputsOf(given, PAIRING, { params: "object" });
  if (isRefusal(read)) return read;
  const params = inputsOf(read["params"] as Inputs, PAIRING, {
    firstValid: "decimal",
    genesisHash: "string",
    genesisId: "string",
    minFee: "decimal",
    feePerByte: "decimal",
  });
  return isRefusal(params) ? params : { params };
}

function revive(c: Record<string, unknown>): Record<string, unknown> | Refusal {
  const p = c["params"];
  if (!isObject(p)) return refuse("x402/choice-malformed");
  const firstValid = bigintOf(p["firstValid"]);
  const minFee = bigintOf(p["minFee"]);
  const feePerByte = bigintOf(p["feePerByte"]);
  if (firstValid === undefined || minFee === undefined || feePerByte === undefined) return refuse("x402/choice-malformed");
  return { ...c, params: { ...p, firstValid, minFee, feePerByte } };
}

export const x402ExactAlgorand = railPiece({
  pairing: PAIRING,
  namespace: "algorand",
  address: /^[A-Z2-7]{58}$/,
  payer: "payer",
  now: false,
  inputs,
  revive,
  answer: signature64,
});
