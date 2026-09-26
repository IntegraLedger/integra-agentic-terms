/**
 * The buyer piece for `mpp/charge/usdc/solana`: the Solana charge's v0 message, whose one LCP memo is the request's
 * `externalId`, with the details read from `methodDetails.solana`; signed by the payer as `solana-message`.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { Inputs } from "../types.js";
import { inputsOf, isObject } from "./common.js";
import { completeWith, mppRailPiece, signature64 } from "./mpp-rails.js";
import { SOLANA_ADDRESS, withUnitPrice } from "./x402-exact-solana.js";

const PAIRING = "mpp/charge/usdc/solana";

function inputs(request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  const md = isObject(request["methodDetails"]) ? request["methodDetails"] : {};
  const d = isObject(md["solana"]) ? md["solana"] : {};
  return inputsOf(given, PAIRING, {
    ...(typeof d["decimals"] === "number" ? {} : { decimals: "uint" as const }),
    ...(typeof d["tokenProgram"] === "string" ? {} : { tokenProgram: "string" as const }),
    ...(typeof d["recentBlockhash"] === "string" ? {} : { recentBlockhash: "string" as const }),
    computeUnitLimit: "optional-uint",
    computeUnitPrice: "optional-decimal",
  });
}

export const mppChargeUsdcSolana = mppRailPiece({
  pairing: PAIRING,
  namespace: "solana",
  address: SOLANA_ADDRESS,
  payer: "payer",
  now: false,
  inputs,
  revive: withUnitPrice,
  complete: completeWith(signature64),
});
