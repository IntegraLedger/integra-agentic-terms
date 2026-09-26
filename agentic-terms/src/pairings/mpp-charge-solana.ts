/**
 * The buyer piece for `mpp/charge/solana`: the v0 message whose one LCP memo is the request's `externalId`, signed by
 * the payer as `solana-message`; the credential is the build's own. The request's `decimals`, `tokenProgram` and
 * `recentBlockhash` are taken first, and the buyer's reads fill what the request leaves out.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { Inputs } from "../types.js";
import { inputsOf, isObject } from "./common.js";
import { completeWith, mppRailPiece, signature64 } from "./mpp-rails.js";
import { SOLANA_ADDRESS, withUnitPrice } from "./x402-exact-solana.js";

const PAIRING = "mpp/charge/solana";

function inputs(request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal {
  const d = isObject(request["methodDetails"]) ? request["methodDetails"] : {};
  const native = request["currency"] === "sol";
  return inputsOf(given, PAIRING, {
    ...(native || typeof d["decimals"] === "number" ? {} : { decimals: "uint" as const }),
    ...(native || typeof d["tokenProgram"] === "string" ? {} : { tokenProgram: "string" as const }),
    ...(typeof d["recentBlockhash"] === "string" ? {} : { recentBlockhash: "string" as const }),
    computeUnitLimit: "optional-uint",
    computeUnitPrice: "optional-decimal",
  });
}

export const mppChargeSolana = mppRailPiece({
  pairing: PAIRING,
  namespace: "solana",
  address: SOLANA_ADDRESS,
  payer: "payer",
  now: false,
  inputs,
  revive: withUnitPrice,
  complete: completeWith(signature64),
});
