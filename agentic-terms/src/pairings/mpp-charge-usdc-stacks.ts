/**
 * The buyer piece for `mpp/charge/usdc/stacks`: the SIP-010 `transfer` whose memo argument is `(some H)`, handed to the
 * buyer's Stacks wallet as `stacks-contract-call`; the wallet answers the signed transaction's consensus bytes as `0x`
 * hex.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { Signature } from "../types.js";
import { bytesOf, refuse } from "./common.js";
import { completeWith, mppRailPiece } from "./mpp-rails.js";

const PAIRING = "mpp/charge/usdc/stacks";
const C32_PRINCIPAL = /^S[0-9A-HJKMNP-TV-Z]{38,40}$/;

function transactionBytes(signature: Signature): Uint8Array | Refusal {
  return bytesOf(signature) ?? refuse("mpp/credential-malformed");
}

export const mppChargeUsdcStacks = mppRailPiece({
  pairing: PAIRING,
  namespace: "stacks",
  address: C32_PRINCIPAL,
  payer: "from",
  now: false,
  inputs: (): Record<string, Json> => ({}),
  revive: (c: Record<string, unknown>) => c,
  complete: completeWith(transactionBytes),
});
