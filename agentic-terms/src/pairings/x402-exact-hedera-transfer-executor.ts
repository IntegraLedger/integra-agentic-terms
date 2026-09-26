/**
 * The buyer piece for `x402/exact/hedera/transfer-executor`: the offered executors, asset, payee, amount and
 * `validBefore`, handed to the buyer's wallet or executor tooling as `hedera-executor`, which answers
 * `{payer, executor, authorization}`.
 */
import type { Refusal } from "@integraledger/lcp";
import type { Signature } from "../types.js";
import { isObject, refuse } from "./common.js";
import { HEDERA_ENTITY } from "./x402-exact-hedera.js";
import { railPiece } from "./x402-rail.js";

/** The wallet's answer, its three members as strings. */
function answer(signature: Signature): { payer: string; executor: string; authorization: string } | Refusal {
  if (!isObject(signature)) return refuse("x402/signature-malformed");
  const { payer, executor, authorization } = signature;
  if (typeof payer !== "string" || typeof executor !== "string" || typeof authorization !== "string") {
    return refuse("x402/signature-malformed");
  }
  return { payer, executor, authorization };
}

export const x402ExactHederaTransferExecutor = railPiece({
  pairing: "x402/exact/hedera/transfer-executor",
  namespace: "hedera",
  address: HEDERA_ENTITY,
  payer: null,
  now: true,
  inputs: () => ({}),
  revive: (c) => c,
  answer,
});
