/**
 * The buyer piece for `mpp/session/hedera`: the opening handed to the signer as the build's `hedera-session-open`
 * request, exactly as built. The signer broadcasts the two calls in order, signs the zero voucher, and answers
 * `{openTx, signature}`, the opening's hash and the voucher signature, with, where it has it, `landed: {transaction,
 * blockNumber, logs}`, the opening's landed receipt, whose escrow log carries the channel's salt that `bound` reads. The
 * payment sent is the credential without the landed receipt. The signer moves the deposit, so a decline keeps it.
 */
import type { Refusal } from "@integraledger/lcp";
import type { MppCredential } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Chosen, Inputs, Presented, Signature } from "../types.js";
import { bigintOf, inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { HEDERA_EVM_ADDRESS, mppRailPiece, sessionRevive } from "./mpp-rails.js";

const PAIRING = "mpp/session/hedera";

async function complete(unsigned: unknown, signature: Signature, _chosen: Chosen): Promise<Presented | Refusal> {
  if (!isObject(signature) || typeof signature["openTx"] !== "string" || typeof signature["signature"] !== "string") {
    return refuse("mpp/credential-malformed");
  }
  const credential = (unsigned as { complete(s: { openTx: string; signature: string }): MppCredential | Refusal }).complete({
    openTx: signature["openTx"],
    signature: signature["signature"],
  });
  if (isRefusal(credential)) return credential;
  const landed = signature["landed"];
  if (landed === undefined) return credential;
  if (!isObject(landed) || typeof landed["transaction"] !== "string" || !Array.isArray(landed["logs"])) {
    return refuse("mpp/credential-malformed");
  }
  const blockNumber = bigintOf(landed["blockNumber"]);
  if (blockNumber === undefined) return refuse("mpp/credential-malformed");
  return { ...credential, landed: { transaction: landed["transaction"], blockNumber, logs: landed["logs"] } } as unknown as Presented;
}

export const mppSessionHedera: BuyerPiece = Object.freeze({
  ...mppRailPiece({
  pairing: PAIRING,
  namespace: "hedera",
  address: HEDERA_EVM_ADDRESS,
  payer: "from",
  now: true,
  inputs: (_request: Record<string, unknown>, given: Inputs) => inputsOf(given, PAIRING, { deposit: "decimal" }),
  revive: sessionRevive,
  complete,
  }),
  moves: () => true,
  sent(signed: Presented): Presented {
    const { landed: _landed, ...credential } = signed as MppCredential & { landed?: unknown };
    return credential;
  },
});
