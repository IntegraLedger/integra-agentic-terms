/**
 * The buyer pieces for `mpp/charge/tempo/split-memo`, the pull form, and `mpp/charge/tempo/split-memo/push`: the first
 * challenge, in document order, that offers the pairing on the account's EVM network, as MPP's `network` reads it
 * (`eip155:` and the challenge's `methodDetails.chainId`). The resource server places H as the memo of a one-unit split
 * in the challenge, and the buyer's stock MPP client builds and signs the Tempo transaction from the challenge, copying
 * each split's memo into its transfer (lcp profile `mpp-charge-tempo-split-memo.md`, rules 1 and 5). The protocol
 * package builds nothing for these pairings and nothing is handed to the signer: the gate compares the ATR, and `check`
 * reads H from the transaction the buyer's client signed. On the pull form the resource server's settler broadcasts
 * that transaction; on the push form the buyer's client broadcasts it and names it by its hash, so `check` reads H with
 * the landed receipt the caller's own reader read for it, given as `landed`: the transaction's hash, block number, logs
 * and signed bytes, as the protocol package's `fetchPresented` holds them.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import { network, type MppChallenge } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Chosen, Inputs, Read } from "../types.js";
import { accountOf, isObject, refuse } from "./common.js";
import { offers } from "./mpp.js";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const nothingToSign = (): Refusal => refuse("mpp/nothing-to-sign");

function splitMemoPiece(pairing: string): BuyerPiece {
  return Object.freeze({
    choose(read: Read, account: string, _inputs: Inputs, now: number, ref: string): Chosen | Refusal {
      const a = accountOf(account);
      if (a === undefined || a.namespace !== "eip155" || !EVM_ADDRESS.test(a.address)) return refuse("mpp/no-payable-option");
      const offer = read.offer;
      const challenges = isObject(offer) && Array.isArray(offer["challenges"]) ? (offer["challenges"] as MppChallenge[]) : [];
      const challenge = challenges.find((c) => offers(c, pairing) && network(c) === a.network);
      if (challenge === undefined) return refuse("mpp/no-payable-option");
      return { pairing, choice: { challenge: challenge as unknown as Json, now }, ref };
    },
    choice(chosen: Chosen): unknown {
      const c = isObject(chosen) && isObject(chosen.choice) ? chosen.choice : undefined;
      return c === undefined || !isObject(c["challenge"]) ? refuse("mpp/choice-malformed") : c;
    },
    request: () => nothingToSign(),
    complete: async () => nothingToSign(),
  });
}

export const mppChargeTempoSplitMemo = splitMemoPiece("mpp/charge/tempo/split-memo");
export const mppChargeTempoSplitMemoPush = splitMemoPiece("mpp/charge/tempo/split-memo/push");
