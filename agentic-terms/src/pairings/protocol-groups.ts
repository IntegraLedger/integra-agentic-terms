/**
 * What the protocol-group pieces (card, AP2, UCP, ACP, ACK) share: the buyer's CAIP-10 account, which names the buyer,
 * the object choice revived from `Chosen`, and the piece of a pairing whose build has nothing for the buyer to sign.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, SigningRequest } from "../types.js";
import { accountOf, choiceOf, isRefusal, refuse } from "./common.js";

/** A refusal `<ns>/no-payable-option` unless the account is CAIP-10. */
export function unnamedBuyer(account: string, ns: string): Refusal | undefined {
  return accountOf(account) === undefined ? refuse(`${ns}/no-payable-option`) : undefined;
}

/** The choice object of `chosen`, or `<ns>/choice-malformed`. */
export function objectChoice(chosen: Chosen, ns: string): Record<string, unknown> | Refusal {
  return choiceOf(chosen) ?? refuse(`${ns}/choice-malformed`);
}

/** The pairing's build input as the piece stores it in `Chosen`. */
export type Choose = (
  read: Read,
  account: string,
  inputs: Inputs,
  now: number,
  ref: string,
  doc?: unknown,
) => Record<string, Json> | Refusal;

/**
 * The piece of a pairing whose build refuses `no-signed-place` or `nothing-to-sign`: it chooses, and the gate confirms
 * only. Nothing is handed to a signer, and nothing completes.
 */
export function confirmOnlyPiece(pairing: string, choose: Choose): BuyerPiece {
  const ns = pairing.split("/")[0]!;
  return Object.freeze({
    choose(read: Read, account: string, inputs: Inputs, now: number, ref: string, doc?: unknown): Chosen | Refusal {
      const choice = choose(read, account, inputs, now, ref, doc);
      if (isRefusal(choice)) return choice;
      return { pairing, choice, ref };
    },
    choice: (chosen: Chosen) => objectChoice(chosen, ns),
    request: (): SigningRequest | Refusal => refuse(`${ns}/nothing-to-sign`),
    complete: async (): Promise<Presented | Refusal> => refuse(`${ns}/nothing-to-sign`),
  });
}
