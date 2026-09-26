/**
 * The buyer pieces shared by the x402 pairings on the Solana, Stellar, XRPL, Hedera and Algorand rails: the first option
 * on the account's network, the buyer's own inputs beside it as JSON, the build's request exactly as built, and the
 * payment the signer's answer completes, with the payment identifier appended where the challenge advertises it.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { bytesOf, choiceOf, firstOption, isObject, isRefusal, refuse, withPaymentIdentifier } from "./common.js";

/** One x402 rail pairing's buyer piece, described by what differs between rails. */
export interface Rail {
  pairing: string;
  /** The account's CAIP-2 namespace, and the form of its address. */
  namespace: string;
  address: RegExp;
  /** The choice field the account's address fills, or null when the build takes none. */
  payer: string | null;
  /** True when the build takes `now`. */
  now: boolean;
  /** The buyer's own values the build takes beside the option, as JSON, or the refusal naming the first missing. */
  inputs(accepted: PaymentRequirements, inputs: Inputs): Record<string, Json> | Refusal;
  /** The choice's JSON fields as the build takes them: integers as bigints where the build names bigints. */
  revive(choice: Record<string, unknown>): Record<string, unknown> | Refusal;
  /** The signer's answer as the build's `complete` takes it. */
  answer(signature: Signature): unknown;
  /** The payment's `payload`, where the build's `complete` returns only the signed transaction as a string. */
  payload?: (completed: string) => Record<string, Json>;
}

/** The x402 payment for a payload, echoing the challenge's `resource` and `extensions` unchanged, omitted when absent. */
function x402Payment(required: PaymentRequired, accepted: PaymentRequirements, payload: Record<string, Json>): Presented {
  return {
    x402Version: 2,
    ...(required.resource !== undefined ? { resource: required.resource } : {}),
    ...(required.extensions !== undefined ? { extensions: required.extensions } : {}),
    accepted,
    payload,
  } as unknown as Presented;
}

/** A 64-byte signature given as `0x` hex, as bytes. */
export function signature64(signature: Signature): Uint8Array | Refusal {
  return bytesOf(signature, 64) ?? refuse("x402/signature-malformed");
}

/** The buyer piece for one x402 rail pairing. */
export function railPiece(rail: Rail): BuyerPiece {
  return Object.freeze({
    choose(read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal {
      const o = firstOption(read, account, rail.namespace, rail.pairing, rail.address);
      if (isRefusal(o)) return refuse("x402/no-payable-option");
      const given = rail.inputs(o.accepted, inputs);
      if (isRefusal(given)) return given;
      const choice: Record<string, Json> = {
        required: o.required as unknown as Json,
        accepted: o.accepted as unknown as Json,
        ...(rail.payer !== null ? { [rail.payer]: o.address } : {}),
        ...(rail.now ? { now } : {}),
        ...given,
      };
      return { pairing: rail.pairing, choice, ref };
    },

    choice(chosen: Chosen): unknown {
      const c = choiceOf(chosen);
      if (c === undefined || !isObject(c["required"]) || !isObject(c["accepted"])) return refuse("x402/choice-malformed");
      return rail.revive(c);
    },

    request(unsigned: unknown): SigningRequest | Refusal {
      const u = unsigned as { request?: unknown };
      return isObject(u) && isObject(u.request) ? (u.request as SigningRequest) : refuse("x402/request-malformed");
    },

    async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
      const answer = rail.answer(signature);
      if (isRefusal(answer)) return answer;
      const c = choiceOf(chosen)!;
      const completed = (unsigned as { complete(a: unknown): unknown }).complete(answer);
      if (isRefusal(completed)) return completed;
      let signed: Presented;
      if (typeof completed === "string") {
        if (rail.payload === undefined) return refuse("x402/payload-malformed");
        signed = x402Payment(
          c["required"] as unknown as PaymentRequired,
          c["accepted"] as unknown as PaymentRequirements,
          rail.payload(completed),
        );
      } else {
        signed = completed as Presented;
      }
      return withPaymentIdentifier(signed, c["required"], chosen.ref);
    },
  });
}
