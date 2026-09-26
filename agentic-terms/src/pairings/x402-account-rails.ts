/**
 * What the x402 pieces on non-EVM rails share: the option on the account's network, with the account's address
 * percent-decoded as CAIP-10 writes it, and the piece for pairings where the payer's wallet builds and signs the
 * rail's own payment around what the build hands it.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import type { BuyerPiece, Chosen, Presented, Read, Signature, SigningRequest } from "../types.js";
import { accountOf, choiceOf, firstOption, isObject, isRefusal, refuse, withPaymentIdentifier, x402Chosen } from "./common.js";

const NO_OPTION = "x402/no-payable-option";

/**
 * The first option on the account's network, for an account in one of `namespaces` whose decoded address passes
 * `address`. The address is returned decoded, as `accountOf` gives it.
 */
export function railOption(
  read: Read,
  account: string,
  namespaces: readonly string[],
  pairing: string,
  address: (a: string) => boolean,
): { required: PaymentRequired; accepted: PaymentRequirements; address: string } | Refusal {
  const a = accountOf(account);
  if (a === undefined || !namespaces.includes(a.namespace)) return refuse(NO_OPTION);
  if (!address(a.address)) return refuse(NO_OPTION);
  const o = firstOption(read, account, a.namespace, pairing);
  if (isRefusal(o)) return refuse(NO_OPTION);
  return { required: o.required, accepted: o.accepted, address: o.address };
}

/** The x402 payment with the payment identifier appended where the challenge advertises it. */
export function identified(signed: unknown, chosen: Chosen): Presented | Refusal {
  if (isRefusal(signed)) return signed;
  return withPaymentIdentifier(signed as Presented, choiceOf(chosen)?.["required"], chosen.ref);
}

/**
 * The buyer piece for an x402 pairing whose build takes only the challenge and the chosen option, and whose request
 * the payer's wallet answers with the payment's own fields: `fields`, each a string, passed to the build's `complete`
 * as one object.
 */
export function walletBuiltPiece(
  pairing: string,
  namespaces: readonly string[],
  address: (a: string) => boolean,
  fields: readonly string[],
): BuyerPiece {
  type Built = { request: SigningRequest; complete(signed: Record<string, string>): unknown };
  return Object.freeze({
    choose(read: Read, account: string, _inputs: unknown, _now: number, ref: string): Chosen | Refusal {
      const o = railOption(read, account, namespaces, pairing, address);
      if (isRefusal(o)) return o;
      return x402Chosen(pairing, { required: o.required as unknown as Json, accepted: o.accepted as unknown as Json }, ref);
    },
    choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("x402/choice-malformed"),
    request: (unsigned: unknown) => (unsigned as Built).request,
    async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
      if (!isObject(signature)) return refuse("x402/signature-malformed");
      const signed: Record<string, string> = {};
      for (const f of fields) {
        const v = signature[f];
        if (typeof v !== "string") return refuse("x402/signature-malformed");
        signed[f] = v;
      }
      return identified(await (unsigned as Built).complete(signed), chosen);
    },
  });
}
