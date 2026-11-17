/**
 * The buyer piece for `x402/exact/sui`: the wallet builds the scheme's payment, adds the request's `pureInput` as the
 * one unused `Pure` input, bounds the expiration by epoch as the request asks, signs, and answers
 * `{signature, transaction}`, with `sent`, the transaction it sent to the option's gas station, on the sponsored path
 * (`extra.gasStation`): the build's `complete` holds the signed transaction to it in everything but the gas data. The
 * epoch bound is this piece's choice, not a condition of the record: a signed transaction without one that carries
 * the hash completes, and is recorded.
 */
import type { Refusal } from "@integraledger/lcp/core";
import type { SuiUnsigned } from "@integraledger/lcp/sui";
import type { BuyerPiece, Chosen, Presented, Signature } from "../types.js";
import { isObject, refuse } from "./common.js";
import { identified, walletBuiltPiece } from "./x402-account-rails.js";

const SUI_ADDRESS = /^0x[0-9a-fA-F]{64}$/;

const wallet = walletBuiltPiece("x402/exact/sui", ["sui"], (a) => SUI_ADDRESS.test(a), ["signature", "transaction"]);

export const x402ExactSui: BuyerPiece = Object.freeze({
  ...wallet,
  async complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
    const sent = isObject(signature) ? signature["sent"] : undefined;
    if (sent === undefined || sent === null) return wallet.complete(unsigned, signature, chosen) as Promise<Presented | Refusal>;
    const s = signature as Record<string, unknown>;
    if (typeof sent !== "string" || typeof s["signature"] !== "string" || typeof s["transaction"] !== "string") {
      return refuse("x402/signature-malformed");
    }
    const signed = { signature: s["signature"], transaction: s["transaction"] };
    return identified((unsigned as SuiUnsigned).complete(signed, sent), chosen);
  },
});
