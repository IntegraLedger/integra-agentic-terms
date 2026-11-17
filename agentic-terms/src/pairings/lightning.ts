/**
 * The buyer pieces for MPP's Lightning methods: the buyer's node pays exactly the invoice the build names, and its
 * answer is the payment preimage, as the build's `complete` takes it. The node moves the payment, so a decline keeps it.
 */
import type { Refusal } from "@integraledger/lcp/core";
import { decodeBolt11, type LnMppUnsigned } from "@integraledger/lcp/lightning";
import type { MppChallenge } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Chosen, Inputs, Presented, Read, Signature } from "../types.js";
import { accountOf, choiceOf, inputsOf, isObject, isRefusal, refuse } from "./common.js";
import { offers, requestOf } from "./mpp.js";

/**
 * The BOLT11 currency of each `lnbtc` network, the CAIP-2 reference being the first 32 hex characters of the network's
 * genesis block hash: `bc` mainnet; `tb` testnet3 and testnet4; `tbs` signet; `bcrt` regtest.
 */
const LN_CURRENCY: { readonly [network: string]: string } = {
  "lnbtc:000000000019d6689c085ae165831e93": "bc",
  "lnbtc:000000000933ea01ad0ee984209779ba": "tb",
  "lnbtc:00000000da84f2bafbbc53dee25a72ae": "tb",
  "lnbtc:00000008819873e925422c1ff0f99f7c": "tbs",
  "lnbtc:0f9188f13cb7b2c71f2a335e3a4fc328": "bcrt",
};

/** The invoice a Lightning challenge asks the node to pay: a charge's `methodDetails.invoice`, a session's deposit. */
function invoiceOf(c: MppChallenge, session: boolean): unknown {
  const request = requestOf(c);
  if (request === undefined) return undefined;
  if (session) return request["depositInvoice"];
  const d = request["methodDetails"];
  return isObject(d) ? d["invoice"] : undefined;
}

/**
 * The MPP Lightning piece: the first challenge offering the pairing whose invoice's BOLT11 currency is the account's
 * `lnbtc` network's. A session's return invoice is the buyer's input, and rides in the build's choice.
 */
export function lnMppPiece(pairing: string, session: boolean): BuyerPiece {
  return Object.freeze({
    async choose(read: Read, account: string, inputs: Inputs, _now: number, ref: string): Promise<Chosen | Refusal> {
      const a = accountOf(account);
      const currency = a === undefined ? undefined : LN_CURRENCY[a.network];
      if (a === undefined || a.namespace !== "lnbtc" || currency === undefined) return refuse("mpp/no-payable-option");
      const offer = read.offer;
      const challenges = isObject(offer) && Array.isArray(offer["challenges"]) ? (offer["challenges"] as MppChallenge[]) : [];
      let challenge: MppChallenge | undefined;
      for (const c of challenges) {
        if (!offers(c, pairing)) continue;
        const invoice = invoiceOf(c, session);
        if (typeof invoice !== "string") continue;
        const b = await decodeBolt11(invoice);
        if (!isRefusal(b) && b.currency === currency) {
          challenge = c;
          break;
        }
      }
      if (challenge === undefined) return refuse("mpp/no-payable-option");
      const given = inputsOf(inputs, pairing, session ? { returnInvoice: "string" } : {});
      if (isRefusal(given)) return given;
      return { pairing, choice: { challenge: challenge as never, ...given }, ref };
    },
    choice: (chosen: Chosen) => choiceOf(chosen) ?? refuse("mpp/choice-malformed"),
    request: (unsigned: unknown) => (unsigned as LnMppUnsigned).request,
    async complete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
      if (typeof signature !== "string") return refuse("ln/preimage-malformed");
      return (unsigned as LnMppUnsigned).complete(signature);
    },
    moves: () => true,
  });
}

export const mppChargeLightning = lnMppPiece("mpp/charge/lightning", false);
export const mppSessionLightning = lnMppPiece("mpp/session/lightning", true);
