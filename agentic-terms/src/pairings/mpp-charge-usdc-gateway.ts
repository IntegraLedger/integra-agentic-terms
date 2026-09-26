/**
 * The buyer piece for `mpp/charge/usdc/gateway`: the first challenge, in document order, that offers the pairing and
 * accepts the account's network as a Gateway source. The request hands the buyer's Gateway client the salt's preimage
 * from the challenge; the client adds its own values, computes `usdcGatewaySalt` and sets the result as `spec.salt`
 * before signing, then answers `{source, sourceNetwork, destinationNetwork, maxFee, burnIntent, signature}`, which the
 * build's `complete` wraps.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { MppChallenge } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Chosen, Inputs, Read, Signature } from "../types.js";
import { accountOf, isObject, refuse } from "./common.js";
import { offers, requestOf } from "./mpp.js";
import { builtRequest, completeWith } from "./mpp-rails.js";

const PAIRING = "mpp/charge/usdc/gateway";

/** The Gateway source networks a challenge accepts. */
function acceptedSources(c: MppChallenge): readonly unknown[] {
  const md = requestOf(c)?.["methodDetails"];
  const g = isObject(md) ? md["gateway"] : undefined;
  const sources = isObject(g) ? g["acceptedSources"] : undefined;
  return Array.isArray(sources) ? sources : [];
}

function answerOf(signature: Signature): unknown {
  return isObject(signature) ? signature : refuse("mpp/credential-malformed");
}

export const mppChargeUsdcGateway: BuyerPiece = Object.freeze({
  choose(read: Read, account: string, _inputs: Inputs, now: number, ref: string): Chosen | Refusal {
    const a = accountOf(account);
    if (a === undefined) return refuse("mpp/no-payable-option");
    const offer = read.offer;
    const challenges = isObject(offer) && Array.isArray(offer["challenges"]) ? (offer["challenges"] as MppChallenge[]) : [];
    const challenge = challenges.find((c) => offers(c, PAIRING) && acceptedSources(c).includes(a.network));
    if (challenge === undefined) return refuse("mpp/no-payable-option");
    return { pairing: PAIRING, choice: { challenge: challenge as unknown as Json, from: a.address, now }, ref };
  },
  choice(chosen: Chosen): unknown {
    const c = isObject(chosen) && isObject(chosen.choice) ? chosen.choice : undefined;
    return c === undefined || !isObject(c["challenge"]) ? refuse("mpp/choice-malformed") : c;
  },
  request: builtRequest,
  complete: completeWith(answerOf),
});
