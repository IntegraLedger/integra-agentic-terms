/**
 * The buyer pieces shared by MPP's charges and sessions on Hedera, Solana, Stellar, XRPL and NEAR Intents: the first
 * challenge, in document order, that offers the pairing on the account's CAIP-2 network, as MPP's `network` reads it;
 * the buyer's own inputs beside it as JSON; the build's request exactly as built; and the credential the signer's
 * answer completes.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import { network, type MppChallenge } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Choose, Chosen, Inputs, Next, Presented, Read, Signature, SigningRequest } from "../types.js";
import { accountOf, bytesOf, isObject, isRefusal, refuse } from "./common.js";
import { mppChoice, offers, requestOf } from "./mpp.js";

export const HEDERA_EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
export const XRPL_ADDRESS = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/;
export const STELLAR_ACCOUNT = /^G[A-Z2-7]{55}$/;

/** One MPP rail pairing's buyer piece, described by what differs between pairings. */
export interface MppRail {
  pairing: string;
  /** The account's CAIP-2 namespace, or null where the challenge's network alone decides. */
  namespace: string | null;
  /** The form of the account's address. */
  address: RegExp;
  /** The choice field the account's address fills, or null when the build takes none. */
  payer: string | null;
  /** True when the build takes `now`. */
  now: boolean;
  /** The buyer's own values the build takes beside the challenge, as JSON, or the refusal naming the first missing. */
  inputs(request: Record<string, unknown>, given: Inputs): Record<string, Json> | Refusal;
  /** The choice as the build takes it: integers as bigints where the build names bigints. */
  revive(choice: Record<string, unknown>): unknown;
  /** The request handed to the signer. */
  request?(unsigned: unknown): SigningRequest | Refusal;
  /** The challenge's network where the account's own network is the configured one, in place of MPP's `network`. */
  network?(challenge: MppChallenge, accountNetwork: string): string | Refusal;
  /** The credential the signer's answer completes, or the next request of an opening signed in steps. */
  complete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Next | Refusal>;
}

/** The first challenge offering the pairing on the account's network, with the choice the build takes. */
export function railChoose(rail: MppRail): Choose {
  return (read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal => {
    const a = accountOf(account);
    if (a === undefined || (rail.namespace !== null && a.namespace !== rail.namespace) || !rail.address.test(a.address)) {
      return refuse("mpp/no-payable-option");
    }
    const offer = read.offer;
    const challenges = isObject(offer) && Array.isArray(offer["challenges"]) ? (offer["challenges"] as MppChallenge[]) : [];
    const networkOf = rail.network ?? ((c: MppChallenge) => network(c));
    const challenge = challenges.find((c) => offers(c, rail.pairing) && networkOf(c, a.network) === a.network);
    if (challenge === undefined) return refuse("mpp/no-payable-option");
    const given = rail.inputs(requestOf(challenge) ?? {}, inputs);
    if (isRefusal(given)) return given;
    const choice: Record<string, Json> = {
      challenge: challenge as unknown as Json,
      ...(rail.payer !== null ? { [rail.payer]: a.address } : {}),
      ...(rail.now ? { now } : {}),
      ...given,
    };
    return { pairing: rail.pairing, choice, ref };
  };
}

/** The build's request, exactly as built. */
export function builtRequest(unsigned: unknown): SigningRequest | Refusal {
  const u = unsigned as { request?: unknown };
  return isObject(u) && isObject(u.request) ? (u.request as SigningRequest) : refuse("mpp/request-malformed");
}

/** The buyer piece for one MPP rail pairing. */
export function mppRailPiece(rail: MppRail): BuyerPiece {
  return Object.freeze({
    choose: railChoose(rail),
    choice(chosen: Chosen): unknown {
      const c = isObject(chosen) && isObject(chosen.choice) ? chosen.choice : undefined;
      if (c === undefined || !isObject(c["challenge"])) return refuse("mpp/choice-malformed");
      return rail.revive(c);
    },
    request: rail.request ?? builtRequest,
    complete: rail.complete,
  });
}

/** A 64-byte signature given as `0x` hex, as bytes. */
export function signature64(signature: Signature): Uint8Array | Refusal {
  return bytesOf(signature, 64) ?? refuse("mpp/credential-malformed");
}

/** Hex digits of a `0x` hex answer, without the prefix. */
export function hexDigits(v: unknown): string | undefined {
  return typeof v === "string" && bytesOf(v) !== undefined && v.length > 2 ? v.slice(2) : undefined;
}

/** The credential of a build whose `complete` takes the signer's answer as given, converted by `answer`. */
export function completeWith(answer: (s: Signature) => unknown): MppRail["complete"] {
  return async (unsigned: unknown, signature: Signature): Promise<Presented | Refusal> => {
    const a = answer(signature);
    if (isRefusal(a)) return a;
    return (await (unsigned as { complete(a: unknown): Presented | Refusal | Promise<Presented | Refusal> }).complete(a)) as
      | Presented
      | Refusal;
  };
}

/** A session opening's choice as the build takes it, with `deposit` as a bigint where the choice carries one. */
export function sessionRevive(c: Record<string, unknown>): unknown {
  return mppChoice({ pairing: "", choice: c as Json, ref: "" });
}
