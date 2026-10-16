/**
 * The buyer pieces shared by MPP's pairings: the first challenge, in document order, that offers the pairing on the
 * signer's chain; the build's request exactly as built; and the credential the signer's answer completes.
 */
import type { Json, Refusal } from "@integraledger/lcp/core";
import { base64UrlBytes, canonicalJson, parseJson } from "@integraledger/lcp/core";
import type { Hex } from "@integraledger/lcp/evm";
import { network, pairingsOfPlaced, type MppChallenge, type MppCredential, type MppUnsigned } from "@integraledger/lcp/mpp";
import type { BuyerPiece, Choose, Chosen, Inputs, Presented, Read, Signature, SigningRequest } from "../types.js";
import { accountOf, bigintOf, broadcasts, choiceOf, held, inputsOf, isObject, isRefusal, refuse } from "./common.js";

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const MAX_DECODED = 8192;
const MAX_JSON_DEPTH = 16;

type Spec = Parameters<typeof inputsOf>[2];

/** The request a challenge carries, read by `decodeObject`, or undefined. */
export function requestOf(c: MppChallenge): Record<string, unknown> | undefined {
  return isObject(c) ? decodeObject(c["request"]) : undefined;
}

/**
 * The JSON object a base64url value holds, read as the protocol package reads an MPP challenge's `request` and
 * `opaque`: base64url without padding, its final character's unused bits zero, at most 8 KiB decoded; UTF-8 whose
 * leading byte order mark is kept as a character; one JSON object, nested at most 16 levels deep, that has an RFC 8785
 * form. Undefined for anything else.
 */
export function decodeObject(s: unknown): Record<string, Json> | undefined {
  const bytes = base64UrlBytes(s, MAX_DECODED);
  if (typeof bytes === "string") return undefined;
  try {
    const v: unknown = parseJson(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
    if (!isObject(v) || depthOf(v, 0) > MAX_JSON_DEPTH) return undefined;
    return typeof canonicalJson(v) === "string" ? (v as Record<string, Json>) : undefined;
  } catch {
    return undefined;
  }
}

/** The nesting depth of objects and arrays in `v`, counting from `d`, stopping once past `MAX_JSON_DEPTH`. */
function depthOf(v: unknown, d: number): number {
  if (d > MAX_JSON_DEPTH || typeof v !== "object" || v === null) return d;
  let max = d + 1;
  for (const x of Object.values(v)) max = Math.max(max, depthOf(x, d + 1));
  return max;
}

/** Whether a placed challenge offers the pairing, by the protocol package's `pairingsOfPlaced`. */
export function offers(c: MppChallenge, pairing: string): boolean {
  return pairingsOfPlaced(c).some((p) => p === pairing);
}

/**
 * The first challenge offering `pairing` on the account's EVM network, as MPP's `network` reads it, with the choice
 * MPP's build takes: the challenge, `from`, `now`, and the buyer's own inputs named in `spec`.
 */
export function mppChoose(pairing: string, spec: Spec): Choose {
  return (read: Read, account: string, inputs: Inputs, now: number, ref: string): Chosen | Refusal => {
    const a = accountOf(account);
    if (a === undefined || a.namespace !== "eip155" || !EVM_ADDRESS.test(a.address)) return refuse("mpp/no-payable-option");
    const offer = read.offer;
    const challenges = isObject(offer) && Array.isArray(offer["challenges"]) ? (offer["challenges"] as MppChallenge[]) : [];
    const challenge = challenges.find((c) => offers(c, pairing) && network(c) === a.network);
    if (challenge === undefined) return refuse("mpp/no-payable-option");
    const given = inputsOf(inputs, pairing, spec);
    if (isRefusal(given)) return given;
    return { pairing, choice: { challenge: challenge as unknown as Json, from: a.address, now, ...given }, ref };
  };
}

/** The choice as MPP's build takes it, with `deposit` as a bigint where the choice carries one. */
export function mppChoice(chosen: Chosen): unknown {
  const c = choiceOf(chosen);
  if (c === undefined) return refuse("mpp/choice-malformed");
  if (c["deposit"] === undefined) return c;
  const deposit = bigintOf(c["deposit"]);
  return deposit === undefined ? refuse("mpp/choice-malformed") : { ...c, deposit };
}

/** The build's request, exactly as built. */
export function mppRequest(unsigned: unknown): SigningRequest | Refusal {
  return (unsigned as MppUnsigned).request;
}

/** The credential for a one-value answer: a signature, a signed transaction or a transaction hash, as `0x` hex. */
export async function mppComplete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
  if (typeof signature !== "string") return refuse("mpp/credential-malformed");
  return (unsigned as { complete(s: Hex): MppCredential | Refusal }).complete(signature as Hex);
}

/** A buyer piece for an MPP charge pairing whose answer is one value. */
export function mppChargePiece(pairing: string, spec: Spec): BuyerPiece {
  return Object.freeze({
    choose: mppChoose(pairing, spec),
    choice: mppChoice,
    request: mppRequest,
    complete: mppComplete,
    moves: broadcasts,
  });
}

/**
 * The credential for a pushed Tempo transfer: the answer is `{hash, landed?: {transaction, blockNumber, logs}}`, the
 * hash the signer broadcast and, where the signer gives it, its landed receipt, which carries the memo `bound` reads,
 * held under the payment's own `FETCHED` member (`@integraledger/lcp`'s symbol, which no wire form carries).
 */
export async function pushComplete(unsigned: unknown, signature: Signature): Promise<Presented | Refusal> {
  if (!isObject(signature) || typeof signature["hash"] !== "string") return refuse("mpp/credential-malformed");
  const credential = (unsigned as { complete(s: Hex): MppCredential | Refusal }).complete(signature["hash"] as Hex);
  if (isRefusal(credential)) return credential;
  const landed = signature["landed"];
  if (landed === undefined) return credential;
  if (!isObject(landed) || typeof landed["transaction"] !== "string" || !Array.isArray(landed["logs"])) {
    return refuse("mpp/credential-malformed");
  }
  const blockNumber = bigintOf(landed["blockNumber"]);
  if (blockNumber === undefined) return refuse("mpp/credential-malformed");
  return held(credential, { transaction: landed["transaction"] as Hex, blockNumber, logs: landed["logs"] });
}
