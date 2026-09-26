/**
 * What the x402 `batch-settlement` pieces share: the deposit the buyer commits, the batch signing request exactly as
 * built, and the payment the list of answers completes, with the payment
 * identifier appended where the challenge advertises it.
 */
import type { Json, Refusal } from "@integraledger/lcp";
import type { PaymentRequirements } from "@integraledger/lcp/x402";
import type { BatchUnsigned } from "@integraledger/lcp/x402-batch-settlement";
import type { Chosen, Inputs, Presented, Signature, SigningRequest } from "../types.js";
import { bigintOf, choiceOf, hexOf, isObject, refuse, withPaymentIdentifier } from "./common.js";

/**
 * The deposit: `extra.minDeposit` when the option carries one, else the buyer's `deposit` input. A deposit above the
 * buyer's `maxDeposit` input, when given, is refused.
 */
export function depositOf(accepted: PaymentRequirements, inputs: Inputs): string | Refusal {
  const min = isObject(accepted.extra) ? accepted.extra["minDeposit"] : undefined;
  const deposit = min !== undefined ? bigintOf(min) : bigintOf(inputs["deposit"]);
  if (deposit === undefined) return refuse(min !== undefined ? "x402/option-malformed" : "x402/input-missing");
  if (inputs["maxDeposit"] !== undefined) {
    const max = bigintOf(inputs["maxDeposit"]);
    if (max === undefined) return refuse("x402/input-missing");
    if (deposit > max) return refuse("x402/deposit-above-maximum");
  }
  return deposit.toString();
}

/** `n` bytes from the platform's CSPRNG. */
export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** 32 random bytes as `0x` hex. */
export function randomSalt32(): string {
  return hexOf(randomBytes(32));
}

/** 8 random bytes as a decimal u64. */
export function randomU64(): string {
  let n = 0n;
  for (const b of randomBytes(8)) n = (n << 8n) | BigInt(b);
  return n.toString();
}

/** The build's requests as one `batch` request, signed in order. */
export function batchRequest(unsigned: unknown): SigningRequest {
  const u = unsigned as BatchUnsigned;
  return {
    kind: "batch",
    requests: u.requests,
  };
}

/** The payment the list of answers, one per request in order, completes. */
export async function batchComplete(unsigned: unknown, signature: Signature, chosen: Chosen): Promise<Presented | Refusal> {
  const u = unsigned as BatchUnsigned;
  if (!Array.isArray(signature) || signature.length !== u.requests.length || !signature.every((s) => typeof s === "string")) {
    return refuse("x402/signature-malformed");
  }
  const signed = u.complete(signature as string[]);
  if ("refused" in signed) return signed;
  return withPaymentIdentifier(signed as unknown as Presented, choiceOf(chosen)?.["required"], chosen.ref);
}

/** The choice with the named decimal members as bigints, or a refusal when one is not a decimal. */
export function reviveDecimals(chosen: Chosen, keys: readonly string[]): Record<string, unknown> | Refusal {
  const c = choiceOf(chosen);
  if (c === undefined) return refuse("x402/choice-malformed");
  const out: Record<string, unknown> = { ...c };
  for (const k of keys) {
    if (c[k] === undefined) continue;
    const v = bigintOf(c[k]);
    if (v === undefined) return refuse("x402/choice-malformed");
    out[k] = v;
  }
  return out;
}

/** The optional inputs of the given kinds that are present, or the refusal naming the first malformed one. */
export function optionalInputs(
  inputs: Inputs,
  ns: string,
  spec: { readonly [k: string]: RegExp | "object" },
): Record<string, Json> | Refusal {
  const out: Record<string, Json> = {};
  for (const [k, kind] of Object.entries(spec)) {
    const v = inputs[k];
    if (v === undefined) continue;
    const ok = kind === "object" ? isObject(v) : typeof v === "string" && kind.test(v);
    if (!ok) return refuse(`${ns}/input-missing`);
    out[k] = v;
  }
  return out;
}
