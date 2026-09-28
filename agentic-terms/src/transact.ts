/**
 * `transact` is `confirm`, the agreement payment when the pairing's payment is not itself a public proof, the signer,
 * then `finish`. The agreement payment is signed only once the buyer's agent has approved it: the first call returns it
 * in `approve`, and a second call with that payment as `approved` pays it and then the resource.
 */
import type { AtrHash } from "@integraledger/lcp";
import { exchange } from "./agreement.js";
import { confirm, declined, isObject, namespaceOf, pieceOf, signSteps, unsupported } from "./gate.js";
import type { AgreementReceipt, Binding, Declined, Fetch, Presented, Signer, ToApprove, TransactOptions } from "./types.js";

/**
 * `confirm`, then, for a pairing whose payment is not itself a public proof, the agreement, then the signer, then
 * `finish`. Without `approved`, an agreement not yet recorded is returned as `approve`, the agreement payment for the
 * agent to approve, and nothing is signed; with `approved`, that payment is signed and paid, and the resource's payment
 * is signed only with the agreement's receipt in hand. On a decline before the signer the signer is never called. Where
 * the build is itself the payment the signer is not called; where the pairing has nothing for the buyer to sign,
 * `signed` is null after the comparison. `agreement` is the agreement's receipt, where the pairing needs one. `landed`
 * is `finish`'s, where it gives one. `signal` ends the agreement exchange. Options holding anything but `inputs`,
 * `agreementSigner`, `approved` and `signal` are declined before any fetch or signer call.
 */
export async function transact(
  doc: unknown,
  binding: Binding,
  signer: Signer,
  fetch: Fetch,
  options?: TransactOptions,
): Promise<
  | { signed: Presented | null; landed?: unknown; bytes: Uint8Array; h: AtrHash; agreement?: AgreementReceipt }
  | ToApprove
  | Declined
> {
  if (pieceOf(binding) === undefined) return unsupported(binding);
  const ns = namespaceOf(binding);
  if (!optionsOk(options)) return declined("no-payable-option", `${ns}/input-malformed`);
  const { inputs = {}, agreementSigner, approved, signal } = options ?? {};
  const confirmed = await confirm(doc, binding, signer.account, fetch, inputs);
  if ("decline" in confirmed) return confirmed;
  const { bytes, chosen } = confirmed;

  let receipt: { agreement: AgreementReceipt } | Record<string, never> = {};
  if (chosen.agreement !== undefined) {
    const agreed = await exchange(bytes, chosen.agreement, agreementSigner ?? signer, fetch, { approved, inputs, signal }, ns);
    if (!("receipt" in agreed)) return agreed;
    receipt = { agreement: agreed.receipt };
  }

  const done = await signSteps(binding, chosen, confirmed.request, signer, bytes, confirmed.h);
  if ("decline" in done) return done;
  const landed = done.landed === undefined ? {} : { landed: done.landed };
  return { signed: done.signed, ...landed, bytes, h: done.h, ...receipt };
}

const OPTION_KEYS: readonly string[] = ["inputs", "agreementSigner", "approved", "signal"];

/**
 * Whether `transact`'s options are absent, or an object holding only `inputs` (an object, or undefined),
 * `agreementSigner` (an object with a `sign` function, or undefined), `approved` (an object, or undefined) and `signal`
 * (an `AbortSignal`, or undefined).
 */
function optionsOk(options: unknown): options is TransactOptions | undefined {
  if (options === undefined) return true;
  if (!isObject(options) || !Object.keys(options).every((k) => OPTION_KEYS.includes(k))) return false;
  const { inputs, agreementSigner, approved, signal } = options as Record<string, unknown>;
  if (inputs !== undefined && !isObject(inputs)) return false;
  if (approved !== undefined && !isObject(approved)) return false;
  if (signal !== undefined && !(signal instanceof AbortSignal)) return false;
  return agreementSigner === undefined || (isObject(agreementSigner) && typeof agreementSigner["sign"] === "function");
}
