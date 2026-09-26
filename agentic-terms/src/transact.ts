/**
 * `transact` is `confirm`, the agreement payment when the pairing's payment is not itself a public proof, the signer,
 * then `finish`.
 */
import type { AtrHash } from "@integraledger/lcp";
import { agree } from "./agreement.js";
import { confirm, declined, isObject, namespaceOf, pieceOf, signSteps, unsupported } from "./gate.js";
import type { AgreementReceipt, Binding, Declined, Fetch, Inputs, Presented, Signer, TransactOptions } from "./types.js";

/**
 * `confirm`, then, for a pairing whose payment is not itself a public proof, the agreement payment and its receipt,
 * then the signer, then `finish`. On a decline before the signer the signer is never called. Where the build is itself
 * the payment the signer is not called; where the pairing has nothing for the buyer to sign, `signed` is null after the
 * comparison. When the agreement was paid first, `agreement` is its receipt. `landed` is `finish`'s, where it gives one.
 * Options holding anything but `inputs` and `agreementSigner` are declined before any fetch or signer call.
 */
export async function transact(
  doc: unknown,
  binding: Binding,
  signer: Signer,
  fetch: Fetch,
  options?: TransactOptions,
): Promise<
  { signed: Presented | null; landed?: unknown; bytes: Uint8Array; h: AtrHash; agreement?: AgreementReceipt } | Declined
> {
  if (pieceOf(binding) === undefined) return unsupported(binding);
  if (!optionsOk(options)) return declined("no-payable-option", `${namespaceOf(binding)}/input-malformed`);
  const given: TransactOptions = options ?? {};
  const inputs: Inputs = given.inputs ?? {};
  const agreementSigner = given.agreementSigner;
  const confirmed = await confirm(doc, binding, signer.account, fetch, inputs);
  if ("decline" in confirmed) return confirmed;
  const { bytes, chosen } = confirmed;

  let receipt: { agreement: AgreementReceipt } | Record<string, never> = {};
  if (confirmed.agreement !== undefined) {
    const agreed = await agree(confirmed.h, confirmed.agreement, agreementSigner ?? signer, fetch, {
      bytes,
      inputs,
      ns: namespaceOf(binding),
    });
    if ("decline" in agreed) return agreed;
    receipt = { agreement: agreed.receipt };
  }

  const done = await signSteps(binding, chosen, confirmed.request, signer, bytes, confirmed.h);
  if ("decline" in done) return done;
  const landed = done.landed === undefined ? {} : { landed: done.landed };
  return { signed: done.signed, ...landed, bytes, h: done.h, ...receipt };
}

const OPTION_KEYS: readonly string[] = ["inputs", "agreementSigner"];

/**
 * Whether `transact`'s options are absent, or an object holding only `inputs` (an object, or undefined) and
 * `agreementSigner` (an object with a `sign` function, or undefined).
 */
function optionsOk(options: unknown): options is TransactOptions | undefined {
  if (options === undefined) return true;
  if (!isObject(options) || !Object.keys(options).every((k) => OPTION_KEYS.includes(k))) return false;
  const { inputs, agreementSigner } = options as { inputs?: unknown; agreementSigner?: unknown };
  if (inputs !== undefined && !isObject(inputs)) return false;
  return agreementSigner === undefined || (isObject(agreementSigner) && typeof agreementSigner["sign"] === "function");
}
