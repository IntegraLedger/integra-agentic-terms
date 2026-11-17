/**
 * `transact` is the gate's checks, the agreement payment when the pairing's payment is not itself a public proof, the
 * signer, then `finish`. Every signing, the agreement payment's among them, is first held to its summary and its
 * ceiling and asked of the caller's approver, and the signer is called only for what it approves (terms' profile
 * `buyer-gate.md`, checks 1 to 12). The agreement payment is also returned for the buyer's agent to approve before
 * anything is signed: the first call returns it in `approve`, and a second call with that payment as `approved` pays it
 * and then the resource.
 */
import { fromLegalContextHeader, toLegalContextHeader, type LegalContextReturn } from "@integraledger/lcp";
import { hash, hashEquals, isHttpsLink, isOtherSchemeLink, type AtrHash } from "@integraledger/lcp/core";
import { agreementOptions, exchange } from "./agreement.js";
import { isCeilings, parseAtr, requestHeld, type Approval } from "./checks.js";
import {
  declined,
  fetchAtr,
  gate,
  hasAccount,
  isFullCoverage,
  isObject,
  namespaceOf,
  newRef,
  pieceOf,
  signSteps,
  unsupported,
} from "./gate.js";
import { isRefusal } from "./pairings/common.js";
import type {
  AgreementReceipt,
  Binding,
  BuyerPiece,
  Declined,
  Fetch,
  Inputs,
  Presented,
  ResourceRequest,
  Signer,
  ToApprove,
  ToReturn,
  TransactOptions,
} from "./types.js";

/**
 * The gate's checks, then, for a pairing whose payment is not itself a public proof, the agreement, paid only on an
 * option the pairing's `agreementOn` admits, then the signer, then `finish`. Without `approved`, an agreement not yet recorded is returned as `approve`, the agreement payment for
 * the agent to approve, and nothing is signed; with `approved`, that payment is asked of `approver`, signed and paid,
 * and the resource's payment is asked of `approver` and signed only with the agreement's receipt in hand. On a decline
 * before the signer the signer is never called. Where the build is itself the payment the signer is not called; where
 * the pairing has nothing for the buyer to sign, `signed` is null after the comparison. `agreement` is the agreement's
 * receipt, where the pairing needs one. `landed` is `finish`'s, where it gives one. `signal` ends the agreement
 * exchange. Options that are not an object holding a function `approver` and an object `resourceRequest`, or that hold
 * a member of another name or form, or a signer or agreement signer whose `account` is not a string, are declined
 * `no-payable-option` with `<namespace>/input-malformed` before any fetch or signer call.
 *
 * Where the pairing is paid after its agreement and the first response offers the agreement and no charge option, its
 * every option naming the charges it serves, `transact` pays the agreement and returns `ToReturn` (`toReturn`).
 * `legalContext` is that response's return value, its `Legal-Context` header or MCP `_meta` value as received: one the
 * protocol package's `fromLegalContextHeader` refuses is declined `offer-unreadable` with its code before any fetch, and
 * one whose H is not the ATR's `hash-mismatch`.
 */
export async function transact(
  doc: unknown,
  binding: Binding,
  signer: Signer,
  fetch: Fetch,
  options: TransactOptions,
): Promise<
  | { signed: Presented | null; landed?: unknown; bytes: Uint8Array; h: AtrHash; agreement?: AgreementReceipt }
  | ToApprove
  | ToReturn
  | Declined
> {
  if (pieceOf(binding) === undefined) return unsupported(binding);
  const ns = namespaceOf(binding);
  if (!optionsOk(options) || !hasAccount(signer)) return declined("no-payable-option", `${ns}/input-malformed`);
  const { approver, resourceRequest, inputs = {}, ceilings, legalContext, agreementSigner, approved, signal } = options;
  let returned: LegalContextReturn | undefined;
  if (legalContext !== undefined) {
    const read = fromLegalContextHeader(legalContext);
    if (isRefusal(read)) return declined("offer-unreadable", read.code);
    returned = read;
  }
  const approval = { approver, ceilings, inputs };

  const offers = ns === "x402" && !isFullCoverage(binding) ? agreementOptions(doc) : undefined;
  if (offers !== undefined) {
    return toReturn(doc, binding, offers, { signer: agreementSigner ?? signer, account: signer.account, fetch, resourceRequest, returned, approval, signal });
  }

  const confirmed = await gate(doc, binding, signer.account, fetch, { resourceRequest, inputs, ceilings });
  if ("decline" in confirmed) return confirmed;
  const { bytes, chosen } = confirmed;
  if (returned !== undefined && !hashEquals(returned.h, confirmed.h)) {
    return declined("hash-mismatch", "The return value names another ATR hash than the one the link served.");
  }

  let receipt: { agreement: AgreementReceipt } | Record<string, never> = {};
  if (chosen.agreement !== undefined) {
    const agreed = await exchange(
      bytes,
      chosen.agreement,
      agreementSigner ?? signer,
      fetch,
      { approved, inputs, signal, chosen },
      ns,
      binding,
      approval,
    );
    if (!("receipt" in agreed)) return agreed;
    receipt = { agreement: agreed.receipt };
  }

  const done = await signSteps(binding, chosen, confirmed.request, signer, bytes, confirmed.h, "payment", approval, confirmed.count);
  if ("decline" in done) return done;
  const landed = done.landed === undefined ? {} : { landed: done.landed };
  return { signed: done.signed, ...landed, bytes, h: done.h, ...receipt };
}

/** Whether the pairing's data holds an agreement that is never a charge (`agreement.only`). */
function isAgreementOnly(binding: Binding): boolean {
  const data: unknown = (binding as { data?: unknown }).data;
  const agreement = isObject(data) ? data["agreement"] : undefined;
  return isObject(agreement) && agreement["only"] === true;
}

/**
 * The return after an agreement (the protocol package's profile `legal-context-return.md`): the ATR fetched from the
 * response's link, compared with its H and with the return value's, parsed, and its request commitment held to the
 * buyer's request; then, for each agreement option in document order and each charge it names as served, `x402/<i>`,
 * the option at index `i` of the ATR's `x402` slot, the first such charge the pairing reads and the account can pay is
 * chosen, and that agreement option is paid, asked of the approver as the act `agreement`, and its receipt awaited. No
 * charge is signed. A pairing whose agreement is never a charge, or a response with no such charge, is
 * `no-payable-option`.
 */
async function toReturn(
  doc: unknown,
  binding: Binding,
  offers: NonNullable<ReturnType<typeof agreementOptions>>,
  o: {
    signer: Signer;
    account: string;
    fetch: Fetch;
    resourceRequest: ResourceRequest;
    returned: LegalContextReturn | undefined;
    approval: Approval;
    signal: AbortSignal | undefined;
  },
): Promise<ToReturn | Declined> {
  const { read } = offers[0]!;
  const url = (read as { agreement?: unknown }).agreement;
  if (typeof url !== "string") return declined("agreement-not-offered", "The first response names no agreement URL.");
  if (!isHttpsLink(read.link)) {
    return declined("link-not-https", `x402/${isOtherSchemeLink(read.link) ? "link-not-https" : "legal-context-malformed"}`);
  }
  const bytes = await fetchAtr(o.fetch, read.link);
  if (!(bytes instanceof Uint8Array)) return bytes;
  const h = await hash(bytes);
  if (!hashEquals(read.h, h) || (o.returned !== undefined && !hashEquals(o.returned.h, h))) {
    return declined("hash-mismatch", "The bytes the link served do not hash to the advertised ATR hash.");
  }
  const parsed = parseAtr(bytes);
  if ("decline" in parsed) return parsed;
  const otherRequest = await requestHeld(binding, parsed.value, o.resourceRequest);
  if (otherRequest !== undefined) return otherRequest;
  if (isAgreementOnly(binding)) return declined("no-payable-option", "x402/no-payable-option");

  const slot = isObject(parsed.value) ? parsed.value["x402"] : undefined;
  const listed = isObject(slot) && Array.isArray(slot["accepts"]) ? (slot["accepts"] as unknown[]) : [];
  const piece = pieceOf(binding) as BuyerPiece;
  const reader = binding as unknown as { read(d: unknown): unknown };
  const inputs: Inputs = o.approval.inputs;
  for (const { option, serves } of offers) {
    for (const name of serves) {
      const at = /^x402\/([0-9]+)$/.exec(name);
      const charge = at === null ? undefined : listed[Number(at[1])];
      if (!isObject(charge)) continue;
      const only = { ...(doc as object), accepts: [charge] };
      const chargeRead = reader.read(only);
      if (isRefusal(chargeRead)) continue;
      const chosen = await piece.choose(chargeRead as never, o.account, inputs, Math.floor(Date.now() / 1000), newRef(), only);
      if (isRefusal(chosen)) continue;
      const approved = { url, option, required: doc as never };
      const agreed = await exchange(bytes, url, o.signer, o.fetch, { approved, inputs, signal: o.signal, chosen }, "x402", binding, o.approval);
      if (!("receipt" in agreed)) return "decline" in agreed ? agreed : declined("agreement-failed", "The agreement was not paid.");
      const header = toLegalContextHeader(h, o.returned?.returnValue);
      if (isRefusal(header)) return declined("offer-unreadable", header.code);
      return { agreement: agreed.receipt, legalContext: header, charge: name, bytes, h };
    }
  }
  return declined("no-payable-option", "x402/no-payable-option");
}

const OPTION_KEYS: readonly string[] = [
  "approver",
  "resourceRequest",
  "inputs",
  "ceilings",
  "legalContext",
  "agreementSigner",
  "approved",
  "signal",
];

/**
 * Whether `transact`'s options are an object holding `approver` (a function) and `resourceRequest` (an object), and
 * only these optional members: `inputs` (an object), `ceilings` (an object), `legalContext` (a string),
 * `agreementSigner` (an object with a `sign` function and a string `account`), `approved` (an object) and `signal` (an
 * `AbortSignal`).
 */
function optionsOk(options: unknown): options is TransactOptions {
  if (!isObject(options) || !Object.keys(options).every((k) => OPTION_KEYS.includes(k))) return false;
  const { approver, resourceRequest, inputs, ceilings, legalContext, agreementSigner, approved, signal } = options;
  if (typeof approver !== "function" || !isObject(resourceRequest)) return false;
  if (inputs !== undefined && !isObject(inputs)) return false;
  if (!isCeilings(ceilings)) return false;
  if (legalContext !== undefined && typeof legalContext !== "string") return false;
  if (approved !== undefined && !isObject(approved)) return false;
  if (signal !== undefined && !(signal instanceof AbortSignal)) return false;
  if (agreementSigner === undefined) return true;
  return isObject(agreementSigner) && typeof agreementSigner["sign"] === "function" && hasAccount(agreementSigner);
}
