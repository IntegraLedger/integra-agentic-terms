/**
 * `transact` is the gate's checks, the agreement payment when the pairing's payment is not itself a public proof, the
 * signer, then `finish`. Every signing, the agreement payment's among them, is first held to its summary and its
 * ceiling and asked of the caller's approver, and the signer is called only for what it approves (terms' profile
 * `buyer-gate.md`, checks 1 to 12). The agreement payment is also returned for the buyer's agent to approve before
 * anything is signed: the first call returns it in `approve`, and a second call with that payment as `approved` pays it
 * and then the resource.
 */
import { fromLegalContextHeader, servesOf, toLegalContextHeader, type LegalContextReturn } from "@integraledger/lcp";
import { hash, hashEquals, isHttpsLink, isOtherSchemeLink, type AtrHash, type Json } from "@integraledger/lcp/core";
import { pairingsOf, type MppChallenge } from "@integraledger/lcp/mpp";
import { agreementOptions, exchange, mppAgreementOptions } from "./agreement.js";
import { floorMissing, isCeilings, LISTING, parseAtr, requestHeld, servedBy, type Approval } from "./checks.js";
import {
  charged,
  declined,
  fetchAtr,
  gate,
  givenChoice,
  hasAccount,
  isAgreementOnly,
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
  AgreementChallenges,
  AgreementReceipt,
  Binding,
  BuyerPiece,
  Chosen,
  Declined,
  Fetch,
  Inputs,
  Presented,
  Read,
  ResourceRequest,
  Signer,
  ToApprove,
  ToReturn,
  TransactOptions,
} from "./types.js";

/**
 * The gate's checks, then, for a pairing whose payment is not itself a public proof, the agreement, paid only on an
 * option the pairing's `agreementOn` admits, then the signer, then `finish`. Without `approved`, an agreement not yet
 * recorded is returned as `approve`, the agreement payment for the agent to approve, and nothing is signed; with `approved`, that payment is asked of `approver`, signed and paid,
 * and the resource's payment is asked of `approver` and signed only with the agreement's receipt in hand. On a decline
 * before the signer the signer is never called. Where the build is itself the payment the signer is not called; where
 * the pairing has nothing for the buyer to sign, `signed` is null after the comparison. `agreement` is the agreement's
 * receipt, where the pairing needs one. `landed` is `finish`'s, where it gives one. `signal` ends the agreement
 * exchange. Options that are not an object holding a function `approver` and an object `resourceRequest`, or that hold
 * a member of another name or form, or a signer or agreement signer whose `account` is not a string, are declined
 * `no-payable-option` with `<namespace>/input-malformed` before any fetch or signer call.
 *
 * With `chosen`, the payment `confirm` chose, unchanged, the gate builds that exact request, the one the approver
 * approved, instead of choosing anew with its clock and a new reference.
 *
 * Where the pairing is paid after its agreement and the first response offers the agreement and no charge option, its
 * every option naming the charges it serves, `transact` pays the agreement and returns `ToReturn` (`toReturn`). On a
 * pairing of `card`, `acp`, `ap2`, `ucp` or `ack`, whose own document offers no agreement option, such a response is an
 * x402 one (`agreementOptions`), else an MPP one (`mppAgreementOptions`), and `binding` is the charge's pairing.
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
  | AgreementChallenges
  | ToReturn
  | Declined
> {
  if (pieceOf(binding) === undefined) return unsupported(binding);
  const ns = namespaceOf(binding);
  if (!optionsOk(options, String(binding.id)) || !hasAccount(signer)) return declined("no-payable-option", `${ns}/input-malformed`);
  const { approver, resourceRequest, inputs = {}, ceilings, legalContext, agreementSigner, approved, signal, chosen: given } = options;
  const floor = floorMissing(String(binding.id), inputs);
  if (floor !== undefined) return floor;
  let returned: LegalContextReturn | undefined;
  if (legalContext !== undefined) {
    const read = fromLegalContextHeader(legalContext);
    if (isRefusal(read)) return declined("offer-unreadable", read.code);
    returned = read;
  }
  const approval = { approver, ceilings, inputs };

  const offered = isFullCoverage(binding) ? undefined : agreementOffered(doc, ns);
  if (offered !== undefined && "decline" in offered) return offered;
  if (offered !== undefined) {
    const o = { signer: agreementSigner ?? signer, account: signer.account, fetch, resourceRequest, returned, approval, signal };
    return toReturn(doc, binding, offered.offers, offered.via, o);
  }

  const confirmed = await gate(doc, binding, signer.account, fetch, { resourceRequest, inputs, ceilings, chosen: given });
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

/** An agreement option of a first response, x402's or MPP's, the read of the response holding it, and what it serves. */
interface Offered {
  readonly option: unknown;
  readonly read: Read;
  readonly serves: readonly string[];
}

/** What the return path reads beside the first response: the agreement signer, the account, and the call's members. */
interface ReturnArgs {
  signer: Signer;
  account: string;
  fetch: Fetch;
  resourceRequest: ResourceRequest;
  returned: LegalContextReturn | undefined;
  approval: Approval;
  signal: AbortSignal | undefined;
}

/** The namespaces of the pairings whose own document offers no agreement option and whose charge an agreement serves. */
const SERVED_SLOTS: readonly string[] = ["card", "acp", "ap2", "ucp", "ack"];

/**
 * The agreement options of a first response that offers the agreement and no charge option, and the protocol offering
 * them, `via`: on x402 `agreementOptions`, on MPP `mppAgreementOptions`, and on a pairing of `card`, `acp`, `ap2`, `ucp`
 * or `ack` the first of the two that reads the response. Undefined where neither reads it; a decline where the read
 * declines it.
 */
function agreementOffered(doc: unknown, ns: string): { offers: Offered[]; via: "x402" | "mpp" } | Declined | undefined {
  const of = (read: ReturnType<typeof agreementOptions> | ReturnType<typeof mppAgreementOptions>, via: "x402" | "mpp") =>
    read === undefined || "decline" in read ? read : { offers: read as Offered[], via };
  if (ns === "x402") return of(agreementOptions(doc), "x402");
  if (ns === "mpp") return of(mppAgreementOptions(doc), "mpp");
  if (!SERVED_SLOTS.includes(ns)) return undefined;
  return of(agreementOptions(doc), "x402") ?? of(mppAgreementOptions(doc), "mpp");
}

/**
 * The return after an agreement (the protocol package's profile `legal-context-return.md`): the ATR fetched from the
 * response's link, compared with its H and with the return value's, and parsed; each agreement option's served names
 * resolved against those bytes (`servesOf`), a name whose slot is not the ATR's binding slot, or whose index is not
 * below the number of charge options that slot holds, declining the response `offer-unreadable` with
 * `return/serves-malformed`; and the ATR's request commitment held to the buyer's request; then, for each agreement
 * option in the seller's order and each charge it names as served, `<slot>/<i>`, the option at index `i` of the list
 * the ATR's binding slot of the pairing's protocol holds (`accepts` in `x402`, `challenges` in `mpp`, `options` in
 * `card`, `acp`, `ap2` and `ucp`, `paymentOptions` in `ack`), the first such charge the account can pay is chosen
 * (`choice`), and its agreement paid. `via` is the protocol of the agreement options, the pairing's own on x402 and
 * MPP. On x402 the agreement option is paid at the agreement URL as offered. On MPP, whose first response offers MPP
 * agreement challenges, which terms builds no credential for, the agreement URL is followed: an x402 agreement option
 * its 402 offers is paid as on x402, and where it offers only MPP agreement challenges, they are returned in
 * `agreementChallenges` for the caller's own MPP client, nothing signed. Each agreement payment is asked of the
 * approver as the act `agreement`. No charge is signed, and no agreement is paid for a charge checks 9 to 11 decline:
 * the next served charge is tried, and where every one is declined there, the first decline is returned. A pairing
 * whose agreement is never a charge, or a response with no such charge, is `no-payable-option`.
 */
async function toReturn(
  doc: unknown,
  binding: Binding,
  offers: readonly Offered[],
  via: "x402" | "mpp",
  o: ReturnArgs,
): Promise<ToReturn | Declined> {
  const { read } = offers[0]!;
  const url = (read as { agreement?: unknown }).agreement;
  if (typeof url !== "string") return declined("agreement-not-offered", "The first response names no agreement URL.");
  if (!isHttpsLink(read.link)) {
    return declined("link-not-https", `${via}/${isOtherSchemeLink(read.link) ? "link-not-https" : "legal-context-malformed"}`);
  }
  const bytes = await fetchAtr(o.fetch, read.link);
  if (!(bytes instanceof Uint8Array)) return bytes;
  const h = await hash(bytes);
  if (!hashEquals(read.h, h) || (o.returned !== undefined && !hashEquals(o.returned.h, h))) {
    return declined("hash-mismatch", "The bytes the link served do not hash to the advertised ATR hash.");
  }
  const parsed = parseAtr(bytes);
  if ("decline" in parsed) return parsed;
  for (const { option } of offers) {
    const resolved = servesOf(option, bytes);
    if (isRefusal(resolved)) return declined("offer-unreadable", resolved.code);
  }
  const otherRequest = await requestHeld(binding, parsed.value, o.resourceRequest);
  if (otherRequest !== undefined) return otherRequest;
  const slot = namespaceOf(binding);
  if (isAgreementOnly(binding)) return declined("no-payable-option", `${slot}/no-payable-option`);

  const held = isObject(parsed.value) ? parsed.value[slot] : undefined;
  const list = isObject(held) ? held[LISTING[slot]!] : undefined;
  const listed: readonly unknown[] = Array.isArray(list) ? list : [];
  const named = new RegExp(`^${slot}/([0-9]+)$`);
  const header = toLegalContextHeader(h, o.returned?.returnValue);
  if (isRefusal(header)) return declined("offer-unreadable", header.code);
  let first: Declined | undefined;
  for (const { option, serves } of offers) {
    for (const name of serves) {
      const at = named.exec(name);
      const charge = at === null ? undefined : listed[Number(at[1])];
      if (!isObject(charge)) continue;
      const chosen = await choice(binding, slot, doc, charge, { h, link: read.link, agreement: url }, bytes, o);
      if (chosen === undefined) continue;
      if ("decline" in chosen) {
        first ??= chosen;
        continue;
      }
      const returned = { legalContext: header, charge: name, bytes, h };
      if (via === "x402") {
        const approved = { url, option: option as never, required: doc as never };
        const agreed = await exchange(bytes, url, o.signer, o.fetch, { approved, inputs: o.approval.inputs, signal: o.signal, chosen }, "x402", binding, o.approval);
        if (!("receipt" in agreed)) return "decline" in agreed ? agreed : declined("agreement-failed", "The agreement was not paid.");
        return { agreement: agreed.receipt, ...returned };
      }
      const given = { inputs: o.approval.inputs, signal: o.signal, chosen };
      const offered = await exchange(bytes, url, o.signer, o.fetch, given, "mpp", binding, o.approval);
      if ("decline" in offered) return offered;
      if ("receipt" in offered) return { agreement: offered.receipt, ...returned };
      if ("agreementChallenges" in offered) return { agreementChallenges: offered.agreementChallenges, ...returned };
      const agreed = await exchange(bytes, url, o.signer, o.fetch, { ...given, approved: offered.approve }, "mpp", binding, o.approval);
      if (!("receipt" in agreed)) return "decline" in agreed ? agreed : declined("agreement-failed", "The agreement was not paid.");
      return { agreement: agreed.receipt, ...returned };
    }
  }
  return first ?? declined("no-payable-option", `${slot}/no-payable-option`);
}

/**
 * The charge `charge`, an option of the ATR's binding slot, chosen for the account; undefined where the pairing does
 * not offer it or the account cannot pay it, and the decline of checks 9 to 11 where they decline it. Where the
 * pairing reads the slot's option in the first response's form, the choice is made from that read and checks 9 to 11
 * (its build with H, its summary and its ceiling) are made on it before its agreement is paid. Where the slot holds the
 * option without what its read needs and the seller writes only once it serves the charge, the choice is made by the
 * option's own checks and checks 9 to 11 are left to the call that pays the charge: an x402 option whose carrier the
 * seller writes after the agreement, held to the pairing's `advertiseBeforeCarrier`, the protocol package's checks of
 * the offer before that carrier (an `x402/exact/lnbtc/payment-hash` option, whose invoice is issued after the
 * agreement); and every MPP challenge, which the slot holds as issued, without the id and the members the seller
 * places when it serves it, held to the pairing's own checks of a challenge (`pairingsOf`). On `card`, `acp`, `ap2`,
 * `ucp` and `ack`, whose charge the second response offers, the choice is the slot's option, where the pairing pays it
 * for the account (`servedBy`), and checks 9 to 11 are left to the call that pays the charge.
 */
async function choice(
  binding: Binding,
  slot: string,
  doc: unknown,
  charge: Record<string, unknown>,
  placed: { h: AtrHash; link: string; agreement: string },
  bytes: Uint8Array,
  o: ReturnArgs,
): Promise<Chosen | Declined | undefined> {
  if (slot !== "x402" && slot !== "mpp") {
    return servedBy(binding, charge, o.account) ? { pairing: String(binding.id), choice: charge as Json, ref: newRef() } : undefined;
  }
  const piece = pieceOf(binding) as BuyerPiece;
  const inputs: Inputs = o.approval.inputs;
  const choose = async (read: unknown, only: unknown): Promise<Chosen | undefined> => {
    const chosen = await piece.choose(read as never, o.account, inputs, Math.floor(Date.now() / 1000), newRef(), only);
    return isRefusal(chosen) ? undefined : chosen;
  };
  if (slot === "mpp") {
    const pairings = pairingsOf(charge as unknown as MppChallenge);
    if (isRefusal(pairings) || !pairings.some((p) => p === binding.id)) return undefined;
    return choose({ ...placed, offer: { challenges: [charge] } }, [charge]);
  }
  const only = { ...(doc as object), accepts: [charge] };
  const read = (binding as unknown as { read(d: unknown): unknown }).read(only);
  if (isRefusal(read)) {
    const before = (binding as { advertiseBeforeCarrier?: (...a: unknown[]) => unknown }).advertiseBeforeCarrier;
    if (typeof before !== "function" || isRefusal(before(only, placed.h, placed.link, charge, placed.agreement))) return undefined;
    return choose({ ...placed, offer: { required: only, options: [charge] } }, only);
  }
  const chosen = await choose(read, only);
  if (chosen === undefined) return undefined;
  const checked = await charged(binding, { ...chosen, agreement: placed.agreement }, o.account, bytes, placed.h, inputs, o.approval.ceilings);
  return "decline" in checked ? checked : chosen;
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
  "chosen",
];

/**
 * Whether `transact`'s options are an object holding `approver` (a function) and `resourceRequest` (an object), and
 * only these optional members: `inputs` (an object), `ceilings` (rule 8's form for `pairing`), `legalContext` (a
 * string), `agreementSigner` (an object with a `sign` function and a string `account`), `approved` (an object),
 * `signal` (an `AbortSignal`) and `chosen` (of `confirm`'s `chosen` form for `pairing`).
 */
function optionsOk(options: unknown, pairing: string): options is TransactOptions {
  if (!isObject(options) || !Object.keys(options).every((k) => OPTION_KEYS.includes(k))) return false;
  const { approver, resourceRequest, inputs, ceilings, legalContext, agreementSigner, approved, signal, chosen } = options;
  if (typeof approver !== "function" || !isObject(resourceRequest)) return false;
  if (chosen !== undefined && givenChoice(chosen, pairing) === undefined) return false;
  if (inputs !== undefined && !isObject(inputs)) return false;
  if (!isCeilings(ceilings, pairing)) return false;
  if (legalContext !== undefined && typeof legalContext !== "string") return false;
  if (approved !== undefined && !isObject(approved)) return false;
  if (signal !== undefined && !(signal instanceof AbortSignal)) return false;
  if (agreementSigner === undefined) return true;
  return isObject(agreementSigner) && typeof agreementSigner["sign"] === "function" && hasAccount(agreementSigner);
}
