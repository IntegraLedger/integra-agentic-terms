import type { Assurance } from "@integraledger/lcp-authority";
import { z } from "zod";

/** The TYPED inputs the gate decides on. It CANNOT carry natural-language prose — the prompt-injection
 *  boundary is architectural (LCP §12.7). Prose is fetched and retained as evidence, never fed to policy. */
export interface GateProposal {
  readonly advertisedAtrHash: `0x${string}`;
  readonly legalContextUrl: string;
  readonly level: 1 | 2 | 3 | 4;
  readonly offer: {
    readonly amount: string;
    readonly unit: string;
  };
  readonly sellerAssurance: Assurance;
}

/**
 * Context the host challenge does NOT carry — the buyer's client establishes it: the LCP trust level and
 * the seller's stated assurance.
 *
 * **There is deliberately no offer-validity window here.** An earlier shape carried `validFrom`/`validUntil`
 * on every proposal and the gate read neither, which told a reader that expiry was gated when it was not.
 * The window is not a gap to fill: whether a quote has gone stale is AGENT OPERATIONS, and LCP has no
 * opinion on those — its subject is that final terms are provably bound to the payment. This gate's job
 * stops at the binding. A buyer that wants offer-expiry policy holds it in its own client, where the
 * decision belongs, and reaches `transact` only when it still intends to pay.
 */
export interface ProposalContext {
  readonly level: 1 | 2 | 3 | 4;
  readonly sellerAssurance: Assurance;
}

// Module-internal structural view of the x402 402 wire format (NOT the seller's type — buyer ≠ seller).
// z.object strips unknown keys, so a real challenge's other fields (scheme/payTo/x402Version) are harmlessly
// ignored. Kept internal + not z.infer-exported (isolatedDeclarations).
//
// x402 v2 carries the reference in TWO Tier A places and BOTH are optional here: the per-requirement
// `accepts[].extra` and the challenge-level `extensions.legalContext` map. Requiring `extra` — as this
// schema did — rejected a spec-legal seller that advertises only in `extensions`, which is a carrier shape
// real seller implementations emit. Which one is present is resolved below, not here:
// Zod's job is the shape, and "at least one of two carriers, agreeing if both" is a rule about meaning.
const X402ChallengeSchema = z.object({
  accepts: z
    .array(
      z.object({
        amount: z.string(),
        network: z.string(),
        asset: z.string(),
        extra: z
          .object({
            atrHash: z.string().optional(),
            legalContextUrl: z.string().optional(),
          })
          .optional(),
      }),
    )
    .min(1),
  extensions: z
    .object({
      legalContext: z.object({
        info: z.object({
          type: z.string(),
          value: z.string(),
          legalContextUrl: z.string().optional(),
        }),
      }),
    })
    .optional(),
});

/**
 * Reconcile ONE field across x402's two Tier A carriers.
 *
 * Field-by-field, not carrier-by-carrier, because the two carriers are not required to be symmetric. LCP
 * v1.38 §C.4's own illustration puts `atrHash` + `legalContextUrl` in `accepts[].extra` while
 * `extensions.legalContext.info` carries only `type` + `value` — so treating each carrier as an atomic
 * {hash, url} pair rejects the spec's canonical example.
 *
 * `accepts[].extra` wins when both agree, because it is the per-requirement carrier and binds to the
 * requirement actually being paid. Disagreement is NOT resolved by preference: two different values on one
 * challenge would let a seller advertise different terms to different readers of the same document, and a
 * buyer that quietly picked one would gate against terms the seller can later disown. That refuses.
 */
function reconcileField(
  field: string,
  fromExtra: string | undefined,
  fromExtensions: string | undefined,
  equal: (a: string, b: string) => boolean,
): string {
  if (fromExtra !== undefined && fromExtensions !== undefined) {
    if (!equal(fromExtra, fromExtensions))
      throw new Error(
        `x402 carriers disagree on ${field} — accepts[].extra advertises "${fromExtra}", ` +
          `extensions.legalContext advertises "${fromExtensions}"`,
      );
    return fromExtra;
  }
  const only = fromExtra ?? fromExtensions;
  if (only === undefined)
    throw new Error(
      `x402 challenge advertises no ${field} — neither accepts[].extra nor extensions.legalContext carries one`,
    );
  return only;
}

const ATR_HASH = /^0x[0-9a-fA-F]{64}$/;
const BASE_UNIT_INT = /^[0-9]+$/; // decimal base-unit integer — no sign, no decimal point, non-empty

/** Parse an x402 402 challenge into a typed GateProposal (the LCP §12.7 boundary — no prose field on the type).
 *  Fail-fast (throws) on a malformed challenge, a non-0x-32-byte atrHash, a non-HTTPS terms URL, or a
 *  non-base-unit-integer amount (this closes the empty/decimal-amount crack at the trust boundary). */
export function parseProposalFromChallenge(
  challenge: unknown,
  ctx: ProposalContext,
): GateProposal {
  const parsed = X402ChallengeSchema.parse(challenge);
  // THE FIRST REQUIREMENT, DELIBERATELY, AND THE GATE DOES NOT CHOOSE.
  //
  // x402's `accepts` is a list of ALTERNATIVE payment requirements. Which one to pay is the agent's own
  // decision — a matter of rails, balances and preference — and this gate has no opinion on it, because
  // choosing how to pay is agent operations rather than binding terms to a payment. A caller that wants a
  // different requirement narrows `accepts` to it BEFORE calling, and gets a proposal gated against that
  // one; the amount checked against the buyer's cap is always the amount on the requirement passed in.
  //
  // What this must never become is a preference rule invented here. Reconciling the reference across two
  // carriers refuses on disagreement precisely because a silent choice lets a seller disown whichever
  // reading lost; a silent choice of REQUIREMENT would gate the buyer against a price it did not pick.
  const req = parsed.accepts[0];
  if (req === undefined)
    throw new Error("x402 challenge has no accepted requirement");
  // The extensions carrier states its own carrier type; anything but sha256 is refused rather than read,
  // because `advertisedAtrHash` is compared against a recomputed record hash and nothing else can be.
  const info = parsed.extensions?.legalContext.info;
  if (info !== undefined && info.type !== "sha256")
    throw new Error(
      `x402 extensions.legalContext.info.type must be sha256, got "${info.type}"`,
    );
  const atrHash = reconcileField(
    "atrHash",
    req.extra?.atrHash,
    info?.value,
    (a, b) => a.toLowerCase() === b.toLowerCase(), // hex is case-insensitive; the ATR-canon any-case rule
  );
  const legalContextUrl = reconcileField(
    "legalContextUrl",
    req.extra?.legalContextUrl,
    info?.legalContextUrl,
    (a, b) => a === b,
  );
  if (!ATR_HASH.test(atrHash))
    throw new Error(
      `advertised atrHash is not a 0x-prefixed 32-byte hex: ${atrHash}`,
    );
  if (!legalContextUrl.startsWith("https://"))
    throw new Error(`legalContextUrl must be HTTPS: ${legalContextUrl}`);
  if (!BASE_UNIT_INT.test(req.amount))
    throw new Error(
      `offer amount must be a base-unit integer string: "${req.amount}"`,
    );
  return {
    advertisedAtrHash: atrHash as `0x${string}`,
    legalContextUrl,
    level: ctx.level,
    offer: {
      amount: req.amount,
      unit: `${req.network}:${req.asset}`,
    },
    sellerAssurance: ctx.sellerAssurance,
  };
}
