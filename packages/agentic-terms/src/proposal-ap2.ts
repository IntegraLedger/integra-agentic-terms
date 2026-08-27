/**
 * The AP2 buyer surface: read the LCP reference off the transport envelope that carries an AP2 mandate, and
 * name the moment "verify before sign" is measured against.
 *
 * AP2 is the one wire in this set where the sign moment is genuinely ambiguous. x402 has one (the EIP-3009
 * authorization), ACP has one (the checkout confirmation). AP2 has FOUR mandates — Checkout and Payment,
 * each in an Open and a Closed stage — signed by different keys in different modes. A gate that says "verify
 * before sign" without saying WHICH sign is a gate that cannot be audited, so `AP2_HALT_POINT` names it, and
 * `parseProposalFromAp2Envelope` refuses to run at or after it.
 */

import { ap2Placement } from "@integraledger/lcp-placement-ap2";
import type { GateProposal, ProposalContext } from "./proposal.js";

/**
 * The steps of AP2 v0.2's authorization flow, in the order a Shopping Agent passes through them. CLOSED —
 * an unknown token is a wire this parser has no halt point for, and inventing one would be the whole defect
 * this type exists to prevent.
 *
 * `agent-key-signing` occurs in Autonomous mode only; `key-binding-presentation` is the `kb+sd-jwt` binding
 * made when the closed mandate is PRESENTED to the merchant, which is why it is a separate step from the
 * signature that created the mandate.
 */
export type Ap2Step =
  | "checkout-jwt-received"
  | "mandate-content-built"
  | "trusted-surface-authorization"
  | "agent-key-signing"
  | "key-binding-presentation";

/** The named sign moment, its defence, and the last step at which gating is still meaningful. */
export interface Ap2HaltPoint {
  /** The last step at which no signing key has been invoked — where the gate must have finished. */
  readonly lastSafeStep: Ap2Step;
  /** The first step at which a signing key IS invoked. The gate halts strictly before this. */
  readonly haltBefore: Ap2Step;
  /** Every step at which some key signs, in flow order. `haltBefore` is the first of them. */
  readonly signingSteps: readonly Ap2Step[];
  /** Why this step and not another — the argument, not a restatement of the field. */
  readonly rationale: string;
  /** The host protocol's own text this is defended against — AP2 decides its flow, not LCP's appendix. */
  readonly specRef: string;
}

/**
 * AP2's halt point: **immediately before the Trusted Surface is invoked.**
 *
 * The defence, from AP2 v0.2's own specification rather than from LCP's Appendix C:
 *
 * - **Human Present (Direct).** "When a Shopping Agent has a Checkout JWT for the closed Checkout from the
 *   Merchant, they construct the Checkout and Payment Mandate Content and pass it to a Trusted Surface for
 *   display to the user and signing." The user's key signs at the Trusted Surface. Nothing signs before it.
 * - **Human Not Present (Autonomous).** "When a Shopping Agent needs to operate autonomously, it will create
 *   open Checkout and Payment Mandate Content and have these authorized by the Trusted Surface. These MUST
 *   include the agent's public key as a `cnf` claim." The Trusted Surface is invoked FIRST here too; the
 *   Shopping Agent's own Agent Key signs the closed mandates only afterwards.
 *
 * So both modes place the Trusted Surface first, and that makes it the halt point for both — the gate does
 * not need to know which mode it is in, which is the property that makes this auditable. `agent-key-signing`
 * is a later signing step, not an earlier one, and gating there would already be too late.
 *
 * **And the window closes hard.** The closed Checkout Mandate carries `checkout_hash`, "a base64url-encoded
 * hash of the merchant-signed `checkout_jwt`", the Payment Mandate "is bound to a particular Checkout using
 * the cryptographic hash of the Checkout JWT", and the closed mandate is a `kb+sd-jwt` whose key-binding
 * signature is constructed over `sd_hash` **at presentation**. Once the Trusted Surface has signed, nothing
 * inside either mandate is mutable and no later verification can be turned back into a decision.
 *
 * **This is a HALT POINT, not a placement constraint.** The reference rides the transport envelope's
 * metadata, which AP2 never signs and never reads — so the SELLER may place it at any time, under no
 * ordering precondition at all. Contrast ACK, where placement must happen BEFORE the issuer signs: a field
 * added after issuance either breaks the embedded signature or falls outside the payload the host treats as
 * authoritative. What is time-critical here is the BUYER's decision, because after this step the buyer has
 * no decision left to make.
 */
export const AP2_HALT_POINT: Ap2HaltPoint = {
  lastSafeStep: "mandate-content-built",
  haltBefore: "trusted-surface-authorization",
  signingSteps: [
    "trusted-surface-authorization",
    "agent-key-signing",
    "key-binding-presentation",
  ],
  rationale:
    "Both AP2 modes invoke the Trusted Surface before any other key: in Direct mode the Shopping Agent passes the Mandate Content to it for user signing, and in Autonomous mode it authorizes the OPEN mandates before the Agent Key signs the closed ones. It is therefore the first signing step in either mode, and the closed mandate's checkout_hash plus its presentation-time key binding leave nothing mutable afterwards.",
  specRef:
    "AP2 v0.2 (google-agentic-commerce/AP2 @ main, release 0.2.0 dated 2026-04-28) docs/ap2/specification.md §Human Present / §Human Not Present, and docs/ap2/checkout_mandate.md (vct mandate.checkout.1, checkout_hash, kb+sd-jwt over sd_hash at presentation); read 2026-07-30",
};

/** Does this step invoke a signing key? Membership in `AP2_HALT_POINT.signingSteps`, as a function. */
export function isAp2SigningStep(step: Ap2Step): boolean {
  return AP2_HALT_POINT.signingSteps.includes(step);
}

/**
 * Throw unless the client is still strictly before the halt point.
 *
 * Fail-fast rather than a returned flag: a caller that gates at `agent-key-signing` has already handed the
 * user's key to the Trusted Surface, and there is no honest outcome to report at that point — the decision
 * the gate exists to make has already been made by someone else.
 */
export function assertBeforeAp2HaltPoint(step: Ap2Step): void {
  if (isAp2SigningStep(step))
    throw new Error(
      `AP2 gate refused at "${step}": that is at or after the halt point (${AP2_HALT_POINT.haltBefore}). ` +
        `Verify before sign means gating no later than "${AP2_HALT_POINT.lastSafeStep}". ${AP2_HALT_POINT.rationale}`,
    );
}

/**
 * The context AP2's wire does NOT carry, which the buyer's client establishes — and it is more than the
 * other parsers need, for two reasons that are both properties of AP2 rather than gaps here.
 */
export interface Ap2ProposalContext extends ProposalContext {
  /**
   * The terms document's locator.
   *
   * AP2's placement is INTEGRITY-ONLY: `AP2_PLACEMENT` declares no `termsUrlFields`, because the A2A
   * `Message.metadata` map holds the reference and AP2 models no terms-URL field anywhere. So unlike ACP
   * (`metadata.legal_context_url`) and x402 (`extra.legalContextUrl`), the locator cannot come off the wire.
   * It comes from LCP §2 discovery — the seller's `/.well-known/legal-context.json` — resolved by the
   * client before it calls this parser. HTTPS is enforced here exactly as it is on every other wire.
   */
  readonly legalContextUrl: string;
  /**
   * The offer the client is about to authorize.
   *
   * AP2 v0.2 carries the price inside the merchant-signed Checkout JWT, referenced from the closed mandate
   * only by `checkout_hash`. The transport carries mandates as OPAQUE SD-JWT compact strings; this parser
   * does not decode one, and decoding one would mean trusting an unverified payload to produce the number
   * the gate compares against a policy cap. The client already holds the checkout it built its Mandate
   * Content from, so it supplies the amount it is about to commit — the honest source.
   */
  readonly offer: {
    readonly amount: string;
    readonly unit: string;
  };
  /** Where the client is in AP2's flow. At or after the halt point this parser refuses. */
  readonly step: Ap2Step;
}

const BASE_UNIT_INT = /^[0-9]+$/; // decimal base-unit integer — no sign, no decimal point, non-empty

/**
 * Parse an AP2 transport envelope into the SAME typed `GateProposal` every other wire produces.
 *
 * The reference is read through `@integraledger/lcp-placement-ap2`, never through a hand-rolled path. The
 * manifest declares both the canonical `metadata.legalContext` and the snake_case alias
 * `metadata.legal_context`; a second reader here would be a second spelling of the manifest, free to drift
 * from the one the seller writes through. It also inherits the placement's deliberate blindness to the Tier
 * B shape — a reference embedded INSIDE the mandate is not read, so a buyer cannot be walked into blessing
 * a placement no shipped package can emit, because LCP's appendix illustrates and the host protocol binds.
 *
 * Fail-fast (throws) on: a step at or after `AP2_HALT_POINT`, an envelope carrying no reference, a carrier
 * that is not `sha256`, a non-HTTPS terms URL, or a non-base-unit-integer amount.
 */
export function parseProposalFromAp2Envelope(
  envelope: unknown,
  ctx: Ap2ProposalContext,
): GateProposal {
  // FIRST, before any reading. A gate that parses and then discovers it was too late has already spent the
  // buyer's time pretending a decision was available.
  assertBeforeAp2HaltPoint(ctx.step);

  const extracted = ap2Placement.extract(envelope);
  if (!("ok" in extracted))
    throw new Error(
      `AP2 envelope carries no readable LCP reference (${extracted.haltClass}/${extracted.code})`,
    );
  // AP2 declares no terms-URL slot, so the advertisement is the reference alone.
  const ref = extracted.value.ref;
  if (ref.type !== "sha256")
    throw new Error(
      `AP2 legalContext must be a sha256 carrier, got "${ref.type}" — the gate compares the advertised ` +
        "hash against a recomputed one, and a locator commits to nothing",
    );
  if (!ctx.legalContextUrl.startsWith("https://"))
    throw new Error(`legalContextUrl must be HTTPS: ${ctx.legalContextUrl}`);
  if (!BASE_UNIT_INT.test(ctx.offer.amount))
    throw new Error(
      `offer amount must be a base-unit integer string: "${ctx.offer.amount}"`,
    );

  // No 0x-32-byte re-check: `extract` decodes through binding-core's codec, whose `sha256` validity rule IS
  // `kernel.isAtrHash`. A second copy of that regex could reject nothing the decode admitted — the same
  // asymmetry `proposal-acp.ts` documents, and for the same reason.
  return {
    advertisedAtrHash: ref.value as `0x${string}`,
    legalContextUrl: ctx.legalContextUrl,
    level: ctx.level,
    offer: {
      amount: ctx.offer.amount,
      unit: ctx.offer.unit,
    },
    sellerAssurance: ctx.sellerAssurance,
  };
}
