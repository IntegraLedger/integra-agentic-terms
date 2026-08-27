import { isAtrHash } from "@integraledger/lcp-kernel";
import { z } from "zod";
import type { GateProposal, ProposalContext } from "./proposal.js";

// Module-internal structural view of the MPP `request` body (NOT the seller's type — buyer ≠ seller).
// `z.object` strips unknown keys, so the optional members this parser has no use for — `description`,
// `expires`, `externalId`, `recipient` — are harmlessly ignored. Kept internal and not `z.infer`-exported
// (isolatedDeclarations), exactly as `X402ChallengeSchema` and `AcpSessionSchema` are.
//
// `methodDetails` is OPTIONAL in the charge intent (draft-payment-intent-charge-00 §5.1.2, Table 3), which
// is why it is optional here and its absence is a refusal below rather than a schema error: a request body
// with no `methodDetails` is a perfectly conformant MPP document that simply advertises no LCP reference,
// and saying so is more useful than a Zod path error.
const MppRequestSchema = z.object({
  amount: z.string(),
  currency: z.string(),
  methodDetails: z
    .object({
      atrHash: z.string().optional(),
      legalContextUrl: z.string().optional(),
    })
    .optional(),
});

// Decimal base-unit integer — no sign, no decimal point, non-empty. Identical in shape to the x402 parser's
// check and required for the same reason: `policy.ts` compares the offer with `BigInt(offer.amount)`, and
// `BigInt("10.50")` THROWS rather than returning, which would escape `evaluate`'s contract to RETURN a
// `GateDecision`. The grammar is the host's, not ours: draft-payment-intent-charge-00 Table 2 defines
// `amount` as "Payment amount in base units (smallest denomination)", and §3 defines base units as "the
// smallest denomination of a currency or asset. For USD, this is cents (1/100)." Every example in the
// specification agrees — "5000"/usd, "1000000"/token, "100000"/sat — so a decimal amount is malformed MPP
// and is refused here rather than thrown from inside the gate.
const BASE_UNIT_INT = /^[0-9]+$/;

/**
 * Parse an MPP `request` body into the SAME typed `GateProposal` the x402 and ACP parsers produce (the
 * LCP §12.7 boundary — no prose field on the type). Fail-fast (throws) on a malformed body, an absent or
 * non-0x-32-byte `atrHash`, a non-HTTPS terms URL, or a non-base-unit-integer amount.
 *
 * **The document is the `request` body, not the challenge.** MPP's identity lives one layer out, in the
 * `WWW-Authenticate: Payment` challenge's auth-params; the body this parses is the base64url(JCS(JSON))
 * payload that challenge's `request` auth-param carries. A caller holding a decoded body is expected to
 * have decoded it from there.
 *
 * **BY NAME, and deliberately not in `PROPOSAL_PARSERS`.** MPP's discriminant is recorded as
 * `kind: "undiscriminable"`: the body's members are `amount` and `currency` plus optionals, and an
 * amount/currency pair is the shape of almost every payment document there is. Nothing in the body names
 * MPP. So a caller must name `mpp` and reach this function directly — the same by-name route
 * `parseProposalFromAp2Envelope` takes, and for a sibling reason. Adding an `mpp` row to the universal
 * dispatch map would not make it reachable; it would make the map claim a discrimination it cannot perform.
 *
 * **The carrier is `bare-value`, so no codec has validated it.** `placement-mpp` declares
 * `field: "methodDetails.atrHash"` with `encoding: "bare-value"` and `carrierTypes: ["sha256"]` — the wire
 * carries the raw hash rather than an `lcp:sha256:0x…` string. That is why this validates the hash itself
 * through the kernel's `isAtrHash`, as the x402 parser validates its raw `extra.atrHash`, and why it does
 * NOT call `decodeLegalContextString` as the ACP parser does. Using the kernel's own predicate rather than
 * restating its regex keeps one definition of what an ATR hash is.
 *
 * **`legalContextUrl` is the field the placement names.** `placement-mpp` declares
 * `termsUrlFields: ["methodDetails.legalContextUrl"]`, so the field this parser demands is the field the
 * manifest names — which is what makes the seller's write and this buyer's read compose. There is no
 * fallback to any other member: MPP defines none that means "these terms", and inventing one would gate the
 * buyer against a document nobody pointed at.
 *
 * **What the carrier is worth is weaker than Tier A alone suggests, and the buyer should know it.** MPP
 * binds the challenge `id` to the challenge parameters, so a client cannot alter the advertised values and
 * still be accepted — but the binding key is a server secret the specification requires implementations to
 * keep server-side, so **the buyer cannot verify that MAC.** What this reference gets is tamper-evidence,
 * not a buyer-verifiable seller commitment. The gate treats it as an advertised value to be recomputed
 * against fetched bytes, exactly as it treats every other protocol's, and that recomputation is what the
 * guarantee actually rests on.
 *
 * `GateProposal` and `ProposalContext` are IMPORTED, never redefined — one type for every wire is the whole
 * point of a single typed proposal, and a second copy would let the two drift.
 */
export function parseProposalFromMppRequest(
  request: unknown,
  ctx: ProposalContext,
): GateProposal {
  const parsed = MppRequestSchema.parse(request);

  // Absence is a refusal, not a permission. A conformant MPP body may omit `methodDetails` entirely, and
  // may carry one that names no LCP reference; neither is a document this gate can bind terms from, and
  // both are named rather than collapsed into one message so a seller reading the error knows which it is.
  const details = parsed.methodDetails;
  if (details === undefined)
    throw new Error(
      "MPP request body carries no `methodDetails` — nothing advertises an LCP reference",
    );
  const { atrHash, legalContextUrl } = details;
  if (atrHash === undefined)
    throw new Error(
      "MPP request body advertises no `methodDetails.atrHash` — the placement's declared carrier is absent",
    );
  if (legalContextUrl === undefined)
    throw new Error(
      "MPP request body advertises no `methodDetails.legalContextUrl` — the placement's declared terms-URL field is absent",
    );

  if (!isAtrHash(atrHash))
    throw new Error(
      `advertised atrHash is not a 0x-prefixed 32-byte hex: ${atrHash}`,
    );
  if (!legalContextUrl.startsWith("https://"))
    throw new Error(`legalContextUrl must be HTTPS: ${legalContextUrl}`);
  if (!BASE_UNIT_INT.test(parsed.amount))
    throw new Error(
      `offer amount must be a base-unit integer string: "${parsed.amount}"`,
    );

  return {
    advertisedAtrHash: atrHash,
    legalContextUrl,
    level: ctx.level,
    offer: {
      amount: parsed.amount,
      // MPP's `currency` is a "Currency or asset identifier" (Table 2) and spans the whole family — an ISO
      // 4217 code for `card`/`stripe`, a token address for `evm`, `sat` for `lightning`. It is carried
      // verbatim as the unit string, exactly as ACP's fiat code and x402's `network:asset` pair are: the
      // gate compares units for equality against the buyer's cap and never interprets them.
      unit: parsed.currency,
    },
    sellerAssurance: ctx.sellerAssurance,
  };
}
