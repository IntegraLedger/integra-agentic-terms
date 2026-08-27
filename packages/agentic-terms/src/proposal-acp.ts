import { decodeLegalContextString } from "@integraledger/lcp-binding-core";
import { z } from "zod";
import type { GateProposal, ProposalContext } from "./proposal.js";

// Module-internal structural view of the ACP checkout session (NOT the seller's type — buyer ≠ seller).
// The session object is TOP-LEVEL and `totals` is an ARRAY (stable 2026-04-17); there is no `checkout`
// wrapper and no `total` string. z.object strips unknown keys, so a real session's many other fields are
// harmlessly ignored. Kept internal and not z.infer-exported (isolatedDeclarations), exactly as
// X402ChallengeSchema is in proposal.ts.
const AcpSessionSchema = z.object({
  currency: z.string(),
  totals: z.array(z.object({ type: z.string(), amount: z.number() })),
  metadata: z.object({
    legal_context: z.string(),
    legal_context_url: z.string(),
  }),
});

/**
 * Parse an ACP checkout session into the SAME typed `GateProposal` the x402 parser produces (the LCP §12.7
 * boundary — no prose field on the type). Fail-fast (throws) on a malformed session, a reference that is not
 * a canonical `lcp:sha256:0x…` 32-byte carrier, a non-HTTPS terms URL, a missing `total` row, or a
 * non-integer minor-unit amount.
 *
 * `legal_context_url` is required, and the ACP placement manifest DECLARES it as
 * `termsUrlFields: ["metadata.legal_context_url"]` — the field this parser demands is a field the placement
 * names, which is what makes the round-trip compose. It is deliberately NOT read from ACP's native
 * `links[type=terms_of_use]`: that link is the merchant's standing policy page, while this names the ATR
 * terms document for this transaction, and falling back to it would substitute one for the other.
 *
 * `GateProposal` and `ProposalContext` are IMPORTED, never redefined — one type for every wire is the whole
 * point of a single typed proposal, and a second copy would let the two drift.
 */
export function parseProposalFromAcpCheckout(
  session: unknown,
  ctx: ProposalContext,
): GateProposal {
  const parsed = AcpSessionSchema.parse(session);
  const { legal_context, legal_context_url } = parsed.metadata;

  // Decoded through binding-core's codec, never by slicing a prefix. The codec enforces the canonical
  // sha256 carrier form (0x-prefixed 32-byte hex) — a bare-digits value throws here rather than being
  // silently re-prefixed into something that looks valid. An earlier draft did `0x${slice(...)}`, which
  // turned a CONFORMANT 0x-carrying reference into `0x0x…` and accepted the non-canonical form instead.
  const ref = decodeLegalContextString(legal_context);
  if (ref === undefined)
    throw new Error(
      `ACP legal_context is not a parseable lcp: reference: ${legal_context}`,
    );
  if (ref.type !== "sha256")
    throw new Error(
      `ACP legal_context must be an lcp:sha256: reference, got lcp:${ref.type}:`,
    );
  // No 0x-32-byte re-check here. `decodeLegalContextString` runs `assertValidValue`, which for `sha256`
  // IS `kernel.isAtrHash` — the identical `/^0x[0-9a-fA-F]{64}$/`. A second copy of that regex could not
  // reject anything the decode admitted: it would be a branch no input reaches, permanently unkillable by
  // any test, and it would tell a reader there is a case here that there is not. The x402 parser carries
  // its own check because it reads a RAW `extra.atrHash` string that no codec has validated; this one
  // does not, and that asymmetry is the point rather than an oversight.

  if (!legal_context_url.startsWith("https://"))
    throw new Error(`legalContextUrl must be HTTPS: ${legal_context_url}`);

  // The `total` ROW, never the first row and never a sum. ACP's `totals` carries several typed rows
  // (`items_base_amount`, `tax`, `fee`, `discount`, …) and only the one typed `total` is the amount the
  // buyer is being asked to authorize. There is deliberately no fallback: a session with no `total` row is
  // malformed, and picking another row would gate the buyer against a number nobody quoted.
  const total = parsed.totals.find((t) => t.type === "total");
  if (total === undefined)
    throw new Error(
      "ACP session carries no row typed `total` — nothing to authorize against",
    );
  if (!Number.isSafeInteger(total.amount) || total.amount < 0)
    throw new Error(
      `offer amount must be a non-negative minor-unit integer: ${total.amount}`,
    );

  return {
    advertisedAtrHash: ref.value as `0x${string}`,
    legalContextUrl: legal_context_url,
    level: ctx.level,
    offer: {
      amount: String(total.amount),
      // ACP settles in a fiat currency code, not a network:asset pair — the unit string says which.
      unit: parsed.currency,
    },
    sellerAssurance: ctx.sellerAssurance,
  };
}
