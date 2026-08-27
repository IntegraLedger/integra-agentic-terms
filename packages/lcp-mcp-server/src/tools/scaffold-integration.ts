import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { readOnlyToolAnnotations } from "../annotations.js";

const inputSchema = z.object({
  target: z
    .enum(["seller", "buyer"])
    .describe(
      "Which side to scaffold: 'seller' (publish legal-context.json and place the reference) or " +
        "'buyer' (verify before signing or paying).",
    ),
});

const outputSchema = z.object({
  target: z.enum(["seller", "buyer"]).describe("The side that was scaffolded."),
  scaffold: z
    .string()
    .describe("Markdown: the steps, and the code to paste, for that side."),
});

const SELLER_SCAFFOLD = `# LCP seller integration

Two obligations, and the second is the one most integrations forget.

## 1. Publish /.well-known/legal-context.json

Terms must be a standalone, downloadable artifact at a stable URL (LCP §2.2) — not a section of a page,
not dynamically rendered HTML. The atrHash is the SHA-256 over the exact bytes you serve.

\`\`\`ts
import { emit } from "@integraledger/lcp-discovery";
import { hashAtr } from "@integraledger/lcp-kernel";

// A bare \`fetch\` is right HERE and wrong on the buyer side, and the asymmetry is the point: this URL is
// YOUR OWN, chosen by you at build time. The buyer fetches a URL a counterparty chose, which is why the
// buyer scaffold below goes through the SSRF-guarded fetcher instead.
const bytes = new Uint8Array(await (await fetch(TERMS_URL)).arrayBuffer());

// emit() drops undefined fields and validates the result — a malformed profile throws here,
// at build time, rather than 404-ing an agent later.
export const legalContext = emit({
  terms: TERMS_URL,
  termsFormat: "markdown",          // an LCP §2.5 token: markdown | json | plain | html | pdf
  atrHash: await hashAtr(bytes),
  acceptanceRequired: true,          // Level 3: explicit signed acceptance before transacting
  disputeResolution: { method: "...", jurisdiction: "..." },   // Level 4
});

// Serve it, with the exact bytes you hashed still at TERMS_URL:
//   GET /.well-known/legal-context.json  ->  Response.json(legalContext)
\`\`\`

Recompute and republish the hash on EVERY terms change. A stale atrHash halts every conformant buyer.

## 2. Carry the reference on the transaction itself

The discovery document says what your terms are. It does not bind them to a particular transaction —
that is the placement's job, and where it goes is the host protocol's decision, not yours.

\`\`\`ts
import { placementFor } from "@integraledger/lcp-placements";

const adapter = placementFor("acp");            // or x402, ucp, ap2, ack, mpp, a2a, visa-tap …
const outcome = adapter?.place(
  { type: "sha256", value: legalContext.atrHash },
  checkoutSession,
);
if (outcome === undefined || !("ok" in outcome)) throw new Error("no placement — halt");
send(outcome.value);
\`\`\`

Or call the \`lcp_place_reference\` tool on this server, which dispatches through the same registry.

An x402 seller gets both halves plus the settlement weld from Integra's separately licensed seller layer,
which is not part of this open one — flagged so you know what completes the picture, not as something you
can npm-install from here.
`;

const BUYER_SCAFFOLD = `# LCP buyer-agent integration — verify BEFORE you sign or pay (LCP §5.3)

The rule: fetch the terms the counterparty advertised, recompute the fingerprint, and HALT before the
signing key is invoked if it does not match.

## The check itself

Both URLs below are the COUNTERPARTY's, so both are fetched through the guarded fetcher — HTTPS-only,
\`redirect: "error"\`, every resolved address re-checked public unicast on every fetch, body capped while
streaming. A bare \`fetch\` here is an SSRF primitive an agent can be talked into aiming anywhere.

\`\`\`ts
import { makeCachingFetcher, nodeDnsLookup } from "@integraledger/agentic-terms";
import { checkListingIntegrity, parseLegalContextJson } from "@integraledger/lcp-discovery";
import { isAtrHash } from "@integraledger/lcp-kernel";

const fetcher = makeCachingFetcher({
  httpFetch: fetch,
  now: () => new Date().toISOString(),
  lookup: nodeDnsLookup,
});

const doc     = await fetcher.fetch(\`\${SELLER_ORIGIN}/.well-known/legal-context.json\`);
const listing = parseLegalContextJson(JSON.parse(new TextDecoder().decode(doc.bytes)));

// \`atrHash\` is optional on the record: absent is LCP Level 1, where there is nothing to verify at all.
// Treat that as a halt, not a pass — the honest answer is that this cannot say the terms are the ones
// committed to.
if (listing.atrHash === undefined || !isAtrHash(listing.atrHash))
  throw new Error("no verifiable fingerprint declared (Level 1) — refusing to pay on an unproven record");

const terms = await fetcher.fetch(listing.terms);
const dsc2  = await checkListingIntegrity(listing, terms.bytes, listing.atrHash);

if (!dsc2.ok) throw new Error(\`LCP verification failed: \${dsc2.detail} — refusing to pay\`);
\`\`\`

Or call the \`lcp_verify_before_pay\` tool on this server, which does exactly this.

## The gate around it

A hash check alone is not a policy. \`@integraledger/agentic-terms\` runs the whole ladder — required level,
fingerprint, the buyer's stated policy over the TYPED envelope only, coverage gaps, seller assurance —
and returns a decision that \`transact\` enforces against a gated signer, so the key is unreachable on
anything but Proceed:

\`\`\`ts
import { makeCachingFetcher, nodeDnsLookup, transact } from "@integraledger/agentic-terms";

const fetcher = makeCachingFetcher({
  httpFetch: fetch,
  now: () => new Date().toISOString(),
  lookup: nodeDnsLookup,       // the SSRF guard: the URL came from the counterparty
});
const result = await transact(proposal, policy, { fetcher, now, log }, signer);
// result.kind === "signed" only on Proceed. On Decline or Escalate the signer is never called.
\`\`\`

Two properties do the work, and neither is a matter of discipline: the typed proposal CANNOT carry
natural-language prose, so the terms body can never reach policy evaluation (the prompt-injection
boundary is architectural, LCP §12.7); and a coverage gap is resolved by the buyer's STATED disposition,
never by a silent default.

Retain the fetched bytes. They are the evidence of what you saw (LCP §5.4).
`;

/**
 * `lcp_scaffold_integration` — copy-pasteable starter code for either side of an LCP integration.
 *
 * BOTH SCAFFOLDS HAND THE INTEGRATOR THE SHIPPED PACKAGES, deliberately. The alternative an integrator
 * reaches for unaided is a hand-rolled zero-dependency verifier — a `createHash("sha256")`, a hand-parsed
 * JWS, and a fetch with no SSRF posture — which is exactly the code nobody should be writing themselves,
 * and which drifts from the standard the moment the standard moves.
 *
 * The `target` tokens are `seller` and `buyer`, matching the vocabulary the rest of this stack uses. The
 * seller scaffold covers BOTH obligations: publishing the discovery document is not the whole integration,
 * because it binds no particular transaction.
 */
export function registerScaffoldIntegration(server: McpServer): void {
  server.registerTool(
    "lcp_scaffold_integration",
    {
      description:
        "Return copy-pasteable starter code and steps for integrating LCP, for `target: 'seller'` " +
        "(publish legal-context.json and carry the reference on the transaction) or `target: 'buyer'` " +
        "(verify before signing or paying). The code uses the shipped @integraledger packages.",
      inputSchema,
      outputSchema,
      annotations: readOnlyToolAnnotations(
        "Scaffold an LCP integration",
        "closed",
      ),
    },
    (args) => {
      const out = {
        target: args.target,
        scaffold: args.target === "seller" ? SELLER_SCAFFOLD : BUYER_SCAFFOLD,
      };
      return {
        content: [{ type: "text" as const, text: out.scaffold }],
        structuredContent: out,
      };
    },
  );
}
