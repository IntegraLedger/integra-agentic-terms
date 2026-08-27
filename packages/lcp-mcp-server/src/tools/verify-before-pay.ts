import {
  checkListingIntegrity,
  parseLegalContextJson,
} from "@integraledger/lcp-discovery";
import { isAtrHash } from "@integraledger/lcp-kernel";
import type { CallToolResult, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { readOnlyToolAnnotations } from "../annotations.js";
import type { LcpMcpPorts } from "../ports.js";
import { legalContextUrl } from "../well-known.js";

const inputSchema = z.object({
  serviceUrl: z
    .url()
    .describe(
      "The service's origin (`https://seller.example`) or its full legal-context URL. " +
        "`/.well-known/legal-context.json` is appended when absent, and a query string, a fragment or " +
        "credentials in the authority are REFUSED — LCP §2.1 defines the well-known URI with none of them.",
    ),
});

/** The Level 1 readout, as ONE literal: it is the tool's most consequential sentence, and a test pins it. */
const LEVEL_1_DETAIL =
  "the document declares no atrHash (LCP Level 1) — there is nothing to verify, so this tool cannot say the served terms are the ones committed to";

const outputSchema = z.object({
  verdict: z
    .enum(["verified", "mismatch", "unverifiable"])
    .describe(
      "verified: the served terms hash to the declared fingerprint. mismatch: they do not. " +
        "unverifiable: no fingerprint was declared, or the terms format is not machine-readable.",
    ),
  wouldHalt: z
    .boolean()
    .describe("True when an agent MUST NOT pay against these terms."),
  atrHashMatch: z
    .boolean()
    .describe("True only on `verified` — the LCP §5.3 comparison itself."),
  legalContextUrl: z.string().describe("The discovery document actually read."),
  termsUrl: z.string().describe("The terms document that document points at."),
  declaredAtrHash: z
    .string()
    .optional()
    .describe("The fingerprint the service declared; absent at Level 1."),
  computedAtrHash: z
    .string()
    .optional()
    .describe(
      "The fingerprint recomputed here; absent when nothing was fetched.",
    ),
  termsBytes: z
    .number()
    .int()
    .optional()
    .describe("How many bytes of terms were hashed."),
  acceptanceRequired: z
    .boolean()
    .optional()
    .describe("Present only where the document declares it (LCP Level 3)."),
  disputeResolutionDeclared: z
    .boolean()
    .describe(
      "Whether the document carries a disputeResolution block (Level 4).",
    ),
  detail: z.string().describe("Why this verdict, in one sentence."),
});

/**
 * `lcp_verify_before_pay` — the agent guardrail (LCP §5.3). Fetch the service's discovery document and the
 * terms it points at, recompute the fingerprint, and say whether an agent must halt before paying.
 *
 * RE-GROUNDED on the shipped packages, and three things follow from that which a hand-rolled verifier
 * typically gets wrong:
 *
 *  1. The intake is `discovery.parseLegalContextJson`, which THROWS on a non-conformant document. Reading
 *     fields off whatever JSON came back would let a document that is not a legal-context document at all
 *     still produce a verdict. A loud failure is the honest answer.
 *  2. The comparison is `discovery.checkListingIntegrity` — DSC-2, the shipped rule — not a local
 *     `sha256` and `===`. It carries a check a hand-rolled comparison omits: a listing whose `termsFormat` is not
 *     machine-readable is `unverifiable` rather than passed through, because an agent cannot evaluate
 *     terms it cannot read. That NARROWS the tool: `application/pdf` is refused rather than accepted.
 *  3. **There is no ES256 `signing` block, and its absence is correct.** A verifier that reads a
 *     seller-signed ATR JWS out of a `signing` object is reading a field LCP does not define: Level 3 is
 *     the BUYER's signed acceptance over the fingerprint (§3, §4.2), and `legal-context.json` carries no
 *     seller signature at any level. Serving one would ship a private extension as though it were LCP.
 *
 * ABSENCE OF A FINGERPRINT IS NOT A PASS. A Level 1 document (terms, no `atrHash`) halts: the tool was
 * asked whether the terms can be trusted before paying, and against a document with nothing to verify the
 * only truthful answer is that it cannot say. A buyer that intends to transact at Level 1 anyway does so
 * through its own policy engine (`@integraledger/agentic-terms`'s stated `requiredLevel`), never by reading a
 * green light out of a tool that verified nothing.
 */
export function registerVerifyBeforePay(
  server: McpServer,
  ports: LcpMcpPorts,
): void {
  server.registerTool(
    "lcp_verify_before_pay",
    {
      description:
        "Verify a service's LCP terms BEFORE paying (LCP §5.3). Fetches /.well-known/legal-context.json and " +
        "the terms it references, recomputes the SHA-256 ATR hash, and compares it to the declared value. " +
        "Returns `{ verdict, wouldHalt, atrHashMatch, … }`. If `wouldHalt` is true, DO NOT PAY — this is a " +
        "legally significant decision, and the absence of a declared fingerprint counts as a halt.",
      inputSchema,
      outputSchema,
      annotations: readOnlyToolAnnotations("LCP verify-before-pay", "network"),
    },
    async (args) => {
      const lcUrl = legalContextUrl(args.serviceUrl);
      const doc = await ports.fetcher.fetch(lcUrl);
      // Fail-fast at the trust boundary: a non-conformant document is a loud error, never a soft verdict.
      const listing = parseLegalContextJson(
        JSON.parse(new TextDecoder().decode(doc.bytes)),
      );
      const common = {
        legalContextUrl: lcUrl,
        termsUrl: listing.terms,
        disputeResolutionDeclared: listing.disputeResolution !== undefined,
        ...(listing.acceptanceRequired !== undefined
          ? { acceptanceRequired: listing.acceptanceRequired }
          : {}),
      };

      const declared = listing.atrHash;
      if (declared === undefined)
        return halt({
          verdict: "unverifiable",
          wouldHalt: true,
          atrHashMatch: false,
          ...common,
          detail: LEVEL_1_DETAIL,
        });
      // `parseLegalContextJson` has ALREADY rejected any atrHash outside /^0x[0-9a-fA-F]{64}$/ — the
      // discovery schema is stricter than the TypeScript type it produces, which types `atrHash` as a bare
      // `string`. This narrowing is a compile-time necessity whose throw arm no parsed document reaches,
      // and it is written as a fail-loud throw rather than a cast precisely so that a future loosening of
      // that schema surfaces here instead of silently handing a malformed value to DSC-2.
      if (!isAtrHash(declared))
        throw new Error(
          `the document declares an atrHash that is not a 32-byte 0x fingerprint: ${declared}`,
        );

      const terms = await ports.fetcher.fetch(listing.terms);
      const integrity = await checkListingIntegrity(
        listing,
        terms.bytes,
        declared,
      );
      // `atrHashMatch` tracks DSC-2's own verdict. A listing refused for its FORMAT never reached the
      // comparison, and reports `false` for the same reason the tool halts on it: nothing was proved.
      const out = {
        verdict:
          integrity.status === "ok"
            ? ("verified" as const)
            : integrity.status === "mismatch"
              ? ("mismatch" as const)
              : ("unverifiable" as const),
        wouldHalt: !integrity.ok,
        atrHashMatch: integrity.ok,
        ...common,
        declaredAtrHash: integrity.advertisedAtrHash,
        computedAtrHash: integrity.servedAtrHash,
        termsBytes: terms.bytes.byteLength,
        detail: integrity.detail,
      };
      if (!integrity.ok) return halt(out);
      return {
        content: [
          {
            type: "text" as const,
            text: `OK to proceed — LCP verification passed.\n\n${JSON.stringify(out, null, 2)}`,
          },
        ],
        structuredContent: out,
      };
    },
  );
}

/** A halting verdict is a tool EXECUTION error, not a protocol error: MCP routes those to the model so it
 *  can act on them, which is exactly what "do not pay" needs to reach. */
function halt(out: Record<string, unknown>): CallToolResult {
  return {
    content: [
      {
        type: "text" as const,
        text: `HALT — do NOT pay. LCP verification did not pass.\n\n${JSON.stringify(out, null, 2)}`,
      },
    ],
    structuredContent: out,
    isError: true,
  };
}
