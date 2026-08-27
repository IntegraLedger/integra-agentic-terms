import {
  emit,
  isKnownTermsFormat,
  KNOWN_TERMS_FORMATS,
  type LegalContextJson,
} from "@integraledger/lcp-discovery";
import { hashAtr } from "@integraledger/lcp-kernel";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { readOnlyToolAnnotations } from "../annotations.js";
import type { LcpMcpPorts } from "../ports.js";

const inputSchema = z.object({
  termsUrl: z
    .url()
    .describe("HTTPS URL of the terms document. Fetched, so it must be live."),
  termsFormat: z
    .string()
    .describe(
      `The LCP §2.5 format token for the terms document — one of: ${KNOWN_TERMS_FORMATS.join(", ")}.`,
    ),
  acceptanceRequired: z
    .boolean()
    .optional()
    .describe(
      "Set true where the service requires explicit signed acceptance before transacting (LCP §3, Level 3).",
    ),
  disputeResolution: z
    .record(z.string(), z.unknown())
    .optional()
    .describe(
      "The service's dispute-resolution metadata (LCP §3, Level 4), e.g. { method, jurisdiction }.",
    ),
  returns: z.string().optional().describe("URL of the returns policy."),
  api: z
    .url()
    .optional()
    .describe("Entry point to richer legal functionality (LCP §3, Level 4)."),
});

const outputSchema = z.object({
  terms: z.string().describe("The terms document URL, echoed from the input."),
  termsFormat: z.string().describe("The LCP §2.5 format token."),
  atrHash: z
    .string()
    .describe("SHA-256 over the bytes served at `terms`, computed here."),
  acceptanceRequired: z
    .boolean()
    .optional()
    .describe("Present only where the input declared it."),
  disputeResolution: z
    .record(z.string(), z.unknown())
    .optional()
    .describe("Present only where the input declared it."),
  returns: z
    .string()
    .optional()
    .describe("Present only where the input declared it."),
  api: z
    .string()
    .optional()
    .describe("Present only where the input declared it."),
});

/**
 * `lcp_generate_legal_context` — build a ready-to-publish `/.well-known/legal-context.json`.
 *
 * Grounded on `discovery.emit`, which drops undefined fields and then VALIDATES what is left, so a profile
 * this tool cannot legally emit fails loudly here rather than 404-ing an agent later. The `atrHash` is
 * `kernel.hashAtr` over the bytes actually served at `termsUrl` — never a value the caller supplies, because
 * a hash the author asserts rather than computes is the one field an author can get wrong and never notice.
 *
 * `termsFormat` is checked against `discovery.KNOWN_TERMS_FORMATS` rather than re-declared as an enum here:
 * the token set is the protocol's, and a second copy in this package would be free to drift from it. The
 * free-string `termsFormat` invites values like `text/plain` and `application/pdf`,
 * neither of which is an LCP §2.5 token.
 *
 * IT RETURNS THE DOCUMENT; IT DOES NOT PUBLISH ONE. Serving it is the deployment's act, on the deployment's
 * origin, under the deployment's name.
 */
export function registerGenerateLegalContext(
  server: McpServer,
  ports: LcpMcpPorts,
): void {
  server.registerTool(
    "lcp_generate_legal_context",
    {
      description:
        "Build a ready-to-publish `/.well-known/legal-context.json` document. Fetches `termsUrl`, " +
        "computes the ATR hash over the served bytes, validates the result against the LCP discovery " +
        "schema, and returns the document to serve. It does not publish anything.",
      inputSchema,
      outputSchema,
      annotations: readOnlyToolAnnotations(
        "Generate LCP legal-context.json",
        "network",
      ),
    },
    async (args) => {
      if (!isKnownTermsFormat(args.termsFormat))
        throw new Error(
          `termsFormat "${args.termsFormat}" is not an LCP §2.5 token — expected one of: ${KNOWN_TERMS_FORMATS.join(", ")}`,
        );
      const bytes = (await ports.fetcher.fetch(args.termsUrl)).bytes;
      const profile: LegalContextJson = {
        terms: args.termsUrl,
        termsFormat: args.termsFormat,
        atrHash: await hashAtr(bytes),
        ...(args.acceptanceRequired !== undefined
          ? { acceptanceRequired: args.acceptanceRequired }
          : {}),
        ...(args.disputeResolution !== undefined
          ? { disputeResolution: args.disputeResolution }
          : {}),
        ...(args.returns !== undefined ? { returns: args.returns } : {}),
        ...(args.api !== undefined ? { api: args.api } : {}),
      };
      const doc = emit(profile);
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(doc, null, 2) },
        ],
        structuredContent: doc,
      };
    },
  );
}
