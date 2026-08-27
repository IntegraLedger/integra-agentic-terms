import { encodeLegalContextString } from "@integraledger/lcp-binding-core";
import { hashAtr } from "@integraledger/lcp-kernel";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { readOnlyToolAnnotations } from "../annotations.js";
import type { LcpMcpPorts } from "../ports.js";

const inputSchema = z.object({
  terms: z
    .string()
    .optional()
    .describe(
      "Raw terms text to hash, as UTF-8 bytes. Provide this OR termsUrl, never both.",
    ),
  termsUrl: z
    .url()
    .optional()
    .describe(
      "HTTPS URL of the terms document to fetch and hash. Provide this OR terms, never both.",
    ),
});

const outputSchema = z.object({
  atrHash: z.string().describe("0x-prefixed SHA-256 of the terms bytes."),
  bytes: z.number().int().describe("How many bytes were hashed."),
  reference: z
    .string()
    .describe("The LCP §8.1 carrier string, `lcp:sha256:0x…`."),
});

/**
 * `lcp_compute_atrhash` — the ATR fingerprint of a terms document, from inline text or a fetchable URL.
 *
 * Grounded on `kernel.hashAtr` (the one implementation of the ATR fingerprint) and
 * `binding-core.encodeLegalContextString` (the one implementation of the §8.1 carrier), rather than on a
 * local `createHash("sha256")` and a template literal. The carrier string it returns is the exact input
 * `lcp_place_reference` takes, so compute → place composes without the agent reformatting anything.
 *
 * EXACTLY ONE of `terms`/`termsUrl`. Neither is a caller who has not said what to hash; both is a caller
 * whose two inputs may disagree, and picking one would silently hash something the caller did not mean.
 */
export function registerComputeAtrHash(
  server: McpServer,
  ports: LcpMcpPorts,
): void {
  server.registerTool(
    "lcp_compute_atrhash",
    {
      description:
        "Compute the LCP ATR hash — the SHA-256 over the exact terms bytes — from inline `terms` text " +
        "or a fetchable `termsUrl`. Returns `{ atrHash, bytes, reference }`, where `reference` is the " +
        "canonical `lcp:sha256:0x…` carrier string. A `termsUrl` is fetched over HTTPS only, is not " +
        "followed through redirects, and is size-capped.",
      inputSchema,
      outputSchema,
      annotations: readOnlyToolAnnotations("Compute LCP ATR hash", "network"),
    },
    async (args) => {
      if (args.terms !== undefined && args.termsUrl !== undefined)
        throw new Error(
          "provide exactly one of `terms` or `termsUrl` — both were supplied, and they may disagree",
        );
      let bytes: Uint8Array;
      if (args.termsUrl !== undefined)
        bytes = (await ports.fetcher.fetch(args.termsUrl)).bytes;
      else if (args.terms !== undefined)
        bytes = new TextEncoder().encode(args.terms);
      else
        throw new Error(
          "provide exactly one of `terms` or `termsUrl` — neither was supplied",
        );

      const atrHash = await hashAtr(bytes);
      const out = {
        atrHash,
        bytes: bytes.byteLength,
        reference: encodeLegalContextString({ type: "sha256", value: atrHash }),
      };
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(out, null, 2) },
        ],
        structuredContent: out,
      };
    },
  );
}
