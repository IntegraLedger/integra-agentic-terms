import {
  isKnownProtocolId,
  KNOWN_PROTOCOL_IDS,
  type PlacementManifest,
  type ReferencePlacementAdapter,
  type Refusal,
} from "@integraledger/lcp-binding-core";
import {
  placementFor,
  supportedProtocols,
} from "@integraledger/lcp-placements";
import type { CallToolResult } from "@modelcontextprotocol/server";
import { z } from "zod";
import type { LcpMcpPorts } from "./ports.js";

/**
 * The one place this server turns a wire token into a placement adapter — `@integraledger/lcp-placements`,
 * the placement registry, and nothing else. No local map, no `switch`, no import of an individual
 * `placement-*` package: a protocol added to the registry is served here the moment it is published, and
 * a protocol the registry does not carry is reported as an absence rather than guessed at.
 *
 * TWO DISTINCT FAILURES, and collapsing them would lose the fix. `"acp2"` is not a protocol — a typo, and
 * the answer is the closed set. `"mcp"` IS a protocol id and has no field placement at all: LCP §C.9 and
 * §10 make MCP a delivery mechanism, which is what THIS PACKAGE is, so there is no document field for a
 * reference to ride in. Answering "unknown protocol" there would invite someone to go build
 * `placement-mcp`, which should not exist.
 */
export function resolveAdapter(
  protocol: string,
  ports: LcpMcpPorts,
): ReferencePlacementAdapter {
  if (!isKnownProtocolId(protocol))
    throw new Error(
      `"${protocol}" is not an LCP protocol id — known ids: ${KNOWN_PROTOCOL_IDS.join(", ")}`,
    );
  const adapter = placementFor(protocol, ports.deployment);
  if (adapter === undefined)
    throw new Error(
      `no reference placement is registered for "${protocol}" — this build can place into: ${supportedProtocols().join(", ")}`,
    );
  return adapter;
}

/**
 * The manifest facts a caller needs to understand where the reference went, without shipping the whole
 * manifest (its `specRef` prose and alias table are documentation, not a tool result).
 *
 * DECLARED ONCE, and both placement tools use it, so the two cannot describe the same block differently.
 *
 * `container` reports the KIND only. The container is a discriminated union whose tagged-array arm carries
 * the array path, tag field, tag value and value field — everything a reader needs is already in `field`,
 * which the manifest keeps as the human-readable locator precisely so a stranger does not have to
 * reassemble one from the walker's parts.
 */
export const PLACEMENT_SUMMARY_SCHEMA: z.ZodObject<{
  protocol: z.ZodString;
  tier: z.ZodString;
  pattern: z.ZodString;
  container: z.ZodString;
  encoding: z.ZodString;
  field: z.ZodString;
}> = z
  .object({
    protocol: z.string().describe("The LCP protocol id."),
    tier: z
      .string()
      .describe(
        "§8.3 wire compatibility: A works against stock today, B needs upstream change.",
      ),
    pattern: z.string().describe("The §8.3 binding pattern this carrier is."),
    container: z
      .string()
      .describe(
        "How the field is reached: object-path, tagged-array or header-map.",
      ),
    encoding: z.string().describe("How the reference sits in the field."),
    field: z
      .string()
      .describe("The host-protocol field the reference occupies."),
  })
  .describe(
    "The placement manifest's own account of where the reference sits.",
  );

export function manifestSummary(manifest: PlacementManifest): {
  protocol: string;
  tier: string;
  pattern: string;
  container: string;
  encoding: string;
  field: string;
} {
  return {
    protocol: manifest.protocol,
    tier: manifest.tier,
    pattern: manifest.pattern,
    container: manifest.container.kind,
    encoding: manifest.encoding,
    field: manifest.field,
  };
}

/**
 * A placement refusal, as MCP sees it.
 *
 * Refusals are VALUES in this codebase, never exceptions — and they stay values here: the halt class and
 * the stable code travel in `structuredContent` where a caller can branch on them, while `isError: true` is
 * what makes MCP hand the whole thing to the model instead of swallowing it.
 */
export function refusalResult(refusal: Refusal): CallToolResult {
  const out = {
    refused: true,
    haltClass: refusal.haltClass,
    code: refusal.code,
    ...(refusal.detail !== undefined ? { detail: refusal.detail } : {}),
  };
  return {
    content: [{ type: "text" as const, text: JSON.stringify(out, null, 2) }],
    structuredContent: out,
    isError: true,
  };
}
