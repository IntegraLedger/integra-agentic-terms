import { encodeLegalContextString } from "@integraledger/lcp-binding-core";
import { supportedProtocols } from "@integraledger/lcp-placements";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { readOnlyToolAnnotations } from "../annotations.js";
import {
  manifestSummary,
  PLACEMENT_SUMMARY_SCHEMA,
  refusalResult,
  resolveAdapter,
} from "../dispatch.js";
import type { LcpMcpPorts } from "../ports.js";

const inputSchema = z.object({
  protocol: z
    .string()
    .describe(
      "The commerce protocol this document belongs to. See the description for the set this build reads.",
    ),
  document: z
    .record(z.string(), z.unknown())
    .describe("The host protocol's own document, as JSON."),
});

const outputSchema = z.object({
  reference: z
    .string()
    .describe("The LCP §8.1 carrier string recovered from the document."),
  type: z.string().describe("The §8.2 carrier type, e.g. `sha256`."),
  value: z.string().describe("The carrier value, e.g. the 0x ATR hash."),
  termsUrl: z
    .discriminatedUnion("kind", [
      z.object({ kind: z.literal("read"), url: z.string() }),
      z.object({ kind: z.literal("no-field-declared") }),
      z.object({
        kind: z.literal("declared-fields-empty"),
        fields: z.array(z.string()),
      }),
    ])
    .describe(
      "Where the document says its terms live. The absences are DISTINCT and both are answers: `no-field-declared` is a fact about the PROTOCOL — it has no slot for a locator — while `declared-fields-empty` is a fact about this DOCUMENT, whose seller left every declared slot empty. Collapsing them would report a seller's silence as a protocol's.",
    ),
  placement: PLACEMENT_SUMMARY_SCHEMA,
});

/**
 * `lcp_extract_reference` — recover an LCP reference from a commerce protocol's own document.
 *
 * The read half of `lcp_place_reference`, through the same placement registry, so a document one produces the
 * other reads. It is what lets an agent on the receiving side of a counterparty's ACP session, x402
 * challenge or A2A task ask "which terms does this document say govern it?" without knowing where that
 * protocol keeps them.
 *
 * A DOCUMENT WITH NO REFERENCE REFUSES; it never returns a placeholder. That refusal is the answer — the
 * counterparty placed nothing — and an empty string or a null would read as a reference to nothing.
 *
 * The adapter reads the manifest's declared field AND its declared aliases, so a counterparty using a
 * spelling the manifest records as accepted is read rather than refused. Which spellings those are is the
 * manifest's data, not this tool's opinion.
 */
export function registerExtractReference(
  server: McpServer,
  ports: LcpMcpPorts,
): void {
  server.registerTool(
    "lcp_extract_reference",
    {
      description:
        "Recover the LCP legal-context reference from a commerce protocol's own document, reading the " +
        "field that protocol's placement manifest declares. Supported protocols in this build: " +
        `${supportedProtocols().join(", ")}. Returns the \`lcp:{type}:{value}\` carrier string and where ` +
        "it was found. A document carrying no reference is refused, not answered with an empty value.",
      inputSchema,
      outputSchema,
      annotations: readOnlyToolAnnotations(
        "Extract an LCP reference",
        "closed",
      ),
    },
    (args) => {
      const adapter = resolveAdapter(args.protocol, ports);
      const outcome = adapter.extract(args.document);
      if (!("ok" in outcome)) return refusalResult(outcome);
      // `extract` answers with the whole advertisement — the reference, and what the document says about
      // where its terms live. The locator's ABSENCE is typed, so the reader is told whether the protocol
      // has no slot at all or the seller left a declared one empty.
      const { ref, termsUrl } = outcome.value;
      const out = {
        reference: encodeLegalContextString(ref),
        type: ref.type,
        value: ref.value,
        termsUrl,
        placement: manifestSummary(adapter.manifest),
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
