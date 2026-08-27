import { decodeLegalContextString } from "@integraledger/lcp-binding-core";
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

/** A host protocol document, as JSON. One shape, used for the argument and for the result. */
const documentShape = z.record(z.string(), z.unknown());

const inputSchema = z.object({
  protocol: z
    .string()
    .describe(
      "The commerce protocol whose document this is. See `lcp_place_reference`'s description for the set this build can place into.",
    ),
  reference: z
    .string()
    .describe(
      "The LCP §8.1 carrier string, `lcp:{type}:{value}` — exactly what `lcp_compute_atrhash` returns as `reference`.",
    ),
  termsUrl: z
    .string()
    .optional()
    .describe(
      "Where the terms document the reference identifies can be fetched — `https://` only. REQUIRED where the protocol declares a slot for it and the reference is a digest: a hash no counterparty can resolve is unverifiable to anyone who does not already hold the terms, so the placement refuses one. Where the protocol declares no slot, supplying it is refused rather than silently dropped.",
    ),
  document: documentShape.describe(
    "The host protocol's own document, as JSON. Returned unchanged with the reference added; the input is never mutated.",
  ),
});

const outputSchema = z.object({
  document: documentShape.describe(
    "The host document with the reference placed.",
  ),
  placement: PLACEMENT_SUMMARY_SCHEMA,
});

/**
 * `lcp_place_reference` — put an LCP reference into any commerce protocol's own document.
 *
 * The tool that makes this server protocol-independent in the sense LCP §10 means: an agent transacting
 * under ACP, x402, UCP, AP2, ACK, MPP, A2A, Visa TAP or Mastercard VI calls the SAME tool, and the
 * registry decides where the reference belongs. Adding a protocol is a registry release, not a change here.
 *
 * The returned `placement` block is the manifest's own account of what happened — which tier it is (does
 * this work against stock implementations today, §8.3), which pattern, and the exact field — so a caller
 * can tell a declared protocol extension from an advisory metadata ride without reading our documentation.
 *
 * IT RETURNS A DOCUMENT; IT DOES NOT SEND ONE. The placement adapters are pure and never mutate their
 * input, and this tool adds no transport. Whether the document goes on the wire is the agent's decision,
 * made with its own credentials — this server holds none.
 */
export function registerPlaceReference(
  server: McpServer,
  ports: LcpMcpPorts,
): void {
  server.registerTool(
    "lcp_place_reference",
    {
      description:
        "Place an LCP legal-context reference into a commerce protocol's own document, at the field that " +
        "protocol's placement manifest declares. Supported protocols in this build: " +
        `${supportedProtocols().join(", ")}. Returns the updated document plus the placement manifest's ` +
        "tier, pattern and field. This is a legally significant act: the resulting document asserts which " +
        "terms govern the transaction. It returns the document — it does not transmit it.",
      inputSchema,
      outputSchema,
      annotations: readOnlyToolAnnotations("Place an LCP reference", "closed"),
    },
    (args) => {
      const adapter = resolveAdapter(args.protocol, ports);
      const ref = decodeLegalContextString(args.reference);
      if (ref === undefined)
        throw new Error(
          `"${args.reference}" is not a recognized LCP §8.1 carrier string — expected lcp:{type}:{value} with a registered type`,
        );
      // An ADVERTISEMENT: the reference, and — where the protocol has room for one — the locator. Passed
      // through by omission rather than as an explicit `undefined`, because the manifest decides which of
      // the two refusals an incomplete one earns.
      const outcome = adapter.place(
        args.termsUrl === undefined
          ? { ref }
          : { ref, termsUrl: args.termsUrl },
        args.document,
      );
      if (!("ok" in outcome)) return refusalResult(outcome);
      // `place` is typed `Outcome<unknown>` because a host document is whatever the host protocol says it
      // is. Parsing rather than casting keeps the widening honest: an adapter that somehow returned a
      // non-object would fail here and say so, instead of reaching the wire as a malformed tool result.
      const out = {
        document: documentShape.parse(outcome.value),
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
