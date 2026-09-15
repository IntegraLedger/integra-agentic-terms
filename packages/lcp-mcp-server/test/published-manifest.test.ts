import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { connectTestClient, servingFetcher } from "./harness.js";

/**
 * ⭐⭐ **THE PUBLISHED TOOL MANIFEST, PINNED BYTE FOR BYTE — because it is a CONTRACT and nothing else
 * asserted it.**
 *
 * `tool-surface.test.ts` asserts the manifest STRUCTURALLY: the names, that each `inputSchema.type` is
 * `"object"`, that the output keys match. All of that stays true while the emitted JSON Schema changes
 * underneath it, and the emitted schema is what a client actually validates against.
 *
 * ⛔ **This is not hypothetical.** `M` 2026-09-15, repinning `zod` 4.5.4 → 4.6.2 renamed an emitted
 * `format` in a sibling workspace that serves an OpenAPI descriptor:
 * `z.url().startsWith("https://")` emitted `"uri"` under 4.5.4 and
 * `"starts_with"` under 4.6.2 — zod's own check name, not a JSON Schema format — and **eighteen fields of
 * that descriptor changed shape**. One pinned fixture caught it there. This repository had
 * none, and its manifest was checked by hand, once, after the bump had already published.
 *
 * ⭐ **The subject is what a CLIENT RECEIVES, not what `zod` emits.** The schema travels through the MCP
 * SDK's own serialisation, so testing `z.toJSONSchema` directly answers a neighbouring question. This
 * connects a real client and calls `listTools()`, which is the only surface a consumer can observe.
 *
 * ## ⛔ WHEN THIS GOES RED
 *
 * A difference here means **a published contract moved**. That may be correct — a new tool, a new field —
 * but it is never incidental, and it is never fixed by regenerating the fixture to make the test pass.
 * Read the diff, decide whether consumers can absorb it, and only then re-record with
 * `UPDATE_MANIFEST=1`. ⚠️ Regenerating without reading is how a dependency bump ships a contract change
 * with a green tick over it.
 */
const FIXTURE = fileURLToPath(
  new URL("./fixtures/tool-manifest.json", import.meta.url),
);

describe("the published tool manifest", () => {
  it("is byte-identical to the recorded contract", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const { tools } = await client.listTools();

    const served = tools.map((t) => ({
      name: t.name,
      inputSchema: t.inputSchema,
      outputSchema: t.outputSchema,
    }));
    const serialised = `${JSON.stringify(served, null, 2)}\n`;

    if (process.env["UPDATE_MANIFEST"] === "1") {
      writeFileSync(FIXTURE, serialised);
      throw new Error(
        "UPDATE_MANIFEST=1 re-recorded the fixture. Re-run without it, and commit the diff only if you have read it.",
      );
    }

    // ⛔ The set size is asserted before the contents, so an empty or truncated manifest reads as a
    // failure rather than as a clean comparison over nothing.
    expect(
      served.length,
      "the manifest is empty — the client served no tools",
    ).toBeGreaterThan(0);

    const recorded = readFileSync(FIXTURE, "utf8");
    expect(
      serialised,
      `the published tool manifest changed — ${served.length} tool(s) compared. This is a CONTRACT a consumer validates against. Read the diff before re-recording with UPDATE_MANIFEST=1.`,
    ).toBe(recorded);
  });
});
