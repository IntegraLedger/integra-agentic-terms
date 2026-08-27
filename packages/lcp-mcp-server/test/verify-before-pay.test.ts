import { createHash } from "node:crypto";
import type { Client } from "@modelcontextprotocol/client";
import { describe, expect, it } from "vitest";
import {
  connectTestClient,
  servingFetcher,
  structured,
  text,
} from "./harness.js";

const SERVICE = "https://seller.example";
const WELL_KNOWN = `${SERVICE}/.well-known/legal-context.json`;
const TERMS_URL = `${SERVICE}/terms/v1.md`;
const TERMS = "# Terms of sale\n\nAll sales final.\n";

/** The oracle, derived from LCP §3's definition — SHA-256 over the exact terms bytes, 0x-prefixed — using
 *  node's own digest rather than the kernel this code calls. */
const oracle = (body: string): string =>
  `0x${createHash("sha256").update(Buffer.from(body, "utf8")).digest("hex")}`;

const listing = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({
    terms: TERMS_URL,
    termsFormat: "markdown",
    atrHash: oracle(TERMS),
    ...over,
  });

const site = (
  discoveryBody: string,
  termsBody = TERMS,
): Record<string, { body: string }> => ({
  [WELL_KNOWN]: { body: discoveryBody },
  [TERMS_URL]: { body: termsBody },
});

describe("lcp_verify_before_pay — LCP §5.3, and what counts as a halt", () => {
  it("passes when the served terms hash to the declared fingerprint", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing())),
    });
    const result = await client.callTool({
      name: "lcp_verify_before_pay",
      arguments: { serviceUrl: SERVICE },
    });
    expect(result.isError ?? false).toBe(false);
    const out = structured(result);
    expect(out["verdict"]).toBe("verified");
    expect(out["wouldHalt"]).toBe(false);
    expect(out["atrHashMatch"]).toBe(true);
    expect(out["computedAtrHash"]).toBe(oracle(TERMS));
    expect(out["declaredAtrHash"]).toBe(oracle(TERMS));
    expect(out["legalContextUrl"]).toBe(WELL_KNOWN);
    expect(out["termsUrl"]).toBe(TERMS_URL);
    expect(out["termsBytes"]).toBe(Buffer.byteLength(TERMS, "utf8"));
    expect(text(result)).toMatch(/OK to proceed/);
    expect(out["detail"]).toMatch(/DSC-2/);
  });

  it("HALTS when the served terms are not the terms committed to", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(
        site(listing(), "# Terms of sale\n\nAll sales refundable.\n"),
      ),
    });
    const result = await client.callTool({
      name: "lcp_verify_before_pay",
      arguments: { serviceUrl: SERVICE },
    });
    expect(result.isError).toBe(true);
    const out = structured(result);
    expect(out["verdict"]).toBe("mismatch");
    expect(out["wouldHalt"]).toBe(true);
    expect(out["atrHashMatch"]).toBe(false);
    expect(text(result)).toMatch(/HALT — do NOT pay/);
  });

  it("HALTS on a document that declares no fingerprint — absence is not a pass", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(
        site(JSON.stringify({ terms: TERMS_URL, termsFormat: "markdown" })),
      ),
    });
    const result = await client.callTool({
      name: "lcp_verify_before_pay",
      arguments: { serviceUrl: SERVICE },
    });
    expect(result.isError).toBe(true);
    const out = structured(result);
    expect(out["verdict"]).toBe("unverifiable");
    expect(out["wouldHalt"]).toBe(true);
    expect(out["atrHashMatch"]).toBe(false);
    expect(out["detail"]).toBe(
      "the document declares no atrHash (LCP Level 1) — there is nothing to verify, so this tool cannot say the served terms are the ones committed to",
    );
    // Nothing was fetched from the terms URL, so nothing is reported about it.
    expect(out).not.toHaveProperty("computedAtrHash");
  });

  it("HALTS on terms an agent cannot read, even where the hash would have matched (DSC-2)", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing({ termsFormat: "pdf" }))),
    });
    const result = await client.callTool({
      name: "lcp_verify_before_pay",
      arguments: { serviceUrl: SERVICE },
    });
    expect(result.isError).toBe(true);
    const out = structured(result);
    expect(out["verdict"]).toBe("unverifiable");
    expect(out["atrHashMatch"]).toBe(false);
  });

  it("reports the Level 3 and Level 4 declarations the document carries", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(
        site(
          listing({
            acceptanceRequired: true,
            disputeResolution: { method: "AAA Commercial Arbitration Rules" },
          }),
        ),
      ),
    });
    const out = structured(
      await client.callTool({
        name: "lcp_verify_before_pay",
        arguments: { serviceUrl: SERVICE },
      }),
    );
    expect(out["acceptanceRequired"]).toBe(true);
    expect(out["disputeResolutionDeclared"]).toBe(true);
  });

  it("omits acceptanceRequired entirely when the document does not declare it", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing())),
    });
    const out = structured(
      await client.callTool({
        name: "lcp_verify_before_pay",
        arguments: { serviceUrl: SERVICE },
      }),
    );
    expect(out).not.toHaveProperty("acceptanceRequired");
    expect(out["disputeResolutionDeclared"]).toBe(false);
  });

  it("fails loudly on a document that is not a legal-context document at all", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(JSON.stringify({ hello: "world" }))),
    });
    const result = await client.callTool({
      name: "lcp_verify_before_pay",
      arguments: { serviceUrl: SERVICE },
    });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toBeUndefined();
  });

  it("fails loudly on a declared atrHash that is not a 32-byte fingerprint", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing({ atrHash: "0xdeadbeef" }))),
    });
    const result = await client.callTool({
      name: "lcp_verify_before_pay",
      arguments: { serviceUrl: SERVICE },
    });
    expect(result.isError).toBe(true);
    // The refusal comes from the discovery schema, not from this package: `parseLegalContextJson` pins the
    // fingerprint pattern, which is why the tool's own narrowing guard is unreachable from here.
    expect(text(result)).toMatch(/atrHash/);
    expect(text(result)).toMatch(/0x\[0-9a-fA-F\]\{64\}/);
    expect(result.structuredContent).toBeUndefined();
  });

  it("refuses a non-HTTPS service — the SSRF posture is live, not documentation", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing())),
    });
    const result = await client.callTool({
      name: "lcp_verify_before_pay",
      arguments: { serviceUrl: "http://seller.example" },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/HTTPS/i);
  });

  it("accepts the full well-known URL as readily as the origin", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing())),
    });
    const out = structured(
      await client.callTool({
        name: "lcp_verify_before_pay",
        arguments: { serviceUrl: WELL_KNOWN },
      }),
    );
    expect(out["legalContextUrl"]).toBe(WELL_KNOWN);
    expect(out["verdict"]).toBe("verified");
  });
});

/**
 * The declared verdict vocabulary is a contract with the MODEL, and nothing above pins it.
 *
 * `mismatch` and `unverifiable` only ever ride an `isError` result, and the SDK does not validate an error
 * result's `structuredContent` against the output schema. So a schema that stopped declaring either one
 * would still serve a tool that returns it — the assertions above read the RUNTIME value and pass either
 * way. What follows reads the schema off the `tools/list` wire, which is the artifact a client actually
 * validates against, and holds it against the verdicts the tool is observed to emit.
 */
describe("lcp_verify_before_pay — the declared verdict vocabulary", () => {
  it("declares exactly the three verdicts, in the order the schema states them", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing())),
    });
    expect(await declaredVerdicts(client)).toEqual([
      "verified",
      "mismatch",
      "unverifiable",
    ]);
  });

  it("declares every verdict it emits, and emits every verdict it declares", async () => {
    // One scenario per verdict, KEYED by the verdict it must produce. Asserting against the keys pins each
    // scenario to its own answer — a set equality alone would still pass if mismatch and unverifiable
    // swapped places. The second assertion then closes the other direction: a verdict dropped from the
    // schema, or declared and never reachable, breaks it.
    const scenarios = {
      verified: site(listing()),
      mismatch: site(listing(), "# Terms of sale\n\nAll sales refundable.\n"),
      unverifiable: site(
        JSON.stringify({ terms: TERMS_URL, termsFormat: "markdown" }),
      ),
    };
    const emitted: string[] = [];
    for (const routes of Object.values(scenarios)) {
      const client = await connectTestClient({
        fetcher: servingFetcher(routes),
      });
      const out = structured(
        await client.callTool({
          name: "lcp_verify_before_pay",
          arguments: { serviceUrl: SERVICE },
        }),
      );
      emitted.push(String(out["verdict"]));
    }
    expect(emitted).toEqual(Object.keys(scenarios));

    const client = await connectTestClient({
      fetcher: servingFetcher(site(listing())),
    });
    expect([...emitted].sort()).toEqual(
      (await declaredVerdicts(client)).sort(),
    );
  });
});

/** The `verdict` enum as a client reads it off `tools/list` — the served schema, not the source constant. */
async function declaredVerdicts(client: Client): Promise<string[]> {
  const schema = (await client.listTools()).tools.find(
    (t) => t.name === "lcp_verify_before_pay",
  )?.outputSchema;
  const props =
    typeof schema === "object" && schema !== null && "properties" in schema
      ? (schema["properties"] as Record<string, unknown>)
      : {};
  const verdict = props["verdict"];
  if (
    typeof verdict !== "object" ||
    verdict === null ||
    !("enum" in verdict) ||
    !Array.isArray(verdict.enum)
  )
    throw new Error(
      `the served output schema declares no verdict enum: ${JSON.stringify(verdict)}`,
    );
  return verdict.enum.map(String);
}
