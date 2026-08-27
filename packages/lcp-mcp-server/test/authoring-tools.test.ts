import { createHash } from "node:crypto";
import { parseLegalContextJson } from "@integraledger/lcp-discovery";
import { describe, expect, it } from "vitest";
import {
  connectTestClient,
  servingFetcher,
  structured,
  text,
} from "./harness.js";

const TERMS_URL = "https://seller.example/terms/v1.md";
const TERMS = "# Terms of sale\n\nAll sales final.\n";

/** SHA-256 over the exact bytes, 0x-prefixed (LCP §3), taken from node's digest rather than the kernel. */
const oracle = (body: string): string =>
  `0x${createHash("sha256").update(Buffer.from(body, "utf8")).digest("hex")}`;

const site = () => servingFetcher({ [TERMS_URL]: { body: TERMS } });

describe("lcp_compute_atrhash", () => {
  it("hashes inline terms to the SHA-256 of their UTF-8 bytes", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_compute_atrhash",
        arguments: { terms: TERMS },
      }),
    );
    expect(out["atrHash"]).toBe(oracle(TERMS));
    expect(out["bytes"]).toBe(Buffer.byteLength(TERMS, "utf8"));
  });

  it("hashes fetched terms to the same value as the same bytes inline", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_compute_atrhash",
        arguments: { termsUrl: TERMS_URL },
      }),
    );
    expect(out["atrHash"]).toBe(oracle(TERMS));
  });

  it("returns the LCP §8.1 carrier string that lcp_place_reference takes", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_compute_atrhash",
        arguments: { terms: TERMS },
      }),
    );
    expect(out["reference"]).toBe(`lcp:sha256:${oracle(TERMS)}`);
  });

  it("refuses BOTH inputs — two sources that may disagree is not a hash request", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const result = await client.callTool({
      name: "lcp_compute_atrhash",
      arguments: { terms: TERMS, termsUrl: TERMS_URL },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/both were supplied/);
  });

  it("refuses NEITHER input", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const result = await client.callTool({
      name: "lcp_compute_atrhash",
      arguments: {},
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/neither was supplied/);
  });

  it("hashes an empty terms string rather than treating it as absent", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_compute_atrhash",
        arguments: { terms: "" },
      }),
    );
    expect(out["bytes"]).toBe(0);
    expect(out["atrHash"]).toBe(oracle(""));
  });
});

describe("lcp_generate_legal_context", () => {
  it("emits a document the discovery schema accepts, hashing the bytes actually served", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_generate_legal_context",
        arguments: { termsUrl: TERMS_URL, termsFormat: "markdown" },
      }),
    );
    expect(out["atrHash"]).toBe(oracle(TERMS));
    expect(out["terms"]).toBe(TERMS_URL);
    expect(() => parseLegalContextJson(out)).not.toThrow();
  });

  it("carries the Level 3 and Level 4 fields through when supplied, and omits them when not", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const rich = structured(
      await client.callTool({
        name: "lcp_generate_legal_context",
        arguments: {
          termsUrl: TERMS_URL,
          termsFormat: "markdown",
          acceptanceRequired: true,
          disputeResolution: { method: "AAA Commercial Arbitration Rules" },
        },
      }),
    );
    expect(rich["acceptanceRequired"]).toBe(true);
    expect(rich["disputeResolution"]).toEqual({
      method: "AAA Commercial Arbitration Rules",
    });

    const bare = structured(
      await client.callTool({
        name: "lcp_generate_legal_context",
        arguments: { termsUrl: TERMS_URL, termsFormat: "markdown" },
      }),
    );
    expect(bare).not.toHaveProperty("acceptanceRequired");
    expect(bare).not.toHaveProperty("disputeResolution");
  });

  it("refuses a termsFormat that is not an LCP §2.5 token, and names the set", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const result = await client.callTool({
      name: "lcp_generate_legal_context",
      arguments: { termsUrl: TERMS_URL, termsFormat: "text/plain" },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/not an LCP .*token/);
    expect(text(result)).toMatch(/markdown/);
  });
});

describe("lcp_scaffold_integration", () => {
  it("hands the seller the shipped packages, both halves of the integration", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_scaffold_integration",
        arguments: { target: "seller" },
      }),
    );
    const scaffold = String(out["scaffold"]);
    expect(out["target"]).toBe("seller");
    expect(scaffold).toContain("@integraledger/lcp-discovery");
    // The half the demo omitted: publishing the document binds no particular transaction.
    expect(scaffold).toContain("@integraledger/lcp-placements");
    // And none of the hand-rolled crypto the demo told integrators to paste.
    expect(scaffold).not.toContain("createHash");
  });

  it("hands the buyer the gate, not just a hash comparison", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_scaffold_integration",
        arguments: { target: "buyer" },
      }),
    );
    const scaffold = String(out["scaffold"]);
    expect(out["target"]).toBe("buyer");
    expect(scaffold).toContain("@integraledger/agentic-terms");
    expect(scaffold).toContain("checkListingIntegrity");
    expect(scaffold).not.toContain("createHash");
  });

  it("refuses a target that is neither side", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const result = await client.callTool({
      name: "lcp_scaffold_integration",
      arguments: { target: "merchant" },
    });
    expect(result.isError).toBe(true);
  });
});

describe("every tool answers in text as well as structure", () => {
  it("returns a non-empty text block beside the structured result", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const calls: { name: string; arguments: Record<string, unknown> }[] = [
      { name: "lcp_compute_atrhash", arguments: { terms: TERMS } },
      {
        name: "lcp_generate_legal_context",
        arguments: { termsUrl: TERMS_URL, termsFormat: "markdown" },
      },
      { name: "lcp_scaffold_integration", arguments: { target: "buyer" } },
      {
        name: "lcp_place_reference",
        arguments: {
          protocol: "acp",
          reference: `lcp:sha256:${oracle(TERMS)}`,
          termsUrl: TERMS_URL,
          document: { metadata: {} },
        },
      },
      {
        name: "lcp_extract_reference",
        arguments: {
          protocol: "acp",
          document: {
            metadata: { legal_context: `lcp:sha256:${oracle(TERMS)}` },
          },
        },
      },
    ];
    // MCP: a tool returning structured content SHOULD also return the serialized JSON in a text block, so a
    // client that reads only `content` still sees the answer.
    for (const call of calls) {
      const result = await client.callTool(call);
      expect(result.isError ?? false, call.name).toBe(false);
      expect(text(result).length, call.name).toBeGreaterThan(0);
    }
  });
});

describe("lcp_generate_legal_context — the remaining optional fields", () => {
  it("carries returns and api through when supplied", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_generate_legal_context",
        arguments: {
          termsUrl: TERMS_URL,
          termsFormat: "markdown",
          returns: "https://seller.example/returns",
          api: "https://seller.example/legal/api",
        },
      }),
    );
    expect(out["returns"]).toBe("https://seller.example/returns");
    expect(out["api"]).toBe("https://seller.example/legal/api");
  });

  it("omits returns and api entirely when they are not", async () => {
    const client = await connectTestClient({ fetcher: site() });
    const out = structured(
      await client.callTool({
        name: "lcp_generate_legal_context",
        arguments: { termsUrl: TERMS_URL, termsFormat: "markdown" },
      }),
    );
    expect(out).not.toHaveProperty("returns");
    expect(out).not.toHaveProperty("api");
  });
});
