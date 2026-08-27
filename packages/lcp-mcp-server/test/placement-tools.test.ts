import { describe, expect, it } from "vitest";
import { resolveAdapter } from "../src/dispatch.js";
import {
  connectTestClient,
  servingFetcher,
  structured,
  text,
} from "./harness.js";

/** ACP declares a terms-URL slot, so an integrity-bearing advertisement must carry a locator. */
const TERMS_URL = "https://seller.example/.well-known/legal-context.json";

/** A 32-byte fingerprint. Any 64 hex digits; the value is not derived from anything, it is the carrier. */
const ATR_HASH = `0x${"ab".repeat(32)}`;
const REFERENCE = `lcp:sha256:${ATR_HASH}`;

/** A minimal ACP checkout session. `metadata` is the map ACP documents as "arbitrary metadata for merchant
 *  use"; `CheckoutSessionBase` is `additionalProperties: false`, which is why the reference rides there. */
const acpSession = (): Record<string, unknown> => ({
  id: "checkout_session_123",
  status: "ready_for_payment",
  currency: "usd",
  metadata: { merchant_ref: "order-9" },
});

const ports = () => ({ fetcher: servingFetcher({}) });

describe("lcp_place_reference — dispatch through the placement registry", () => {
  it("places into ACP at the field the manifest declares, and reports where", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: {
        protocol: "acp",
        reference: REFERENCE,
        termsUrl: TERMS_URL,
        document: acpSession(),
      },
    });
    expect(result.isError ?? false).toBe(false);
    const out = structured(result);
    // Pinned from ACP's own placement docblock and LCP §8.3, not from what the code emitted: the carrier is
    // `metadata.legal_context`, it rides an arbitrary-metadata map (§8.3.7 http-advisory), it works against
    // stock ACP today (Tier A), and it carries the canonical `lcp:` string.
    expect(out["placement"]).toEqual({
      protocol: "acp",
      tier: "A",
      pattern: "http-advisory",
      container: "object-path",
      encoding: "lcp-string",
      field: "metadata.legal_context",
    });
    const doc = out["document"] as { metadata: Record<string, unknown> };
    expect(doc.metadata["legal_context"]).toBe(REFERENCE);
    expect(doc.metadata["merchant_ref"]).toBe("order-9");
  });

  it("never mutates the document it was given", async () => {
    const client = await connectTestClient(ports());
    const original = acpSession();
    await client.callTool({
      name: "lcp_place_reference",
      arguments: {
        protocol: "acp",
        reference: REFERENCE,
        termsUrl: TERMS_URL,
        document: original,
      },
    });
    expect(original["metadata"]).toEqual({ merchant_ref: "order-9" });
  });

  it("round-trips: what place writes, extract reads back byte-for-byte", async () => {
    const client = await connectTestClient(ports());
    const placed = structured(
      await client.callTool({
        name: "lcp_place_reference",
        arguments: {
          protocol: "acp",
          reference: REFERENCE,
          termsUrl: TERMS_URL,
          document: acpSession(),
        },
      }),
    );
    const extracted = structured(
      await client.callTool({
        name: "lcp_extract_reference",
        arguments: { protocol: "acp", document: placed["document"] },
      }),
    );
    expect(extracted["reference"]).toBe(REFERENCE);
    expect(extracted["type"]).toBe("sha256");
    expect(extracted["value"]).toBe(ATR_HASH);
  });

  it("refuses `mcp` by name — a registered protocol that has no field placement at all", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: { protocol: "mcp", reference: REFERENCE, document: {} },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(
      /no reference placement is registered for "mcp"/,
    );
    // The refusal names what this build CAN place into, so the caller can act rather than guess.
    expect(text(result)).toMatch(/acp/);
  });

  it("refuses a token that is not a protocol id, and answers with the closed set", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: { protocol: "acp2", reference: REFERENCE, document: {} },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/not an LCP protocol id/);
    expect(text(result)).toMatch(/x402/);
  });

  it("refuses a prototype key rather than walking it", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: {
        protocol: "constructor",
        reference: REFERENCE,
        termsUrl: TERMS_URL,
        document: {},
      },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/not an LCP protocol id/);
  });

  it("refuses a reference string that is not an LCP carrier", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: {
        protocol: "acp",
        reference: ATR_HASH,
        document: acpSession(),
      },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/not a recognized LCP .*carrier string/);
  });

  it("refuses a carrier type outside the LCP §8.2 registry rather than placing it", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: {
        protocol: "acp",
        reference: "lcp:blake3:deadbeef",
        document: acpSession(),
      },
    });
    expect(result.isError).toBe(true);
    expect(text(result)).toMatch(/not a recognized LCP .*carrier string/);
  });
});

describe("lcp_extract_reference — the read half", () => {
  it("refuses a document carrying no reference, and never answers with a placeholder", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_extract_reference",
      arguments: { protocol: "acp", document: acpSession() },
    });
    expect(result.isError).toBe(true);
    const out = structured(result);
    expect(out["refused"]).toBe(true);
    expect(typeof out["haltClass"]).toBe("string");
    expect(typeof out["code"]).toBe("string");
    expect(out).not.toHaveProperty("reference");
  });
});

describe("a namespaced placement needs the deployment's own namespace", () => {
  it("throws for mastercard-vi when no reverse domain was configured", async () => {
    const client = await connectTestClient(ports());
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: {
        protocol: "mastercard-vi",
        reference: REFERENCE,
        termsUrl: TERMS_URL,
        document: {},
      },
    });
    expect(result.isError).toBe(true);
    // The registry raises it; this server does not restate the rule, so the message is the registry's.
    expect(text(result).length).toBeGreaterThan(0);
  });

  it("builds the adapter once the deployment states one", () => {
    const adapter = resolveAdapter("mastercard-vi", {
      fetcher: servingFetcher({}),
      deployment: { reverseDomain: "com.integraledger" },
    });
    expect(adapter.manifest.protocol).toBe("mastercard-vi");
  });

  it("needs no deployment for a singleton registration", () => {
    expect(
      resolveAdapter("acp", { fetcher: servingFetcher({}) }).manifest.protocol,
    ).toBe("acp");
  });
});

describe("a placement that REFUSES the document it was handed", () => {
  it("refuses a Mastercard VI mandate — the placement is declaration-only and writes nothing", async () => {
    const client = await connectTestClient({
      fetcher: servingFetcher({}),
      deployment: { reverseDomain: "com.integraledger" },
    });
    const result = await client.callTool({
      name: "lcp_place_reference",
      arguments: {
        protocol: "mastercard-vi",
        reference: REFERENCE,
        termsUrl: TERMS_URL,
        document: { constraints: [] },
      },
    });
    expect(result.isError).toBe(true);
    const out = structured(result);
    // The refusal is a VALUE: the halt class and the stable code reach the caller, not just prose.
    expect(out["refused"]).toBe(true);
    expect(out["haltClass"]).toBe("verification-failure");
    expect(out["code"]).toBe("mastercard-vi/tier-b-not-writable");
    expect(typeof out["detail"]).toBe("string");
    // And it is also readable text, so a model that never parses structuredContent still learns why.
    expect(text(result)).toContain(String(out["code"]));
  });
});
