import { supportedProtocols } from "@integraledger/lcp-placements";
import { describe, expect, it } from "vitest";
import { LCP_TOOL_NAMES } from "../src/server.js";
import { connectTestClient, servingFetcher } from "./harness.js";

/** The three tools that reach the network, and the three that do not. Stated here rather than derived from
 *  the source so the assertion is an independent claim about each tool, not a restatement of its code. */
const NETWORK_TOOLS = [
  "lcp_compute_atrhash",
  "lcp_generate_legal_context",
  "lcp_verify_before_pay",
];

/** LCP v1.38 §C.9's illustrative table lists these alongside the ones we serve. Every one of them asserts a
 *  custodian or forum role, and the mandate boundary forbids all five. */
const FORBIDDEN_TOOLS = [
  "accept_terms",
  "create_agreement",
  "get_agreement",
  "initiate_dispute",
  "get_dispute_status",
];

describe("the tool surface a client actually sees", () => {
  it("serves exactly the six LCP tools, in registration order", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).toEqual([...LCP_TOOL_NAMES]);
  });

  it("keeps the four names already in service", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const names = (await client.listTools()).tools.map((t) => t.name);
    // A deployed server already answers to these four. Renaming any of them breaks working integrations,
    // which is why §C.9's different illustration does not win.
    for (const name of [
      "lcp_compute_atrhash",
      "lcp_generate_legal_context",
      "lcp_verify_before_pay",
      "lcp_scaffold_integration",
    ])
      expect(names).toContain(name);
  });

  it("serves NO agreement, acceptance-recording or dispute tool — the mandate boundary", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const names = (await client.listTools()).tools.map((t) => t.name);
    for (const forbidden of FORBIDDEN_TOOLS)
      expect(names).not.toContain(forbidden);
  });

  it("annotates every tool read-only and explicitly non-destructive", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    for (const tool of (await client.listTools()).tools) {
      // MCP defaults destructiveHint to TRUE. Omitting it would describe every one of these as possibly
      // destructive, so the value is stated, not left out.
      expect(tool.annotations?.readOnlyHint, tool.name).toBe(true);
      expect(tool.annotations?.destructiveHint, tool.name).toBe(false);
      expect(tool.annotations?.idempotentHint, tool.name).toBe(true);
      expect(typeof tool.annotations?.title, tool.name).toBe("string");
    }
  });

  it("declares openWorldHint true for exactly the tools that fetch", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const open = (await client.listTools()).tools
      .filter((t) => t.annotations?.openWorldHint === true)
      .map((t) => t.name);
    expect(open.sort()).toEqual([...NETWORK_TOOLS].sort());
  });

  it("titles every tool for display, with the label its deployment shows", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const titles = Object.fromEntries(
      (await client.listTools()).tools.map((t) => [
        t.name,
        t.annotations?.title,
      ]),
    );
    expect(titles).toEqual({
      lcp_compute_atrhash: "Compute LCP ATR hash",
      lcp_generate_legal_context: "Generate LCP legal-context.json",
      lcp_verify_before_pay: "LCP verify-before-pay",
      lcp_scaffold_integration: "Scaffold an LCP integration",
      lcp_place_reference: "Place an LCP reference",
      lcp_extract_reference: "Extract an LCP reference",
    });
  });

  it("declares an object input schema and an output schema on every tool", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    for (const tool of (await client.listTools()).tools) {
      expect(tool.inputSchema.type, tool.name).toBe("object");
      expect(tool.outputSchema, tool.name).toBeDefined();
    }
  });

  it("names, in every output schema, the fields that tool actually returns", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const declared = Object.fromEntries(
      (await client.listTools()).tools.map((t) => [
        t.name,
        Object.keys(properties(t.outputSchema)).sort(),
      ]),
    );
    // An output schema is a promise to the client: MCP says a server MUST return structured results that
    // conform to it, and clients SHOULD validate against it. An empty one promises nothing at all.
    expect(declared).toEqual({
      lcp_compute_atrhash: ["atrHash", "bytes", "reference"],
      lcp_generate_legal_context: [
        "acceptanceRequired",
        "api",
        "atrHash",
        "disputeResolution",
        "returns",
        "terms",
        "termsFormat",
      ],
      lcp_verify_before_pay: [
        "acceptanceRequired",
        "atrHashMatch",
        "computedAtrHash",
        "declaredAtrHash",
        "detail",
        "disputeResolutionDeclared",
        "legalContextUrl",
        "termsBytes",
        "termsUrl",
        "verdict",
        "wouldHalt",
      ],
      lcp_scaffold_integration: ["scaffold", "target"],
      lcp_place_reference: ["document", "placement"],
      lcp_extract_reference: [
        "placement",
        "reference",
        "termsUrl",
        "type",
        "value",
      ],
    });
  });

  it("names the placement block's own fields, on both placement tools alike", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const tools = (await client.listTools()).tools;
    // One schema, shared: the two tools cannot describe the same block differently.
    for (const name of ["lcp_place_reference", "lcp_extract_reference"]) {
      const schema = tools.find((t) => t.name === name)?.outputSchema;
      expect(
        Object.keys(properties(properties(schema)["placement"])).sort(),
        name,
      ).toEqual([
        "container",
        "encoding",
        "field",
        "pattern",
        "protocol",
        "tier",
      ]);
    }
  });

  it("describes every input and output field, nested ones included", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    // The model fills arguments and reads results from these. A nested block is no less model-facing
    // than a top-level one, which is why the walk recurses rather than stopping at depth one.
    for (const tool of (await client.listTools()).tools)
      for (const [where, schema] of [
        ["input", tool.inputSchema],
        ["output", tool.outputSchema],
      ] as const)
        for (const [path, described] of describedFields(schema, where))
          expect(described, `${tool.name} ${path}`).toBe(true);
  });

  it("gives every tool a description an agent can act on", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    for (const tool of (await client.listTools()).tools)
      expect((tool.description ?? "").length, tool.name).toBeGreaterThan(80);
  });

  it("names, in both placement tools, every protocol this build can actually reach", async () => {
    // The set is part of the contract with the model, and it is derived rather than written down: a
    // description naming none leaves an agent to guess, and one naming a protocol this build cannot reach
    // sends it to a refusal it could have avoided. Derived from the registry here for the same reason it is
    // derived there — a hand-written list is a second place the answer lives.
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const desc = Object.fromEntries(
      (await client.listTools()).tools.map((t) => [
        t.name,
        t.description ?? "",
      ]),
    );
    for (const tool of ["lcp_place_reference", "lcp_extract_reference"])
      for (const protocol of supportedProtocols())
        expect(desc[tool], `${tool} must name ${protocol}`).toContain(protocol);
  });

  it("keeps the load-bearing instruction in each safety-critical description", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const desc = Object.fromEntries(
      (await client.listTools()).tools.map((t) => [
        t.name,
        t.description ?? "",
      ]),
    );
    // These phrases are the tool's contract with the model, and dropping one changes what an agent does.
    expect(desc["lcp_verify_before_pay"]).toContain("DO NOT PAY");
    expect(desc["lcp_verify_before_pay"]).toContain(
      "absence of a declared fingerprint counts as a halt",
    );
    // The verify-before-sign citation, which replaced an internal id a stranger could not resolve.
    expect(desc["lcp_verify_before_pay"]).toContain("LCP §5.3");
    expect(desc["lcp_place_reference"]).toContain("legally significant");
    expect(desc["lcp_place_reference"]).toContain("it does not transmit it");
    expect(desc["lcp_extract_reference"]).toContain(
      "refused, not answered with an empty value",
    );
    expect(desc["lcp_generate_legal_context"]).toContain(
      "does not publish anything",
    );
    expect(desc["lcp_compute_atrhash"]).toContain("HTTPS only");
    expect(desc["lcp_scaffold_integration"]).toContain("@integraledger");
  });
});

/** Every `[path, hasDescription]` pair in a JSON Schema object, recursing into nested objects. */
function describedFields(schema: unknown, prefix: string): [string, boolean][] {
  const out: [string, boolean][] = [];
  for (const [field, spec] of Object.entries(properties(schema))) {
    const path = `${prefix}.${field}`;
    const described =
      typeof spec === "object" && spec !== null && "description" in spec
        ? spec.description
        : undefined;
    out.push([path, typeof described === "string" && described.length > 0]);
    out.push(...describedFields(spec, path));
  }
  return out;
}

/** The `properties` map of a JSON Schema object, or an empty one. */
function properties(schema: unknown): Record<string, unknown> {
  if (
    typeof schema !== "object" ||
    schema === null ||
    !("properties" in schema)
  )
    return {};
  const props = schema.properties;
  return typeof props === "object" && props !== null
    ? (props as Record<string, unknown>)
    : {};
}
