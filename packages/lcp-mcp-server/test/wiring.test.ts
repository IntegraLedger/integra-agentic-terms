import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { LCP_MCP_EXTENSION_ID } from "@integraledger/lcp-discovery";
import { LCP_SPEC_VERSION } from "@integraledger/lcp-kernel";
import { InMemoryTransport, McpServer } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import { isoNow, nodePorts, REVERSE_DOMAIN_ENV } from "../src/node-ports.js";
import { LCP_TOOL_NAMES, SERVER_NAME } from "../src/server.js";
import { serveLcpStdio } from "../src/stdio.js";
import { readManifestVersion, serverVersion } from "../src/version.js";
import { legalContextUrl, WELL_KNOWN_PATH } from "../src/well-known.js";
import { connectTestClient, servingFetcher } from "./harness.js";

/**
 * The version this package's own manifest states, parsed HERE rather than through the code under test —
 * so the assertions below travel manifest → module → `McpServer` → client and not module → module.
 */
function manifestVersion(): string {
  const manifest: unknown = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  if (
    typeof manifest !== "object" ||
    manifest === null ||
    !("version" in manifest) ||
    typeof manifest.version !== "string"
  )
    throw new Error("this package's own manifest states no string version");
  return manifest.version;
}

/** A manifest file holding exactly `json`, as a URL `readManifestVersion` can be pointed at. */
function manifestFileUrl(json: string): URL {
  const path = join(mkdtempSync(join(tmpdir(), "lcp-mcp-manifest-")), "p.json");
  writeFileSync(path, json, "utf8");
  return pathToFileURL(path);
}

describe("the well-known locator (LCP §2.1)", () => {
  it("appends the well-known path to a bare origin", () => {
    expect(legalContextUrl("https://seller.example")).toBe(
      `https://seller.example${WELL_KNOWN_PATH}`,
    );
  });
  it("strips trailing slashes before appending, so the path is never doubled", () => {
    expect(legalContextUrl("https://seller.example///")).toBe(
      `https://seller.example${WELL_KNOWN_PATH}`,
    );
  });
  it("leaves a URL that is already the well-known document alone", () => {
    const full = `https://seller.example${WELL_KNOWN_PATH}`;
    expect(legalContextUrl(full)).toBe(full);
  });
  it("appends beneath a path prefix rather than replacing it", () => {
    expect(legalContextUrl("https://host.example/tenant")).toBe(
      `https://host.example/tenant${WELL_KNOWN_PATH}`,
    );
  });
  it("leaves a PREFIXED well-known document alone too — the match is on the tail", () => {
    const full = `https://host.example/tenant${WELL_KNOWN_PATH}`;
    expect(legalContextUrl(full)).toBe(full);
  });
  it("names the exact path LCP §2.1 specifies", () => {
    expect(WELL_KNOWN_PATH).toBe("/.well-known/legal-context.json");
  });

  // LCP §2.1 defines the well-known URI with no parameters, so a caller supplying one is asking for
  // behaviour the standard does not define. Refused BY NAME: concatenation put the well-known path inside
  // the query, and the failure then read as a broken discovery document at the service root.
  it("refuses a query string rather than burying the well-known path inside it", () => {
    expect(() => legalContextUrl("https://x.example?level=3")).toThrow(
      /query or fragment/,
    );
  });
  it("refuses a fragment for the same reason", () => {
    expect(() => legalContextUrl("https://x.example#terms")).toThrow(
      /query or fragment/,
    );
  });
  it("refuses a URL with no network origin — the tools' `z.url()` accepts these", () => {
    for (const u of ["mailto:legal@x.example", "data:text/plain,x", "urn:x:y"])
      expect(() => legalContextUrl(u)).toThrow(/no network origin/);
  });

  // `URL`'s `origin` drops userinfo, so parsing rather than concatenating would hand back a URL addressed
  // differently from the one supplied. Each spelling is asserted on its own: a refusal that only fires when
  // BOTH halves are present would let `https://u@h.example` through silently stripped.
  it("refuses credentials in the authority rather than silently dropping them", () => {
    for (const u of [
      "https://u:p@h.example",
      "https://u@h.example",
      "https://:p@h.example",
    ])
      expect(() => legalContextUrl(u)).toThrow(/credentials in its authority/);
  });
});

describe("server identity", () => {
  it("keeps the name the live deployment registers under", () => {
    expect(SERVER_NAME).toBe("lcp-mcp");
  });

  // `changeset version` rewrites the manifest and nothing else, so a version restated in TypeScript drifts
  // on the first release cut — this package sits at an unpublished 0.1.0 behind a `minor` changeset, which
  // versions to 0.2.0. Reading the manifest is what makes the drift impossible; these pin the read.
  it("reads its version out of its own manifest, at the package root", () => {
    expect(serverVersion()).toBe(manifestVersion());
  });

  it("refuses a manifest that states no version at all", () => {
    expect(() => readManifestVersion(manifestFileUrl("{}"))).toThrow(
      /no non-empty string "version"/,
    );
  });

  it("refuses a version that is not a string", () => {
    expect(() =>
      readManifestVersion(manifestFileUrl('{"version":123}')),
    ).toThrow(/no non-empty string "version"/);
  });

  it("refuses an empty version", () => {
    expect(() =>
      readManifestVersion(manifestFileUrl('{"version":""}')),
    ).toThrow(/no non-empty string "version"/);
  });

  it("refuses JSON that is not an object, and JSON that is null", () => {
    expect(() => readManifestVersion(manifestFileUrl("123"))).toThrow(
      /no non-empty string "version"/,
    );
    expect(() => readManifestVersion(manifestFileUrl("null"))).toThrow(
      /no non-empty string "version"/,
    );
  });

  it("names the file it could not read a version from", () => {
    const url = manifestFileUrl("{}");
    expect(() => readManifestVersion(url)).toThrow(url.href);
  });

  it("declares itself to a connected client", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    expect(client.getServerVersion()?.name).toBe(SERVER_NAME);
    // Against the MANIFEST, not against the module's own constant: this is the end of the chain the
    // release cut walks, and it is the assertion that would have caught a 0.2.0 release announcing 0.1.0.
    expect(client.getServerVersion()?.version).toBe(manifestVersion());
  });

  it("declares the tools capability, and no capability it does not serve", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const caps = client.getServerCapabilities();
    expect(caps?.tools).toBeDefined();
    expect(caps?.resources).toBeUndefined();
    expect(caps?.prompts).toBeUndefined();
  });

  it("lists no prompts and no resources — §C.9's are all agreement or dispute surfaces", async () => {
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    // The client short-circuits an unadvertised capability to an empty list rather than a round trip, so
    // an empty answer here is the client reading the capability set above and finding nothing declared.
    expect((await client.listPrompts()).prompts).toEqual([]);
    expect((await client.listResources()).resources).toEqual([]);
  });
});

describe("the Node wiring", () => {
  it("carries a stated reverse domain through to the placement deployment", () => {
    const ports = nodePorts({ [REVERSE_DOMAIN_ENV]: "com.integraledger" });
    expect(ports.deployment).toEqual({ reverseDomain: "com.integraledger" });
  });

  it("supplies NO deployment when the environment states none", () => {
    const ports = nodePorts({});
    expect("deployment" in ports).toBe(false);
  });

  it("reads the one variable it documents, and no other", () => {
    expect(REVERSE_DOMAIN_ENV).toBe("LCP_MCP_REVERSE_DOMAIN");
    expect(
      nodePorts({ REVERSE_DOMAIN: "com.example" }).deployment,
    ).toBeUndefined();
  });

  it("wires the guarded fetcher, not bare fetch — a non-HTTPS URL is refused", async () => {
    await expect(
      nodePorts({}).fetcher.fetch("http://seller.example/terms"),
    ).rejects.toThrow(/https/i);
  });

  it("clocks in ISO-8601, at the current instant", () => {
    const before = Date.now();
    const stamp = isoNow();
    expect(stamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(Date.parse(stamp)).toBeGreaterThanOrEqual(before - 1000);
    expect(Date.parse(stamp)).toBeLessThanOrEqual(Date.now() + 1000);
  });
});

describe("the stdio entry", () => {
  it("serves the same six tools over stdio as over any other transport", async () => {
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const handle = serveLcpStdio(
      { fetcher: servingFetcher({}) },
      { transport: serverTransport },
    );
    const { Client } = await import("@modelcontextprotocol/client");
    const client = new Client({ name: "stdio-test", version: "0.0.0" });
    await client.connect(clientTransport);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual([...LCP_TOOL_NAMES]);
    await client.close();
    await handle.close();
  });
});

describe("the LCP capability declaration", () => {
  it("reaches a real client, under the identifier the protocol package owns", async () => {
    // A DECLARATION IS ONLY REAL IF THE COUNTERPARTY SEES IT. Asserting the constructor argument would
    // prove we passed an object; the SDK strips unknown capability keys silently, so the only question
    // worth asking is what comes out the far side of a transport.
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const caps = client.getServerCapabilities();
    expect(caps?.extensions?.[LCP_MCP_EXTENSION_ID]).toEqual({
      specVersion: LCP_SPEC_VERSION,
    });
    // The identifier is MCP's shape, not UCP's, and the two are one character apart.
    expect(LCP_MCP_EXTENSION_ID).toContain("/");
    await client.close();
  });

  it("shows nothing when the declaration is absent — the control that lets the assertion fail", async () => {
    // Same SDK, same transport, same client; the ONLY difference is the missing capabilities option. If
    // this returned the extension too, the test above would be asserting something it did not cause.
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const bare = new McpServer({ name: SERVER_NAME, version: "0.0.0" });
    bare.registerTool("noop", { description: "noop", inputSchema: {} }, () => ({
      content: [],
    }));
    const { Client } = await import("@modelcontextprotocol/client");
    const client = new Client({ name: "control", version: "0.0.0" });
    await Promise.all([
      bare.connect(serverTransport),
      client.connect(clientTransport),
    ]);
    expect(client.getServerCapabilities()?.extensions).toBeUndefined();
    await client.close();
  });

  it("changes no tool behaviour — graceful degradation is total", async () => {
    // The specification's fallback branch: a client that ignores the extension MUST get the same server.
    // Declaring it must not add, remove or rename a tool, or the declaration has become a feature flag.
    const client = await connectTestClient({ fetcher: servingFetcher({}) });
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toEqual([...LCP_TOOL_NAMES]);
    await client.close();
  });
});
