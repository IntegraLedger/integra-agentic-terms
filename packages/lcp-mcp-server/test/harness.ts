import {
  type HostLookup,
  makeCachingFetcher,
  type TermsFetcher,
} from "@integraledger/agentic-terms";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";
import type { LcpMcpPorts } from "../src/ports.js";
import { createLcpMcpServer } from "../src/server.js";

/**
 * A client talking to a real server over the SDK's own linked in-memory transport pair.
 *
 * NOT a stub of either side: `Client` and `McpServer` are the shipped implementations and every assertion
 * below travels the real `tools/list` and `tools/call` wire, through the SDK's input validation, output
 * validation and error projection. What the tests read is what an agent host reads.
 */
export async function connectTestClient(ports: LcpMcpPorts): Promise<Client> {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await createLcpMcpServer(ports).connect(serverTransport);
  const client = new Client({ name: "lcp-mcp-test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  return client;
}

/** Every resolution answers with a public unicast address: these suites exercise LCP behaviour, not the
 *  SSRF guard, whose own coverage lives in `agentic-terms`'s `fetch.test.ts`. */
const publicHost: HostLookup = async () => [
  { address: "93.184.216.34", family: 4 },
];

/**
 * The REAL terms fetcher — `agentic-terms`'s `makeCachingFetcher` — over an in-process origin.
 *
 * Its two ports are injected exactly as the package's own tests inject them, so the HTTPS-only rule, the
 * `redirect: "error"` posture, the unicast check and the streaming byte cap are all live here. Only the
 * socket is absent. A hand-written `TermsFetcher` stub would have skipped all four.
 */
export function servingFetcher(
  routes: Readonly<Record<string, { body: string; contentType?: string }>>,
): TermsFetcher {
  const httpFetch = (async (
    input: string | URL | Request,
  ): Promise<Response> => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const route = routes[url];
    if (route === undefined)
      return new Response("no such route", { status: 404 });
    return new Response(route.body, {
      headers: { "content-type": route.contentType ?? "text/markdown" },
    });
  }) as typeof fetch;
  return makeCachingFetcher({
    httpFetch,
    now: () => new Date().toISOString(),
    lookup: publicHost,
  });
}

/** The `structuredContent` of a tool result, as a plain record the tests can index. */
export function structured(result: {
  structuredContent?: unknown;
}): Record<string, unknown> {
  const sc = result.structuredContent;
  if (typeof sc !== "object" || sc === null)
    throw new Error(`tool result carried no structuredContent: ${String(sc)}`);
  return sc as Record<string, unknown>;
}

/** The concatenated text content of a tool result — where a thrown handler error lands. */
export function text(result: { content?: readonly unknown[] }): string {
  return (result.content ?? [])
    .map((block) =>
      typeof block === "object" &&
      block !== null &&
      "text" in block &&
      typeof block.text === "string"
        ? block.text
        : "",
    )
    .join("\n");
}
