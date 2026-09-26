// The built entry point where there is no filesystem: dist/index.js bundled by esbuild for the neutral platform, with
// its dependencies (the terms and protocol packages, the MCP server and zod) handed in from outside, then run in a bare
// node:vm context whose globals are the language's own plus TextEncoder and URL, with no require, no process and no
// Buffer, and where import.meta.url is not a file URL. The expected values: `initialize` is answered with the version in
// package.json, and BINDINGS is the protocol package's own list.
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { build, type Plugin } from "esbuild";
import { describe, expect, it } from "vitest";
import * as lcp from "@integraledger/lcp";
import * as terms from "@integraledger/terms";
import * as mcp from "@modelcontextprotocol/server";
import * as zod from "zod";
import type { createBuyerServer } from "../src/index.js";
import { at, connect } from "./stdio.js";

const root = new URL("../", import.meta.url);
const ENTRY = fileURLToPath(new URL("dist/index.js", root));
const VERSION: string = JSON.parse(readFileSync(new URL("package.json", root), "utf8")).version;
const DEPS: Record<string, unknown> = {
  "@integraledger/lcp": lcp,
  "@integraledger/terms": terms,
  "@modelcontextprotocol/server": mcp,
  zod,
};

/** Resolves each dependency to the module handed in through the context's `deps`. */
const handedIn: Plugin = {
  name: "handed-in",
  setup(b) {
    b.onResolve({ filter: /.*/ }, (a) => (a.path in DEPS ? { path: a.path, namespace: "dep" } : undefined));
    b.onLoad({ filter: /.*/, namespace: "dep" }, (a) => ({
      contents: `module.exports = globalThis.deps[${JSON.stringify(a.path)}];`,
      loader: "js",
    }));
  },
};

/** The bundle's exports, evaluated in a context holding only what an edge runtime's global scope offers. */
async function loadBundle(): Promise<{ exports: Record<string, unknown>; globals: string }> {
  expect(existsSync(ENTRY), "dist/index.js is missing: build the package first").toBe(true);
  const out = await build({
    entryPoints: [ENTRY],
    bundle: true,
    write: false,
    platform: "neutral",
    format: "iife",
    globalName: "termsMcp",
    external: ["node:*"],
    define: { "import.meta.url": JSON.stringify("worker") },
    plugins: [handedIn],
    logLevel: "silent",
  });
  const context: Record<string, unknown> = { TextEncoder, URL, deps: DEPS };
  const globals = runInNewContext("[typeof require, typeof process, typeof Buffer].join()", context) as string;
  runInNewContext(out.outputFiles[0]!.text, context, { filename: "bundle.js" });
  return { exports: context["termsMcp"] as Record<string, unknown>, globals };
}

describe("the entry point bundled for an edge runtime", () => {
  it("loads with no filesystem, and its server answers initialize with the package's version", async () => {
    const { exports, globals } = await loadBundle();
    expect(globals).toBe("undefined,undefined,undefined");
    expect(exports["BINDINGS"]).toBe(lcp.BINDINGS);

    const create = exports["createBuyerServer"] as typeof createBuyerServer;
    const c = connect({ fetch: async () => new Response(null, { status: 404 }) }, create);
    const init = await c.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "t", version: "1" },
    });
    expect(at(init, "result.serverInfo.version")).toBe(VERSION);
    await c.close();
  });
});
