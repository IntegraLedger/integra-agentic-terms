import "server-only";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// The versions these pages document, read from the packages' manifests at build time. `next build` runs in website/,
// one level below the packages.

interface Manifest {
  version?: unknown;
  engines?: { node?: unknown };
  peerDependencies?: Record<string, unknown>;
}

function text(value: unknown, what: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${what} is missing`);
  return value;
}

function manifest(folder: string): Manifest {
  return JSON.parse(readFileSync(join(process.cwd(), "..", folder, "package.json"), "utf8")) as Manifest;
}

const terms = manifest("agentic-terms");
const mcp = manifest("agentic-terms-mcp");

/** The version of the packages these pages document, read from @integraledger/terms's manifest at build time. */
export const packageVersion: string = text(terms.version, "agentic-terms/package.json's version");

/** The Node.js versions @integraledger/terms runs on: its manifest's `engines.node`. */
export const nodeRange: string = text(terms.engines?.node, "agentic-terms/package.json's engines.node");

/** The range of @integraledger/lcp that @integraledger/terms asks for, a peer dependency. */
export const lcpRange: string = text(terms.peerDependencies?.["@integraledger/lcp"], "agentic-terms/package.json's peer @integraledger/lcp");

/** @integraledger/terms-mcp's version, and the Node.js versions it runs on. */
export const mcpVersion: string = text(mcp.version, "agentic-terms-mcp/package.json's version");
export const mcpNodeRange: string = text(mcp.engines?.node, "agentic-terms-mcp/package.json's engines.node");

/** integraledger-terms's version and `requires-python`, from the [project] table of its pyproject.toml. */
export const python: { version: string; requires: string } = (() => {
  const file = join(process.cwd(), "..", "agentic-terms-py", "pyproject.toml");
  const project = /^\[project\]\n([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(readFileSync(file, "utf8"))?.[1] ?? "";
  const field = (name: string) => text(new RegExp(`^${name}\\s*=\\s*"([^"]+)"`, "m").exec(project)?.[1], `${file}'s ${name}`);
  return { version: field("version"), requires: field("requires-python") };
})();

/** What these pages document, as each Markdown copy names it. */
export const documents = `@integraledger/terms ${packageVersion}, @integraledger/terms-mcp ${mcpVersion} and integraledger-terms ${python.version}`;
