// One stdio connection to a server from `createBuyerServer`, or from the factory given, over two PassThrough streams;
// or to the built `terms-mcp` binary, run as a child process. Raw JSON-RPC lines in, the answers read back by id.
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { PassThrough, type Readable, type Writable } from "node:stream";
import { StdioServerTransport, serveStdio } from "@modelcontextprotocol/server/stdio";
import type { Fetch, Signer } from "@integraledger/terms";
import { createBuyerServer } from "../src/index.js";

/**
 * Whether the gate has no summary yet of the request the pairing's build hands the signer: terms' own SUMMARY_PENDING
 * set (agentic-terms/test/support.ts), the one list of them. A test that pays such a pairing through a tool asserts the
 * decline summary-missing with no signer call while it is listed, and pays it in full once it is not.
 */
export { summaryPending } from "../../agentic-terms/test/support.js";

export type Message = { id?: number; result?: unknown; error?: { code: number; message: string; data?: unknown } };

/** The value at a dotted path inside a parsed JSON-RPC message, or undefined. */
export const at = (v: unknown, path: string): unknown =>
  path.split(".").reduce<unknown>((o, k) => (typeof o === "object" && o !== null ? (o as Record<string, unknown>)[k] : undefined), v);

/**
 * The buyer's request the 402 answered, as the tools take it: the protocol package's x402-request-commitment.json
 * http[0].request, a POST with a query and a JSON body, its body's bytes as base64.
 */
const COMMITTED = JSON.parse(
  readFileSync(new URL("../node_modules/@integraledger/lcp/vectors/x402-request-commitment.json", import.meta.url), "utf8"),
).http[0].request as { method: string; target: string; bodyUtf8: string };
export const REQUEST = {
  method: COMMITTED.method,
  target: COMMITTED.target,
  body: Buffer.from(COMMITTED.bodyUtf8, "utf8").toString("base64"),
};

/**
 * What the host gives every test server whose subject is not the ceiling: the delegation forms, which sign no end,
 * raised to "no-end", as terms' profile asks a caller to raise them.
 */
const HOST = {
  ceilings: { "x402/exact/eip155/erc7710": "no-end", "x402/exact/eip155/erc7710-salt": "no-end" },
} as const;

type Requests = { request(method: string, params?: object): Promise<unknown> };

/**
 * `atr_transact` as an agent that approves each signing it is shown: while the result holds `approve`, the call is made
 * again with `approved` set to `approve`, unchanged, at most `rounds` times. The last result, and each `approve` shown.
 */
export async function transacted(
  c: Requests,
  args: object,
  meta: object,
  rounds = 6,
): Promise<{ m: Message; shown: unknown[] }> {
  const shown: unknown[] = [];
  let m = (await c.request("tools/call", { name: "atr_transact", arguments: args, _meta: meta })) as Message;
  for (let i = 0; i < rounds; i++) {
    const approve = at(m, "result.structuredContent.approve");
    if (approve === undefined || at(m, "result.isError") === true) break;
    shown.push(approve);
    m = (await c.request("tools/call", { name: "atr_transact", arguments: { ...args, approved: approve }, _meta: meta })) as Message;
  }
  return { m, shown };
}

export function connect(
  options: Parameters<typeof createBuyerServer>[0],
  create: typeof createBuyerServer = createBuyerServer,
) {
  const input = new PassThrough();
  const output = new PassThrough();
  const handle = serveStdio(() => create({ ...HOST, ...options }), {
    legacy: "serve",
    transport: new StdioServerTransport(input, output),
  });
  return { ...lines(input, output), close: () => handle.close() };
}

/**
 * One stdio connection to `dist/bin.js`, the built binary, in its own Node.js process. A request waits for the binary's
 * own answer, and fails when the process closes before it answers.
 */
export function spawnBin() {
  const bin = fileURLToPath(new URL("../dist/bin.js", import.meta.url));
  const child = spawn(process.execPath, [bin], { stdio: ["pipe", "pipe", "inherit"] });
  // "close" follows the end of the binary's output, so every answer it wrote has been read by then.
  const closed = once(child, "close").then(
    ([code, signal]) => `the terms-mcp binary closed (${signal ?? `exit ${code}`})`,
  );
  // A write to a binary that has closed fails its request through `closed`.
  child.stdin.on("error", () => {});
  return {
    ...lines(child.stdin, child.stdout, closed),
    close: async () => {
      child.stdin.end();
      await closed;
    },
  };
}

/**
 * Writes JSON-RPC lines to `input` and reads the answers from `output` by id. A request waits for its answer, or until
 * `ended` settles, when it is given. It sets no time bound of its own: a request that is never answered is stopped by
 * the test's two-minute timeout (vitest.config.ts).
 */
function lines(input: Writable, output: Readable, ended?: Promise<string>) {
  const waiting = new Map<number, (m: Message) => void>();
  const failing = new Map<number, (why: string) => void>();
  let gone: string | undefined;
  ended?.then(
    (why) => end(why),
    (e: unknown) => end(String(e)),
  );
  function end(why: string) {
    gone = why;
    for (const fail of failing.values()) fail(why);
  }
  let buffer = "";
  output.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf8");
    let nl: number;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 1);
      if (line.trim() === "") continue;
      const m: Message = JSON.parse(line);
      if (m.id !== undefined) waiting.get(m.id)?.(m);
    }
  });
  let next = 1;
  /** Writes one request and resolves with the answer carrying its id, or rejects when `ended` settles first. */
  function request(method: string, params: object = {}): Promise<Message> {
    const id = next++;
    return new Promise<Message>((resolve, reject) => {
      const fail = (why: string) => {
        waiting.delete(id);
        failing.delete(id);
        reject(new Error(`no answer to ${method}: ${why}`));
      };
      waiting.set(id, (m) => {
        waiting.delete(id);
        failing.delete(id);
        resolve(m);
      });
      failing.set(id, fail);
      if (gone !== undefined) fail(gone);
      else input.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }
  const notify = (method: string, params: object = {}) =>
    input.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  return { request, notify };
}
