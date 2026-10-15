// One stdio connection to a server from `createBuyerServer`, or from the factory given, over two PassThrough streams;
// or to the built `terms-mcp` binary, run as a child process. Raw JSON-RPC lines in, the answers read back by id.
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { PassThrough, type Readable, type Writable } from "node:stream";
import { StdioServerTransport, serveStdio } from "@modelcontextprotocol/server/stdio";
import type { Fetch, Signer } from "@integraledger/terms";
import { createBuyerServer } from "../src/index.js";

export type Message = { id?: number; result?: unknown; error?: { code: number; message: string; data?: unknown } };
/** How long a request to a server in this process waits for its answer: a bound well past its time under load. */
const ANSWER_MS = 30_000;

/** The value at a dotted path inside a parsed JSON-RPC message, or undefined. */
export const at = (v: unknown, path: string): unknown =>
  path.split(".").reduce<unknown>((o, k) => (typeof o === "object" && o !== null ? (o as Record<string, unknown>)[k] : undefined), v);

/** One stdio connection to a server from the factory: writes JSON-RPC lines, reads the answers by id. */
export function connect(
  options: { fetch: Fetch; signer?: Signer; agreementSigner?: Signer },
  create: typeof createBuyerServer = createBuyerServer,
) {
  const input = new PassThrough();
  const output = new PassThrough();
  const handle = serveStdio(() => create(options), {
    legacy: "serve",
    transport: new StdioServerTransport(input, output),
  });
  return { ...lines(input, output), close: () => handle.close() };
}

/**
 * One stdio connection to `dist/bin.js`, the built binary, in its own Node.js process. A request waits for the binary's
 * own answer, and fails when the process closes before it answers: no clock bounds it.
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
 * Writes JSON-RPC lines to `input` and reads the answers from `output` by id. A request waits for its answer until
 * `ended` settles, when it is given, and otherwise for ANSWER_MS.
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
  /**
   * Writes one request and resolves with the answer carrying its id, or rejects when `ended` settles first, or, with no
   * `ended`, when none comes within ANSWER_MS.
   */
  function request(method: string, params: object = {}): Promise<Message> {
    const id = next++;
    return new Promise<Message>((resolve, reject) => {
      const fail = (why: string) => {
        clearTimeout(timer);
        waiting.delete(id);
        failing.delete(id);
        reject(new Error(`no answer to ${method}: ${why}`));
      };
      const timer = ended === undefined ? setTimeout(() => fail(`none within ${ANSWER_MS} ms`), ANSWER_MS) : undefined;
      waiting.set(id, (m) => {
        clearTimeout(timer);
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
