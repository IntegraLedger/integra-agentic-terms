// One stdio connection to a server from `createBuyerServer`, or from the factory given, over two PassThrough streams:
// raw JSON-RPC lines in, the answers read back by id.
import { PassThrough } from "node:stream";
import { StdioServerTransport, serveStdio } from "@modelcontextprotocol/server/stdio";
import type { Fetch, Signer } from "@integraledger/terms";
import { createBuyerServer } from "../src/index.js";

export type Message = { id?: number; result?: unknown; error?: { code: number; message: string; data?: unknown } };
/** How long a request waits for its answer: patient under a loaded machine, and still bounded. */
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
  const waiting = new Map<number, (m: Message) => void>();
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
  /** Writes one request and resolves with the answer carrying its id, or rejects when none comes within ANSWER_MS. */
  function request(method: string, params: object = {}): Promise<Message> {
    const id = next++;
    return new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => {
        waiting.delete(id);
        reject(new Error(`no answer to ${method}`));
      }, ANSWER_MS);
      waiting.set(id, (m) => {
        clearTimeout(timer);
        waiting.delete(id);
        resolve(m);
      });
      input.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });
  }
  const notify = (method: string, params: object = {}) =>
    input.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
  return { request, notify, close: () => handle.close() };
}
