import {
  type ServeStdioOptions,
  type StdioServerHandle,
  serveStdio,
} from "@modelcontextprotocol/server/stdio";
import type { LcpMcpPorts } from "./ports.js";
import { createLcpMcpServer } from "./server.js";

/**
 * Serve this server over stdio — the transport every desktop agent host speaks.
 *
 * `serveStdio` rather than a hand-wired `StdioServerTransport`: the MCP v2 entry owns the era decision for
 * the connection, pinning ONE instance from the factory for its lifetime, so a 2025-era client and a
 * 2026-07-28 client are both served correctly from the same registration. Hand-wiring a single transport
 * would serve only one of them, and which one would depend on the SDK version rather than on the client.
 *
 * `options` is passed straight through — a test drives a linked in-memory transport through it, and a
 * deployment that binds stdio to a socket per MCP's custom-transport guidance uses the same door.
 */
export function serveLcpStdio(
  ports: LcpMcpPorts,
  options?: ServeStdioOptions,
): StdioServerHandle {
  return serveStdio(() => createLcpMcpServer(ports), options);
}
