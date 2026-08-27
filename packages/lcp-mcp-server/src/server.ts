import { LCP_MCP_EXTENSION_ID } from "@integraledger/lcp-discovery";
import { LCP_SPEC_VERSION } from "@integraledger/lcp-kernel";
import { McpServer } from "@modelcontextprotocol/server";
import type { LcpMcpPorts } from "./ports.js";
import { registerComputeAtrHash } from "./tools/compute-atrhash.js";
import { registerExtractReference } from "./tools/extract-reference.js";
import { registerGenerateLegalContext } from "./tools/generate-legal-context.js";
import { registerPlaceReference } from "./tools/place-reference.js";
import { registerScaffoldIntegration } from "./tools/scaffold-integration.js";
import { registerVerifyBeforePay } from "./tools/verify-before-pay.js";
import { serverVersion } from "./version.js";

/**
 * The MCP server name, and the reason it is not the one the specification illustrates.
 *
 * LCP v1.38 §C.9 shows a different tool vocabulary (`get_legal_context`, `verify_terms`, …) and says in the
 * same breath that "the standard does not canonize a particular tool registry" and that the MCP stewards
 * are invited to publish canonical names. An appendix example is not an interoperability fact: names an
 * agent host has already learned are, because a host that has learned a name breaks when it changes.
 * Renaming these to match an illustration the specification itself declines to canonize would break working
 * integrations and make nothing canonical in exchange.
 */
export const SERVER_NAME = "lcp-mcp";

/**
 * Every tool this server exposes, in registration order.
 *
 * Exported so the boundary can be ASSERTED rather than described. LCP §C.9's illustrative table also lists
 * `accept_terms`, `create_agreement`, `get_agreement`, `initiate_dispute` and `get_dispute_status`; none of
 * them is here and none is coming. Recording an acceptance, holding the agreement record, or running the
 * dispute are the roles of a custodian and a forum — we are neither. Integra is the record engine; the
 * custodian of the record and the forum for the dispute are the deployment's and the counterparties' own.
 * A server that offered `initiate_dispute` would be asserting an operating role the mandate forbids, and it
 * is far easier to not add a seventh tool than to remove it after an agent has learned to call it.
 */
export const LCP_TOOL_NAMES = [
  "lcp_compute_atrhash",
  "lcp_generate_legal_context",
  "lcp_verify_before_pay",
  "lcp_scaffold_integration",
  "lcp_place_reference",
  "lcp_extract_reference",
] as const;

/**
 * Build the LCP MCP server.
 *
 * A FACTORY, not a singleton, because that is what the transports want: `serveStdio` and
 * `createMcpHandler` both take a factory and may build one instance per connection or per era. Handing
 * them a shared instance would make one client's state another's.
 *
 * The server declares `tools` by REGISTERING tools rather than by asserting a capability in the
 * constructor. MCP requires a server that supports tools to declare the capability and does not permit
 * declaring one that is not served; the SDK derives the declaration from the registrations, so a
 * constructor-side `{ capabilities: { tools: {} } }` is a second statement of the same fact that cannot be
 * wrong today and could be wrong tomorrow. Measured: removing it changes nothing a client sees, which is
 * exactly why it does not belong.
 *
 * ONE capability is asserted in the constructor beside it — the LCP extension, for the opposite reason:
 * nothing derives it. See the comment on the assertion itself.
 *
 * There are no resources and no prompts. §C.9 illustrates both — `lcp://agreement/{id}`,
 * `dispute_evidence_assembly` — and every one of its examples is an agreement or dispute surface, which is
 * the boundary above. When there is a resource to serve that is not one of those, it is declared then.
 */
export function createLcpMcpServer(ports: LcpMcpPorts): McpServer {
  const server = new McpServer(
    { name: SERVER_NAME, version: serverVersion() },
    {
      // THE ONE CAPABILITY THAT MUST BE ASSERTED, AND IT DOES NOT CONTRADICT THE PARAGRAPH ABOVE.
      //
      // `tools` is left to the registrations because the SDK DERIVES it — restating it in the constructor
      // is a second statement of a fact something else already owns. An extension has no such deriver:
      // nothing about registering a tool implies this server speaks LCP, so the constructor is the only
      // place the declaration can come from, and asserting it here states a fact rather than duplicating
      // one. Do not "consistency-fix" this by deleting it; measured, removing it makes the extension
      // vanish from what a client sees, which is precisely what the sibling test asserts.
      //
      // BOTH VALUES ARE IMPORTED, NEITHER IS SPELLED HERE. The identifier is a wire identity a
      // counterparty must recognise, and `check:wire` seals it by importing `lcp-discovery`; a local copy
      // would be a second home the gate cannot see. `LCP_SPEC_VERSION` is the kernel's own answer to which
      // revision this stack implements, so a literal here would drift the first time the spec moved.
      capabilities: {
        extensions: {
          [LCP_MCP_EXTENSION_ID]: { specVersion: LCP_SPEC_VERSION },
        },
      },
    },
  );
  registerComputeAtrHash(server, ports);
  registerGenerateLegalContext(server, ports);
  registerVerifyBeforePay(server, ports);
  registerScaffoldIntegration(server);
  registerPlaceReference(server, ports);
  registerExtractReference(server, ports);
  return server;
}
