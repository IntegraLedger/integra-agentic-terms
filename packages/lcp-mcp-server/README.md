# @integraledger/lcp-mcp-server

The LCP delivery surface for MCP. An agent host that already speaks the Model Context Protocol gains
legal-context capability with no per-platform integration — and the same server works whichever commerce
protocol the agent is transacting under, because where the reference belongs is the placement registry's
decision, not this server's.

```bash
npm install @integraledger/lcp-mcp-server
```

> **Free and open source (Apache-2.0). No account, no key, no token, nothing to sign up for.**
>
> Every tool is **read-only** and works against **any** counterparty's documents — whether or not they use
> Integra software. Nothing here calls home: no telemetry, no callback.

Run it over stdio, which is what every desktop agent host speaks:

```jsonc
// .mcp.json
{
  "mcpServers": {
    "lcp": { "command": "npx", "args": ["-y", "@integraledger/lcp-mcp-server"] }
  }
}
```

Or mount it yourself, supplying the ports:

```ts
import {
  createLcpMcpServer,
  nodePorts,
  serveLcpStdio,
} from "@integraledger/lcp-mcp-server";

const ports = nodePorts(process.env);

serveLcpStdio(ports); // stdio, ports wired for Node
const server = createLcpMcpServer(ports); // or build one and connect any MCP transport
```

## The tools

| Tool | What it does |
|---|---|
| `lcp_compute_atrhash` | SHA-256 over terms bytes (inline or fetched) → `atrHash` and the `lcp:sha256:0x…` carrier |
| `lcp_generate_legal_context` | Builds a validated, ready-to-publish `/.well-known/legal-context.json` |
| `lcp_verify_before_pay` | Verify before sign (LCP §5.3): fetch, recompute, compare, and say whether an agent must halt |
| `lcp_scaffold_integration` | Starter code for the seller side or the buyer side |
| `lcp_place_reference` | Puts a reference into any registered commerce protocol's own document |
| `lcp_extract_reference` | Reads one back out |

**These `lcp_*` names are stable.** LCP v1.38 §C.9 illustrates a different vocabulary
(`get_legal_context`, `verify_terms`, …) and says in the same breath that the standard canonizes no tool
registry. Names a deployed server already answers to are the stronger interoperability fact, so renaming
them to match an appendix's example would break working integrations and make nothing canonical.

**There is no `create_agreement`, `accept_terms`, `initiate_dispute` or `get_dispute_status`, and there will
not be.** §C.9's table lists all four. Each asserts a custodian or forum role: holding the agreement record,
recording the acceptance, running the dispute. Integra is the record engine; the custodian and the forum are
the deployment's and the counterparties' own. A test asserts their absence.

Every tool **reads**. Nothing here publishes a document, transmits one, or holds a credential:
`lcp_generate_legal_context` returns a document for you to serve, and `lcp_place_reference` returns a
document for your agent to send with its own keys.

## Ports

`LcpMcpPorts` has no defaults, and both entries are the reason:

- **`fetcher`** — `agentic-terms`'s `makeCachingFetcher`: HTTPS-only, `redirect: "error"`, every resolved
  address checked public unicast on *every* network fetch, body capped while streaming, LCP §2.6 cache
  discipline. The URLs this server fetches are chosen by a counterparty, so bare `fetch` here would turn
  `lcp_verify_before_pay` into an SSRF primitive an agent can be talked into aiming anywhere.
- **`deployment.reverseDomain`** — optional, and absent by default. Only namespaced placements need it
  (Mastercard VI's custom Layer-2 constraint type). LCP §8 canonizes no per-protocol integration profile, so
  a default would write *our* domain into someone else's signed document. Set `LCP_MCP_REVERSE_DOMAIN` and
  `nodePorts` passes it through.

## The LCP capability declaration

The server declares an LCP extension capability in its constructor, carrying the specification version this
stack implements. An MCP host can therefore discover that this server verifies the legal context bound to a
payment **without calling a tool**.

That one capability is asserted rather than derived, and `tools` beside it is the opposite. The SDK derives
`tools` from the registrations, so restating it in the constructor would be a second statement of a fact
something else owns. Nothing derives an extension: no registration implies this server speaks LCP, so the
constructor is the only place the declaration can come from.

Both values are **imported**, never spelled locally — the identifier is a wire identity a counterparty must
recognize, and the specification version is the kernel's own answer to which revision this stack implements.

**Graceful degradation is total.** A client that ignores the identifier gets a byte-identical server; no
branch of the extension refuses a request, and a test asserts the tool list is unchanged. A client must not
read the declaration as a claim that any seller's terms are bound — it describes this server's capability,
never a transaction.

## One protocol line in the tree

This server declares the protocol line as a **caret at the minor's zero patch**, and `agentic-terms` peers it
the same way. That is what puts **one** line of the protocol packages in `node_modules` when you install
both: the two ranges overlap, so a package manager resolves a single copy that satisfies each. An exact
runtime pin would do the opposite — it cannot be satisfied by the sibling's range, so the resolver nests a
second copy underneath this package, and the two halves of one install then read different protocol code.

If a mixed install ever does put two lines in one tree, the seam stays safe: what this package takes from
`agentic-terms` is the fetcher and nothing else — `makeCachingFetcher`, `nodeDnsLookup`, and the
`TermsFetcher` type — whose entire vocabulary is `fetch(url: string)` in, `{ bytes, format, fetchedAt }`
out, plus a `{ address, family }` DNS answer. Not one of those names an `lcp-kernel`, `lcp-binding-core` or
`lcp-discovery` type in either direction, so two lines never exchange a value.

## Checked against the live MCP specification — 2026-07-30

Checked against the **live MCP specification**, revision `2026-07-28`, not against LCP's Appendix C.

| Checked | Source | Finding |
|---|---|---|
| Tool registration | `modelcontextprotocol.io/specification/2026-07-28/server/tools` | `tools/list` + `tools/call`; a server supporting tools MUST declare the capability; tool names SHOULD be `[A-Za-z0-9_.-]`, 1–128 chars, unique per server. `lcp_*` conforms. |
| Annotation semantics | `schema/2026-07-28/schema.ts`, `ToolAnnotations` | **Defaults are `readOnlyHint: false`, `destructiveHint: true`, `idempotentHint: false`, `openWorldHint: true`.** `destructiveHint` is "meaningful only when `readOnlyHint == false`". |
| Trust posture | same page, Data Types → Tool | "clients **MUST** consider tool annotations to be untrusted unless they come from trusted servers". |
| Result shape | same page, Tool Result | Structured results conform to `outputSchema` when declared; a tool returning structured content SHOULD also return the serialized JSON in a text block. Business-logic failures are `isError: true` in the result, not JSON-RPC errors. |
| SDK | `@modelcontextprotocol/server@2.0.0`, published 2026-07-27T23:55Z | v2 is the stable line implementing this revision; v1's monolithic `@modelcontextprotocol/sdk` is superseded. Age checked against the workspace's 24h `minimumReleaseAge` on 2026-07-30 — clear. The quarantine exclusion covers `@integraledger/*` only. |

**One finding corrects the plan.** LCP §C.9 says annotations "such as `destructiveHint` and `openWorldHint`
signal that LCP-aware tools perform legally significant actions". MCP defines `destructiveHint` as *may
perform destructive updates to its environment* — there is no annotation meaning "legally significant", and
repurposing one would assert something no client can read. Every tool here is therefore
`readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, with `openWorldHint` true for
exactly the three that fetch. The legal significance is carried where a client *does* read it: in each
tool's `description`. Stating `destructiveHint: false` rather than omitting it is load-bearing — the default
is `true`, so silence would describe every one of these as possibly destructive.

**One finding narrows a tool.** A verifier that reads an ES256 `signing` block out of
`legal-context.json` is reading a field LCP does not define — Level 3 is the *buyer's* signed acceptance over the
fingerprint (§3, §4.2), and the discovery document carries no seller signature at any level. Re-grounding on
`@integraledger/lcp-discovery` drops it, because promoting it would have shipped a private extension as LCP.
`lcp_verify_before_pay` also inherits DSC-2's machine-readable-format rule, so a `pdf` listing is reported
`unverifiable` rather than passed through.

Part of [Integra Agentic Terms](https://github.com/IntegraLedger/integra-agentic-terms).
