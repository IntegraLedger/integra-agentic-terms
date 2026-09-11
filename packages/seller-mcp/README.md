# @integraledger/seller-mcp

The MCP seller face — a seller exposes a paid tool, and the payment that unlocks it welds a terms record.

> **A library mount, not a service.** You mount this in your own MCP server process, beside your own tool
> handler and your own x402 middleware. It hosts nothing, calls nobody, and holds no credential.

## Why this package exists, and why there are not seven of these

The obvious shape of "make agentic commerce reachable" is one seller-face adapter per agent framework.
Verified against live sources, **six of the seven candidates have no seller face to adapt**:

- Coinbase AgentKit's x402 action provider is entirely buyer-side — discover, request, retry, register a
  service to call, list.
- LangChain JS has no server or hosting surface at all.
- The OpenAI Agents SDK's MCP module is a *client* that connects to MCP servers.
- Google ADK JS's server ships as a separate devtools package.
- AWS AgentCore is Python-only, so a TypeScript adapter is not installable.

Agent frameworks are overwhelmingly client-side orchestration. ⇒ **What they converge on is MCP.** A seller
exposes a paid capability as an MCP tool, and every one of those frameworks reaches it as a client. So the
missing surface is this one, not seven near-duplicates — and building the other six would mean inventing
seller faces their owners have not defined.

## It is a TRANSPORT adapter, and deliberately nothing more

The ordered on-chain gates in an x402 seller's settle path are the safety property, and burning the proposal
is irreversible. This package **reimplements none of it**. It translates an MCP tool call into the
web-standard `Request` a seller middleware already takes, and translates the `Response` back — exactly what
a framework adapter for Express, Hono, Next or Workers does.

The weld is identical because it is the same code on the other side: the buyer's EIP-3009 nonce **is** the
`atrHash`. Only the envelope differs.

## Use

```ts
import { paidTool, type SellerMiddlewareLike } from "@integraledger/seller-mcp";

// ⛔ Mount the middleware so that IT DOES NOT FULFIL. An MCP tool's answer is an `McpToolResult` with its
//    own content blocks, which no `Response` models — so your handler below is the fulfilment, and the
//    middleware produces a body-less 200 carrying only the receipt. A middleware that also calls a
//    fulfilment port of its own would call your system TWICE for one sale.
declare const middleware: SellerMiddlewareLike;

const summarize = paidTool<{ url: string }>(
  middleware,
  { resourceUrl: "https://seller.example/tools/summarize" },
  async (args, welded) => ({
    content: [{ type: "text", text: `summary of ${args.url}, under ${welded.atrHash}` }],
  }),
);
// then register `summarize` with your MCP server under whatever name you expose it as.
```

## No dependencies, at either edge

Both edges are **structurally typed**: the MCP shapes this adapter reads (`McpToolResult`,
`McpToolExtraLike`) and the middleware shapes it drives (`SellerMiddlewareLike`, `WeldFacts`) are described
here rather than imported. So this package has **no runtime dependencies at all** — it mounts on any MCP
server implementation, against any middleware with that shape, and a reader can see the whole of what
happens between a tool call and a payment.

`WeldFacts` is deliberately minimal: the two facts a failure report must name. It is a *lower bound*, not a
ceiling — `paidTool` is generic in the weld, so a middleware carrying a richer welded settlement passes
every field of it through to your handler unchanged.

## API surface

| Export | What it is |
|---|---|
| `paidTool` | Wrap a tool handler so its call is gated by a welded payment |
| `PaidToolHandler`, `PaidToolOptions`, `Fulfil` | The handler, its options, and what runs once payment is welded |
| `SellerMiddlewareLike`, `MiddlewareResultLike`, `WeldFacts` | The middleware edge, structurally typed |
| `deliverWeld`, `WeldSink` | The weld sink, and the rule that its failure never reaches the buyer |
| `MCP_PAYMENT_META_KEY`, `MCP_PAYMENT_RESPONSE_META_KEY` | The `_meta` keys the payment and the receipt travel under. ⛔ The response key carries the `PAYMENT-RESPONSE` **header**, never the 200's body |
| `McpToolResult`, `McpTextContent`, `McpToolExtraLike` | The minimal MCP shapes, structurally typed |
| `SUPPORTED_X402_VERSION`, `declaredX402Version` | The x402 version this face speaks, and what a request declared |

## The carrier is `_meta`, which is MCP's own extension point

MCP gives tool results and requests a `_meta` map for exactly this. The payment and the receipt ride there
rather than in a field this package invented — the host governs, and a surface that asked MCP to adopt our
shape first would not be installable today. The keys are spelled x402's way because they are x402's keys;
`test/meta-keys.test.ts` drives them against MCP's published key grammar rather than asserting conformance
in a comment.

## Two rules that are easy to lose

**The receipt is the header, not the body.** A middleware puts the host's settlement response on
`PAYMENT-RESPONSE`, base64-encoded; the 200's body is the resource. Returning the body under
`_meta["x402/payment-response"]` hands a buyer the thing they bought where the proof they bought it belongs.

**A weld sink that throws must never reach the buyer.** By the time a weld exists the proposal is burned and
that is irreversible, so a sink failure that propagated would answer a buyer who has paid with an error —
for a sale that completed. `deliverWeld` reports it on the error channel, naming the `atrHash` and the
payment identifier, and the buyer is served.

## Boundaries

**No settlement logic.** Every on-chain gate, the ordering between them, and the irreversible burn stay in
the middleware you mount.

**No credential.** This adapter wraps a middleware in your own process; the weld is the buyer's EIP-3009
nonce. Nothing here is configured with, stores, or transmits a key.

**Not a hosted route.** `paidTool` is a mount-time factory, not an operation: two of its three arguments —
a mounted middleware and your own tool handler — are things a wire cannot carry and a configuration document
cannot hold. The shape shown under Use is the supported one.

Licensed Apache-2.0. The seller-side application this is designed to mount in is separately licensed and is
not part of this distribution.
