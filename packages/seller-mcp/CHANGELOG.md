# @integraledger/seller-mcp

## 0.10.0

### Minor Changes

- The MCP seller face, published.

  A seller exposes a paid tool, and the payment that unlocks it welds a terms record. This package is the
  translation between the two: an MCP tool call becomes the web-standard `Request` an x402 seller middleware
  already takes, and the `Response` becomes an `McpToolResult`.

  **It is one package rather than the seven an agent-framework sweep would suggest, and the reason is
  evidence.** Verified against live sources: Coinbase AgentKit's x402 action provider is entirely buyer-side;
  LangChain JS has no server or hosting surface; the OpenAI Agents SDK's MCP module is a client that connects
  to MCP servers; Google ADK JS's server ships as a separate devtools package; AWS AgentCore is Python-only.
  Agent frameworks are overwhelmingly client-side orchestration, and what they converge on is MCP — so this
  one surface reaches them, and building the others would mean inventing seller faces their owners have not
  defined.

  **A transport adapter and nothing more.** The ordered on-chain gates in a seller's settle path are the
  safety property and burning the proposal is irreversible, so none of it is reimplemented here. The weld is
  identical because it is the same code on the other side: the buyer's EIP-3009 nonce IS the `atrHash`.

  The carrier is `_meta` — MCP's own documented arbitrary-key map, so nothing is asked of the protocol that
  it has not already defined. `test/meta-keys.test.ts` drives the two keys against MCP's published key
  grammar rather than asserting conformance in a comment.

  **Structurally typed at both edges, so it takes no dependency at all.** The MCP shapes it reads and the
  middleware shapes it drives are described here rather than imported, which is what lets a transport adapter
  ship publicly beside a separately licensed seller application: it holds no key, contains no settlement
  logic, and can be read in full by anyone who wants to know exactly what happens between a tool call and a
  payment. `paidTool` is generic in the weld, so a middleware carrying a richer welded settlement passes
  every field of it through to the seller's handler unchanged.

  ⚠️ **Versions before this one were never published.** The package was developed privately as part of the
  seller-side application; the version number is carried across unchanged rather than restarted, because it
  is the same package and its own history is what these notes describe.
