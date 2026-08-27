---
"@integraledger/agentic-terms": minor
---

Renamed from `@integraledger/agent-guard` to `@integraledger/agentic-terms`.

The former name collided with at least ten concurrent products in AI-agent security, every one of them
senior to this package's first publish on 2026-08-13 — among them AppOmni's AgentGuard (2025-11-19) and
Jozu's Agent Guard (2026-03-12), both announced through wire services. The name identified nothing.

`@integraledger/agent-guard` is deprecated and will receive no further releases. Versioning continues on
the same line rather than restarting, so changelog history reads straight through.

**Breaking:** the exported type `GuardedSigner` is now `GatedSigner`. No alias is provided. Every other
export is unchanged — `transact`, `GatePorts`, `GateProposal`, `BuyerPolicy` and `makeCachingFetcher` keep
their names and signatures.

`@integraledger/lcp-mcp-server` is unaffected in name, in its `lcp-mcp` server identity, and in all six of
its `lcp_*` tool names; it moves only because the two packages version in lockstep.

The documentation site moves to <https://agenticterms.integraledger.com>.
