# Integra Agentic Terms

The buyer/developer side of Legal Context Protocol commerce. Two packages, **Apache-2.0, free forever —
no account, no key, no token, nothing to sign up for.**

| Package | What it is |
|---|---|
| [`@integraledger/agentic-terms`](packages/agentic-terms) | Verify before sign, as a type and as a runtime guarantee. The gate fetches the terms the seller advertised, recomputes the LCP `atrHash` over the bytes actually served, and halts before any signing key is invoked if they disagree. |
| [`@integraledger/lcp-mcp-server`](packages/lcp-mcp-server) | Read-only Model Context Protocol server exposing LCP tools to an AI agent — verify before pay, compute an atrHash, extract and place references across the nine commerce protocols that have one. |

```bash
npm install @integraledger/agentic-terms
npm install @integraledger/lcp-mcp-server
```

📘 **Full documentation: [agenticterms.integraledger.com](https://agenticterms.integraledger.com)** — quickstart,
the buyer policy field by field, per-protocol pages, the six MCP tools, and the API reference.

Both work against **any** seller — the checks run over what a seller publicly advertises, so they are
useful whether or not that seller has ever heard of Integra. Nothing here calls home: no telemetry, no
callback, no network request other than fetching the terms the seller pointed you at.

## For agents

[`skills/verifying-terms-before-paying`](skills/verifying-terms-before-paying) is an Agent Skill — plain
markdown, no dependency on anything here — for an agent that is about to pay and wants to know whether the
terms it read are the terms the seller committed to. Copy the directory into wherever your tool reads
skills from.

It exists because the failure is not the one people expect. Agents handed a fingerprint that disagrees
already halt, reliably and unprompted. What they do instead is treat a seller who advertised **no**
fingerprint as nothing to check — and then hash the bytes themselves and call the gap closed, which records
what they saw and binds the seller to nothing.

## The standard

The [Legal Context Protocol](https://legalcontextprotocol.org/standard) is co-stewarded by Integra Ledger
and AAA-ICDR. These packages implement its buyer side over the public
[`@integraledger/lcp-*`](https://www.npmjs.com/search?q=%40integraledger%2Flcp) protocol packages. The
seller-side application they interoperate with is separately licensed and is not part of this repository.

## Developing

pnpm 11 workspace, Node ≥ 24.

```bash
pnpm install
pnpm verify          # versions → wire → public-boundary → audit → build → lint → typecheck → docs → test
pnpm mutation agentic-terms
pnpm docs:dev        # the documentation site in website/ (its own npm lockfile, not a workspace member)
```

See [AGENTS.md](AGENTS.md) for the gates and the constraints that outlive any one change.

## Licence

[Apache-2.0](LICENSE). See [NOTICE](NOTICE) for trademark and stewardship statements.
