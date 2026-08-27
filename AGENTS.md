# integra-agentic-terms — agent instructions

Two packages, both **public, Apache-2.0, free forever and never monetized**: `agentic-terms`, the buyer-side
verify-before-sign gate, and `lcp-mcp-server`, its Model Context Protocol packaging. Anything that makes
either harder to install is a defect, not a hardening measure. Both work against any seller.

Consumes the Legal Context Protocol's public `@integraledger/lcp-*` packages from npmjs, exact-pinned. The
separately licensed seller-side application is **not** part of this repository and nothing here may depend
on it — `check:public-boundary` refuses any `@integraledger/*` dependency that is neither a workspace
sibling nor on the `lcp-*` line, because such a dependency resolves in a private workspace and breaks only
for the first stranger to `npm install`, after the version is burned.

pnpm 11 workspace, Node ≥ 24, TypeScript with `isolatedDeclarations`.

## Gates

```
pnpm verify  =  check:versions → check:commit-messages → check:wire → check:public-boundary → check:vocab
                → audit → build → lint → typecheck → check:docs → test
pnpm mutation <pkg>            (STRYKER_PKG required; ratchets in stryker.config.mjs — raise, never lower)
pnpm check:runtime             (packs, installs as a consumer, runs the gate — the Node leg of the matrix)
```

⚠️ **`check:runtime` is NOT in `verify`, and the matrix is CI-only.** It packs a tarball and installs from
npmjs, which does not belong in the inner loop — but that makes it a gate a green `verify` does not cover.
`pnpm check:runtime` runs the Node leg locally; Bun and Deno run only in `ci.yml`. Check the run before
assuming a green `verify` means a green CI.

`pnpm verify` is not hermetic — the audit stage fails on any newly published advisory against an unchanged
tree. If only that stage fails: record the advisory, run the rest explicitly, proceed, triage separately.
Never weaken the threshold.

## Rules

- **The protocol dependency is declared for the job it does, and the declaration is the contract.** Repin
  deliberately with a changeset; a repin is a release, not a chore. **Exact where CI must exercise one
  version — `devDependencies`, and only there. A caret at the minor's zero patch everywhere a consumer must
  own one copy — `peerDependencies` and shipped `dependencies`.** Two copies of `lcp-binding-core` in one
  tree break `instanceof CarrierError`, and an EXACT runtime pin beside a caret-peered sibling is how the
  second copy gets in; a raised caret floor is how consumers on an earlier patch get stranded.
  `check:wire` enforces all three shapes.
- **Refuse ambiguity rather than choosing.** `parseProposalUniversal` refuses when two protocols match;
  a step's four-valued status maps totally onto a disposition; gaps resolve by the buyer's stated policy,
  never by a silent default. Preserve this — it is load-bearing.
- **The typed proposal cannot carry natural-language prose.** The prompt-injection boundary is
  architectural: the terms body can never reach policy evaluation. Nothing may widen the proposal type in
  a way that admits prose.
- **The documentation site is part of the public surface.** `website/` holds the site published at
  agenticterms.integraledger.com — Next.js static export, Fumadocs, its own npm lockfile, and deliberately
  NOT a pnpm workspace member (`pnpm-workspace.yaml` globs `packages/*` only), so `pnpm -r` never touches
  it. `check:docs` DOES: every `ts` fence under `website/content/docs` is typechecked against the built
  workspace exactly as the READMEs' are. `pnpm docs:dev` runs it; `siteConfig` in `website/src/lib/site.ts`
  is the single source for the canonical origin and nothing else may hardcode it.
- **The security claims in the READMEs are enforced claims.** HTTPS-only, `redirect: "error"`, public
  unicast re-checked on every re-fetch, a streaming byte cap with a declared-length pre-check; the MCP
  tools are read-only and declare `readOnlyHint`; nothing calls home. A change that weakens any of these
  is a behaviour change to a published guarantee, not a refactor.
- **Changesets for anything publishable.** The two packages are a **`fixed` group** in
  `.changeset/config.json` and version in lockstep, so a changeset naming either moves both. `lcp-mcp-server`
  also depends on `agentic-terms` through `workspace:*`, which changesets rewrites to the released version on
  publish.

## Publishing

Steady state is trusted publishing from CI — no long-lived token. The **first** release of any new package
name cannot use it: npm can neither configure trusted publishing for a name that has never been published
nor stage a brand-new name, so a new name needs a one-time token-gated publish, run **from GitHub Actions,
never from a laptop** — provenance is minted at publish time by the workflow's OIDC identity, an npm
version can never be reused, and a laptop publish leaves that version permanently unattested.

After any publish, verify against the version-specific endpoint
(`registry.npmjs.org/<pkg>/<version>`) — `npm view` and the full packument can lag a fresh publish and
report a successful release as absent.

## Layout

`agentic-terms` — the gate: typed proposal, policy evaluation, mechanical verification, universal parsing ·
`lcp-mcp-server` — six read-only MCP tools over the same kernel, plus stdio wiring for desktop agent hosts.
