---
"@integraledger/lcp-mcp-server": patch
---

The published tarball cites an LCP revision no reader of it can obtain

`0.17.0` is on the registry carrying `LCP v1.38 §C.9` in two shipped files — `src/annotations.ts:23` and
`src/server.ts:16`. `v1.38` is an internal draft published nowhere a reader can reach, so a consumer
holding this package meets a citation they cannot follow, in a document whose existence and numbering the
citation itself discloses.

⛔ **The fix landed in source and was never published**, which is the whole of the distance between the
tree and the artifact. `check:published-parity` found it as *different bytes*; it does not know, and is
not asked to know, that those particular bytes are the disclosure. A version bump is the only thing that
moves it — a published version is a promise about bytes, and the bytes that went out are what consumers
hold.

`M` 2026-09-14 against the published tarballs: **7** occurrences in `lcp-mcp-server@0.17.0` and **10** in
`agentic-terms@0.17.0`, across `src/` and `dist/`. Source at `d3eb6ff` carries **0**, against a control
that fires — the same pathspec still sees `LCP` in eight shipped files, so the zero is an absence rather
than a broken query.

⭐ A bare `LCP §N` is the correct citation and loses nothing: section numbering is identical between the
internal and published editions, which is what makes the bare form resolvable for a reader who has only
the public specification.

Declared `patch`, because that is what this change is: comment text in shipped source, with no export,
signature or behaviour moving. ⚠️ It will nonetheless land as **0.18.0** — `agentic-terms` and
`lcp-mcp-server` are a `fixed` changeset group and version in lockstep, so the sibling's `minor` promotes
this one. That is the group working as intended rather than an inflated bump: the two share a
`workspace:*` dependency and a version that could drift between them would be worse than a version that
moves without cause.
