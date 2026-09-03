---
"@integraledger/agentic-terms": minor
"@integraledger/lcp-mcp-server": minor
---

Peer the protocol at `^0.15.0` — and the two public pages that told a reader otherwise.

Protocol `0.15.0` is live. On a `0.x` line a caret pins the MINOR, so `^0.14.0` means `>=0.14.0 <0.15.0`
and **excludes the line it names**. The gap is invisible to `check:wire` by construction: that gate reads
the declarations for coherence, and a caret anchored at the dev pin satisfies every rule it has.

**Measured against the live registry, not derived** — fresh directory, no lockfile, full nested
enumeration (`find node_modules -path '*lcp-kernel/package.json'`), npm 11.6.2 / node v25.2.1:

```
npm i agentic-terms lcp-kernel          exit 0, ZERO warnings  one line at 0.14.0
npm i lcp-kernel agentic-terms          exit 0, ONE warning    0.15.0 top-level, and 0.14.0 nested
                                                               five times under authority,
                                                               binding-core, discovery, evidence, verify
npm i lcp-kernel@0.15.0 agentic-terms   exit 1, ERESOLVE       nothing installed
```

Six `lcp-kernel` identities at two versions, decided by which name the caller types first — the tree
`check:wire` exists to refuse, arriving with exit 0 and one warning that scrolls past. ⭐ Note the
inversion: a consumer who PINS gets an honest hard failure; one who does not gets the split.

29 pins move together, across all four manifest surfaces — the root's `lcp-conformance` (the root is not
a package, and a `packages/*` sweep does not reach it), ten dev pins and nine peers in `agentic-terms`,
and nine **runtime `dependencies`** in `lcp-mcp-server`, the field that was reported as needing no edit
during the last repin and was wrong then. Plus the fifth surface a manifest sweep never reaches: the two
public install pages that state the range, `quickstart.mdx` and `reference/agentic-terms.mdx`. The dated
records that state the old range are left alone — rewriting a record to match the present falsifies it.

**No source change, and that was checked rather than assumed.** `0.15.0` renames `Envelope` → `Atr`,
`AtrFile`/`atrFile` → `AtrBytes`/`atrBytes`, `Component` → `Slot`, and `assemble/component-shape` →
`assemble/slot-shape`. None of it lands here: every `Envelope` in this tree is the AP2 transport envelope,
which that release deliberately keeps, and the one `assemble()` caller destructures `atrHash` alone. The
ACP round-trip assembles a real ATR rather than pinning a digest, so the ATR's moved first member
(`atrVersion`) is absorbed by the round-trip instead of stranding a fixture.
