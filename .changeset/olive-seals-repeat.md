---
"@integraledger/agentic-terms": minor
"@integraledger/lcp-mcp-server": minor
---

The peer floor moves to 0.18.3 and the catalog follows it to `zod` 4.6.2 — one line, converged in one change

`protocol-latest` went red on `main` because the published protocol line moved and this repository's ranges
did not. Under the floor rule adopted at `0.18.1`, the peer floor must EQUAL the exercised dev pin, so
neither side can drift alone — the range, the pin and the lockfile move together or not at all.

    protocol devDependencies   0.18.2  -> 0.18.3   (11 pins, the exercised line)
    protocol peers + shipped   ^0.18.2 -> ^0.18.3  (18 ranges)
    the two published install pages that state the range
    catalog `zod`              4.5.4   -> 4.6.2

⛔ **A CARET RANGE THAT ADMITS A VERSION IS NOT A RANGE THAT TRACKS IT.** `^0.18.2` admits `0.18.3`, and the
gate refuses it anyway: the rule is equality with the exercised pin, not admissibility. `M` Planted — peer
`^0.18.2` against a line at `0.18.3` exits **1**. That is the whole point of the equality: *"a bot raising
the peer goes red against the pin, and a bot raising every pin goes red against the peers."*

## ⭐ Why `catalog: zod` moves now, having deliberately not moved this morning

The rule did not change; the published line did. This catalog is held equal to the **published** protocol
line it compiles against, never to protocol's working tree. `M` At 07:00Z protocol's `main` carried `4.6.2`
**unpublished** while published `0.18.2` declared `4.5.4`, so following would have created the two-copy
divergence the pin exists to prevent. `0.18.3` published `4.6.2`, so the same sentence now requires the move:

    lcp-discovery@0.18.2   zod 4.5.4      lcp-discovery@0.18.3   zod 4.6.2
    lcp-binding-sui@0.18.2 sui 2.29.0     lcp-binding-sui@0.18.3 sui 2.30.0

⭐⭐ **And `zod` is safe where this repository uses it — traced, not assumed.** The catalog comment claims
*"trust boundaries only — never inside verification logic"*. ⛔ A first predicate — files containing both
`zod` and a verification primitive — flagged **7 of 10**, which is a query matching almost everything rather
than a finding, and was discarded. The question is whether a zod-PARSED value reaches the digest, and it does
not: in `compute-atrhash.ts` zod's `inputSchema` validates the **MCP tool arguments**, while the hash is
`kernel.hashAtr` over `binding-core.encodeLegalContextString` — the file says so about itself, *"grounded on
`kernel.hashAtr` … rather than on a local `createHash("sha256")` and a template literal."* ⇒ zod shapes the
envelope; the bytes are hashed in the kernel.

⚠️ **The limit of that evidence, stated rather than rounded off:** 294 `agentic-terms` tests pass with
`4.6.2` resolved and seven of its test files are proposal parsers that go through zod, so zod is exercised.
Whether a zod **rejection** path is driven is **unconfirmed** — the query shape used to look for one is
unproven, so treat it as unmeasured rather than absent.

Planted, `package.json` restored from a byte copy and diffed identical after each:

    peer   ^0.18.3 -> ^0.18.2   exit 1   a lower floor the caret would have admitted
    devDep  0.18.2 ->  0.18.1   exit 1   the exercised line drifting alone
    peer   ^0.18.2 -> ^0.18.3   exit 1   bot drift, measured at the previous target
    unmodified tree             exit 0   the null plant
