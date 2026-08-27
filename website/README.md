# Integra Agentic Terms — documentation site

The public documentation for the two packages in this repository, published at
**<https://agenticterms.integraledger.com>**.

Next.js 16 (static export) · Fumadocs 16 (MDX) · Tailwind 4 · Cloudflare Pages. The same stack as the LCP
standard's site, so a change made in one is legible in the other.

```bash
npm install          # this app has its own lockfile; it is NOT a pnpm workspace member
npm run dev          # http://localhost:3000
npm run build        # static export to out/
npm run typecheck    # the app, then the Pages Function under functions/
```

From the repository root: `pnpm docs:dev` and `pnpm docs:build`. CI builds the site on every push (the
`docs` job in `.github/workflows/ci.yml`), so a page that fails to compile fails the push.

## Layout

| Path | What it is |
|---|---|
| `content/docs/**.mdx` | every documentation page |
| `content/docs/**/meta.json` | sidebar order and section headings |
| `src/lib/site.ts` | **single source of truth** for the canonical origin, titles, and JSON-LD |
| `src/lib/version.ts` | the documented package version, read from `packages/agentic-terms/package.json` at build |
| `src/app/page.tsx` | the landing page |
| `src/app/(docs)/` | the Fumadocs shell and the catch-all docs route |
| `src/app/llms.txt/`, `src/app/llms-full.txt/`, `src/app/md/` | the AI-crawler index, the full-text export, and each page as `/md/<page>.md` — all generated from the same source as the HTML (`src/lib/llms.ts`) |
| `src/app/{icon.svg,apple-icon.tsx,manifest.ts,opengraph-image.tsx}` | favicon, touch icon, web manifest, social card — Next file conventions, no hand-kept `<link>` tags |
| `public/_headers` | security headers (HSTS, a `'self'` CSP, …) and caching Cloudflare Pages applies to every response |
| `public/.well-known/security.txt` | RFC 9116 pointer at the GitHub Security Advisories intake |
| `functions/_middleware.ts` | folds the `.pages.dev` alias into the canonical host with a 301 |

Never hardcode the domain outside `src/lib/site.ts` — every absolute URL, canonical tag, sitemap entry,
robots directive and JSON-LD `@id` derives from `siteConfig.url`.

## What is derived, and from where

- **Last-modified dates** — the sitemap's `<lastmod>`, each page's "last updated" line and its
  `article:modified_time` come from git (`fumadocs-mdx/plugins/last-modified`). A shallow clone has no
  history to read; build from a full one.
- **"Edit on GitHub"** on every page points at the page's own `.mdx` on `main`.
- **Fonts** — Inter and JetBrains Mono are self-hosted by `next/font` and ship with the export. A page view
  makes no request to any third party.
- **The version chip** in the footer and the `version` in the `SoftwareSourceCode` JSON-LD are the
  workspace's, not typed here.
- **"Copy Markdown" / "Open in …"** on every page point at that page's `/md/<page>.md`, rendered by the
  same function as `/llms-full.txt`, so what an agent is handed is what the page says.
- **Colour tokens** in `src/app/global.css` carry their measured WCAG contrast ratios in the comment
  beside them; change a colour, re-measure, restate the number.

The `functions/_middleware.ts` 301 and `public/_headers` are the same pair the LCP site uses; measured
there, the headers apply to responses that pass through the function. `npm run typecheck` covers the
function under its own `functions/tsconfig.json` (Workers types, not DOM). Biome lints and formats
`website/src`, `website/functions` and the root config files from the repository root (`pnpm lint`).

## The TypeScript in these pages is typechecked

Every column-0 ` ```ts ` fence under `content/docs/` is extracted by the repository's `check:docs` gate,
written to `reports/doc-snippets/`, and compiled against the built workspace — the same treatment the
package READMEs get, and for the same reason: a fence that does not compile teaches an integrator to write
code that does not compile.

```bash
pnpm -r build && pnpm check:docs
```

A failure names the source document and the line the fence opened at. Mark a deliberate fragment
` ```ts no-check `; anything else must compile.

Fences must open at **column 0** — the extractor sees nothing else, and an indented `ts` fence is a hard
error rather than a silent skip.

<!-- markdownlint-disable-next-line -->
> **Peer types.** Snippets compile at the repository root, where the `@integraledger/lcp-*` peers are not
> installed. A fence that needs one of those types should take it off the exported function's own signature
> (`Parameters<typeof fn>`) rather than importing the peer directly.

## Adding a page

1. Write `content/docs/<name>.mdx` with `title` and `description` frontmatter.
2. Add `<name>` to the enclosing `meta.json` `pages` array — a page missing from it still builds, but is
   unreachable from the sidebar.
3. `pnpm check:docs` if it carries TypeScript.

The sitemap, search index, `llms.txt` and `llms-full.txt` pick the page up on the next build; nothing to
register.

## Deploying

Static export in `out/`, served by Cloudflare Pages (`wrangler.toml` sets `pages_build_output_dir`).
Deploys are manual, as every Cloudflare surface in this organization is:

```bash
npm run build && wrangler pages deploy
```

**The canonical-host fold is armed separately.** `functions/_middleware.ts` 301s the
`integra-agentic-terms.pages.dev` alias to `agenticterms.integraledger.com` — it has to be a Pages Function,
because that alias lives on Cloudflare's zone and no redirect rule on `integraledger.com` can reach it.
It fires only while `CANONICAL_HOST_ATTACHED = "true"` in `wrangler.toml`, and that ships `"false"`:
until the custom domain is attached to the Pages project (Pages project → Custom domains; Cloudflare
creates the CNAME on the `integraledger.com` zone) and `curl -sI https://agenticterms.integraledger.com`
returns 200, the alias is the only host that answers, and a 301 to the apex would take it down. Once the
apex answers, flip the var to `"true"` and deploy again; nothing else changes.
