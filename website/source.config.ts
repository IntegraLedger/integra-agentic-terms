import { resolve } from "node:path";
import { type RehypeCodeOptions, rehypeCodeDefaultOptions } from "fumadocs-core/mdx-plugins";
import { applyMdxPreset, defineConfig, defineDocs } from "fumadocs-mdx/config";
import { transformerTwoslash } from "fumadocs-twoslash";
import { rehypeMermaid } from "./src/lib/rehype-docs";
import { remarkDocLinks } from "./src/lib/remark-doc-links";

/** The repository root. The site builds in website/, and this file is compiled into website/.source/. */
const REPO = resolve(process.cwd(), "..");
/** The repository's documentation, the site's one source of content. */
const DOCS_DIR = resolve(REPO, "docs");

export const docs = defineDocs({
  dir: "../docs",
  docs: {
    lastModified: true,
    postprocess: { includeProcessedMarkdown: { headingIds: false } },
  },
});

/**
 * How every code block is highlighted. Each token colour of these two themes is at least 4.5:1 on its code background
 * (global.css): white in light mode, the card colour in dark mode.
 */
const codeOptions: RehypeCodeOptions = {
  ...rehypeCodeDefaultOptions,
  themes: { light: "github-light-default", dark: "github-dark-default" },
  langs: ["ts", "typescript", "python", "json", "sh"],
};

/**
 * The API pages TypeDoc writes from the packages' TypeScript source (`pnpm api`). Their code blocks are declarations,
 * not samples, so they are highlighted without Twoslash.
 */
export const api = defineDocs({
  dir: "content",
  docs: {
    postprocess: { includeProcessedMarkdown: { headingIds: false } },
    mdxOptions: applyMdxPreset({ rehypeCodeOptions: codeOptions }),
  },
});

/** The compiler options of the repository's packages, for type-checking every TypeScript sample. */
const compilerOptions = {
  strict: true,
  noUncheckedIndexedAccess: true,
  exactOptionalPropertyTypes: true,
  verbatimModuleSyntax: true,
  module: "nodenext",
  moduleResolution: "nodenext",
  target: "es2024",
  lib: ["es2024", "dom"],
  types: ["node"],
};

/**
 * Every TypeScript sample is type-checked as if it sat in the @integraledger/terms package, so the packages resolve as
 * they are built in this repository; the MCP package, and its MCP server dependency, resolve from their own folder.
 */
const twoslash = transformerTwoslash({
  explicitTrigger: false,
  twoslashOptions: {
    cwd: resolve(REPO, "agentic-terms"),
    compilerOptions: {
      ...compilerOptions,
      paths: {
        "@integraledger/terms-mcp": [resolve(REPO, "agentic-terms-mcp", "dist", "index.d.ts")],
        "@modelcontextprotocol/server/stdio": [
          resolve(REPO, "agentic-terms-mcp", "node_modules", "@modelcontextprotocol", "server", "dist", "stdio.d.mts"),
        ],
      },
    },
  },
});

export default defineConfig({
  mdxOptions: {
    remarkPlugins: [[remarkDocLinks, { root: DOCS_DIR }]],
    // Each Mermaid diagram is rendered to SVG before code highlighting (src/lib/mermaid.ts).
    rehypePlugins: (plugins) => [rehypeMermaid, ...plugins],
    rehypeCodeOptions: {
      ...codeOptions,
      transformers: [...(rehypeCodeDefaultOptions.transformers ?? []), twoslash],
    },
  },
});
