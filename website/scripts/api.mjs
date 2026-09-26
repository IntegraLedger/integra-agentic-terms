// Writes the API reference pages from the packages' TypeScript source with TypeDoc, into content/api/, where the
// site's `api` collection reads them. The pages are generated on every build and never committed.
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Application } from "typedoc";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");
const out = resolve(here, "..", "content", "api");

const PACKAGES = [
  { folder: "agentic-terms", name: "@integraledger/terms", slug: "terms" },
  { folder: "agentic-terms-mcp", name: "@integraledger/terms-mcp", slug: "terms-mcp" },
];

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

for (const pkg of PACKAGES) {
  const app = await Application.bootstrapWithPlugins({
    entryPoints: [join(repo, pkg.folder, "src", "index.ts")],
    tsconfig: join(repo, pkg.folder, "tsconfig.json"),
    plugin: ["typedoc-plugin-markdown"],
    out: join(out, pkg.slug),
    name: pkg.name,
    readme: "none",
    entryFileName: "index.md",
    outputFileStrategy: "modules",
    hidePageHeader: true,
    hideBreadcrumbs: true,
    disableSources: true,
    excludePrivate: true,
    excludeInternal: true,
    useCodeBlocks: true,
    sanitizeComments: true,
    validation: { notExported: false, invalidLink: true, notDocumented: false },
  });
  const project = await app.convert();
  if (project === undefined || app.logger.hasErrors()) throw new Error(`TypeDoc could not read ${pkg.name}`);
  await app.generateOutputs(project);
}

// Each page takes its first heading as its title, which the site renders itself.
const pages = [];
const walk = (dir) => {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (e.name.endsWith(".md")) pages.push(p);
  }
};
walk(out);
for (const page of pages) {
  const text = readFileSync(page, "utf8");
  const heading = /^#\s+(.+)$/m.exec(text);
  const title = (heading?.[1] ?? "API").replace(/\\/g, "").trim();
  const body = heading === null ? text : text.replace(heading[0], "").trimStart();
  writeFileSync(page, `---\ntitle: ${JSON.stringify(title)}\ndescription: Generated from the TypeScript source by TypeDoc.\n---\n\n${body}`);
}
writeFileSync(join(out, "meta.json"), `${JSON.stringify({ title: "API", pages: PACKAGES.map((p) => p.slug) }, null, 2)}\n`);
console.log(`api: ${pages.length} pages in ${out}`);
