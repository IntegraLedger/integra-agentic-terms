// Writes the API reference pages from the packages' TypeScript source with TypeDoc, into content/api/, where the
// site's `api` collection reads them. The pages are generated on every build and never committed.
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { Application } from "typedoc";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..");
const out = resolve(here, "..", "content", "api");

// Each package, and the hand-written reference page beside its generated one: a page's description, which the page,
// its Markdown copy and /llms.txt show, names what each holds, so an agent can choose between the two.
const PACKAGES = [
  { folder: "agentic-terms", name: "@integraledger/terms", slug: "terms", reference: "TypeScript API", for: "how to use each export" },
  {
    folder: "agentic-terms-mcp",
    name: "@integraledger/terms-mcp",
    slug: "terms-mcp",
    reference: "MCP tools and skill",
    for: "the tools and their arguments",
  },
];

/** A package's page description, from the exports TypeDoc read. */
function describe(pkg, exports) {
  const names = [...exports].sort((a, b) => a.localeCompare(b, "en", { sensitivity: "base" }));
  const list = names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names.at(-1)}`;
  const what = names.length <= 4 ? `the declarations of ${list}` : `the declaration of each of its ${names.length} exports`;
  return `Generated from the source: ${what}, with their doc comments. For ${pkg.for}, read ${pkg.reference}.`;
}

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
  pkg.description = describe(pkg, (project.children ?? []).map((c) => c.name));
  await app.generateOutputs(project);
}

// Each page takes its first heading as its title, which the site renders itself, and its package's description.
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
  const pkg = PACKAGES.find((p) => page.startsWith(join(out, p.slug) + sep));
  if (pkg === undefined) throw new Error(`${page} is not the page of a package`);
  const text = readFileSync(page, "utf8");
  const heading = /^#\s+(.+)$/m.exec(text);
  const title = (heading?.[1] ?? "API").replace(/\\/g, "").trim();
  const body = heading === null ? text : text.replace(heading[0], "").trimStart();
  writeFileSync(page, `---\ntitle: ${JSON.stringify(title)}\ndescription: ${JSON.stringify(pkg.description)}\n---\n\n${body}`);
}
writeFileSync(join(out, "meta.json"), `${JSON.stringify({ title: "API", pages: PACKAGES.map((p) => p.slug) }, null, 2)}\n`);
console.log(`api: ${pages.length} pages in ${out}`);
