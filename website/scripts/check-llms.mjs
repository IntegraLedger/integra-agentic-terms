#!/usr/bin/env node
// Checks the files the site writes for AI agents, in out/, the last step of `pnpm run build`:
// - every link of the site's own in /llms.txt names a file the site serves: a page's Markdown address its copy under
//   /md/ (worker.js answers it), any other address its file;
// - each size /llms.txt states for a file, "<n> KB, about <n> tokens", is that file's;
// - every page's Markdown copy is listed in /llms.txt, and each copy names /llms.txt;
// - /.well-known/agent-skills/index.json names each skill at a file of out/ whose SHA-256 is its digest.
// Each failure names the file and the link.
//
// Usage, from website/, after `next build` and the step after it:
//   node scripts/check-llms.mjs
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const OUT = join(import.meta.dirname, "..", "out");
/** The site's canonical origin, `siteConfig.url` in src/lib/site.ts. */
const ORIGIN = /^ {2}url: "([^"]+)"/m.exec(readFileSync(join(import.meta.dirname, "..", "src", "lib", "site.ts"), "utf8"))?.[1];
if (ORIGIN === undefined) throw new Error("src/lib/site.ts names no url");

const isFile = (path) => statSync(path, { throwIfNoEntry: false })?.isFile() === true;

/** The file of out/ that answers an address of the site, or undefined. */
function served(address) {
  const candidates =
    address === "/"
      ? ["index.html"]
      : address.endsWith(".md")
        ? [join("md", address === "/index.md" ? "index.md" : address.slice(1)), address.slice(1)]
        : [address.slice(1), `${address.slice(1)}.html`];
  return candidates.map((c) => join(OUT, c)).find(isFile);
}

/** The size the build states for a text: as src/lib/llms.ts's sizeOf writes it. */
function sizeOf(bytes) {
  const size = bytes >= 1e6 ? `${(bytes / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1e3))} KB`;
  const step = bytes >= 40_000 ? 1000 : 100;
  const tokens = Math.max(step, Math.round(bytes / 4 / step) * step);
  return `${size}, about ${tokens.toLocaleString("en-US")} tokens`;
}

const failures = [];
let links = 0;
let sizes = 0;
const listed = new Set();
for (const line of readFileSync(join(OUT, "llms.txt"), "utf8").split("\n")) {
  for (const m of line.matchAll(/\]\((https:\/\/[^)\s]+)\)/g)) {
    const url = m[1];
    if (!url.startsWith(`${ORIGIN}/`)) continue;
    links++;
    const address = url.slice(ORIGIN.length).split("#")[0];
    const file = served(address);
    if (file === undefined) {
      failures.push(`llms.txt: ${url} names no file of out/`);
      continue;
    }
    if (address.endsWith(".md")) listed.add(relative(OUT, file).split(sep).join("/"));
    const size = /\): (?:[^;]*; )?(\d+(?:\.\d)? (?:KB|MB), about [\d,]+ tokens)/.exec(line.slice(m.index))?.[1];
    if (size !== undefined) {
      sizes++;
      const actual = sizeOf(statSync(file).size);
      if (size !== actual) failures.push(`llms.txt: ${url} is stated as ${size}; it is ${actual}`);
    }
  }
}
const copies = readdirSync(join(OUT, "md"), { recursive: true, withFileTypes: true })
  .filter((e) => e.isFile() && e.name.endsWith(".md"))
  .map((e) => relative(OUT, join(e.parentPath, e.name)).split(sep).join("/"));
for (const copy of copies) {
  if (!listed.has(copy)) failures.push(`llms.txt does not list ${copy}`);
  if (!readFileSync(join(OUT, copy), "utf8").includes(`${ORIGIN}/llms.txt`)) failures.push(`${copy} does not name /llms.txt`);
}
const skills = JSON.parse(readFileSync(join(OUT, ".well-known", "agent-skills", "index.json"), "utf8")).skills ?? [];
for (const skill of skills) {
  const file = typeof skill.url === "string" && skill.url.startsWith(`${ORIGIN}/`) ? served(skill.url.slice(ORIGIN.length)) : undefined;
  if (file === undefined) failures.push(`agent-skills/index.json: ${skill.name} names no file of out/`);
  else if (`sha256:${createHash("sha256").update(readFileSync(file)).digest("hex")}` !== skill.digest) {
    failures.push(`agent-skills/index.json: ${skill.name}'s digest is not its file's SHA-256`);
  }
}
if (links === 0 || sizes === 0 || skills.length === 0) failures.push(`read ${links} links, ${sizes} sizes and ${skills.length} skills`);

if (failures.length > 0) {
  console.error(`${failures.length} failures in the files for AI agents:`);
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}
console.log(
  `llms.txt: each of its ${links} links names a file of out/, each of ${sizes} sizes is its file's, and it lists all ` +
    `${copies.length} Markdown copies, each of which names it; agent-skills/index.json names each of its ` +
    `${skills.length} skill files with its SHA-256`,
);
