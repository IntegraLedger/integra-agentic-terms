#!/usr/bin/env node
// check:docs — extract ```ts fences from the documentation a reader actually gets and typecheck them
// against the built workspace. Three sources: the root README, every package README, and every page of the
// public documentation site under website/content/docs.
//
// THE PACKAGE READMES ARE THE POINT. They are the code on the npmjs page and the only documentation inside
// a tarball, so they are the fences most likely to be copied verbatim and, until this gate, the ones nothing
// could check. A fence that does not compile teaches an integrator to write code that does not compile; a
// fence that models an unsafe pattern teaches that instead. For a package whose whole subject is verifying
// before you sign, the second is the worse failure.
//
// THE DOCUMENTATION SITE IS THE SAME POINT AT LARGER SCALE. Its pages carry far more example code than the
// READMEs do, and it is the surface an integrator lands on from a search rather than from a tarball. Adding
// it here is deliberate: the gate's own history is a tree that WAS walked, stopped existing, and reported
// "nothing to check" for four shipped fences. Site pages are MDX; a ```ts fence in MDX is the same fence.
//
// A fence opened ```ts (or ```typescript) is checked. ```ts no-check is exempt and is for deliberate
// fragments. Fences MUST open at column 0 — the extractor sees nothing else — so an indented ts fence is a
// hard error rather than a silent skip, and a snippet can never look checked while never being checked.
//
// Snippets materialize under reports/doc-snippets/ (gitignored) as <doc-path>__L<line>.ts, so a tsc error
// names its source document and the line its fence opened at. Requires a prior `pnpm -r build`: workspace
// types come from each package's emitted dist.
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative } from "node:path";

const ROOT = process.cwd();
const PACKAGES = join(ROOT, "packages");
const SITE_DOCS = join(ROOT, "website", "content", "docs");
const OUT = join(ROOT, "reports", "doc-snippets");
// A ts fence the extractor's column-0 regex would never see. Only tested outside an open fence.
const INDENTED_TS_FENCE = /^\s+`{3,}\s*(?:ts|typescript)(?:\s+no-check)?\s*$/;

const mdFiles = [];
const rootReadme = join(ROOT, "README.md");
if (existsSync(rootReadme)) mdFiles.push(rootReadme);
for (const entry of readdirSync(PACKAGES, { withFileTypes: true })) {
  if (!entry.isDirectory()) continue;
  const readme = join(PACKAGES, entry.name, "README.md");
  if (existsSync(readme)) mdFiles.push(readme);
}
// The documentation site. Absent in a checkout that has not built it? No — `content/` is committed, so an
// absent directory means the site was deleted or moved, and that is a defect this gate must not paper over:
// the canary below derives the same set independently and the two must agree.
for (const entry of readdirSync(SITE_DOCS, {
  recursive: true,
  withFileTypes: true,
})) {
  if (!entry.isFile() || !entry.name.endsWith(".mdx")) continue;
  mdFiles.push(join(entry.parentPath, entry.name));
}
// An empty file list is a DEFECT, not a no-op. This gate previously walked a `docs/developer` tree that
// does not exist here and printed "nothing to check" — reporting clean while checking nothing, which is
// indistinguishable from passing and is how four shipped fences went unchecked.
if (mdFiles.length === 0)
  throw new Error(
    "check:docs found no markdown at all. The package READMEs are not optional; a silent zero here " +
      "would report every fence as checked while checking none.",
  );
mdFiles.sort();

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

let snippets = 0;
for (const md of mdFiles) {
  const lines = readFileSync(md, "utf8").split("\n");
  let fence = null;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = line.match(/^(`{3,})\s*(.*)$/);
    if (!m) {
      if (fence) {
        fence.buf.push(line);
      } else if (INDENTED_TS_FENCE.test(line)) {
        console.error(
          `check:docs — indented ts fence in ${relative(ROOT, md)} at line ${i + 1}.\n` +
            "Checked fences must start at column 0 (the extractor only sees column-0 fences).\n" +
            "Unindent it, or mark it ```ts no-check if it is a deliberate fragment.",
        );
        process.exit(1);
      }
      continue;
    }
    if (!fence) {
      fence = { ticks: m[1].length, info: m[2].trim(), start: i + 1, buf: [] };
      continue;
    }
    if (m[1].length >= fence.ticks && m[2].trim() === "") {
      const { info, start, buf } = fence;
      fence = null;
      if (info !== "ts" && info !== "typescript") continue; // includes `ts no-check`
      snippets++;
      // Relative to ROOT, so a package README's slug never begins with a dot. A dot-prefixed filename is
      // hidden, and TypeScript excludes hidden files from a directory `include` without saying so — the
      // fences would be extracted, counted, and reported clean while tsc never opened one.
      const slug = relative(ROOT, md)
        .replaceAll("/", "__")
        .replace(/\.mdx?$/, "");
      writeFileSync(join(OUT, `${slug}__L${start}.ts`), `${buf.join("\n")}\n`);
    } else {
      fence.buf.push(line);
    }
  }
  if (fence) {
    console.error(
      `check:docs — unclosed \`\`\` fence in ${relative(ROOT, md)} at line ${fence.start}`,
    );
    process.exit(1);
  }
}

// THE BLIND-GATE CANARIES. A gate that stops finding files reports "clean" forever, which is exactly what
// the previous implementation did. So the expectation is DERIVED by a second traversal that does not share
// the walker's logic, and the two must agree exactly — equality, not a floor, because a floor catches a
// walker that narrows and misses one that widens, and a floor is what gets adjusted downward under
// deadline.
const expectedDocs = (() => {
  let n = existsSync(rootReadme) ? 1 : 0;
  for (const entry of readdirSync(PACKAGES, { withFileTypes: true }))
    if (
      entry.isDirectory() &&
      existsSync(join(PACKAGES, entry.name, "README.md"))
    )
      n++;
  // An explicit stack walk, NOT `readdirSync(..., { recursive: true })` — the collector above uses that, and
  // a canary that calls the same primitive with the same flags checks nothing but arithmetic.
  const stack = [SITE_DOCS];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) stack.push(path);
      else if (name.endsWith(".mdx")) n++;
    }
  }
  return n;
})();

if (mdFiles.length !== expectedDocs) {
  console.error(
    `check:docs — BLIND GATE: walked ${mdFiles.length} doc(s), an independent enumeration expects ` +
      `${expectedDocs} (root README + every package README + every website/content/docs page). The two ` +
      `must agree; "clean" from a walker ` +
      `that disagrees would mean nothing.`,
  );
  process.exit(1);
}

if (snippets === 0) {
  console.error(
    `check:docs — BLIND GATE: ${mdFiles.length} doc(s) walked and NOT ONE checkable ts fence found. ` +
      `Every fence being no-check is a defect, not a pass.`,
  );
  process.exit(1);
}

// The same trick for the fences themselves: count column-0 ```ts openers with a plain scan and require the
// extractor to have produced one snippet each.
const expectedSnippets = mdFiles.reduce((acc, md) => {
  let fenced = false;
  let n = 0;
  for (const line of readFileSync(md, "utf8").split("\n")) {
    const m = line.match(/^(`{3,})\s*(.*)$/);
    if (!m) continue;
    if (!fenced) {
      fenced = true;
      if (m[2].trim() === "ts" || m[2].trim() === "typescript") n++;
      continue;
    }
    if (m[2].trim() === "") fenced = false;
  }
  return acc + n;
}, 0);

if (snippets !== expectedSnippets) {
  console.error(
    `check:docs — BLIND GATE: extracted ${snippets} snippet(s), an independent scan counts ` +
      `${expectedSnippets} checkable ts fence(s). Fences are being missed or silently skipped.`,
  );
  process.exit(1);
}

try {
  execFileSync("pnpm", ["exec", "tsc", "-p", "tsconfig.docs.json"], {
    stdio: "inherit",
  });
} catch {
  console.error(
    "check:docs — FAILED. Each reports/doc-snippets/<doc>__L<line>.ts above maps to that doc's fence at that line.",
  );
  process.exit(1);
}
console.log(
  `check:docs — ${snippets}/${expectedSnippets} snippet(s) across ${mdFiles.length}/${expectedDocs} doc(s) typechecked clean`,
);
