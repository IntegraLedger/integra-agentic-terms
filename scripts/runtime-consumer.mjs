/**
 * Build the directory `runtime-smoke.mjs` runs in: a CLEAN CONSUMER INSTALL of the packed tarball, with
 * the protocol line resolved from npmjs exactly as a stranger's `npm install` resolves it.
 *
 * WHY NOT JUST RUN THE SMOKE IN THE WORKSPACE. It would resolve `dist/` through pnpm's symlinks and prove
 * that the source tree works on a runtime — which is not the claim. The claim in
 * `packages/agentic-terms/README.md` is about the PUBLISHED package, and this repository has already been
 * bitten once by the gap between the two: the manifests said one thing and what a consumer actually
 * resolved was another. Packing first means the runtime matrix measures the artifact, the caret range and
 * the runtime in one shot, and a `files` entry that forgot to ship something fails here rather than in
 * someone's install.
 *
 * Deliberately `npm`, not `pnpm`: pnpm's symlinked store is this repository's convention, not a consumer's,
 * and a runtime that mishandles symlinked `node_modules` would be a real finding we would hide by using it.
 */
import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const dir = join(root, ".runtime-consumer");
const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, stdio: "pipe", encoding: "utf8" });

rmSync(dir, { recursive: true, force: true });
mkdirSync(dir, { recursive: true });

// `pnpm pack` rewrites `workspace:*` and `catalog:` to real versions, so the tarball is what would publish.
const packed = run(
  "pnpm",
  ["pack", "--pack-destination", dir],
  join(root, "packages", "agentic-terms"),
)
  .trim()
  .split("\n")
  .pop()
  .trim();

writeFileSync(
  join(dir, "package.json"),
  `${JSON.stringify({ name: "runtime-consumer", private: true, type: "module", version: "1.0.0" }, null, 2)}\n`,
);

// No lockfile, no overrides: whatever the published peer range resolves to today is the thing under test.
run("npm", ["install", "--no-audit", "--no-fund", packed], dir);
cpSync(
  join(root, "scripts", "runtime-smoke.mjs"),
  join(dir, "runtime-smoke.mjs"),
);

const resolved = JSON.parse(
  run(
    "node",
    ["-p", "JSON.stringify(require('@integraledger/lcp-kernel/package.json'))"],
    dir,
  ),
).version;

console.log(`consumer ready: ${dir}`);
console.log(`  agentic-terms  ${packed.split("/").pop()}`);
console.log(`  protocol line resolved from npmjs: ${resolved}`);
