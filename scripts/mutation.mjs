#!/usr/bin/env node
/**
 * Run Stryker over one package, or every publishable package with tests.
 *
 * PRIVATE PACKAGES ARE EXCLUDED — `private: true` in a manifest means no tarball, so there is no published
 * surface for a mutation score to be a statement about.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";

const root = new URL("..", import.meta.url).pathname;
const all = readdirSync(`${root}/packages`).filter((p) => {
  // A stray file in packages/ (a .gitkeep, a .DS_Store) must not crash the enumerate step that CI's
  // matrix depends on.
  if (!statSync(`${root}/packages/${p}`).isDirectory()) return false;
  if (!existsSync(`${root}/packages/${p}/package.json`)) return false;
  if (!existsSync(`${root}/packages/${p}/test`)) return false;
  return !JSON.parse(readFileSync(`${root}/packages/${p}/package.json`, "utf8"))
    .private;
});

const args = process.argv.slice(2);
// `--list` prints the package set as JSON so CI can fan out over it as a matrix instead of running every
// package back-to-back in one job. Keeps the list in ONE place: this script.
if (args[0] === "--list") {
  console.log(JSON.stringify(all));
  process.exit(0);
}
const targets = args.length > 0 ? args : all;
const unknown = targets.filter((t) => !all.includes(t));
if (unknown.length > 0) {
  console.error(
    `unknown package(s): ${unknown.join(", ")}\nknown: ${all.join(", ")}`,
  );
  process.exit(1);
}

const failed = [];
for (const pkg of targets) {
  console.log(`\n━━━ mutation: ${pkg} ━━━`);
  try {
    execFileSync("npx", ["stryker", "run", "stryker.config.mjs"], {
      cwd: root,
      stdio: "inherit",
      env: { ...process.env, STRYKER_PKG: pkg },
    });
  } catch {
    failed.push(pkg); // below its ratchet — keep going so one run reports every regression
  }
}
if (failed.length > 0) {
  console.error(`\nBELOW RATCHET: ${failed.join(", ")}`);
  process.exit(1);
}
