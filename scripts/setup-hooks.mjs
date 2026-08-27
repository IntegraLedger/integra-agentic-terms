#!/usr/bin/env node
/**
 * Point git at the tracked hooks, so a clone gets them without anyone remembering.
 *
 * ⛔⛔ **HOOKS LIVE IN A CLONE AND NEVER IN THE PUSHED TREE.** `.git/hooks` is not versioned, so every
 * second machine starts with none. `core.hooksPath` is the supported way to redirect git at a directory
 * that IS tracked, and running it from `prepare` means an install does it.
 *
 * ⚠️ **A CONVENIENCE, NEVER THE ENFORCEMENT.** `check:commit-messages` inside `ci.yml`'s verify is what
 * holds the line: a contributor who has not installed, or who passes `--no-verify`, is caught there. What
 * the hook changes is WHEN — before a banned message becomes public history rather than after, which
 * matters here more than usual because this repository's remote forbids force-pushing to `main` and the
 * only remedy afterwards is rewriting history for every clone.
 *
 * ⛔ Not fatal outside a work tree. `prepare` also runs for a consumer installing this package from the
 * registry, where there is no `.git` and nothing to configure — exiting non-zero there would break an
 * ordinary install for a hook the consumer neither has nor wants.
 */
import { execFileSync } from "node:child_process";

const git = (args) =>
  execFileSync("git", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

try {
  if (git(["rev-parse", "--is-inside-work-tree"]) !== "true")
    throw new Error("not a work tree");
} catch {
  console.log(
    "setup-hooks — no git work tree here, so no hooks to install (this is fine).",
  );
  process.exit(0);
}

execFileSync("git", ["config", "--local", "core.hooksPath", ".githooks"], {
  stdio: "inherit",
});
console.log(
  "setup-hooks — core.hooksPath -> .githooks (a banned commit message is now refused at push, not after).",
);
