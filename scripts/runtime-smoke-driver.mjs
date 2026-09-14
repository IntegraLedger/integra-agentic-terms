#!/usr/bin/env node
/**
 * Run `runtime-smoke.mjs` inside the clean consumer install, on ONE named runtime.
 *
 * ⛔⛔ **THIS FILE EXISTS SO THERE IS ONE DEFINITION OF "HOW TO SMOKE A RUNTIME" RATHER THAN TWO.**
 * `M` 2026-09-14, `integra-agentic-terms` `25a231e`: `pnpm check:runtime` ran the smoke on **node only**,
 * while `ci.yml`'s `runtime` job ran it on **node, bun and deno** from a `case` statement written out in
 * the workflow. Two homes for one judgement, and they had **already diverged** — CI's deno leg carried
 * `--allow-read --allow-env --allow-sys --node-modules-dir=manual` and the `package.json` script carried
 * no notion of deno at all. ⇒ A developer running `pnpm check:runtime` before pushing exercised one of the
 * three runtimes the `README.md` table claims, while the script's name said the check had been made.
 *
 * ⚠️ **Nothing was unmeasured** — CI did and does exercise all three. This closes the trap, not a hole.
 *
 * ## ⭐ WHY THE PERMISSION FLAGS LIVE HERE
 *
 * They are part of the claim. `--allow-read --allow-env --allow-sys` and **not** `-A`: the smoke reads
 * modules and touches no network, so a dependency that started reaching out must fail rather than be
 * waved through. A flag list that lives in a workflow is a claim nothing in the repository can test;
 * living here, `runtime-smoke-driver.test.mjs` asserts it.
 *
 * ⛔ **AN ABSENT RUNTIME REFUSES, IT DOES NOT SKIP.** A missing `bun` is not evidence about the tarball,
 * and a smoke that quietly passes because the interpreter was not installed is the empty-subject-set
 * defect with an exit code of 0.
 *
 * USAGE
 *   node scripts/runtime-smoke-driver.mjs          # node, the default
 *   INTEGRA_RUNTIME=deno node scripts/runtime-smoke-driver.mjs
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

/**
 * ⭐ THE SINGLE DEFINITION. Every runtime the README's table claims, and the exact argv each is smoked
 * with. CI selects a row; it does not carry one.
 */
export const RUNTIMES = Object.freeze({
  node: ["node", ["runtime-smoke.mjs"]],
  bun: ["bun", ["run", "runtime-smoke.mjs"]],
  // Deno resolves the npm tree already on disk rather than fetching its own, so this leg runs over the
  // same bytes the other two saw. Permissions are explicit on purpose — see the docblock.
  deno: [
    "deno",
    [
      "run",
      "--allow-read",
      "--allow-env",
      "--allow-sys",
      "--node-modules-dir=manual",
      "runtime-smoke.mjs",
    ],
  ],
});

const die = (message) => {
  console.error(`\nRefusing to verify: check:runtime — ${message}\n`);
  process.exit(1);
};

/**
 * The command for one runtime.
 *
 * @param {string} runtime
 * @returns {[string, string[]]}
 */
export function commandFor(runtime) {
  if (!Object.hasOwn(RUNTIMES, runtime))
    throw new Error(
      `unknown runtime \`${runtime}\` — this repository claims ${Object.keys(RUNTIMES).join(", ")}`,
    );
  return RUNTIMES[runtime];
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const runtime = process.env["INTEGRA_RUNTIME"] ?? "node";
  let command;
  try {
    command = commandFor(runtime);
  } catch (error) {
    die(error instanceof Error ? error.message : String(error));
  }
  const cwd = join(process.cwd(), ".runtime-consumer");
  if (!existsSync(cwd))
    die(
      `${cwd} does not exist — run \`node scripts/runtime-consumer.mjs\` first. The smoke runs against a\n` +
        "clean consumer install of the PACKED tarball, never against the workspace.",
    );
  const [bin, args] = command;
  console.log(
    `check:runtime — smoking on ${runtime}: ${bin} ${args.join(" ")}`,
  );
  const r = spawnSync(bin, args, { cwd, stdio: "inherit" });
  if (r.error !== undefined && r.error.code === "ENOENT")
    die(
      `\`${bin}\` is not on PATH. ⛔ An absent runtime REFUSES rather than skipping: a smoke that passes\n` +
        "because the interpreter was missing is an exit code of 0 over nothing exercised.",
    );
  if (r.error !== undefined)
    die(`\`${bin}\` failed to start: ${r.error.message}`);
  process.exit(r.status ?? 1);
}
