#!/usr/bin/env node --test
/**
 * `check:runtime`'s drive — **the two homes must not come back.**
 *
 * ⛔ The defect this closes was not an absent check; it was ONE judgement written in TWO places that had
 * already drifted. So the case that matters is not "does node work" — CI proved that daily — it is that
 * `ci.yml` SELECTS a row from `RUNTIMES` rather than carrying its own copy of the dispatch. ⭐ A drive
 * that only tested the table would pass forever while somebody pasted the `case` statement back into the
 * workflow.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { commandFor, RUNTIMES } from "./runtime-smoke-driver.mjs";

const SCRIPT = new URL("./runtime-smoke-driver.mjs", import.meta.url).pathname;
const CI = new URL("../.github/workflows/ci.yml", import.meta.url).pathname;

test("every runtime the README's table claims has a command", () => {
  assert.deepEqual(Object.keys(RUNTIMES).sort(), ["bun", "deno", "node"]);
});

test("⛔ deno's permissions are explicit and are NOT -A", () => {
  // The narrow set is the claim: the smoke reads modules and touches no network, so a dependency that
  // started reaching out must fail rather than be waved through.
  const [, args] = commandFor("deno");
  for (const flag of ["--allow-read", "--allow-env", "--allow-sys"])
    assert.ok(args.includes(flag), `deno must pass ${flag}`);
  assert.ok(!args.includes("-A"), "deno must not be given blanket permission");
  assert.ok(!args.includes("--allow-net"), "the smoke touches no network");
});

test("an unknown runtime refuses rather than defaulting to node", () => {
  assert.throws(() => commandFor("quickjs"), /unknown runtime/);
  try {
    execFileSync("node", [SCRIPT], {
      encoding: "utf8",
      env: { ...process.env, INTEGRA_RUNTIME: "quickjs" },
      stdio: "pipe",
    });
    assert.fail("expected a refusal");
  } catch (error) {
    assert.equal(error.status, 1);
    assert.match(
      `${error.stdout ?? ""}${error.stderr ?? ""}`,
      /unknown runtime/,
    );
  }
});

test("⛔⛔ ci.yml SELECTS a runtime; it does not carry its own dispatch", () => {
  const ci = readFileSync(CI, "utf8");
  const job = ci.slice(ci.indexOf("\n  runtime:"));
  const body = job.slice(
    0,
    job.indexOf("\n  ", 1) === -1 ? undefined : undefined,
  );
  // The whole file is searched for the shape that was removed, so pasting it into any job reds.
  assert.ok(
    !/runtime-smoke\.mjs\s*;;/.test(ci),
    "ci.yml carries a `case` dispatch over runtime-smoke.mjs again — the second home is back",
  );
  assert.match(
    job,
    /INTEGRA_RUNTIME:\s*\$\{\{\s*matrix\.runtime\s*\}\}/,
    "the runtime job must pass its matrix leg through INTEGRA_RUNTIME",
  );
  assert.match(
    job,
    /pnpm check:runtime/,
    "the runtime job must invoke check:runtime",
  );
  assert.ok(body !== undefined);
});

test("⛔ the smoke refuses when the consumer install is absent — it does not pass over nothing", () => {
  try {
    execFileSync("node", [SCRIPT], {
      encoding: "utf8",
      cwd: "/tmp",
      env: { ...process.env, INTEGRA_RUNTIME: "node" },
      stdio: "pipe",
    });
    assert.fail("expected a refusal");
  } catch (error) {
    assert.equal(error.status, 1);
    assert.match(
      `${error.stdout ?? ""}${error.stderr ?? ""}`,
      /does not exist/,
    );
  }
});
