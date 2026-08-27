#!/usr/bin/env node
/**
 * Refuse a commit MESSAGE carrying a marker that must not appear in a public repository.
 *
 * WHY THIS EXISTS, AND WHY IT IS SEPARATE FROM `check:vocab`. `CLAUDE.md` names commit messages, in the
 * same breath as files, as world-readable. `check-vocab.mjs` walks the working tree — it cannot see a
 * message, and a message cannot be fixed by editing a file afterwards: once pushed it is in every clone and
 * on the web, and the only remedy is rewriting history for everyone. That asymmetry is the whole argument
 * for a separate gate. Five commits reached the public remote carrying a `Co-Authored-By` trailer and a
 * session URL before anything looked.
 *
 * ⛔ FORWARD-ONLY, DELIBERATELY. It checks the commits a push actually introduces, not the whole history.
 * Auditing history would fail every run until someone force-pushed a public repository, which breaks every
 * clone and is a decision no gate should force. Existing commits are a separate, human call. This stops the
 * NEXT one.
 *
 * Range comes from the push event: `--range <before>..<after>`, or `--last N`, or bare (HEAD only).
 * A `before` of all zeros means a new branch, which has no meaningful predecessor — that falls back to
 * HEAD rather than walking the entire repository.
 */
import { execFileSync } from "node:child_process";
import { FORBIDDEN_LITERALS } from "./forbidden-literals.mjs";

const argv = process.argv.slice(2);
const arg = (flag) => {
  const i = argv.indexOf(flag);
  return i === -1 ? undefined : argv[i + 1];
};

const git = (args) =>
  execFileSync("git", args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });

const ZERO = /^0{40}$/;

/** Is this revision actually in this clone? A force-pushed-away commit is not, and neither is a shallow one. */
function exists(rev) {
  try {
    execFileSync(
      "git",
      ["rev-parse", "--verify", "--quiet", `${rev}^{commit}`],
      { stdio: "ignore" },
    );
    return true;
  } catch {
    return false;
  }
}

function revisions() {
  const range = arg("--range");
  if (range) {
    const [before, after] = range.split("..");
    // A new branch reports an all-zero `before`. Walking from there would audit the whole history and fail
    // on commits this push did not introduce.
    const head = after || "HEAD";
    if (before && !ZERO.test(before) && exists(before))
      return git(["rev-list", `${before}..${head}`])
        .split("\n")
        .filter(Boolean);

    // ⛔ `before` CAN NAME A COMMIT THAT NO LONGER EXISTS, and `fetch-depth: 0` does not help. A force-push
    // orphans the previous tip: it becomes unreachable from every ref, so it is never fetched. Dependabot
    // force-pushes on every PR update, so this is routine rather than exotic — it reddened a Dependabot
    // branch within a day of this gate existing, under an error message blaming shallow clones.
    //
    // The honest fallback is not a NARROWER range but the correct one: what this ref adds relative to the
    // base branch. That set is always resolvable, and for a force-pushed branch it is what a reviewer
    // actually cares about. It is announced rather than silently substituted — a gate that quietly checks
    // something other than what it was asked to check is the failure this whole file exists to prevent.
    for (const base of ["origin/main", "main"]) {
      if (!exists(base)) continue;
      const range = `${base}..${head}`;
      const revs = git(["rev-list", range]).split("\n").filter(Boolean);
      // EMPTY IS LEGITIMATE HERE, unlike for an explicit range. A branch reset onto its base adds nothing,
      // and so does a re-run on the base itself — neither is a wrong range, so neither may hard-fail.
      // Falling through to the tip keeps the gate examining something real rather than reporting on
      // nothing, which is the distinction the zero-commit guard below cannot make on its own.
      if (revs.length === 0) break;
      console.log(
        `check:commit-messages — ${before.slice(0, 7)} is unreachable (force-push); examining ${range} instead.`,
      );
      return revs;
    }
    console.log(
      `check:commit-messages — ${before.slice(0, 7)} is unreachable and the base adds nothing; examining ${head} only.`,
    );
    return git(["rev-list", "-1", head]).split("\n").filter(Boolean);
  }
  const last = arg("--last");
  if (last)
    return git(["rev-list", `-${Number(last)}`, "HEAD"])
      .split("\n")
      .filter(Boolean);
  return git(["rev-list", "-1", "HEAD"]).split("\n").filter(Boolean);
}

const revs = revisions();

// A range that resolves to nothing is not a pass. A push always introduces at least one commit, so an
// empty set means the range was wrong — and a checker that silently examines nothing reports clean.
if (revs.length === 0) {
  console.error(
    "check:commit-messages examined ZERO commits. A push introduces at least one, so the range is wrong. Refusing to report clean.",
  );
  process.exit(1);
}

const findings = [];
for (const rev of revs) {
  const message = git(["log", "-1", "--format=%B", rev]);
  for (const [re, what] of FORBIDDEN_LITERALS)
    if (re.test(message))
      findings.push({
        rev: rev.slice(0, 7),
        what,
        subject: git(["log", "-1", "--format=%s", rev]).trim(),
      });
}

// Prove the matcher still discriminates before trusting a clean result — the same defence `check:vocab`
// carries. A pattern that stopped matching would report every commit clean and look identical to success.
// ⭐ ASSEMBLED, NOT WRITTEN. Spelling the marker out here would put it in a file of this repository and
// make this gate trip `check:vocab` — so the canary would need an exemption, and every exemption is a hole
// someone later widens. Built from parts, the source carries no marker and needs no exemption; the value
// under test at runtime is byte-identical to the real thing.
const CANARIES = [
  [`Co-Authored${"-By: "}Claude <noreply@anthropic.com>`, true],
  ["Reviewed-By: a colleague", false],
];
for (const [sample, shouldFlag] of CANARIES) {
  const flagged = FORBIDDEN_LITERALS.some(([re]) => re.test(sample));
  if (flagged !== shouldFlag) {
    console.error(
      `check:commit-messages canary FAILED: ${JSON.stringify(sample)} should ${shouldFlag ? "" : "NOT "}be flagged. The gate is not discriminating.`,
    );
    process.exit(1);
  }
}

if (findings.length > 0) {
  console.error(
    `\ncheck:commit-messages — ${findings.length} marker(s) that must not be in a public repository:\n`,
  );
  for (const f of findings)
    console.error(`  ${f.rev}  ${f.what}\n          ${f.subject}`);
  console.error(
    "\nA pushed message cannot be edited — it is in every clone. Amend before pushing:\n" +
      "  git commit --amend            (then re-run this)\n" +
      "  git rebase -i <base>          for more than the tip commit\n",
  );
  process.exit(1);
}

console.log(
  `check:commit-messages — ${revs.length} commit message(s) carry no forbidden marker, 2/2 canaries.`,
);
