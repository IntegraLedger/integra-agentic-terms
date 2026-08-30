/**
 * Drive for `reconcile-tags.mjs`'s classification — the half that decides WHICH repository a published
 * version belongs to, and therefore whether an absent tag here is a defect or a fact about history.
 *
 * The reconciliation itself reads the registry and `origin` and is proven by running it. What is driven
 * here is every decision it makes once both of those reads succeed — which repository a URL names, which
 * repository this tree is, and what is owed for one published version whose tag is absent.
 *
 * ⛔ THE FIRST VERSION OF THIS DRIVE TESTED ONLY STRING PARSING. Deleting the pin-equality check, deleting
 * the staleness check, or INVERTING the `sameRepository` test all left it green — the three guarantees the
 * gate's own docblock advertises had no coverage at all, while the least load-bearing one had plenty.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  BUILT_BEFORE_THE_MOVE,
  classifyVersion,
  parseRepositorySlug,
  repositoryIdentity,
  sameRepository,
  staleDeclarations,
} from "./reconcile-tags.mjs";

const SELF = "IntegraLedger/integra-agentic-terms";
const PINNED = Object.entries(BUILT_BEFORE_THE_MOVE)[0];

test("a provenance dependency URI yields owner/name, with the ref suffix removed", () => {
  assert.equal(
    parseRepositorySlug(
      "git+https://github.com/OtherOwner/other-repo@refs/heads/main",
    ),
    "OtherOwner/other-repo",
  );
});

test("an npm `repository.url` yields the same shape, with `.git` removed", () => {
  assert.equal(
    parseRepositorySlug(
      "git+https://github.com/IntegraLedger/integra-agentic-terms.git",
    ),
    "IntegraLedger/integra-agentic-terms",
  );
});

test("⭐ the two forms of the SAME repository compare equal — or every version reads as foreign", () => {
  assert.equal(
    parseRepositorySlug(
      "git+https://github.com/IntegraLedger/integra-agentic-terms.git",
    ),
    parseRepositorySlug(
      "git+https://github.com/IntegraLedger/integra-agentic-terms@refs/heads/main",
    ),
  );
});

test("⛔ an ssh URL's `git@` is not mistaken for the ref separator", () => {
  assert.equal(
    parseRepositorySlug("git+ssh://git@github.com/IntegraLedger/repo.git"),
    "IntegraLedger/repo",
  );
});

test("⛔ a non-GitHub host is null, never a half-parsed slug", () => {
  assert.equal(
    parseRepositorySlug("git+https://gitlab.com/owner/repo.git"),
    null,
  );
  assert.equal(parseRepositorySlug("https://example.invalid/owner/repo"), null);
});

test("⛔ a URL with no repository name is null — `owner/` must not classify as a repository", () => {
  assert.equal(parseRepositorySlug("https://github.com/IntegraLedger"), null);
  assert.equal(parseRepositorySlug("https://github.com/IntegraLedger/"), null);
});

test("⛔ a deeper path is null — a tree URL names a file, not the repository line", () => {
  assert.equal(
    parseRepositorySlug("https://github.com/owner/repo/tree/main/packages"),
    null,
  );
});

test("⛔ a non-string is null rather than throwing — an absent `repository` is a manifest defect the caller reports by name", () => {
  assert.equal(parseRepositorySlug(undefined), null);
  assert.equal(parseRepositorySlug(null), null);
});

test("one declared repository across the publishable packages is the identity", () => {
  assert.equal(
    repositoryIdentity([
      {
        name: "@x/a",
        repository: { url: "git+https://github.com/O/R.git" },
      },
      {
        name: "@x/b",
        repository: { url: "git+https://github.com/O/R.git" },
      },
    ]),
    "O/R",
  );
});

test("⛔⛔ packages that DISAGREE throw — picking one would silently classify the other's releases as foreign", () => {
  assert.throws(
    () =>
      repositoryIdentity([
        { name: "@x/a", repository: { url: "https://github.com/O/R.git" } },
        { name: "@x/b", repository: { url: "https://github.com/O/OTHER.git" } },
      ]),
    /disagree about their repository: O\/OTHER, O\/R/,
  );
});

test("⛔⛔ an EMPTY publishable set throws — reconciling nothing would report a green over nothing", () => {
  assert.throws(() => repositoryIdentity([]), /empty set/);
});

test("⛔ a package with no usable `repository.url` throws, naming the package", () => {
  assert.throws(
    () => repositoryIdentity([{ name: "@x/a", repository: undefined }]),
    /@x\/a declares no usable/,
  );
});

test("⛔⛔ every pin is a full 40-hex commit — a truncated or prefixed value can never equal a provenance SHA, so the entry would refuse a version that is actually fine", () => {
  const entries = Object.entries(BUILT_BEFORE_THE_MOVE);
  assert.ok(
    entries.length > 0,
    "nothing declared as predating the move — delete the table and this drive together rather than letting it assert over nothing",
  );
  for (const [tag, sha] of entries)
    assert.match(
      sha,
      /^[0-9a-f]{40}$/,
      `${tag} is not pinned to a full commit`,
    );
});

test("⛔ every key is `@scope/name@version` — a malformed key matches no published version and would fail as a stale entry rather than as the typo it is", () => {
  for (const tag of Object.keys(BUILT_BEFORE_THE_MOVE))
    assert.match(
      tag,
      /^@[^@/]+\/[^@/]+@\d+\.\d+\.\d+$/,
      `${tag} is not a package@version`,
    );
});

test("⛔ the table is frozen — a run that mutated it would classify differently as it went", () => {
  assert.ok(Object.isFrozen(BUILT_BEFORE_THE_MOVE));
});

test("a version built in THIS repository is one this repository owes a tag", () => {
  assert.deepEqual(
    classifyVersion({
      tag: "@x/a@1.0.0",
      sha: "a".repeat(40),
      repository: SELF,
      self: SELF,
    }),
    { kind: "tag-here", tag: "@x/a@1.0.0", sha: "a".repeat(40) },
  );
});

test("⛔⛔ INVERTING the same-repository test is caught — a foreign build is never this repository's tag to write", () => {
  const decided = classifyVersion({
    tag: "@x/a@1.0.0",
    sha: "a".repeat(40),
    repository: "SomeoneElse/other",
    self: SELF,
  });
  assert.equal(decided.kind, "refuse");
  assert.match(decided.reason, /not declared as predating the move/);
});

test("⛔ owner casing does not decide it — GitHub is case-insensitive and this comparison is equality", () => {
  assert.equal(
    classifyVersion({
      tag: "@x/a@1.0.0",
      sha: "a".repeat(40),
      repository: SELF.toLowerCase(),
      self: SELF,
    }).kind,
    "tag-here",
  );
  assert.equal(sameRepository("O/R", "o/r"), true);
  assert.equal(sameRepository("O/R", "O/OTHER"), false);
  assert.equal(sameRepository(null, null), false);
});

test("a pinned pre-move version whose provenance still matches the pin passes, and says where it was built", () => {
  const [tag, sha] = PINNED;
  const decided = classifyVersion({
    tag,
    sha,
    repository: "Someone/predecessor",
    self: SELF,
  });
  assert.equal(decided.kind, "pre-move");
  assert.match(decided.note, /Someone\/predecessor/);
});

test("⛔⛔ THE DEFECT — a pinned version whose provenance MOVED is refused, not exempted", () => {
  const [tag, sha] = PINNED;
  const moved = `${sha.slice(0, 39)}${sha.endsWith("f") ? "e" : "f"}`;
  const decided = classifyVersion({
    tag,
    sha: moved,
    repository: "Someone/predecessor",
    self: SELF,
  });
  assert.equal(decided.kind, "refuse");
  // Both SHAs in full, or the operator is told that something differs and nothing about what.
  assert.ok(decided.reason.includes(sha) && decided.reason.includes(moved));
});

test("⛔ an unparseable provenance repository is refused, never treated as this repository", () => {
  const decided = classifyVersion({
    tag: "@x/a@1.0.0",
    sha: "a".repeat(40),
    repository: null,
    self: SELF,
  });
  assert.equal(decided.kind, "refuse");
  assert.match(decided.reason, /cannot parse/);
});

test("⛔ a prototype key cannot borrow a pin — and the REASON is what tells `Object.hasOwn` from a bare lookup", () => {
  for (const tag of ["constructor", "toString", "__proto__"]) {
    const decided = classifyVersion({
      tag,
      sha: "a".repeat(40),
      repository: "Someone/else",
      self: SELF,
    });
    assert.equal(decided.kind, "refuse");
    // A bare `BUILT_BEFORE_THE_MOVE[tag]` finds `Object.prototype.constructor` and refuses too — with
    // "declared at function Object() { … }". Asserting only `kind` cannot tell the two apart.
    assert.match(decided.reason, /not declared as predating the move/);
  }
});

test("⛔⛔ a pin the registry no longer serves is reported stale — the subject set emptying", () => {
  const [tag] = PINNED;
  assert.deepEqual(
    staleDeclarations(new Set(Object.keys(BUILT_BEFORE_THE_MOVE))),
    [],
  );
  const short = new Set(
    Object.keys(BUILT_BEFORE_THE_MOVE).filter((t) => t !== tag),
  );
  const stale = staleDeclarations(short);
  assert.equal(stale.length, 1);
  assert.match(stale[0], /delete the entry/);
});
