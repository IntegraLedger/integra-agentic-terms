# Contributing

Thank you for helping. This file covers how to build and test the repository, the rules a change follows, and how to
submit it.

## Setting up

You need:

- Node.js 26.11.1 (`.node-version`);
- pnpm 12.11.2 (the `packageManager` field of `package.json`);
- [uv](https://docs.astral.sh/uv/), for the Python package.

```sh
pnpm install --frozen-lockfile
pnpm -r --if-present run build
```

The workspace installs with `minimumReleaseAge: 1440` (no package version younger than a day), `trustPolicy:
no-downgrade` and `strictDepBuilds: true`, and `permissions` denies the builds of `esbuild` and `secp256k1`, each
`{build: false}`. Every dependency and devDependency is pinned to an exact version. Peer dependencies are ranges:
`@integraledger/lcp` is a peer of both TypeScript packages, with an exact devDependency for their own tests, so an
application and the gate share one copy of lcp. A change that adds a dependency pins an exact version.

CI's install-policy step holds the policy: every `pnpm-workspace.yaml` git lists, the root's and the site's, sets
`minimumReleaseAge: 1440`, `trustPolicy: no-downgrade` and `strictDepBuilds: true`, and before the install `pnpm config
get` reads those three values in each folder that holds one, every override as an exact version or a removal below one,
every catalog entry as an exact version, `autoInstallPeers` unset or `false`, and no `pnpmfile`, `globalPnpmfile` or
`configDependencies`. No other setting is admitted but `packages` (the root's alone: relative globs that exclude each
folder holding its own workspace file, here `"*"` and `"!website"`, so `pnpm -r` reaches every package), `permissions`
(each package's `build` and `skills` decisions, every one `false`), `minimumReleaseAgeExclude` (exact
`'@integraledger/<name>@<x.y.z>'` versions a lockfile installs, one to an entry, or several of one package in pnpm's own
form, `'@integraledger/<name>@<x.y.z> || <x.y.z>'`, single- or double-quoted as pnpm writes them), `overrides` (exact
registry versions: no range, prerelease, URL, `file:`, `link:`, git, `github:` or `npm:` alias; or `"-"`, which removes
a dependency and adds no code, under a selector that names a parent at an exact version and a child with no version,
`"<name>@<x.y.z>><child>": "-"`, quoted either way), `catalog` and `catalogs` (the versions a manifest names by
`catalog:`, each an exact registry version by the same rule, and none a `catalog:` reference), `patchedDependencies`
(exact versions, each patched by a file under `patches/` that git lists) and `autoInstallPeers: false`, so that no peer
enters an install unless a package declares it. In `permissions`, `overrides` and the catalogs, a package name and a
version may each be plain, single- or double-quoted. Any line may end in a comment, one or more spaces, `#` and any
text, and what comes before it is held as the line would be without one; a `#` with no space before it, or inside
quotes, is part of the value. `allowBuilds`, `allowSkills`, `ignoredBuiltDependencies`, `pnpmfile`, `globalPnpmfile`,
`configDependencies` and every other key are refused, each by name, so every package decision is in one place and no
file of hooks is named, and a line indented under a setting is refused too. Every `package.json`'s `pnpm.overrides`,
`resolutions` and `overrides`, npm's nested form included, name exact versions. Every package in every lockfile comes
from the registry by its integrity, a `link:` reaches only a workspace package, and no dependency is a file, directory,
git or tarball source. Every `.npmrc` git lists, at any depth, holds only comments, blank lines,
`registry=https://registry.npmjs.org/` and `engine-strict=true`, whatever pnpm reads from it; any other line is refused
by its file and line. Git lists no `.pnpmfile.cjs` or `.pnpmfile.mjs`, at any depth, since pnpm runs the hooks in the
root's at install time; each is refused by its file. No workflow sets pnpm's settings by a `pnpm_config_` environment
variable, a `--config.` flag or the `pnpm config` command, its alias or its shorthands; the one line admitted is the
step's own `config get` read. The step reads the committed files, pnpm's reading of them and the workflows' lines. A
workflow step that rewrites a checked file before the install, such as a `sed -i` on `pnpm-workspace.yaml`, or that
builds a setting's name at run time, is code, like a step that deletes this check, and this check does not read it.

CI's Node.js step reads every workflow in `.github/workflows`, `.yml` and `.yaml`. Every job that runs a step fetches
the Node.js `.node-version` names, checked against one SHA-256, in one step, byte for byte the same in every job, before
its first other step that runs, and no workflow names another Node.js download; the step runs under that Node.js and
fails under another. Every download in a workflow is
`curl -fsSL --retry 5 --retry-all-errors -o "$RUNNER_TEMP/<file>" https://<address>`, which retries a failed transfer
five times whatever the error, and writes one file. No workflow uses `setup-node`, `continue-on-error`, `if:`,
`container:`, `shell:` or a `PATH:` key, or writes `$GITHUB_ENV`, and only the Node.js and pnpm fetches write
`$GITHUB_PATH`. Every workflow is written in YAML's plain block style: outside a block scalar (`run: |`), each line is
blank, a comment, or one plain key and its value, with no flow mapping but `{}`, no flow sequence of anything but plain
words, and no anchor, alias, tag or quoted value that does not close on its own line, and a block scalar's header holds
only its indicators and a comment. Each workflow has one `jobs:` line, and every line under it is blank, a comment, a
job's own line (`<name>:`, indented two spaces) or a line inside a job. The step reads the jobs' steps only outside a
block scalar, so the text a block scalar holds is never read as a step.

## The layout

| Folder | What it holds |
| --- | --- |
| `agentic-terms/` | `@integraledger/terms`, the TypeScript buyer gate. `src/pairings/` holds one module per pairing. |
| `agentic-terms-mcp/` | `@integraledger/terms-mcp`, the MCP server, and `skills/`, the agent skill. |
| `agentic-terms-py/` | `integraledger-terms`, the Python buyer gate, with its own bindings. |
| `docs/` | The documentation, in Markdown. It is the only source of the documentation site. |
| `scripts/docs.mjs` | Generates the pairing tables and checks every documentation sample. |
| `website/` | The documentation site's app. It reads `docs/` and has its own lockfile. |

The TypeScript packages import only `@integraledger/lcp` (and the MCP server also `@integraledger/terms`). CI checks
that boundary.

## Testing

These are the commands CI runs. Run them before you open a pull request:

```sh
pnpm -r --if-present run build
pnpm -r --if-present run typecheck
pnpm -r --if-present run test

cd agentic-terms-py
uv run --locked --python 3.11 pytest -q
uv run --locked --python 3.14 pytest -q
uv run --locked --python 3.14 mypy --strict src tests
cd ..

node scripts/docs.mjs check
```

The Python tests read the shared vectors from `agentic-terms/node_modules/@integraledger/lcp/vectors`, so install the
TypeScript side first.

## Rules for a change

- **Both gates change together.** The TypeScript and Python gates are two implementations of one set of rules. A change
  to what the gate reads, fetches, builds, compares or declines lands in both, and the shared vectors decide what is
  right.
- **Expected values come from outside the code.** A test's expected value comes from a specification, a published
  vector, or a recording of a real rail, never from the output of the code under test.
- **Hash the exact bytes.** Nothing in the gate parses, re-serialises or normalises the ATR.
- **No business or legal logic.** The gate compares hashes and builds payments. It does not judge terms, prices,
  payees or amounts.
- **Comments say what the code does.**

## Documentation

Every code sample in the READMEs and in `docs/` is checked. `node scripts/docs.mjs check` extracts each fenced block and:

| Fence | What the check does |
| --- | --- |
| ` ```ts ` | Type-checks it against the built packages, then runs it with Node.js. |
| ` ```ts no-run ` | Type-checks it only. Use it for a sample that needs a live seller, wallet or client. |
| ` ```python ` | Runs it in the Python package's environment. |
| ` ```python no-run ` | Compiles it only. |
| ` ```json ` | Parses it. |
| ` ```text output ` | Compares it with what the runnable sample just before it printed. |

A sample is complete: its imports, its values, and a local stand-in for any network it needs. Samples use the shared
vectors' values, so they print the same output on every run. A TypeScript sample imports from the package names
(`@integraledger/terms`), never from relative paths.

The pairing tables in the package READMEs and in `docs/reference/pairings.md` are generated from the code. After you
add or change a pairing, run:

```sh
node scripts/docs.mjs generate
```

The site in `website/` builds, after the packages, with `pnpm install --frozen-lockfile && pnpm run browser && pnpm
run build` inside that folder, on Linux x64. `pnpm run browser` fetches, retrying a failed download five times, the
browser build the Mermaid diagrams are drawn in, Chrome Headless Shell, which `website/scripts/browser.mjs` pins by
version and by the SHA-256 of its archive, and the build refuses any other. The build is pinned for Linux x64 alone, since a browser build for another platform
measures text through that platform's own font engine, so the site is built in CI or on a maintainer's Linux x64
machine. After the build, `node scripts/check-diagrams.mjs` in `website/` draws every diagram twice, the second time
under a font configuration that changes every font's rendering, and checks that both give the same SVGs, that a
diagram with a character Inter does not draw is refused, and that the site serves the Inter files the diagrams are
drawn in. `node scripts/check-highlighting.mjs` in `website/` highlights a TypeScript and a Python sample with the
options `website/source.config.ts` gives the code highlighter, once with the clock as it is and once with a clock that
moves 600 ms at every read while a sample is tokenized and its Twoslash popups are highlighted. It checks that both give
the same HTML, that `const` and `True` take github-light-default's colours, and that no other source under `website/`
imports a module that highlights code. Each line is tokenized to its end however long that takes
(`tokenizeTimeLimit: 0`), so a busy machine colours the code as an idle one does. `node scripts/check-worker.mjs` in
`website/` runs `website/worker.js` and checks that each kind of response it returns carries the headers
`website/public/_headers` gives the request's path, once each, and that `scripts/check-live-headers.mjs`, the check of
the deployed site, passes against a server of the export and fails when one header is dropped. The build writes each
page's script policy into the page (`website/scripts/script-policy.mjs`), and `node scripts/check-script-policy.mjs` in
`website/` parses every page in that browser and checks that each holds one `<meta
http-equiv="Content-Security-Policy">`, first in its head after the character encoding, whose `script-src` names
`'self'` and the SHA-256 of each inline script the page holds, and no other. It also checks that every file of the
export that is not a page takes a second header policy from `website/public/_headers`, `default-src 'none'; script-src
'none'`, and no page does, and it serves the export with those headers and checks that every page, and each SVG and
XML file opened as a document, refuses an inline script added to it.

Two builds of one commit are byte-equal. The build ID, which every page carries and which names the folder of the
build's manifests under `/_next/static/`, is the commit's sha (`website/next.config.ts`); with uncommitted changes it
is the sha and a digest of those changes. The Mermaid diagrams are drawn in the browser build and the font the
repository pins, with no font of the machine's; text and code are set in the theme's font stacks; and each social card
is drawn in Geist, the font next/og bundles, alone, so a page whose title or description holds a character Geist does
not draw stops the build, naming it. `next build` runs with its upgrade check off (`next.config.ts`, and the `build`
script in `package.json` empties `__NEXT_AGENT_UPGRADE`, which turns it on) and its telemetry off (`package.json`), so
the build reads nothing from the network. To check it, in `website/`:

```sh
first=$(mktemp -d) && pnpm run build && mv out "$first/out" && rm -rf .next && pnpm run build && diff -r --brief "$first/out" out
```

## Submitting a change

1. Fork the repository and create a branch.
2. Make the change, with its tests and documentation.
3. Run the commands above.
4. Commit with a sign-off (below), push, and open a pull request that says what the change does and how you tested it.

### Sign your commits

Every commit carries a [Developer Certificate of Origin](https://developercertificate.org) sign-off: a
`Signed-off-by:` line with your name and email, which certifies that you wrote the change or have the right to submit
it under the repository's license.

```sh
git commit -s -m "Describe what the change does"
```

To sign off commits you have already made on your branch:

```sh
git rebase --signoff main
```

On every push to `main`, CI reads every commit in `main`'s history and fails if a commit has no `Signed-off-by:` trailer
or its message matches the agent pattern in `.github/workflows/ci.yml` (`Co-authored-by`, `generated with` and the names
it lists, in upper or lower case). It runs after the push and cannot hold a commit back, so sign off every commit before
you open a pull request.

## Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](./LICENSE).
