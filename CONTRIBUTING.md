# Contributing

Thank you for helping. This file covers how to build and test the repository, the rules a change follows, and how to
submit it.

## Setting up

You need:

- Node.js 26.10 (`.node-version`);
- pnpm 11.27.1 (the `packageManager` field of `package.json`);
- [uv](https://docs.astral.sh/uv/), for the Python package.

```sh
pnpm install --frozen-lockfile
pnpm -r --if-present run build
```

The install policy is strict: dependencies are exact versions, a version must have been published for at least a day
before it installs (`minimumReleaseAge`), and dependency build scripts do not run unless allowed. A change that adds a
dependency pins an exact version.

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

CI checks every pushed commit. It fails on a commit without a `Signed-off-by:` line, and on a commit message that
carries a `Co-authored-by:` trailer or a tool's attribution line.

## Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](./LICENSE).
