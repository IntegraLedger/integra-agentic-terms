#!/usr/bin/env node
// The documentation's generated parts and its sample check.
//
//   node scripts/docs.mjs generate   writes the pairing tables from the registries
//   node scripts/docs.mjs check      fails when a generated part differs from the registries, and compiles and runs
//                                    every sample in the READMEs and docs/
//   node scripts/docs.mjs check <file.md>...   compiles and runs the samples of the named files only
//
// Both need the packages built first (`pnpm -r build`) and, for the Python half, `uv` on the path.
//
// The pairing tables come from @integraledger/lcp's `BINDINGS` and the gate's buyer pieces. The check also asks the
// Python package for its bindings and fails unless both languages serve the same pairings under the names the tables
// print.
//
// Samples are fenced code blocks:
//   ```ts, ```typescript   type-checked against the built packages, then run with node
//   ```ts no-run           type-checked only
//   ```python              run with the Python package's environment
//   ```python no-run       compiled only
//   ```json                parsed
//   ```text output         compared with the standard output of the runnable sample just before it
// Any other fence (sh, text, mermaid, http) is prose.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TS_PACKAGE = join(ROOT, "agentic-terms");
const MCP_PACKAGE = join(ROOT, "agentic-terms-mcp");
const PY_PACKAGE = join(ROOT, "agentic-terms-py");
const OUT = ".docs-check";
const RUN_TIMEOUT_MS = 120_000;

const fail = (message) => {
  console.error(`docs: ${message}`);
  process.exit(1);
};

// ── The registries ───────────────────────────────────────────────────────────────────────────────────────────────

/** The rail each pairing pays on, as its section in the tables names it. */
const RAILS = {
  "x402/exact/eip155/eip3009": "EVM",
  "x402/exact/eip155/permit2": "EVM",
  "x402/exact/eip155/erc7710": "EVM",
  "x402/exact/eip155/erc7710-salt": "EVM",
  "x402/upto/eip155/permit2": "EVM",
  "x402/auth-capture/eip155/eip3009": "EVM",
  "x402/auth-capture/eip155/permit2": "EVM",
  "x402/batch-settlement/eip155": "EVM",
  "mpp/charge/evm/authorization": "EVM",
  "mpp/charge/evm/permit2": "EVM",
  "mpp/charge/evm/transaction": "EVM",
  "mpp/charge/evm/hash": "EVM",
  "mpp/charge/usdc/evm": "EVM",
  "mpp/charge/usdc/gateway": "EVM",
  "mpp/session/evm": "EVM",
  "mpp/charge/tempo/memo": "Tempo",
  "mpp/charge/tempo/push": "Tempo",
  "mpp/session/tempo": "Tempo",
  "mpp/subscription/tempo": "Tempo",
  "x402/exact/solana": "Solana",
  "x402/upto/solana": "Solana",
  "x402/batch-settlement/solana": "Solana",
  "mpp/charge/solana": "Solana",
  "mpp/charge/usdc/solana": "Solana",
  "mpp/session/solana": "Solana",
  "x402/exact/stellar": "Stellar",
  "mpp/charge/stellar": "Stellar",
  "x402/exact/xrpl": "XRP Ledger",
  "mpp/charge/xrpl": "XRP Ledger",
  "mpp/session/xrpl": "XRP Ledger",
  "x402/exact/hedera": "Hedera",
  "x402/exact/hedera/transfer-executor": "Hedera",
  "mpp/charge/hedera": "Hedera",
  "mpp/session/hedera": "Hedera",
  "x402/exact/algorand": "Algorand",
  "x402/exact/aptos": "Aptos",
  "x402/exact/sui": "Sui",
  "x402/exact/near": "NEAR",
  "mpp/charge/nearintents": "NEAR",
  "x402/exact/starknet": "Starknet",
  "x402/exact/polkadot/lcp-assets-remark": "Polkadot",
  "x402/exact/tron/lcp-trc20-memo": "TRON",
  "x402/exact/tvm": "TON",
  "x402/exact/cardano": "Cardano",
  "x402/exact/casper": "Casper",
  "x402/exact/ccd": "Concordium",
  "mpp/charge/usdc/stacks": "Stacks",
  "x402/exact/lnbtc": "Lightning",
  "x402/exact/lnbtc/invoice-named": "Lightning",
  "mpp/charge/lightning": "Lightning",
  "mpp/session/lightning": "Lightning",
  "x402/batch-settlement/cloudflare": "Cloudflare",
  "card/visa-tap": "Card",
  "card/mastercard-vi/immediate": "Card",
  "card/mastercard-vi/autonomous": "Card",
  "card/seller-reference": "Card",
  "mpp/charge/card": "Card",
  "mpp/charge/stripe": "Stripe",
  "mpp/subscription/stripe": "Stripe",
  "ap2/checkout-mandate": "Mandate",
  "ucp/checkout/ap2-mandate": "Mandate",
  "ucp/checkout/unsigned": "Checkout",
  "ucp/booking/ap2-mandate": "Mandate",
  "ucp/booking/unsigned": "Checkout",
  "acp/checkout/delegated": "Checkout",
  "acp/checkout/undelegated": "Checkout",
  "ack/payment-request": "Checkout",
};
const RAIL_ORDER = [
  "EVM",
  "Tempo",
  "Solana",
  "Stellar",
  "XRP Ledger",
  "Hedera",
  "Algorand",
  "Aptos",
  "Sui",
  "NEAR",
  "Starknet",
  "Polkadot",
  "TRON",
  "TON",
  "Cardano",
  "Casper",
  "Concordium",
  "Stacks",
  "Lightning",
  "Cloudflare",
  "Card",
  "Stripe",
  "Mandate",
  "Checkout",
];

/** The Python constant that names a pairing: its id upper-cased, with `/` and `-` as `_`. */
const pythonName = (id) => id.toUpperCase().replace(/[/-]/g, "_");

/** Every pairing of @integraledger/lcp's registry, with its pattern, its export and whether the gate serves it. */
async function pairings() {
  const require = createRequire(join(TS_PACKAGE, "package.json"));
  const load = (spec) => import(pathToFileURL(require.resolve(spec)).href);
  const lcp = await load("@integraledger/lcp");
  const manifest = JSON.parse(readFileSync(join(dirname(require.resolve("@integraledger/lcp")), "..", "package.json"), "utf8"));
  const pieces = join(TS_PACKAGE, "dist", "pairings", "index.js");
  if (!existsSync(pieces)) fail("agentic-terms/dist is missing: run `pnpm -r build` first");
  const { PIECES } = await import(pathToFileURL(pieces).href);

  const exported = new Map();
  for (const subpath of Object.keys(manifest.exports)) {
    const module = await load(`@integraledger/lcp${subpath.slice(1)}`);
    for (const [name, value] of Object.entries(module)) {
      if (value === null || typeof value !== "object" || typeof value.id !== "string" || value.pattern === undefined) continue;
      if (!exported.has(value.id)) exported.set(value.id, { from: `@integraledger/lcp${subpath.slice(1)}`, name });
    }
  }

  const rows = lcp.BINDINGS.map((b) => {
    const rail = RAILS[b.id];
    if (rail === undefined) fail(`${b.id} has no rail in scripts/docs.mjs`);
    const ts = exported.get(b.id);
    if (ts === undefined) fail(`${b.id} is exported by no entry point of @integraledger/lcp`);
    if (!PIECES.has(b.id)) fail(`${b.id} is in BINDINGS and the gate has no buyer piece for it`);
    return { id: b.id, rail, pattern: b.pattern, ts, py: pythonName(b.id) };
  });
  for (const id of PIECES.keys()) {
    if (!rows.some((r) => r.id === id)) fail(`the gate has a buyer piece for ${id}, which is not in BINDINGS`);
  }
  rows.sort((a, b) => RAIL_ORDER.indexOf(a.rail) - RAIL_ORDER.indexOf(b.rail) || a.id.localeCompare(b.id));
  return rows;
}

const yes = (v) => (v ? "yes" : "no");

/** Prose as Markdown that MDX also reads: `<`, `{` and `}` escaped. */
const mdx = (text) => text.replace(/[<{}]/g, (c) => `\\${c}`);

/** The table a README carries: every pairing, with whether the buyer signs H and whether an agreement comes first. */
function readmeTable(rows, language) {
  const name = language === "python" ? "Python binding" : language === "mcp" ? "`pairing` argument" : "Binding export";
  const lines = [
    `| Rail | Pairing | ${name} | Buyer signs H | Agreement payment first |`,
    "| --- | --- | --- | --- | --- |",
  ];
  for (const r of rows) {
    const binding =
      language === "python" ? `\`${r.py}\`` : language === "mcp" ? `\`"${r.id}"\`` : `\`${r.ts.name}\` from \`${r.ts.from}\``;
    lines.push(
      `| ${r.rail} | \`${r.id}\` | ${binding} | ${yes(r.pattern.buyerSigns)} | ${r.pattern.publicProof ? "no" : "yes"} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

/** The reference page: every pairing with its binding pattern, its flags, its imports and what its payment proves. */
function referencePage(rows) {
  const out = [
    "---",
    "title: Pairings",
    "description: Every pairing the gate pays, with its binding, its imports in each language, and what its payment proves.",
    "---",
    "",
    `The gate serves ${rows.length} pairings, in TypeScript and in Python alike. This page is generated from the code:`,
    "`node scripts/docs.mjs generate` writes it from `BINDINGS` in `@integraledger/lcp` and the pairings the gate serves,",
    "and `node scripts/docs.mjs check` fails when it differs from them or from the Python package's bindings.",
    "",
    "Columns:",
    "",
    "- **Pattern**: how H rides in the pairing's payment (see [Concepts](../concepts.md#how-h-rides-in-a-payment)).",
    "- **Buyer signs H**: whether what the buyer's wallet signs contains H.",
    "- **On chain**: whether H is written on a public ledger when the payment settles.",
    "- **Public proof**: whether the payment is itself a public proof of H. When it is not, the gate pays the seller's",
    "  agreement payment first (see [Agreement payments](../guides/agreement-payments.md)).",
    "",
    "Below each table, every pairing's statement of what its payment proves, as its binding states it (`pattern.proves`).",
    "Where a statement names `<network>` and `<transaction>`, they stand for the agreement payment's network and",
    "transaction.",
    "",
  ];
  for (const rail of RAIL_ORDER) {
    const group = rows.filter((r) => r.rail === rail);
    if (group.length === 0) continue;
    out.push(`## ${rail}`, "");
    out.push("| Pairing | Pattern | Buyer signs H | On chain | Public proof | TypeScript | Python |");
    out.push("| --- | --- | --- | --- | --- | --- | --- |");
    for (const r of group) {
      const p = r.pattern;
      out.push(
        `| \`${r.id}\` | ${p.pattern} | ${yes(p.buyerSigns)} | ${yes(p.onChain)} | ${yes(p.publicProof)} | \`${r.ts.name}\` from \`${r.ts.from}\` | \`${r.py}\` |`,
      );
    }
    out.push("");
    for (const r of group) {
      out.push(`**\`${r.id}\`**: ${mdx(r.pattern.proves)}`, "");
    }
  }
  return `${out.join("\n").trimEnd()}\n`;
}

const MARK = (name) => [`<!-- pairings:${name}:start -->`, `<!-- pairings:${name}:end -->`];

/** The files the generator writes, with their generated text. */
async function generated() {
  const rows = await pairings();
  const files = new Map();
  files.set(join(ROOT, "docs", "reference", "pairings.md"), referencePage(rows));
  const marked = [
    [join(ROOT, "agentic-terms", "README.md"), "typescript"],
    [join(ROOT, "agentic-terms-mcp", "README.md"), "mcp"],
    [join(ROOT, "agentic-terms-py", "README.md"), "python"],
  ];
  for (const [file, language] of marked) {
    const text = readFileSync(file, "utf8");
    const [start, end] = MARK(language);
    const a = text.indexOf(start);
    const b = text.indexOf(end);
    if (a === -1 || b === -1 || b < a) fail(`${relative(ROOT, file)} has no ${start} … ${end} section`);
    files.set(file, `${text.slice(0, a + start.length)}\n${readmeTable(rows, language)}${text.slice(b)}`);
  }
  return { rows, files };
}

/** The Python package's pairings, by constant name, and the ids its buyer pieces serve. */
function pythonPairings() {
  const script = [
    "import json, integraledger_terms as t",
    "from integraledger_terms.pieces import PIECES",
    "names = {n: getattr(t, n).id for n in t.__all__ if n.isupper() and n != 'MAX_ATR_BYTES'}",
    "print(json.dumps({'names': names, 'pieces': sorted(PIECES)}))",
  ].join("\n");
  const out = execFileSync("uv", ["run", "--locked", "--quiet", "python", "-c", script], { cwd: PY_PACKAGE, encoding: "utf8" });
  return JSON.parse(out);
}

// ── The samples ──────────────────────────────────────────────────────────────────────────────────────────────────

/** The Markdown a reader gets: the root files, each package README and skill, and every page under docs/. */
function markdownFiles() {
  const files = [];
  for (const f of ["README.md", "CONTRIBUTING.md", "SECURITY.md"]) if (existsSync(join(ROOT, f))) files.push(join(ROOT, f));
  for (const dir of [TS_PACKAGE, MCP_PACKAGE, PY_PACKAGE]) {
    const readme = join(dir, "README.md");
    if (!existsSync(readme)) fail(`${relative(ROOT, readme)} is missing`);
    files.push(readme);
  }
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.mdx?$/.test(e.name)) files.push(p);
    }
  };
  if (!existsSync(join(ROOT, "docs"))) fail("docs/ is missing");
  walk(join(ROOT, "docs"));
  walk(join(MCP_PACKAGE, "skills"));
  return files.sort();
}

/** Every fenced block of a Markdown file, with its info string and the line it opens on. */
function fences(file) {
  const lines = readFileSync(file, "utf8").split("\n");
  const found = [];
  let open = null;
  for (let i = 0; i < lines.length; i++) {
    const m = /^( {0,3})(`{3,})\s*([^`]*)$/.exec(lines[i]);
    if (open === null) {
      if (m !== null) open = { indent: m[1].length, ticks: m[2].length, info: m[3].trim(), line: i + 1, body: [] };
      continue;
    }
    if (m !== null && m[2].length >= open.ticks && m[3].trim() === "") {
      found.push({ info: open.info, line: open.line, text: `${open.body.join("\n")}\n` });
      open = null;
      continue;
    }
    open.body.push(open.indent > 0 ? lines[i].replace(new RegExp(`^ {0,${open.indent}}`), "") : lines[i]);
  }
  if (open !== null) fail(`${relative(ROOT, file)}:${open.line}: the fence is never closed`);
  return found;
}

const words = (info) => info.split(/\s+/).filter(Boolean);

/** The base tsconfig of the tree: the workspace's, wherever the terms folder sits. */
function baseTsconfig() {
  for (let dir = ROOT; ; dir = dirname(dir)) {
    const f = join(dir, "tsconfig.base.json");
    if (existsSync(f)) return f;
    if (dirname(dir) === dir) fail("no tsconfig.base.json above the terms folder");
  }
}

function checkSamples(only) {
  const samples = [];
  for (const file of only ?? markdownFiles()) {
    const blocks = fences(file);
    for (let i = 0; i < blocks.length; i++) {
      const b = blocks[i];
      const [lang, ...flags] = words(b.info);
      const where = `${relative(ROOT, file)}:${b.line}`;
      if (lang === "json") {
        try {
          JSON.parse(b.text);
        } catch (e) {
          fail(`${where}: the JSON does not parse: ${e.message}`);
        }
        samples.push({ where, kind: "json" });
        continue;
      }
      if (lang !== "ts" && lang !== "typescript" && lang !== "python") continue;
      const next = blocks[i + 1];
      const output = next !== undefined && words(next.info).join(" ") === "text output" ? next.text : undefined;
      const run = !flags.includes("no-run");
      if (!run && output !== undefined) fail(`${where}: a no-run sample is followed by an output block`);
      const slug = relative(ROOT, file).replace(/[/\\.]/g, "_");
      samples.push({ where, kind: lang === "python" ? "python" : "ts", text: b.text, run, output, slug: `${slug}__L${b.line}` });
    }
  }

  const ts = samples.filter((s) => s.kind === "ts");
  const py = samples.filter((s) => s.kind === "python");
  const dirs = new Map();
  for (const s of ts) {
    const dir = /["']@integraledger\/terms-mcp["']/.test(s.text) ? MCP_PACKAGE : TS_PACKAGE;
    s.dir = dir;
    s.file = join(dir, OUT, `${s.slug}.ts`);
    if (!dirs.has(dir)) dirs.set(dir, []);
    dirs.get(dir).push(s);
  }
  for (const [dir, group] of dirs) {
    const out = join(dir, OUT);
    rmSync(out, { recursive: true, force: true });
    mkdirSync(out, { recursive: true });
    for (const s of group) writeFileSync(s.file, s.text);
    writeFileSync(
      join(out, "tsconfig.json"),
      `${JSON.stringify(
        {
          extends: relative(out, baseTsconfig()),
          compilerOptions: { noEmit: true, lib: ["es2024", "dom"], types: ["node"] },
          include: ["*.ts"],
        },
        null,
        2,
      )}\n`,
    );
    const tsc = spawnSync("pnpm", ["exec", "tsc", "-p", join(OUT, "tsconfig.json")], { cwd: dir, encoding: "utf8" });
    if (tsc.status !== 0) {
      console.error(tsc.stdout, tsc.stderr);
      fail(`the TypeScript samples in ${relative(ROOT, dir)} do not type-check`);
    }
  }

  const pyOut = mkdtempSync(join(tmpdir(), "terms-docs-"));
  for (const s of py) {
    s.dir = PY_PACKAGE;
    s.file = join(pyOut, `${s.slug}.py`);
    writeFileSync(s.file, s.text);
  }
  if (py.length > 0) {
    const compiled = spawnSync("uv", ["run", "--locked", "--quiet", "python", "-m", "py_compile", ...py.map((s) => s.file)], {
      cwd: PY_PACKAGE,
      encoding: "utf8",
    });
    if (compiled.status !== 0) {
      console.error(compiled.stdout, compiled.stderr);
      fail("the Python samples do not compile");
    }
  }

  for (const s of [...ts, ...py]) {
    if (!s.run) {
      console.log(`compiled  ${s.where}`);
      continue;
    }
    const [cmd, args] =
      s.kind === "ts" ? ["node", [s.file]] : ["uv", ["run", "--locked", "--quiet", "python", s.file]];
    const r = spawnSync(cmd, args, { cwd: s.dir, encoding: "utf8", timeout: RUN_TIMEOUT_MS, stdio: ["ignore", "pipe", "pipe"] });
    if (r.status !== 0) {
      console.error(r.stdout, r.stderr, r.error ?? "");
      fail(`${s.where}: the sample exits ${r.status}`);
    }
    if (s.output !== undefined && r.stdout.trimEnd() !== s.output.trimEnd()) {
      console.error(`expected:\n${s.output}\nprinted:\n${r.stdout}`);
      fail(`${s.where}: the sample prints something other than the output shown after it`);
    }
    console.log(`ran       ${s.where}${s.output !== undefined ? " (output matches)" : ""}`);
  }
  const counted = (k) => samples.filter((s) => s.kind === k).length;
  return { ts: counted("ts"), python: counted("python"), json: counted("json") };
}

// ── Commands ─────────────────────────────────────────────────────────────────────────────────────────────────────

const command = process.argv[2];
if (command === "generate") {
  const { rows, files } = await generated();
  const written = [];
  for (const [file, text] of files) {
    if (!existsSync(dirname(file))) {
      console.log(`skipped ${relative(ROOT, file)}: ${relative(ROOT, dirname(file))}/ does not exist`);
      continue;
    }
    writeFileSync(file, text);
    written.push(relative(ROOT, file));
  }
  console.log(`${rows.length} pairings written to ${written.join(", ")}`);
} else if (command === "check" && process.argv.length > 3) {
  const n = checkSamples(process.argv.slice(3).map((f) => resolve(f)));
  console.log(`${n.ts} TypeScript, ${n.python} Python and ${n.json} JSON samples checked`);
} else if (command === "check") {
  const n = checkSamples();
  console.log(`${n.ts} TypeScript, ${n.python} Python and ${n.json} JSON samples checked`);
  const { rows, files } = await generated();
  for (const [file, text] of files) {
    if (!existsSync(file) || readFileSync(file, "utf8") !== text) {
      fail(`${relative(ROOT, file)} differs from the registries: run node scripts/docs.mjs generate`);
    }
  }
  const py = pythonPairings();
  const ids = rows.map((r) => r.id).sort();
  if (JSON.stringify(py.pieces) !== JSON.stringify(ids)) fail("the Python gate's buyer pieces are not the TypeScript gate's pairings");
  for (const r of rows) {
    if (py.names[r.py] !== r.id) fail(`the Python package exports no ${r.py} for ${r.id}`);
  }
  if (Object.keys(py.names).length !== rows.length) fail("the Python package exports a binding the tables do not list");
  console.log(`${rows.length} pairings: the tables match @integraledger/lcp's BINDINGS, the gate's pairings and the Python bindings`);
} else {
  fail("usage: node scripts/docs.mjs generate | check [file.md ...]");
}
