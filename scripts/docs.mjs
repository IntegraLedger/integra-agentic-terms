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
  "x402/exact/eip155/gateway-batched": "EVM",
  "mpp/session/evm": "EVM",
  "spend-permissions/eip155": "EVM",
  "mpp/charge/tempo/split-memo": "Tempo",
  "mpp/charge/tempo/split-memo/push": "Tempo",
  "mpp/session/tempo": "Tempo",
  "mpp/subscription/tempo": "Tempo",
  "x402/exact/solana": "Solana",
  "x402/upto/solana": "Solana",
  "x402/batch-settlement/solana": "Solana",
  "mpp/charge/solana": "Solana",
  "mpp/charge/solana/unsponsored": "Solana",
  "mpp/charge/usdc/solana": "Solana",
  "mpp/subscription/solana": "Solana",
  "mpp/session/solana/memo": "Solana",
  "mpp/session/solana/stock": "Solana",
  "x402/exact/stellar/precondition": "Stellar",
  "x402/exact/xrpl": "XRP Ledger",
  "x402/upto/xrpl": "XRP Ledger",
  "mpp/charge/xrpl": "XRP Ledger",
  "mpp/session/xrpl": "XRP Ledger",
  "mpp/session/xrpl/stock": "XRP Ledger",
  "x402/exact/hedera": "Hedera",
  "x402/exact/hedera/transfer-executor": "Hedera",
  "mpp/charge/lcp/hedera": "Hedera",
  "mpp/session/hedera/stock": "Hedera",
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
  "x402/exact/cardano/lock": "Cardano",
  "x402/exact/casper": "Casper",
  "x402/exact/ccd": "Concordium",
  "mpp/charge/usdc/stacks": "Stacks",
  "x402/exact/lnbtc/payment-hash": "Lightning",
  "mpp/charge/lightning": "Lightning",
  "mpp/session/lightning": "Lightning",
  "x402/batch-settlement/cloudflare": "Cloudflare",
  "card/visa-tap": "Card",
  "card/visa-vic": "Card",
  "card/mastercard-agent-pay": "Card",
  "card/mastercard-vi/immediate": "Card",
  "card/mastercard-vi/autonomous": "Card",
  "card/seller-reference": "Card",
  "mpp/charge/card": "Card",
  "mpp/charge/stripe": "Stripe",
  "mpp/subscription/stripe": "Stripe",
  "ap2/checkout-mandate": "Mandate",
  "ap2/checkout-mandate/x402": "Mandate",
  "ucp/checkout/ap2-mandate": "Mandate",
  "ucp/checkout/unsigned": "Checkout",
  "ucp/checkout/agent-signed": "Checkout",
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

/** Every pairing of @integraledger/lcp's registry, with its registry data, its export and whether the gate serves it. */
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
      if (value === null || typeof value !== "object" || typeof value.id !== "string" || value.data === undefined) continue;
      if (!exported.has(value.id)) exported.set(value.id, { from: `@integraledger/lcp${subpath.slice(1)}`, name });
    }
  }

  const rows = lcp.BINDINGS.map((b) => {
    const rail = RAILS[b.id];
    if (rail === undefined) fail(`${b.id} has no rail in scripts/docs.mjs`);
    const ts = exported.get(b.id);
    if (ts === undefined) fail(`${b.id} is exported by no entry point of @integraledger/lcp`);
    if (!PIECES.has(b.id)) fail(`${b.id} is in BINDINGS and the gate has no buyer piece for it`);
    if (b.data.coverage !== "full" && b.data.coverage !== "none") fail(`${b.id} states no coverage in its registry data`);
    return { id: b.id, rail, data: b.data, ts, py: pythonName(b.id) };
  });
  for (const id of PIECES.keys()) {
    if (!rows.some((r) => r.id === id)) fail(`the gate has a buyer piece for ${id}, which is not in BINDINGS`);
  }
  rows.sort((a, b) => RAIL_ORDER.indexOf(a.rail) - RAIL_ORDER.indexOf(b.rail) || a.id.localeCompare(b.id));
  return rows;
}

/** Whether the pairing is paid after an agreement payment, and on which network that agreement may be (`agreementOn`). */
function agreementFirst(data) {
  if (data.coverage === "full") return "no";
  const on = data.agreementOn ?? "any";
  if (on === "any") return "yes, any network";
  if (on === "same-network") return "yes, its network";
  return `yes, \`${on}\``;
}

/**
 * What the gate does with the pairing's payment as an agreement: `only` where the registry data's agreement is never a
 * charge (`agreement.only`); `yes` where the gate pays, through the pairing, the agreement payment another pairing
 * follows, which it does only on an x402 pairing at coverage `full` whose data holds `agreement` (`X402` and
 * `isAgreementPairing` in agentic-terms/src/agreement.ts, `_x402_bindings` in the Python package); `no` otherwise, an
 * MPP pairing whose data holds `agreement` among them.
 */
function paysAgreement(r) {
  const agreement = r.data.agreement;
  if (agreement === undefined) return "no";
  if (agreement.only === true) return "only";
  return r.id.startsWith("x402/") && r.data.coverage === "full" ? "yes" : "no";
}

/** Whether something outside the protocol package has shown the pairing's form as its profile defines it. */
function confirmed(data) {
  if (data.confirmed !== "yes" && data.confirmed !== "no") fail(`a pairing states no confirmed value: ${data.confirmed}`);
  return data.confirmed;
}

/** Prose as Markdown that MDX also reads: `<`, `{` and `}` escaped. */
const mdx = (text) => text.replace(/[<{}]/g, (c) => `\\${c}`);

/**
 * The table a README carries: every pairing, with its coverage, whether it is confirmed, whether an agreement comes
 * first, and whether the gate pays one through it.
 */
function readmeTable(rows, language) {
  const name = language === "python" ? "Python binding" : language === "mcp" ? "`pairing` argument" : "Binding export";
  const lines = [
    `| Rail | Pairing | ${name} | Coverage | Confirmed | Agreement payment first | Pays an agreement |`,
    "| --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const r of rows) {
    const binding =
      language === "python" ? `\`${r.py}\`` : language === "mcp" ? `\`"${r.id}"\`` : `\`${r.ts.name}\` from \`${r.ts.from}\``;
    lines.push(
      `| ${r.rail} | \`${r.id}\` | ${binding} | ${r.data.coverage} | ${confirmed(r.data)} | ${agreementFirst(r.data)} | ${paysAgreement(r)} |`,
    );
  }
  return `${lines.join("\n")}\n`;
}

/** The reference page: every pairing with its coverage, its agreement, its imports and what its payment proves. */
function referencePage(rows) {
  const out = [
    "---",
    "title: Pairings",
    "description: Every pairing the gate pays, with its coverage, whether it is confirmed, its agreement, its imports in each language, and what its payment proves.",
    "---",
    "",
    `The gate serves ${rows.length} pairings, in TypeScript and in Python alike. This page is generated from the code:`,
    "`node scripts/docs.mjs generate` writes it from `BINDINGS` in `@integraledger/lcp` and the pairings the gate serves,",
    "and `node scripts/docs.mjs check` fails when it differs from them or from the Python package's bindings.",
    "",
    "Columns, each read from the pairing's registry data (`data`) in `@integraledger/lcp`, and the last also from the",
    "gate's own rule:",
    "",
    "- **Coverage**: `full` where the payment is itself a public proof of H, the payer's own signed act on a public",
    "  ledger binding all of H; `none` otherwise (see [Concepts](../concepts.md#coverage)).",
    "- **Confirmed**: `yes` where something outside the protocol package has shown the form as its profile defines it",
    "  (`confirmed`); `no` otherwise. The gate builds and reads a pairing at `no` exactly as its profile defines it,",
    "  though nothing outside the protocol package has yet shown that form.",
    "- **Agreement payment first**: whether the gate pays the seller's agreement payment before this payment, and on",
    "  which network that agreement may be (`agreementOn`): any network, or only the payment's own (see",
    "  [Agreement payments](../guides/agreement-payments.md)).",
    "- **Pays an agreement**: what the gate does with this pairing's payment as an agreement. `yes`: the gate pays,",
    "  through this pairing, the agreement payment another pairing follows (`transact` and `agree`), and the payment can",
    "  also be a charge; these are x402 pairings whose registry data holds an agreement form (`agreement`). `only`: the",
    "  payment is never a charge, only an agreement (`agreement.only`): `transact` declines it as a charge, the approver",
    "  is asked about each of its signings as the act `agreement`, and on an x402 pairing the gate pays it as the",
    "  agreement another pairing follows.",
    "  `no`: the gate pays no agreement through it. The gate pays an agreement only through x402 pairings: an MPP pairing",
    "  whose registry data holds `agreement` reads `no`, and the gate returns the seller's MPP agreement challenges as",
    "  `agreementChallenges`, for your own MPP client to pay.",
    "",
    "Below each table, every pairing's statement of what its payment proves, as its registry data states it",
    "(`data.proves`). Where a statement names `<network>` and `<transaction>`, they stand for the agreement payment's",
    "network and transaction.",
    "",
  ];
  for (const rail of RAIL_ORDER) {
    const group = rows.filter((r) => r.rail === rail);
    if (group.length === 0) continue;
    out.push(`## ${rail}`, "");
    out.push("| Pairing | Coverage | Confirmed | Agreement payment first | Pays an agreement | TypeScript | Python |");
    out.push("| --- | --- | --- | --- | --- | --- | --- |");
    for (const r of group) {
      out.push(
        `| \`${r.id}\` | ${r.data.coverage} | ${confirmed(r.data)} | ${agreementFirst(r.data)} | ${paysAgreement(r)} | \`${r.ts.name}\` from \`${r.ts.from}\` | \`${r.py}\` |`,
      );
    }
    out.push("");
    for (const r of group) {
      out.push(`**\`${r.id}\`**: ${mdx(r.data.proves)}`, "");
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
    "names = {n: getattr(t, n).id for n in t.__all__ if n.isupper() and n not in ('MAX_ATR_BYTES', 'FLOOR_INPUTS')}",
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
