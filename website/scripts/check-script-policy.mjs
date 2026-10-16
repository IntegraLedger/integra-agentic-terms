#!/usr/bin/env node
// Checks the script policy of every page of the built site, out/, as the pinned browser (scripts/browser.mjs) parses
// the page, so the pages are read by a browser's own HTML parser, not by the build step that writes the policies
// (scripts/script-policy.mjs):
// - each page holds one <meta http-equiv="Content-Security-Policy">, the first element of its <head> after the
//   character encoding declaration, whose policy is script-src with 'self' and SHA-256 sources alone;
// - those sources are the SHA-256 of each inline script the page holds that a policy governs (a classic or a module
//   script, an import map or speculation rules), every one of them and no other;
// - no page holds a script inside SVG or MathML, an event handler attribute or a javascript: URL, which a policy of
//   hashes refuses;
// - out/_headers, read as Cloudflare reads it (headers.mjs), keeps within Cloudflare's 100 rules and 2,000 characters
//   a line; every file of out/ that is not a page, and each page's Markdown address, takes a second policy of
//   default-src 'none' and script-src 'none', and no page address takes a policy that runs no script; every page
//   address takes frame-ancestors 'none';
// - every page, served with the headers out/_headers gives its address, loads with no policy violation and runs its
//   inline scripts, and an inline script added to it is refused; an inline script added to each SVG and XML file runs
//   when the file is opened as a document without those headers, and is refused with them, and each SVG file opens
//   with them with no violation. (Chrome shows an XML file in a viewer of its own, whose inline styles and data:
//   images both policies refuse.)
//
// Usage, from website/, after `pnpm run browser` and `pnpm run build` there:
//   node scripts/check-script-policy.mjs
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join, relative, sep } from "node:path";
import { chromium } from "playwright-core";
import { headersFor, parseHeaders } from "../headers.mjs";
import { browserExecutable } from "./browser.mjs";
import { governs, scriptHash } from "./script-policy.mjs";

const OUT = "out";
const HASH = /^'sha256-[A-Za-z0-9+/]{43}='$/;
/** ASCII lowercase, as a policy's directive names are compared. */
const lower = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

/** The files under a folder, in path order. */
function filesUnder(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? filesUnder(join(dir, e.name)) : [join(dir, e.name)]))
    .sort();
}

/** The address Cloudflare serves a file of out/ at: a page's without .html, and / for index.html. */
function addressOf(file) {
  const path = `/${relative(OUT, file).split(sep).join("/")}`;
  if (!path.endsWith(".html")) return path;
  return path === "/index.html" ? "/" : path.slice(0, -".html".length);
}

/** The policies a Content-Security-Policy value holds, each as its directives: a name and its sources. */
function policiesOf(value) {
  return (value ?? "")
    .split(",")
    .map((policy) => {
      const directives = new Map();
      for (const directive of policy.split(";")) {
        const [name, ...sources] = directive.trim().split(/[\t\n\f\r ]+/);
        if (name !== "" && !directives.has(lower(name))) directives.set(lower(name), sources);
      }
      return directives;
    })
    .filter((directives) => directives.size > 0);
}
/** Whether a policy runs no script: its script-src, or without one its default-src, is 'none'. */
const runsNoScript = (policy) => (policy.get("script-src") ?? policy.get("default-src"))?.join(" ") === "'none'";
/** Whether a policy loads nothing and runs no script. */
const strict = (policy) => policy.get("default-src")?.join(" ") === "'none'" && runsNoScript(policy);

/** What the browser reads in one page: its policies, its scripts, its event handler attributes and javascript: URLs. */
function read(html) {
  const XHTML = "http://www.w3.org/1999/xhtml";
  const lower = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());
  const doc = new DOMParser().parseFromString(html, "text/html");
  // The character encoding declaration, when the head holds one, is its first element, so the policy that follows it
  // keeps it within the first 1,024 bytes.
  const children = [...doc.head.children];
  const charset = children.findIndex((e) => e.localName === "meta" && e.hasAttribute("charset"));
  const first = charset <= 0 ? children[charset + 1] : undefined;
  const policies = [...doc.querySelectorAll("meta")]
    .filter((e) => e.namespaceURI === XHTML && lower(e.getAttribute("http-equiv") ?? "") === "content-security-policy")
    .map((e) => ({ content: e.getAttribute("content"), inHead: e.parentElement === doc.head, first: e === first }));
  const scripts = [...doc.querySelectorAll("script")].map((e) => ({
    html: e.namespaceURI === XHTML,
    src: e.hasAttribute("src"),
    type: e.getAttribute("type"),
    language: e.getAttribute("language"),
    text: e.namespaceURI === XHTML ? e.text : e.textContent,
  }));
  const handlers = [];
  const urls = [];
  for (const e of doc.querySelectorAll("*")) {
    for (const a of e.attributes) {
      if (lower(a.name).startsWith("on")) handlers.push(`<${e.localName} ${a.name}>`);
      const url = a.value.replace(/^[\0- ]+|[\0- ]+$/g, "").replace(/[\t\n\r]/g, "");
      if (/^(href|src|action|formaction|xlink:href)$/.test(lower(a.name)) && /^javascript:/i.test(url)) {
        urls.push(`<${e.localName} ${a.name}>`);
      }
    }
  }
  return { policies, scripts, handlers, urls };
}

const everything = filesUnder(OUT);
const files = everything.filter((f) => f.endsWith(".html"));
if (files.length === 0) {
  console.error(`${OUT}/ holds no HTML page: run pnpm run build in website/ first`);
  process.exit(1);
}

// out/_headers: Cloudflare's limits, and which addresses take the policy that runs no script.
const failures = [];
const headersText = readFileSync(join(OUT, "_headers"), "utf8");
const lines = headersText.split("\n");
let rules = [];
try {
  rules = parseHeaders(headersText);
} catch (error) {
  failures.push(`out/${error.message}`);
}
if (rules.length > 100) failures.push(`out/_headers holds ${rules.length} rules, and Cloudflare reads 100 at most`);
for (const [index, line] of lines.entries()) {
  if (line.length > 2000) failures.push(`out/_headers line ${index + 1} is ${line.length} characters long, and Cloudflare reads 2,000 at most`);
}
/** An address no file has, which the 404 page answers. */
const NOWHERE = "/no-such-page";
const policy = (address) => policiesOf(headersFor(rules, address).find(([name]) => lower(name) === "content-security-policy")?.[1]);
const pageAddresses = [...files.map(addressOf), NOWHERE];
const markdownAddresses = files
  .map(addressOf)
  .filter((a) => existsSync(join(OUT, "md", a === "/" ? "index.md" : `${a.slice(1)}.md`)))
  .map((a) => (a === "/" ? "/index.md" : `${a}.md`));
const otherAddresses = everything.filter((f) => !f.endsWith(".html") && f !== join(OUT, "_headers")).map(addressOf);
if (rules.length > 0) {
  for (const address of [...otherAddresses, ...markdownAddresses]) {
    if (!policy(address).some(strict)) {
      failures.push(`${address} is not a page, and out/_headers gives it no policy of default-src 'none' and script-src 'none'`);
    }
  }
  for (const address of pageAddresses) {
    if (policy(address).some(runsNoScript)) failures.push(`${address} is a page address, and out/_headers gives it a policy that runs no script`);
    if (!policy(address).some((p) => p.get("frame-ancestors")?.join(" ") === "'none'")) {
      failures.push(`${address} is a page address, and out/_headers gives it no frame-ancestors 'none'`);
    }
  }
}

// Each page and each SVG and XML file of out/, served at https://site.test with the headers out/_headers gives each
// address (or none), and with an inline script added or not.
const ORIGIN = "https://site.test";
const TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json",
  ".md": "text/markdown; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".txt": "text/plain; charset=utf-8",
  ".webmanifest": "application/manifest+json",
  ".woff2": "font/woff2",
  ".xml": "application/xml",
};
const PLANT = "<script>window.__planted = 1</script>";
const DOCUMENT_PLANT = '<script xmlns="http://www.w3.org/1999/xhtml">window.__planted = 1</script>';
const documents = everything.filter((f) => /\.(svg|xml)$/.test(f));
/** What the next load is served: with or without the headers, and the address whose body holds an added script. */
let serving = { headers: true, planted: undefined, body: undefined };

/** The file of out/ that answers an address, and its status, as the static assets answer it. */
function answer(address) {
  const path = join(OUT, decodeURIComponent(address));
  const found = (address === "/" ? [join(OUT, "index.html")] : [path, `${path}.html`]).find(
    (f) => f.startsWith(`${OUT}${sep}`) && existsSync(f) && statSync(f).isFile(),
  );
  return found === undefined ? [404, join(OUT, "404.html")] : [200, found];
}

/** Loads an address in a tab: its status, whether the added script ran, its violations and whether Next.js's ran. */
async function load(tab, address, { headers = true, body } = {}) {
  serving = { headers, planted: body === undefined ? undefined : address, body };
  const response = await tab.goto(`${ORIGIN}${address}`, { waitUntil: "load" });
  const seen = await tab.evaluate(() => ({
    planted: window.__planted === 1,
    violations: window.__violations ?? [],
    inline: Array.isArray(self.__next_f),
  }));
  return { status: response?.status(), ...seen };
}

const pages = [];
let loads = 0;
const dir = await mkdtemp(join(tmpdir(), "check-script-policy-"));
try {
  const context = await chromium.launchPersistentContext(join(dir, "profile"), {
    executablePath: browserExecutable(),
    headless: true,
    artifactsDir: dir,
    env: { HOME: dir, TMPDIR: dir },
  });
  try {
    const tab = await context.newPage();
    for (const file of files) pages.push({ page: relative(OUT, file), ...(await tab.evaluate(read, readFileSync(file, "utf8"))) });
    if (rules.length > 0) {
      await context.addInitScript(() => {
        window.__violations = [];
        document.addEventListener("securitypolicyviolation", (e) => window.__violations.push(`${e.violatedDirective} ${e.blockedURI}`));
      });
      await context.route(`${ORIGIN}/**`, async (route) => {
        const address = new URL(route.request().url()).pathname;
        const [status, file] = answer(address);
        const headers = { "content-type": TYPES[extname(file)] ?? "application/octet-stream" };
        if (serving.headers) for (const [name, value] of headersFor(rules, address)) headers[lower(name)] = value;
        await route.fulfill({ status, headers, body: address === serving.planted ? serving.body : readFileSync(file) });
      });
      const view = await context.newPage();
      for (const file of files) {
        const address = addressOf(file);
        const html = readFileSync(file, "utf8");
        const plain = await load(view, address);
        const planted = await load(view, address, { body: html.replace(/<\/body>/i, `${PLANT}$&`) });
        loads += 2;
        if (plain.violations.length > 0) failures.push(`${address} loads with policy violations: ${plain.violations.join("; ")}`);
        if (!plain.inline) failures.push(`${address} loads without running its inline scripts`);
        if (planted.planted || !planted.violations.some((v) => v.startsWith("script-src") && v.endsWith(" inline"))) {
          failures.push(`${address} runs an inline script added to it, or refuses it without a violation`);
        }
      }
      for (const file of documents) {
        const address = addressOf(file);
        const text = readFileSync(file, "utf8");
        const body = text.replace(/<\/[^<]*$/, `${DOCUMENT_PLANT}$&`);
        const bare = await load(view, address, { headers: false, body });
        const planted = await load(view, address, { body });
        loads += 2;
        if (!bare.planted) failures.push(`an inline script added to ${address} does not run without its headers, so it proves nothing`);
        if (planted.planted || planted.violations.length === 0) failures.push(`${address}, opened as a document, runs an inline script added to it`);
        if (file.endsWith(".svg")) {
          const plain = await load(view, address);
          loads++;
          if (plain.violations.length > 0) failures.push(`${address}, opened as a document, has policy violations: ${plain.violations.join("; ")}`);
        }
      }
    }
  } finally {
    await context.close();
  }
} finally {
  await rm(dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 1000 });
}

let count = 0;
for (const { page, policies, scripts, handlers, urls } of pages) {
  const held = new Set();
  for (const s of scripts) {
    if (!s.html) failures.push(`${page} holds a script inside SVG or MathML`);
    else if (!s.src && governs(s.type, s.language)) {
      held.add(scriptHash(s.text));
      count++;
    }
  }
  for (const h of handlers) failures.push(`${page} holds an event handler attribute, ${h}`);
  for (const u of urls) failures.push(`${page} holds a javascript: URL, ${u}`);
  if (policies.length !== 1) {
    failures.push(`${page} holds ${policies.length === 0 ? "no script policy" : `${policies.length} script policies`}`);
    continue;
  }
  const [{ content, inHead, first }] = policies;
  if (!inHead || !first) {
    failures.push(`${page}'s script policy is not the first element of its <head> after the character encoding declaration`);
  }
  const directives = (content ?? "")
    .split(";")
    .map((d) => d.trim())
    .filter((d) => d !== "");
  const [name, ...sources] = directives[0]?.split(/[\t\n\f\r ]+/) ?? [];
  if (directives.length !== 1 || lower(name ?? "") !== "script-src") {
    failures.push(`${page}'s script policy is not one script-src directive: "${content}"`);
    continue;
  }
  if (!sources.includes("'self'")) failures.push(`${page}'s script policy does not name 'self'`);
  for (const s of sources) {
    if (s !== "'self'" && !HASH.test(s)) failures.push(`${page}'s script policy names ${s}, neither 'self' nor a SHA-256`);
  }
  const named = new Set(sources.filter((s) => HASH.test(s)));
  const missing = [...held].filter((h) => !named.has(h));
  const extra = [...named].filter((h) => !held.has(h));
  if (missing.length > 0) failures.push(`${page}'s script policy does not name ${missing.length} of its inline scripts: ${missing.join(" ")}`);
  if (extra.length > 0) {
    const sources = extra.length === 1 ? "a source" : `${extra.length} sources`;
    failures.push(`${page}'s script policy names ${sources} no inline script of the page has: ${extra.join(" ")}`);
  }
}

if (failures.length > 0) {
  for (const f of failures) console.log(f);
  process.exit(1);
}
console.log(
  `${pages.length} pages each hold one script policy, the first element of the head after the character encoding ` +
    `declaration, that names 'self' and the SHA-256 of each of their ${count} inline scripts and nothing else; ` +
    "no page holds an event handler attribute or a javascript: URL",
);
console.log(
  `out/_headers holds ${rules.length} rules, of Cloudflare's 100, and its longest line is ` +
    `${Math.max(...lines.map((l) => l.length))} characters, of 2,000; ${otherAddresses.length} files that are not ` +
    `pages and ${markdownAddresses.length} Markdown addresses each take default-src 'none' and script-src 'none', and ` +
    `none of ${pageAddresses.length} page addresses takes a policy that runs no script`,
);
console.log(
  `${pages.length} pages load with their headers with no policy violation and run their inline scripts, and refuse ` +
    `an inline script added to them; an inline script added to each of ${documents.length} SVG and XML files runs ` +
    `without their headers and is refused with them (${loads} loads)`,
);
