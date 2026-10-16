#!/usr/bin/env node
// Checks the headers of the responses worker.js returns. Cloudflare does not apply public/_headers to a response a
// Worker returns (https://developers.cloudflare.com/workers/static-assets/headers/), so worker.js sets them itself,
// from public/_headers through headers.mjs. The Worker runs in this process, with public/_headers loaded as the text
// module wrangler.toml's rule makes of it:
// - against an env.ASSETS whose responses carry no header, each kind of response the Worker returns (a page, the home
//   page, a HEAD request, a page's Markdown address, a page asked for as Markdown, a 304 for a copy the reader holds,
//   the 404 page for a page address and for a .md address, and a redirect) carries exactly the headers
//   public/_headers gives the request's path, besides the Worker's own `Vary: Accept` and the redirect's Location;
// - against an env.ASSETS whose responses already carry the headers public/_headers gives their own path, as the
//   static assets may give them, each of those headers carries public/_headers' value once;
// - scripts/check-live-headers.mjs passes against a server of out/ that answers as Cloudflare does (the static assets,
//   with public/_headers, for the files wrangler.toml serves directly, and worker.js for every other address), and
//   fails when that server drops one header.
//
// Usage, from website/, after `pnpm run build` there:
//   node scripts/check-worker.mjs
import { existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { registerHooks } from "node:module";
import { extname, join, resolve, sep } from "node:path";
import { headersFor, parseHeaders } from "../headers.mjs";
import { ADDRESSES, checkLiveHeaders } from "./check-live-headers.mjs";

// wrangler.toml's Text rule: an import of a file named _headers gives the file's text.
registerHooks({
  load(url, context, nextLoad) {
    if (!url.startsWith("file:") || !url.endsWith("/_headers")) return nextLoad(url, context);
    const text = readFileSync(new URL(url), "utf8");
    return { format: "module", source: `export default ${JSON.stringify(text)};`, shortCircuit: true };
  },
});
const worker = (await import("../worker.js")).default;
const RULES = parseHeaders(readFileSync("public/_headers", "utf8"));
const failures = [];

// A site of three pages, each with a Markdown copy. Bodies are bytes, so a Response adds no Content-Type of its own.
const PAGES = new Set(["/", "/getting-started", "/concepts"]);
const COPIES = new Set(["/md/index.md", "/md/getting-started.md", "/md/concepts.md"]);
const ETAG = '"copy"';
const bytes = (text) => new TextEncoder().encode(text);

/** env.ASSETS answering that site; with `applied`, each response carries the headers public/_headers gives its path. */
function mockAssets(applied) {
  return {
    async fetch(input) {
      const request = input instanceof Request ? input : new Request(input);
      const { pathname } = new URL(request.url);
      const headers = new Headers(applied ? headersFor(RULES, pathname) : []);
      const page = pathname.endsWith("/") ? pathname.slice(0, -1) : undefined;
      if (page !== undefined && page !== "" && PAGES.has(page)) {
        headers.set("Location", page);
        return new Response(null, { status: 307, headers });
      }
      if (PAGES.has(pathname)) return new Response(bytes("<!doctype html><title>page</title>"), { headers });
      if (COPIES.has(pathname)) {
        if (request.headers.get("if-none-match") === ETAG) return new Response(null, { status: 304, headers });
        return new Response(bytes("# Page\n"), { headers });
      }
      return new Response(bytes("<!doctype html><title>Page not found</title>"), { status: 404, headers });
    },
  };
}

/** Each kind of response the Worker returns: the request, its status, and whether it varies on Accept. */
const CASES = [
  ["/getting-started", { headers: { accept: "text/html" } }, 200, true],
  ["/", { headers: { accept: "text/html" } }, 200, true],
  ["/getting-started", { method: "HEAD" }, 200, true],
  ["/getting-started.md", {}, 200, false],
  ["/index.md", {}, 200, false],
  ["/concepts", { headers: { accept: "text/markdown" } }, 200, true],
  ["/getting-started.md", { headers: { "if-none-match": ETAG } }, 304, false],
  ["/no-such-page", {}, 404, true],
  ["/no-such-page.md", {}, 404, true],
  ["/getting-started/", {}, 307, true],
];

let compared = 0;
for (const applied of [false, true]) {
  const env = { ASSETS: mockAssets(applied) };
  const kind = applied ? "already carrying its headers" : "with no header";
  for (const [path, init, status, varies] of CASES) {
    const request = new Request(`https://site.test${path}`, init);
    const response = await worker.fetch(request, env);
    const label = `${request.method} ${path}${init.headers ? ` (${Object.entries(init.headers).map(([k, v]) => `${k}: ${v}`).join(", ")})` : ""}, from assets ${kind},`;
    if (response.status !== status) failures.push(`${label} answers ${response.status}, not ${status}`);
    const expected = headersFor(RULES, path);
    if (expected.length === 0) failures.push(`public/_headers gives ${path} no header`);
    for (const [name, value] of expected) {
      compared++;
      const held = response.headers.get(name);
      if (held !== value) failures.push(`${label} carries ${name}: ${held === null ? "nothing" : `"${held}"`}, not "${value}"`);
    }
    if (response.headers.get("vary") !== (varies ? "Accept" : null)) {
      failures.push(`${label} carries Vary: ${response.headers.get("vary")}, not ${varies ? "Accept" : "nothing"}`);
    }
    if (!applied) {
      const own = new Set(["vary", ...(status === 307 ? ["location"] : [])]);
      const given = new Set(expected.map(([name]) => name.toLowerCase()));
      for (const [name] of response.headers) {
        if (!given.has(name) && !own.has(name)) failures.push(`${label} carries ${name}, which public/_headers does not give it`);
      }
    }
  }
}

// The deployed site's check, against a server of out/ that answers as Cloudflare does.
const OUT = resolve("out");
const TYPES = { ".html": "text/html; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".svg": "image/svg+xml" };
const runFirst = [...(/run_worker_first\s*=\s*\[([\s\S]*?)\]/.exec(readFileSync("wrangler.toml", "utf8"))?.[1] ?? "").matchAll(/"([^"]+)"/g)].map(
  (m) => m[1],
);
const pattern = (p) => new RegExp(`^${p.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*")}$`);
const include = runFirst.filter((p) => !p.startsWith("!")).map(pattern);
const exclude = runFirst.filter((p) => p.startsWith("!")).map((p) => pattern(p.slice(1)));
const workerFirst = (path) => include.some((r) => r.test(path)) && !exclude.some((r) => r.test(path));
const isFile = (path) => existsSync(path) && statSync(path).isFile();

/** The static assets for one request: html_handling's page addresses, and not_found_handling's 404 page. */
function assetsFor(request, applyHeaders) {
  const { pathname } = new URL(request.url);
  const at = resolve(OUT, `.${decodeURIComponent(pathname)}`);
  const inside = at === OUT || at.startsWith(OUT + sep);
  const file = !inside
    ? undefined
    : [pathname === "/" ? join(OUT, "index.html") : undefined, pathname.endsWith(".html") ? undefined : at, `${at}.html`].find(
        (f) => f !== undefined && isFile(f),
      );
  const status = file === undefined ? 404 : 200;
  const served = file ?? join(OUT, "404.html");
  const headers = new Headers({ "content-type": TYPES[extname(served)] ?? "application/octet-stream" });
  if (applyHeaders) for (const [name, value] of headersFor(RULES, pathname)) headers.set(name, value);
  return new Response(request.method === "HEAD" ? null : readFileSync(served), { status, headers });
}

/** A server of out/: worker.js for the addresses wrangler.toml runs it first for, the static assets for the rest. */
async function serve(drop) {
  const env = { ASSETS: { fetch: async (input) => assetsFor(input instanceof Request ? input : new Request(input), false) } };
  const server = createServer(async (req, res) => {
    const request = new Request(new URL(req.url, "http://127.0.0.1"), { method: req.method, headers: req.headers });
    const { pathname } = new URL(request.url);
    const response = workerFirst(pathname) ? await worker.fetch(request, env) : assetsFor(request, true);
    const headers = Object.fromEntries([...response.headers].filter(([name]) => name !== drop));
    res.writeHead(response.status, headers).end(Buffer.from(await response.arrayBuffer()));
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  return { base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((done) => server.close(done)) };
}

if (!isFile(join(OUT, "404.html"))) {
  failures.push("out/ holds no 404.html: run pnpm run build in website/ first");
} else {
  const site = await serve(undefined);
  const live = await checkLiveHeaders(site.base, RULES).finally(site.close);
  for (const f of live.failures) failures.push(`check-live-headers, against out/ served as Cloudflare serves it: ${f}`);
  const dropped = await serve("x-frame-options");
  const red = await checkLiveHeaders(dropped.base, RULES).finally(dropped.close);
  if (!red.failures.some((f) => f.includes("carries no X-Frame-Options"))) {
    failures.push("check-live-headers passes against a server of out/ that drops X-Frame-Options");
  }
  compared += live.compared;
}

if (failures.length > 0) {
  for (const f of failures) console.log(f);
  process.exit(1);
}
console.log(
  `worker.js sets the headers public/_headers gives the request's path on each of ${CASES.length} kinds of response, ` +
    `once each, whether the assets answer with no header or with their own; check-live-headers.mjs passes on ` +
    `${ADDRESSES.length} addresses of out/ served as Cloudflare serves it, and fails when one header is dropped ` +
    `(${compared} headers compared)`,
);
