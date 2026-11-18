#!/usr/bin/env node
// Checks the deployed site's response headers, the step after each deploy: each response carries every header
// public/_headers gives its path, with the value public/_headers gives (headers.mjs), whether the static assets or
// worker.js answered it, and the Link worker.js adds after the rules' own. It requests these addresses, without
// following a redirect, and checks each status:
//   /getting-started      a page, as a browser asks for it; worker.js answers, naming its Markdown address (200)
//   /getting-started.md   the page as Markdown; worker.js answers with the page's copy, naming the page (200)
//   /icon.svg             a file that is not a page; the static assets serve it directly (200)
//   /no-such-page         an address no file has; worker.js answers with the site's 404 page (404)
//   /no-such-page.md      a .md address that names no page; worker.js answers in Markdown (404)
//
// Usage, from website/, with the address the site is deployed at:
//   node scripts/check-live-headers.mjs https://agenticterms.integraledger.com
import { readFileSync } from "node:fs";
import { headersFor, parseHeaders } from "../headers.mjs";

/** The site's canonical origin, `siteConfig.url` in src/lib/site.ts, which the Links worker.js adds name. */
export const ORIGIN = /^ {2}url: "([^"]+)"/m.exec(readFileSync(new URL("../src/lib/site.ts", import.meta.url), "utf8"))?.[1];
if (ORIGIN === undefined) throw new Error("src/lib/site.ts names no url");

/** The Link worker.js adds to a page's HTML: the page's Markdown address. */
export const alternateLink = (page) =>
  `<${ORIGIN}${page === "/" ? "/index.md" : `${page}.md`}>; rel="alternate"; type="text/markdown"`;
/** The Link worker.js adds to a page's Markdown at its .md address: the page. */
export const canonicalLink = (page) => `<${ORIGIN}${page === "/" ? "" : page}>; rel="canonical"`;

/** The headers public/_headers gives a path, with the Link worker.js adds after the rules' own. */
export function expectedHeaders(rules, path, link) {
  return headersFor(rules, path).map(([name, value]) =>
    link !== undefined && name.toLowerCase() === "link" ? [name, `${value}, ${link}`] : [name, value],
  );
}

/** The addresses requested, each with the status it answers with and the Link worker.js adds. */
export const ADDRESSES = [
  ["/getting-started", 200, alternateLink("/getting-started")],
  ["/getting-started.md", 200, canonicalLink("/getting-started")],
  ["/icon.svg", 200],
  ["/no-such-page", 404],
  ["/no-such-page.md", 404],
];

/** The headers public/_headers gives each address, compared with what `base` answers: the failures, and the count. */
export async function checkLiveHeaders(base, rules = parseHeaders(readFileSync(new URL("../public/_headers", import.meta.url), "utf8"))) {
  const failures = [];
  let compared = 0;
  for (const [path, status, link] of ADDRESSES) {
    const response = await fetch(new URL(path, base), {
      redirect: "manual",
      headers: { accept: "text/html,application/xhtml+xml,*/*;q=0.8" },
    });
    await response.arrayBuffer();
    if (response.status !== status) failures.push(`${path} answers ${response.status}, not ${status}`);
    const expected = expectedHeaders(rules, path, link);
    if (expected.length === 0) failures.push(`public/_headers gives ${path} no header`);
    for (const [name, value] of expected) {
      compared++;
      const held = response.headers.get(name);
      if (held === null) failures.push(`${path} carries no ${name}; public/_headers gives "${value}"`);
      else if (held !== value) failures.push(`${path} carries ${name}: "${held}"; public/_headers gives "${value}"`);
    }
  }
  return { failures, compared };
}

if (import.meta.main) {
  const base = process.argv[2];
  if (!base || !URL.canParse(base)) {
    console.error("usage: node scripts/check-live-headers.mjs <base-url>, the address the site is deployed at");
    process.exit(2);
  }
  const { failures, compared } = await checkLiveHeaders(base);
  if (failures.length > 0) {
    for (const f of failures) console.log(f);
    process.exit(1);
  }
  console.log(
    `${ADDRESSES.map(([path]) => path).join(", ")} at ${base} each carry the headers public/_headers gives their path, ` +
      `${compared} in all, with its values`,
  );
}
