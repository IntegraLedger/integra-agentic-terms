#!/usr/bin/env node
// Checks the deployed site's response headers, the step after each deploy: each response carries every header
// public/_headers gives its path, with the value public/_headers gives (headers.mjs), whether the static assets or
// worker.js answered it. It requests these addresses, without following a redirect, and checks each status:
//   /getting-started      a page, as a browser asks for it; worker.js answers (200)
//   /getting-started.md   the page as Markdown; worker.js answers with the page's copy (200)
//   /icon.svg             a file that is not a page; the static assets serve it directly (200)
//   /no-such-page         an address no file has; worker.js answers with the site's 404 page (404)
//
// Usage, from website/, with the address the site is deployed at:
//   node scripts/check-live-headers.mjs https://agenticterms.integraledger.com
import { readFileSync } from "node:fs";
import { headersFor, parseHeaders } from "../headers.mjs";

/** The addresses requested, each with the status it answers with. */
export const ADDRESSES = [
  ["/getting-started", 200],
  ["/getting-started.md", 200],
  ["/icon.svg", 200],
  ["/no-such-page", 404],
];

/** The headers public/_headers gives each address, compared with what `base` answers: the failures, and the count. */
export async function checkLiveHeaders(base, rules = parseHeaders(readFileSync(new URL("../public/_headers", import.meta.url), "utf8"))) {
  const failures = [];
  let compared = 0;
  for (const [path, status] of ADDRESSES) {
    const response = await fetch(new URL(path, base), {
      redirect: "manual",
      headers: { accept: "text/html,application/xhtml+xml,*/*;q=0.8" },
    });
    await response.arrayBuffer();
    if (response.status !== status) failures.push(`${path} answers ${response.status}, not ${status}`);
    const expected = headersFor(rules, path);
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
