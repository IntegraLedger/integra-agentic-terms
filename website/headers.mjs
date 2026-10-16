// The response headers public/_headers gives a path, read as Cloudflare reads that file
// (https://developers.cloudflare.com/workers/static-assets/headers/): a rule is a path pattern followed by indented
// `Name: value` lines; a request takes the headers of every rule whose pattern matches its path, and a header that
// more than one rule sets takes their values joined by a comma. A pattern matches the whole path: its one splat (*)
// matches any characters, and a placeholder (:name) any characters but "/".
//
// worker.js sets these headers on every response it returns, and the site's checks compare responses with them, so
// public/_headers is their one source. The reader stops, naming the line, at what it would read otherwise than
// Cloudflare: a line that detaches a header (`! Name`), since the documentation does not order a detach against the
// rules that set the header; a pattern that is an absolute URL or holds more than one splat; and a value that names
// its rule's splat or a placeholder, which Cloudflare fills in.

/** The rules of a `_headers` file, in file order: each pattern, its regular expression and its `[name, value]` pairs. */
export function parseHeaders(text) {
  const rules = [];
  for (const [index, line] of text.split("\n").entries()) {
    const at = `_headers line ${index + 1}`;
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      if (!trimmed.startsWith("/")) throw new Error(`${at}: the pattern ${trimmed} is not a path`);
      if (trimmed.split("*").length > 2) throw new Error(`${at}: the pattern ${trimmed} holds more than one splat`);
      const names = [...trimmed.matchAll(/:([A-Za-z]\w*)/g)].map((m) => m[1]);
      const source = trimmed
        .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
        .replace("*", ".*")
        .replace(/:[A-Za-z]\w*/g, "[^/]+");
      rules.push({ pattern: trimmed, match: new RegExp(`^${source}$`), names, headers: [] });
      continue;
    }
    const rule = rules.at(-1);
    if (rule === undefined) throw new Error(`${at}: a header comes before any path pattern`);
    if (trimmed.startsWith("!")) throw new Error(`${at}: ${trimmed} detaches a header`);
    const colon = trimmed.indexOf(":");
    if (colon <= 0) throw new Error(`${at}: ${trimmed} is not a "Name: value" header`);
    const name = trimmed.slice(0, colon).trim();
    const value = trimmed.slice(colon + 1).trim();
    for (const placeholder of rule.pattern.includes("*") ? ["splat", ...rule.names] : rule.names) {
      if (new RegExp(`:${placeholder}(?!\\w)`).test(value)) throw new Error(`${at}: ${name}'s value names :${placeholder}`);
    }
    rule.headers.push([name, value]);
  }
  return rules;
}

/**
 * The headers the rules give a path, as `[name, value]` pairs: each header once, named as its first rule writes it,
 * with the values of every rule that sets it joined by ", ", in file order.
 */
export function headersFor(rules, pathname) {
  const headers = new Map();
  for (const rule of rules) {
    if (!rule.match.test(pathname)) continue;
    for (const [name, value] of rule.headers) {
      const key = name.toLowerCase();
      const held = headers.get(key);
      headers.set(key, held === undefined ? [name, value] : [held[0], `${held[1]}, ${value}`]);
    }
  }
  return [...headers.values()];
}
