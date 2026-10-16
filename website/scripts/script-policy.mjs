#!/usr/bin/env node
// Writes each exported page's own script policy. A static export carries no nonce, and the inline scripts of one page
// (the Next.js payload and the theme script) take thousands of characters to name, past the 2,000 a line of
// public/_headers may hold. So every HTML page of out/ gets a <meta http-equiv="Content-Security-Policy"> as the first
// element of its <head> after the character encoding declaration, ahead of every script, with one directive:
// script-src 'self' and the SHA-256 of each inline script the page holds, in the page's order. The browser applies
// this policy and the one public/_headers sets together, so an inline script runs only when its page's policy names it.
//
// The step reads and writes out/ alone, and one export gives one result, so two builds of one commit are byte-equal.
// It reads a page as the HTML standard's tokenizer does, as far as the pages need, and stops the build, naming the page,
// at what it does not read: a page that is not UTF-8, has no <head> start tag or holds a Content-Security-Policy meta
// element; a script before the <head> start tag, or inside SVG, MathML, a template or a noscript element; a script
// whose text holds "<!--" or a NUL, or whose type or language attribute holds a character reference; a style, title,
// textarea or other text element inside SVG or MathML whose text holds "<".
// scripts/check-script-policy.mjs checks the pages it writes, as the pinned browser reads them.
//
// Usage, from website/, after `next build` there (the `build` script runs it):
//   node scripts/script-policy.mjs
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

/** The JavaScript MIME type essences (WHATWG MIME Sniffing, "JavaScript MIME type"). */
const JAVASCRIPT_TYPES = new Set([
  "application/ecmascript",
  "application/javascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/javascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
]);

/** ASCII lowercase, as the HTML standard compares names and types. */
const lower = (s) => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

/**
 * Whether an inline script element is one a content policy governs, from its type and language attributes (`null`
 * when absent), as the HTML standard's "prepare the script element" reads them: a classic or a module script, an
 * import map or speculation rules. Any other type is a data block, such as a page's JSON-LD, which the browser
 * neither runs nor checks against a policy.
 */
export function governs(type, language) {
  const string =
    type === "" || (type === null && !language)
      ? "text/javascript"
      : type !== null
        ? type.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, "")
        : `text/${language}`;
  const kind = lower(string);
  return JAVASCRIPT_TYPES.has(kind) || kind === "module" || kind === "importmap" || kind === "speculationrules";
}

/** A script's SHA-256 source, over its text as the browser holds it: UTF-8, each CR or CR LF read as LF. */
export function scriptHash(text) {
  return `'sha256-${createHash("sha256").update(text.replace(/\r\n?/g, "\n"), "utf8").digest("base64")}'`;
}

const DELIMITER = /[\t\n\f\r />]/;
const SPACE = /[\t\n\f\r ]/;
/** The elements whose content is text up to their end tag (RAWTEXT and RCDATA). */
const TEXT_ELEMENTS = new Set(["style", "xmp", "iframe", "noembed", "noframes", "textarea", "title"]);

/** The index of the end tag `</name` that closes a text element's content from `from`, or the page's end. */
function endTag(html, name, from) {
  const re = new RegExp(`</${name}[\\t\\n\\f\\r />]`, "gi");
  re.lastIndex = from;
  return re.exec(html)?.index ?? html.length;
}

/** A tag's attributes, from the end of its name: the index past its `>`, the attributes and whether it ends in `/>`. */
function attributes(html, at) {
  const found = new Map();
  let i = at;
  let selfClosing = false;
  for (;;) {
    while (i < html.length && (SPACE.test(html[i]) || html[i] === "/")) selfClosing = html[i++] === "/";
    if (i >= html.length) return undefined;
    if (html[i] === ">") return { end: i + 1, attrs: found, selfClosing };
    selfClosing = false;
    let j = i + 1;
    while (j < html.length && !/[\t\n\f\r />=]/.test(html[j])) j++;
    const name = lower(html.slice(i, j));
    i = j;
    while (i < html.length && SPACE.test(html[i])) i++;
    let value = "";
    if (html[i] === "=") {
      i++;
      while (i < html.length && SPACE.test(html[i])) i++;
      const quote = html[i];
      if (quote === '"' || quote === "'") {
        const close = html.indexOf(quote, i + 1);
        if (close < 0) return undefined;
        value = html.slice(i + 1, close);
        i = close + 1;
      } else {
        let k = i;
        while (k < html.length && !/[\t\n\f\r >]/.test(html[k])) k++;
        value = html.slice(i, k);
        i = k;
      }
    }
    if (!found.has(name)) found.set(name, value);
  }
}

/**
 * Reads a page: where its policy goes (after the <head> start tag, and after a <meta charset> that is the head's first
 * element) and the text of each inline script a policy governs, in the page's order. Throws, naming the page, at what
 * it does not read (above).
 */
export function readPage(html, page) {
  const fail = (what) => {
    throw new Error(`${page} ${what}, which scripts/script-policy.mjs does not read`);
  };
  const scripts = [];
  let at = -1;
  let afterHead = false;
  let foreign = 0;
  let template = 0;
  let i = 0;
  while (i < html.length) {
    i = html.indexOf("<", i);
    if (i < 0) break;
    if (html.startsWith("<!--", i)) {
      // A comment ends at "-->" or "--!>"; "<!-->" and "<!--->" end where they stand.
      if (html.startsWith(">", i + 4)) i += 5;
      else if (html.startsWith("->", i + 4)) i += 6;
      else {
        const close = /--!?>/g;
        close.lastIndex = i + 4;
        const found = close.exec(html);
        i = found ? found.index + found[0].length : html.length;
      }
      continue;
    }
    if (foreign > 0 && html.startsWith("<![CDATA[", i)) {
      const close = html.indexOf("]]>", i + 9);
      i = close < 0 ? html.length : close + 3;
      continue;
    }
    if (html[i + 1] === "!" || html[i + 1] === "?") {
      const close = html.indexOf(">", i + 2);
      i = close < 0 ? html.length : close + 1;
      continue;
    }
    const isEnd = html[i + 1] === "/";
    const nameAt = i + (isEnd ? 2 : 1);
    if (!/[A-Za-z]/.test(html[nameAt] ?? "")) {
      if (!isEnd) i++;
      else if (html[nameAt] === ">") i = nameAt + 1;
      else {
        const close = html.indexOf(">", nameAt);
        i = close < 0 ? html.length : close + 1;
      }
      continue;
    }
    let n = nameAt;
    while (n < html.length && !DELIMITER.test(html[n])) n++;
    const name = lower(html.slice(nameAt, n));
    const tag = attributes(html, n);
    if (!tag) fail(`has a <${name}> tag that does not end`);
    i = tag.end;
    if (isEnd) {
      if (name === "svg" || name === "math") foreign = Math.max(0, foreign - 1);
      if (name === "template") template = Math.max(0, template - 1);
      continue;
    }
    if (afterHead) {
      afterHead = false;
      if (name === "meta" && tag.attrs.has("charset")) at = tag.end;
    }
    if (name === "script") {
      if (at < 0) fail("has a script before its <head> start tag");
      if (foreign > 0) fail("has a script inside SVG or MathML");
      if (template > 0) fail("has a script inside a template element");
      const close = endTag(html, "script", tag.end);
      const text = html.slice(tag.end, close);
      if (text.includes("<!--")) fail('has a script whose text holds "<!--"');
      if (text.includes("\0")) fail("has a script whose text holds a NUL character");
      i = close;
      if (tag.attrs.has("src")) continue;
      const type = tag.attrs.get("type") ?? null;
      const language = tag.attrs.get("language") ?? null;
      if (`${type ?? ""}${language ?? ""}`.includes("&")) fail("has a script whose type or language holds a character reference");
      if (governs(type, language)) scripts.push(text);
      continue;
    }
    if (foreign > 0 && (TEXT_ELEMENTS.has(name) || name === "noscript" || name === "plaintext")) {
      // Inside SVG or MathML, such an element holds markup, but past an element that ends foreign content, or inside
      // foreignObject or an SVG title, the browser reads its content as text. With no "<" in it, the two readings agree.
      const text = html.slice(tag.end, endTag(html, name, tag.end));
      if (name === "plaintext" || text.includes("<")) fail(`has a <${name}> inside SVG or MathML whose text holds "<"`);
    }
    if (name === "svg" || name === "math") {
      if (!tag.selfClosing) foreign++;
      continue;
    }
    if (foreign > 0) continue;
    if (name === "head" && at < 0) {
      at = tag.end;
      afterHead = true;
    } else if (name === "meta" && lower(tag.attrs.get("http-equiv") ?? "") === "content-security-policy") {
      fail("holds a Content-Security-Policy meta element");
    } else if (name === "template") {
      template++;
    } else if (name === "noscript") {
      const close = endTag(html, "noscript", tag.end);
      if (/<script/i.test(html.slice(tag.end, close))) fail("has a script inside a noscript element");
      i = close;
    } else if (name === "plaintext") {
      break;
    } else if (TEXT_ELEMENTS.has(name)) {
      i = endTag(html, name, tag.end);
    }
  }
  if (at < 0) fail("has no <head> start tag");
  return { at, scripts };
}

/** The HTML files under a folder, in path order. */
function htmlFiles(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => {
      const path = join(dir, e.name);
      if (e.isDirectory()) return htmlFiles(path);
      return e.name.endsWith(".html") ? [path] : [];
    })
    .sort();
}

function main() {
  const OUT = "out";
  const files = htmlFiles(OUT);
  if (files.length === 0) throw new Error(`${OUT}/ holds no HTML page: run next build in website/ first`);
  let count = 0;
  let longest = { page: "", length: 0 };
  for (const file of files) {
    const page = relative(OUT, file);
    const bytes = readFileSync(file);
    const html = bytes.toString("utf8");
    if (!Buffer.from(html, "utf8").equals(bytes)) throw new Error(`${page} is not UTF-8, which scripts/script-policy.mjs does not read`);
    const { at, scripts } = readPage(html, page);
    const policy = ["script-src", "'self'", ...new Set(scripts.map(scriptHash))].join(" ");
    writeFileSync(file, `${html.slice(0, at)}<meta http-equiv="Content-Security-Policy" content="${policy}"/>${html.slice(at)}`);
    count += scripts.length;
    if (policy.length > longest.length) longest = { page, length: policy.length };
  }
  console.log(
    `${files.length} pages hold their script policies, naming ${count} inline scripts by SHA-256; the longest, ` +
      `${longest.page}'s, is ${longest.length} characters`,
  );
}

if (import.meta.main) main();
