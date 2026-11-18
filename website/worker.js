// The site's Worker. The exported site in out/ is its static assets; wrangler.toml runs this script first for page
// addresses and their .md addresses, and never for the build's files (scripts, the pages' RSC payloads, the Markdown
// copies, the search index), so that a reader who asks for a page as Markdown gets the page's Markdown copy, which the
// build writes at /md/<page>.md:
//
//   GET /<page>.md, /index.md                 the page as Markdown (https://llmstxt.org)
//   GET /<page> with an Accept that ranks     the same Markdown, at the page's own address
//     text/markdown or text/x-markdown at
//     least as high as text/html, text/* and */*
//
// Every other request is answered by the static assets, which redirect a page address that ends in a slash to the
// address without it, whatever the Accept header asks for. A request carrying If-None-Match or another conditional
// header can be answered 304, and a page address's response carries `Vary: Accept`. A .md address that names no page
// is answered 404 in Markdown that names /llms.txt, the index of every page, so an agent that guessed an address can
// recover.
//
// Links. Beside the `Link: </llms.txt>; rel="describedby"` public/_headers gives every path, a page's HTML (a 200 or a
// 304 at a page address) names its Markdown address, `rel="alternate"; type="text/markdown"`, and a page's Markdown at
// its .md address names the page as its canonical address, `rel="canonical"`, so an agent that reads no HTML head, and
// a search engine, find both (https://llmstxt.org; RFC 8288).
//
// Cloudflare applies public/_headers to the files it serves directly, but not to a response a Worker returns
// (https://developers.cloudflare.com/workers/static-assets/headers/). So this script sets, on every response it
// returns, the headers public/_headers gives the request's path, read from that file by headers.mjs: wrangler.toml
// bundles the file as a text module. Each header replaces any value the response holds, so a response the static
// assets have given those headers carries each once.
import { isMarkdownPreferred } from "fumadocs-core/negotiation";
import headersFile from "./public/_headers";
import { headersFor, parseHeaders } from "./headers.mjs";

/** The rules of public/_headers. */
const RULES = parseHeaders(headersFile);

/** The site's canonical origin, `siteConfig.url` in src/lib/site.ts (scripts/check-worker.mjs compares them). */
const ORIGIN = "https://agenticterms.integraledger.com";

/** The media types that ask for Markdown. `text/plain` is not one of them: it asks for any text. */
const MARKDOWN_TYPES = ["text/markdown", "text/x-markdown"];

/** The path of a page's Markdown copy: `/md/<page>.md`, and `/md/index.md` for the home page. */
function copyOf(page) {
  return page === "/" ? "/md/index.md" : `/md${page}.md`;
}

/** The page a .md address names: the home page for `/index.md`, `<page>` for `/<page>.md`, else none. */
function pageOf(pathname) {
  if (pathname === "/index.md") return "/";
  const page = pathname.slice(0, -".md".length);
  return page.endsWith("/") ? undefined : page;
}

/**
 * The page's Markdown copy as a 200 or 304 response, or undefined when the site holds no copy for that page. The
 * request's conditional headers go with it, so a copy the reader holds is answered 304.
 */
async function markdown(env, request, page) {
  const headers = new Headers();
  for (const [name, value] of request.headers) if (name.startsWith("if-")) headers.set(name, value);
  const response = await env.ASSETS.fetch(
    new Request(new URL(copyOf(page), request.url), { method: request.method, headers }),
  );
  return response.status === 200 || response.status === 304 ? response : undefined;
}

/** A page's Link to its Markdown, on its HTML. */
function alternate(page) {
  return `<${ORIGIN}${page === "/" ? "/index.md" : `${page}.md`}>; rel="alternate"; type="text/markdown"`;
}

/** A page's Link to itself, on its Markdown at its .md address. */
function canonical(page) {
  return `<${ORIGIN}${page === "/" ? "" : page}>; rel="canonical"`;
}

/** The 404 for a .md address that names no page: Markdown, which names the index rather than the address asked for. */
function notFound(request) {
  const text = `# Page not found\n\nThis site has no page at this address. Every page is listed, with its Markdown address, in ${ORIGIN}/llms.txt.\n`;
  return new Response(request.method === "HEAD" ? null : text, {
    status: 404,
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
}

/**
 * The response with the headers public/_headers gives `pathname` set on it, `link` added to its Link header, and, for
 * a page address, `Vary: Accept`.
 */
function respond(response, pathname, varyOnAccept, link) {
  const out = new Response(response.body, response);
  for (const [name, value] of headersFor(RULES, pathname)) out.headers.set(name, value);
  if (link !== undefined) out.headers.append("Link", link);
  if (varyOnAccept) out.headers.append("Vary", "Accept");
  return out;
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const reads = request.method === "GET" || request.method === "HEAD";
    if (reads && pathname.endsWith(".md")) {
      const page = pageOf(pathname);
      const found = page === undefined ? undefined : await markdown(env, request, page);
      if (found !== undefined) return respond(found, pathname, false, canonical(page));
      const asset = await env.ASSETS.fetch(request);
      return respond(asset.status === 404 ? notFound(request) : asset, pathname, false);
    }
    const page = reads && (pathname === "/" || !pathname.endsWith("/"));
    if (page && isMarkdownPreferred(request, { markdownMediaTypes: MARKDOWN_TYPES })) {
      const found = await markdown(env, request, pathname);
      if (found !== undefined) return respond(found, pathname, true);
    }
    const response = await env.ASSETS.fetch(request);
    const type = response.headers.get("content-type");
    const html = (response.status === 200 || response.status === 304) && (type === null || type.startsWith("text/html"));
    return respond(response, pathname, true, page && html ? alternate(pathname) : undefined);
  },
};
