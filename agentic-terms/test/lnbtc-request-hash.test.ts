// x402 `lnbtc`: the buyer recomputes the request hash from its own request and requires the option's
// `extra.requestHash` and the invoice's description hash to equal it, before the node is asked to pay. Expected values:
// x402's `scheme_exact_lnbtc.md`, "Request Binding Test Vectors" (HTTP: article A `0d6623f7…c018`, article B
// `4a99860f…d509`; MCP: article A `03941bfe…93f4`, article B `b3e42597…0678`, `delete_article` `3a52bbf1…3455`, another
// server `96903c29…6e45`; a bound metadata member absent `6e340b9c…a01d`, present `null` `c58dcb77…8b16`), and its
// client check 4 ("compute the digest from the intended request … Both the description hash and `extra.requestHash`
// MUST equal the computed digest"). The option and its invoice (`h` = article A's digest) are the vector file's.
import { describe, expect, it } from "vitest";
import { exactLnbtc } from "@integraledger/lcp/lightning";
import { confirm, type Binding } from "../src/index.js";
import { bindingOf, requestHashOf } from "../src/pairings/lnbtc-request.js";
import { ABC, code, H, isDeclined, LINK, offered, serving, vectors } from "./support.js";

const NOW = 1_790_000_000;
async function at<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => NOW * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

const HTTP_A = "0d6623f775e025501fa7f0a30b54da25aad62b6ccfe35c85da38016711e6c018";
const HTTP_B = "4a99860f75eed1ea8178a5db488e044173bc570c8a6210f2c8590cdf8622d509";
const MCP_A = "03941bfedc6af8a09b2f459fe83470284a76a8c75801caa9e1487a9276a693f4";
const MCP_B = "b3e425970d64cd4f08fc4d57a11b76da59ce6a5760d92687398c91f063120678";
const MCP_DELETE = "3a52bbf19dda8b5765a27246b12e805770298273b48526956c421f02fe043455";
const MCP_OTHER_SERVER = "96903c29186c6aabc95e48abafd8ce3ad32b4060f5d5bf22cf75f3fbfe816e45";
const META_ABSENT = "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
const META_NULL = "c58dcb77cee9027d1f4b3207bd876d232e61f79ee9f9dbd4e6d834778da78b16";

const ARTICLE_A = "https://api.example.com/article/A";
const ARTICLE_B = "https://api.example.com/article/B";
const SERVER = "https://api.example.com/mcp";

describe("the request binding, from the buyer's own request", () => {
  const http = { headers: [] };
  it("HTTP: GET of article A with an empty body and no bound headers is the specification's digest; article B is its other", async () => {
    expect(await requestHashOf("http:1", http, { method: "GET", url: ARTICLE_A }, ARTICLE_A)).toBe(HTTP_A);
    expect(await requestHashOf("http:1", http, { method: "GET", url: ARTICLE_B }, ARTICLE_B)).toBe(HTTP_B);
    expect(await requestHashOf("http:1", http, { method: "GET", url: ARTICLE_A, body: "0x" }, ARTICLE_A)).toBe(HTTP_A);
  });
  it("HTTP: the method, the body and the resource URL each count", async () => {
    expect(await requestHashOf("http:1", http, { method: "POST", url: ARTICLE_A }, ARTICLE_A)).not.toBe(HTTP_A);
    expect(await requestHashOf("http:1", http, { method: "GET", url: ARTICLE_A, body: "0x78" }, ARTICLE_A)).not.toBe(HTTP_A);
    expect(await requestHashOf("http:1", http, { method: "GET", url: ARTICLE_A }, ARTICLE_B)).toEqual({
      refused: true,
      code: "ln/request-resource-mismatch",
    });
  });
  it("MCP: get_article with article A is the specification's digest, and its three changes give the specification's three", async () => {
    const params = { server: SERVER, metadata: [] };
    const call = { server: SERVER, name: "get_article", arguments: { article: "A" } };
    expect(await requestHashOf("mcp:1", params, call, undefined)).toBe(MCP_A);
    expect(await requestHashOf("mcp:1", params, { ...call, arguments: { article: "B" } }, undefined)).toBe(MCP_B);
    expect(await requestHashOf("mcp:1", params, { ...call, name: "delete_article" }, undefined)).toBe(MCP_DELETE);
    const other = "https://other.example.com/mcp";
    expect(await requestHashOf("mcp:1", { ...params, server: other }, { ...call, server: other }, undefined)).toBe(MCP_OTHER_SERVER);
  });
  it("MCP: a bound metadata member absent, and present as null, hash as the specification's", async () => {
    const params = { server: SERVER, metadata: ["m"] };
    const call = { server: SERVER, name: "get_article", arguments: { article: "A" } };
    expect(await bindingOf("mcp:1", params, call, undefined)).toMatchObject({ metadata: [{ name: "m", valueHash: META_ABSENT }] });
    expect(await bindingOf("mcp:1", params, { ...call, meta: { m: null } }, undefined)).toMatchObject({
      metadata: [{ name: "m", valueHash: META_NULL }],
    });
  });
  it("MCP: the server the option names must be the buyer's own; omitted arguments are {}", async () => {
    const params = { server: "https://other.example.com/mcp", metadata: [] };
    expect(await requestHashOf("mcp:1", params, { server: SERVER, name: "get_article", arguments: { article: "A" } }, undefined)).toEqual({
      refused: true,
      code: "ln/request-server-mismatch",
    });
    const noArgs = await requestHashOf("mcp:1", { server: SERVER, metadata: [] }, { server: SERVER, name: "get_article" }, undefined);
    const empty = await requestHashOf("mcp:1", { server: SERVER, metadata: [] }, { server: SERVER, name: "get_article", arguments: {} }, undefined);
    expect(noArgs).toBe(empty);
  });
  it.each([
    ["an unknown profile", "http:2", { headers: [] }, { method: "GET", url: ARTICLE_A }, "ln/request-profile-mismatch"],
    ["http:1 for an MCP tool call", "http:1", { headers: [] }, { server: SERVER, name: "get_article" }, "ln/request-profile-mismatch"],
    ["an unknown parameter", "http:1", { headers: [], extra: 1 }, { method: "GET", url: ARTICLE_A }, "ln/request-binding-malformed"],
    ["headers out of order", "http:1", { headers: ["range", "accept"] }, { method: "GET", url: ARTICLE_A }, "ln/request-binding-malformed"],
    ["payment-signature bound", "http:1", { headers: ["payment-signature"] }, { method: "GET", url: ARTICLE_A }, "ln/request-binding-malformed"],
    ["a URL with a fragment", "http:1", { headers: [] }, { method: "GET", url: `${ARTICLE_A}#x` }, "ln/request-binding-malformed"],
    ["a URL with user information", "http:1", { headers: [] }, { method: "GET", url: "https://u@api.example.com/article/A" }, "ln/request-binding-malformed"],
    ["x402/payment bound", "mcp:1", { server: SERVER, metadata: ["x402/payment"] }, { server: SERVER, name: "get_article" }, "ln/request-binding-malformed"],
    ["null arguments", "mcp:1", { server: SERVER, metadata: [] }, { server: SERVER, name: "get_article", arguments: null }, "ln/request-binding-malformed"],
  ] as const)("%s is refused", async (_case, profile, params, request, expected) => {
    expect(await requestHashOf(profile, params, request, ARTICLE_A)).toEqual({ refused: true, code: expected });
  });
});

describe("x402/exact/lnbtc: the gate compares the recomputed request hash before the node is asked to pay", () => {
  const V = vectors<{ fixed: { O: Record<string, unknown>; resource: { url: string } } }>("x402-exact-lnbtc.json");
  const account = `${V.fixed.O["network"] as string}:${V.fixed.O["payTo"] as string}`;
  const doc = (() => {
    const placed = (exactLnbtc as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(
      { x402Version: 2, resource: V.fixed.resource, accepts: [V.fixed.O] },
      H,
      LINK,
      V.fixed.O,
    );
    if (typeof placed !== "object" || placed === null || "refused" in placed) throw new Error(JSON.stringify(placed));
    return placed;
  })();
  const binding = offered(exactLnbtc as unknown as Binding);

  it("the buyer's GET of article A: the invoice is handed to the node", () =>
    at(async () => {
      const out = await confirm(doc, binding, account, serving(ABC), { request: { method: "GET", url: ARTICLE_A } });
      if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
      expect(out.request).toEqual({ kind: "bolt11-pay", invoice: (V.fixed.O["extra"] as { invoice: string }).invoice });
    }));
  it.each([
    ["a POST of article A", { method: "POST", url: ARTICLE_A }, "ln/request-hash-mismatch"],
    ["a GET of article A with the body 0x78", { method: "GET", url: ARTICLE_A, body: "0x78" }, "ln/request-hash-mismatch"],
    ["a GET of article B, which the challenge's resource does not name", { method: "GET", url: ARTICLE_B }, "ln/request-resource-mismatch"],
    ["an MCP tool call, under the option's http:1", { server: SERVER, name: "get_article" }, "ln/request-profile-mismatch"],
  ] as const)("%s: no-payable-option before any fetch", (_case, request, detail) =>
    at(async () => {
      const fetch = serving(ABC);
      const out = await confirm(doc, binding, account, fetch, { request });
      expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail });
      expect(fetch.calls).toBe(0);
    }));
  it("no request given: no-payable-option, x402/input-missing, before any fetch", () =>
    at(async () => {
      const fetch = serving(ABC);
      const out = await confirm(doc, binding, account, fetch);
      expect(code(out)).toBe("no-payable-option");
      expect(isDeclined(out) && out.decline.detail).toBe("x402/input-missing");
      expect(fetch.calls).toBe(0);
    }));
  it("an option whose extra.requestHash is article B's, over article A's invoice: refused though the request is B", () =>
    at(async () => {
      const O = { ...V.fixed.O, extra: { ...(V.fixed.O["extra"] as object), requestHash: HTTP_B } };
      const fetch = serving(ABC);
      const placed = { x402Version: 2, resource: { url: ARTICLE_B }, accepts: [O], extensions: (doc as { extensions: unknown }).extensions };
      const out = await confirm(placed, binding, account, fetch, { request: { method: "GET", url: ARTICLE_B } });
      expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "ln/request-hash-mismatch" });
      expect(fetch.calls).toBe(0);
    }));
});
