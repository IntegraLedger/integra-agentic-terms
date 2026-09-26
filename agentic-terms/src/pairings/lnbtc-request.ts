/**
 * x402 `lnbtc`'s request binding, computed by the buyer from its own request: the option's profile and parameters are
 * validated, the binding object is built from the request the buyer gives, and `requestHash` is SHA-256 over the UTF-8
 * of its RFC 8785 form. The option's `extra.requestHash` and the invoice's description hash must both equal it.
 *
 * The buyer's request, the `request` input:
 * - `http:1`: `{method, url, body?, headers?}`, `body` the content bytes as `0x` hex (absent is empty), `headers` the
 *   value of each present header by lower-case name, each field line's values joined as RFC 9421 §2.1 joins them.
 * - `mcp:1`: `{server, name, arguments?, meta?}`, `server` the MCP server's URI as the buyer's own configuration spells
 *   it, `name` and `arguments` the `tools/call` params, `meta` its `params._meta`.
 */
import { canonicalJson, hash, type Json, type Refusal } from "@integraledger/lcp";
import { decodeBolt11, invoiceH } from "@integraledger/lcp/lightning";
import { bytesOf, isObject, isRefusal, refuse } from "./common.js";

const HTTP_DOMAIN = "x402:exact:lnbtc:bolt11:http:1";
const MCP_DOMAIN = "x402:exact:lnbtc:bolt11:mcp:1";
const REQUEST_HASH = /^[0-9a-f]{64}$/;
const FIELD_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]+$/;
const METHOD = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const FIELD_VALUE = /^[\t\x20-\x7e]*$/;
const ASCII_URI = /^[\x21-\x7e]+$/;
/** `http` or `https`, `//`, an authority with no user information, then a path or query and no fragment. */
const HTTP_TARGET = /^https?:\/\/[^/?#@]+(?:[/?][^#]*)?$/i;
/** A scheme, then no fragment; where there is an authority, no user information in it. */
const ABSOLUTE_URI = /^[A-Za-z][A-Za-z0-9+.-]*:[^#]*$/;
const USERINFO = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*@/;
const EXCLUDED_META: readonly string[] = ["x402/payment", "progressToken"];

const malformed = (): Refusal => refuse("ln/request-binding-malformed");

function exactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(o);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(o, k));
}

/** Lower-case hex of SHA-256 over `bytes`. */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return (await hash(bytes)).slice(2);
}

/** SHA-256 of `0x01 || bytes` for a present value, of the single byte `0x00` for an absent one. */
async function valueHash(bytes: Uint8Array | undefined): Promise<string> {
  if (bytes === undefined) return sha256Hex(Uint8Array.of(0x00));
  const b = new Uint8Array(bytes.length + 1);
  b[0] = 0x01;
  b.set(bytes, 1);
  return sha256Hex(b);
}

/** An absolute `http` or `https` URL in ASCII syntax, with a host, and no fragment or user information. */
function isTargetUri(url: unknown): url is string {
  return typeof url === "string" && ASCII_URI.test(url) && HTTP_TARGET.test(url) && URL.canParse(url);
}

/** Strictly ascending and without duplicates, by UTF-16 code units, which is RFC 8785's member order. */
function ascending(names: readonly string[]): boolean {
  for (let i = 1; i < names.length; i++) if (!(names[i - 1]! < names[i]!)) return false;
  return true;
}

async function httpBinding(params: Record<string, unknown>, request: Record<string, unknown>, resourceUrl: unknown): Promise<Json | Refusal> {
  if (!exactKeys(params, ["headers"]) || !Array.isArray(params["headers"])) return malformed();
  const names = params["headers"] as unknown[];
  if (!names.every((n): n is string => typeof n === "string" && FIELD_NAME.test(n) && n !== "payment-signature")) return malformed();
  if (!ascending(names)) return malformed();
  const { method, url, body, headers } = request;
  if (typeof method !== "string" || !METHOD.test(method) || !isTargetUri(url)) return malformed();
  if (resourceUrl !== url) return refuse("ln/request-resource-mismatch");
  const content = body === undefined ? new Uint8Array(0) : bytesOf(body);
  if (content === undefined) return malformed();
  if (headers !== undefined && !isObject(headers)) return malformed();
  const given = (headers ?? {}) as Record<string, unknown>;
  const bound: Json[] = [];
  for (const name of names) {
    const v = Object.hasOwn(given, name) ? given[name] : undefined;
    if (v !== undefined && (typeof v !== "string" || !FIELD_VALUE.test(v))) return malformed();
    const value = v === undefined ? undefined : new TextEncoder().encode(v.replace(/^[\t ]+|[\t ]+$/g, ""));
    bound.push({ name, valueHash: await valueHash(value) });
  }
  return { domain: HTTP_DOMAIN, method, url, bodyHash: await sha256Hex(content), headers: bound };
}

async function mcpBinding(params: Record<string, unknown>, request: Record<string, unknown>): Promise<Json | Refusal> {
  if (!exactKeys(params, ["server", "metadata"]) || !Array.isArray(params["metadata"])) return malformed();
  const names = params["metadata"] as unknown[];
  if (!names.every((n): n is string => typeof n === "string" && n !== "" && !EXCLUDED_META.includes(n))) return malformed();
  if (!ascending(names)) return malformed();
  const { server, name, meta } = request;
  if (!isAbsoluteUri(server)) return malformed();
  if (params["server"] !== server) return refuse("ln/request-server-mismatch");
  if (typeof name !== "string" || name === "") return malformed();
  const args = Object.hasOwn(request, "arguments") ? request["arguments"] : {};
  if (!isObject(args)) return malformed();
  if (meta !== undefined && !isObject(meta)) return malformed();
  const given = (meta ?? {}) as Record<string, unknown>;
  const bound: Json[] = [];
  for (const n of names) {
    if (!Object.hasOwn(given, n)) {
      bound.push({ name: n, valueHash: await valueHash(undefined) });
      continue;
    }
    const text = canonicalJson(given[n] as Json);
    if (typeof text !== "string") return malformed();
    bound.push({ name: n, valueHash: await valueHash(new TextEncoder().encode(text)) });
  }
  return { domain: MCP_DOMAIN, server, method: "tools/call", name, arguments: args as Json, metadata: bound };
}

/** An absolute URI in ASCII syntax, with no user information and no fragment. */
function isAbsoluteUri(v: unknown): v is string {
  return typeof v === "string" && ASCII_URI.test(v) && ABSOLUTE_URI.test(v) && !USERINFO.test(v) && URL.canParse(v);
}

/**
 * The binding object of the buyer's own `request` under a profile and its parameters, the profile being the one the
 * request's transport uses: `http:1` for an HTTP request, `mcp:1` for a `tools/call`.
 */
export async function bindingOf(
  profile: unknown,
  params: unknown,
  request: unknown,
  resourceUrl: unknown,
): Promise<Json | Refusal> {
  if (!isObject(params) || !isObject(request)) return malformed();
  const isMcp = Object.hasOwn(request, "server");
  if (profile === "http:1" && !isMcp) return httpBinding(params, request, resourceUrl);
  if (profile === "mcp:1" && isMcp) return mcpBinding(params, request);
  return refuse("ln/request-profile-mismatch");
}

/** `requestHash`: lower-case hex of SHA-256 over the UTF-8 of the binding object's RFC 8785 form. */
export async function requestHashOf(
  profile: unknown,
  params: unknown,
  request: unknown,
  resourceUrl: unknown,
): Promise<string | Refusal> {
  const binding = await bindingOf(profile, params, request, resourceUrl);
  if (isRefusal(binding)) return binding;
  const text = canonicalJson(binding);
  if (typeof text !== "string") return malformed();
  return sha256Hex(new TextEncoder().encode(text));
}

/**
 * The request hash of the buyer's own `request` under the option's profile, when the option's `extra.requestHash` and
 * the invoice's description hash both equal it; otherwise the refusal naming what differs.
 */
export async function checkRequestHash(
  option: unknown,
  resourceUrl: unknown,
  request: unknown,
): Promise<string | Refusal> {
  const extra = isObject(option) ? option["extra"] : undefined;
  if (!isObject(extra)) return malformed();
  const { requestHash, requestBindingProfile: profile, requestBindingParams: params, invoice } = extra;
  if (typeof requestHash !== "string" || !REQUEST_HASH.test(requestHash)) return malformed();
  const computed = await requestHashOf(profile, params, request, resourceUrl);
  if (isRefusal(computed)) return computed;
  if (computed !== requestHash) return refuse("ln/request-hash-mismatch");
  if (typeof invoice !== "string") return refuse("ln/invoice-malformed");
  const b = await decodeBolt11(invoice);
  if (isRefusal(b)) return b;
  const d = invoiceH(b, "h");
  if (isRefusal(d)) return d;
  if (d !== `0x${computed}`) return refuse("ln/request-hash-mismatch");
  return computed;
}
