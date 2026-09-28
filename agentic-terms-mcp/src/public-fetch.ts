/**
 * The fetch `terms-mcp` serves the tools with: WHATWG `fetch`'s call shape over `node:https`, connecting only to public
 * addresses. A link that names an address is checked before any connection. A link that names a host is resolved once,
 * every address it resolves to is checked, and the socket connects to one of those checked addresses. A refused address
 * rejects the fetch, which the gate reads as a link that could not be fetched. The body is returned as sent, with the
 * response's own headers: nothing is decoded and no redirect is followed.
 */
import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from "node:dns";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { Readable } from "node:stream";
import type { Fetch } from "@integraledger/terms";

/** An address block: its first address and prefix length, from the IANA special-purpose address registries. */
type Block = readonly [address: string, prefix: number];

/** IPv4 blocks that are not globally reachable, and multicast and reserved space. */
const V4_NOT_PUBLIC: readonly Block[] = [
  ["0.0.0.0", 8], // "this network"
  ["10.0.0.0", 8], // private-use
  ["100.64.0.0", 10], // shared address space
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local
  ["172.16.0.0", 12], // private-use
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // documentation (TEST-NET-1)
  ["192.88.99.0", 24], // 6to4 relay anycast
  ["192.168.0.0", 16], // private-use
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // documentation (TEST-NET-2)
  ["203.0.113.0", 24], // documentation (TEST-NET-3)
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved, and the limited broadcast address
];

/** The IPv6 global unicast block; every IPv6 address outside it, but for the two IPv4 forms below, is refused. */
const V6_GLOBAL_UNICAST: Block = ["2000::", 3];
/** Blocks inside global unicast that are not globally reachable. */
const V6_NOT_PUBLIC: readonly Block[] = [
  ["2001::", 23], // IETF protocol assignments, Teredo included
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4
  ["3fff::", 20], // documentation
];
/** IPv6 forms that carry an IPv4 address in their last 32 bits, which is checked as IPv4. */
const V6_CARRIES_V4: readonly Block[] = [
  ["::ffff:0:0", 96], // IPv4-mapped
  ["64:ff9b::", 96], // the NAT64 well-known prefix
];

/** The four bytes of a dotted-quad IPv4 address, or undefined. */
function v4Bytes(text: string): number[] | undefined {
  if (isIP(text) !== 4) return undefined;
  return text.split(".").map(Number);
}

/** The sixteen bytes of an IPv6 address in any of its text forms, or undefined. */
function v6Bytes(text: string): number[] | undefined {
  if (isIP(text) !== 6 || text.includes("%")) return undefined;
  let tail: number[] = [];
  let body = text;
  const dotted = text.lastIndexOf(":");
  if (text.includes(".", dotted)) {
    const v4 = v4Bytes(text.slice(dotted + 1));
    if (v4 === undefined) return undefined;
    tail = v4;
    body = `${text.slice(0, dotted + 1)}0:0`;
  }
  const [head, rest] = body.split("::") as [string, string | undefined];
  const groups = (s: string): number[] => (s === "" ? [] : s.split(":").map((g) => parseInt(g, 16)));
  const left = groups(head);
  const right = rest === undefined ? [] : groups(rest);
  const fill = 8 - left.length - right.length;
  if (fill < 0 || (rest === undefined && fill !== 0)) return undefined;
  const words = [...left, ...Array<number>(fill).fill(0), ...right];
  const bytes = words.flatMap((w) => [w >> 8, w & 0xff]);
  if (tail.length === 4) bytes.splice(12, 4, ...tail);
  return bytes;
}

/** Whether `bytes` lies inside `block`, whose address is of the same family. */
function within(bytes: readonly number[], [address, prefix]: Block): boolean {
  const base = bytes.length === 4 ? v4Bytes(address)! : v6Bytes(address)!;
  for (let bit = 0; bit < prefix; bit++) {
    const mask = 0x80 >> bit % 8;
    if ((bytes[bit >> 3]! & mask) !== (base[bit >> 3]! & mask)) return false;
  }
  return true;
}

/**
 * Whether `address`, an IP address in text form, is public: outside every block of the IANA special-purpose address
 * registries that is not globally reachable (loopback, private-use, shared, link-local, unique-local, documentation,
 * benchmarking, 6to4, Teredo), and outside multicast and reserved space. An IPv4-mapped or NAT64 address is judged by
 * the IPv4 address it carries. Anything that is not an IP address is not public.
 */
export function isPublicAddress(address: string): boolean {
  const v4 = v4Bytes(address);
  if (v4 !== undefined) return !V4_NOT_PUBLIC.some((b) => within(v4, b));
  const v6 = v6Bytes(address);
  if (v6 === undefined) return false;
  if (V6_CARRIES_V4.some((b) => within(v6, b))) return isPublicAddress(v6.slice(12).join("."));
  return within(v6, V6_GLOBAL_UNICAST) && !V6_NOT_PUBLIC.some((b) => within(v6, b));
}

/** A resolver with `dns.lookup`'s call shape, asked for every address. */
export type Resolve = (
  hostname: string,
  options: LookupOptions & { all: true },
  callback: (err: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void,
) => void;

function notPublic(what: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`${what} is not a public address.`), { code: "ENOTPUBLIC" });
}

/**
 * A lookup for `net.connect` that resolves the host with `resolve` and answers only when every address it resolves to
 * is public, so the socket connects to a checked address.
 */
export function publicLookup(resolve: Resolve = dnsLookup as Resolve): LookupFunction {
  return (hostname, options, callback) => {
    resolve(hostname, { ...options, all: true }, (err, addresses) => {
      if (err !== null) return callback(err, "", 0);
      const refused = addresses.find((a) => !isPublicAddress(a.address));
      if (addresses.length === 0 || refused !== undefined) {
        return callback(notPublic(refused?.address ?? hostname), "", 0);
      }
      if (options.all === true) return callback(null, addresses);
      return callback(null, addresses[0]!.address, addresses[0]!.family);
    });
  };
}

/** Statuses whose response has no body. */
const NULL_BODY = new Set([204, 205, 304]);

/**
 * `fetch`'s call shape over a Node request function, with `lookup` resolving each host it connects to. The request
 * carries exactly the headers given, redirects are returned as they are, and the body is the bytes as sent.
 */
export function fetchVia(send: typeof httpsRequest, lookup: LookupFunction): Fetch {
  return (url, init) =>
    new Promise<Response>((resolve, reject) => {
      const { signal } = init;
      if (signal.aborted) return reject(signal.reason);
      const req = send(url, { method: init.method, headers: init.headers ?? {}, lookup, signal }, (res) => {
        try {
          const status = res.statusCode ?? 0;
          const headers = new Headers();
          const raw = res.rawHeaders;
          for (let i = 0; i + 1 < raw.length; i += 2) headers.append(raw[i]!, raw[i + 1]!);
          if (NULL_BODY.has(status)) res.resume();
          const body = NULL_BODY.has(status) ? null : (Readable.toWeb(res) as unknown as ReadableStream<Uint8Array>);
          resolve(new Response(body, { status, headers }));
        } catch (e) {
          res.destroy();
          reject(e);
        }
      });
      req.on("error", reject);
      req.end();
    });
}

/** The address a URL's host names, when it names one: IPv6 without its brackets. */
function literalAddress(hostname: string): string | undefined {
  const host = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return isIP(host) === 0 ? undefined : host;
}

const overHttps = fetchVia(httpsRequest, publicLookup());

/** The binary's fetch: https only, and only to public addresses. */
export const publicFetch: Fetch = async (url, init) => {
  const target = new URL(url);
  if (target.protocol !== "https:") throw new TypeError("Only https links are fetched.");
  const literal = literalAddress(target.hostname);
  if (literal !== undefined && !isPublicAddress(literal)) throw notPublic(literal);
  return overHttps(url, init);
};
