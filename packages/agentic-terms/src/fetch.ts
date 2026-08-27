import { isUnicastPublic } from "@integraledger/lcp-evidence";

export interface FetchedTerms {
  readonly bytes: Uint8Array;
  readonly format: string;
  readonly fetchedAt: string;
}
export interface TermsFetcher {
  fetch(url: string): Promise<FetchedTerms>;
}

/** One resolved address for a host. Mirrors `node:dns/promises` `lookup(host, { all: true })`. */
export interface ResolvedAddress {
  readonly address: string;
  readonly family: number;
}
/**
 * The host-resolution port. REQUIRED, and deliberately not defaulted: the buyer fetches a URL the SELLER
 * chose, so this is the guard between an agent's HTTP client and the buyer's own network — a config that
 * can omit it silently omits the guard. Node deployments pass `nodeDnsLookup`; a Workers deployment passes
 * its own (or one that throws, stating it relies on the platform's private-range egress blocking). The
 * port MUST return literal-IP hosts unchanged, as `node:dns` does.
 */
export type HostLookup = (host: string) => Promise<readonly ResolvedAddress[]>;

export interface CachingFetcherConfig {
  readonly httpFetch: typeof fetch;
  readonly now: () => string;
  /** Resolves a hostname to the addresses the unicast guard checks. See `HostLookup` — no default. */
  readonly lookup: HostLookup;
  /** LCP §2.6: clients SHOULD NOT cache beyond this; default 24h. Re-fetch after it is a MUST (enforced here). */
  readonly maxAgeSeconds?: number;
  /** Fail-loud byte ceiling (DoS guard); default 1 MiB. */
  readonly maxBytes?: number;
  /** Max distinct URLs retained (bounded memory / anti-DoS); default 256. Oldest inserted entry evicted past it. */
  readonly maxEntries?: number;
}
const DAY = 86_400;

/**
 * `node:dns/promises` as a `HostLookup`. Imported lazily so the module graph stays runtime-neutral (the
 * gate is client-side and may run where `node:dns` does not exist) — a Workers build that never calls this
 * never pulls it in.
 */
export const nodeDnsLookup: HostLookup = async (host: string) => {
  const dns = await import("node:dns/promises");
  return dns.lookup(host, { all: true });
};

/**
 * HTTPS-only, cached (LCP §2.6), size-capped, SSRF-guarded terms fetcher. The MUST (re-fetch after expiry) is
 * unconditional; the SHOULD (≤24h) is the default cap.
 *
 * SSRF posture — this is the BUYER's exposure, because the URL comes off the seller's 402 challenge:
 *  - HTTPS scheme required;
 *  - `redirect: "error"`, so a redirect to a non-HTTPS or internal host fails loudly rather than being
 *    followed silently;
 *  - EVERY resolved address for the host must be public unicast (`evidence.isUnicastPublic` — the one
 *    implementation of that predicate; this package does not re-derive it). The check runs on every
 *    network fetch, not once per URL, so a cache expiry re-opens it rather than grandfathering a host.
 *  - the byte cap is enforced while STREAMING, plus a `Content-Length` pre-check. Reading the whole body
 *    and measuring afterwards protects the check but not the memory, and a chunked response with no
 *    declared length is exactly the case the cap exists for.
 *
 * HONEST LIMITATION — DNS rebinding, carried verbatim from `evidence`'s resolver: the guard validates what
 * `lookup` returns, but `httpFetch` performs its own resolution and nothing pins the connection to the
 * validated address. This is real defense-in-depth (the naive name → private IP case is blocked outright),
 * NOT a complete guarantee; closing it needs connection-level IP pinning inside the injected `httpFetch`.
 */
export function makeCachingFetcher(cfg: CachingFetcherConfig): TermsFetcher {
  const maxAge = cfg.maxAgeSeconds ?? DAY;
  const maxBytes = cfg.maxBytes ?? 1024 * 1024;
  const maxEntries = cfg.maxEntries ?? 256;
  const cache = new Map<string, { at: number; terms: FetchedTerms }>();
  const secs = (iso: string): number => Math.floor(Date.parse(iso) / 1000);

  async function assertPublicHost(url: URL): Promise<void> {
    // BRACKETS ARE URL SYNTAX, NOT ADDRESS SYNTAX, and stripping them here is what lets an IPv6 literal
    // reach the guard at all. `new URL("https://[::1]/x").hostname` is `"[::1]"`, and `node:dns` answers
    // that with ENOTFOUND — so the request was refused for the right outcome and the WRONG REASON: the
    // buyer's record named a DNS failure where the truth was an SSRF refusal, and that message is what a
    // buyer would report to a seller.
    //
    // It also refused hosts it should allow. `isUnicastPublic` parses the bracketed form correctly, but the
    // lookup never returned an address for it, so a seller publishing a legitimate PUBLIC IPv6 literal was
    // refused with the same ENOTFOUND as a loopback one.
    //
    // Unbracketed, `node:dns` returns a literal unchanged — `::1` comes back as `{address:"::1",family:6}`,
    // exactly as `127.0.0.1` does — which is the behaviour the `HostLookup` contract already requires of
    // every port. Normalising here rather than inside `nodeDnsLookup` means a Workers or Deno port inherits
    // the fix instead of having to repeat it.
    // ONE regex rather than `startsWith("[") && endsWith("]")`, because a matching pair is ONE fact and the
    // conjunction spelt it as two. `new URL()` cannot produce a hostname with only one bracket, so neither
    // conjunct was individually observable — mutating either left behaviour identical, which is a survivor
    // no test can honestly kill. Expressing the pair as a single match makes the check say what it means and
    // leaves nothing unobservable behind it.
    const host = /^\[(.+)\]$/.exec(url.hostname)?.[1] ?? url.hostname;
    const addrs = await cfg.lookup(host);
    if (addrs.length === 0)
      throw new Error(`no address for ${url.hostname} — refused (SSRF guard)`);
    for (const { address } of addrs)
      if (!isUnicastPublic(address))
        throw new Error(
          `${url.hostname} resolves to a non-public address (${address}) — refused (SSRF guard)`,
        );
  }

  async function readCapped(res: Response): Promise<Uint8Array> {
    const body = res.body;
    if (body === null) return new Uint8Array(0);
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`terms exceed ${maxBytes} bytes (fail-loud)`);
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) {
      out.set(c, o);
      o += c.length;
    }
    return out;
  }

  return {
    async fetch(url: string): Promise<FetchedTerms> {
      if (!url.startsWith("https://"))
        throw new Error(`terms url must be HTTPS (SSRF posture): ${url}`);
      const nowS = secs(cfg.now());
      const hit = cache.get(url);
      if (hit !== undefined && nowS - hit.at < maxAge) return hit.terms; // SHOULD: serve fresh from cache

      // Re-validated on every network fetch — an expiring cache entry must not grandfather a host.
      await assertPublicHost(new URL(url));

      const res = await cfg.httpFetch(url, { redirect: "error" }); // MUST: re-fetch after expiry; never follow redirects
      if (!res.ok) throw new Error(`terms fetch failed: ${res.status} ${url}`);
      const declared = res.headers.get("content-length");
      if (
        declared !== null &&
        Number.isFinite(Number(declared)) &&
        Number(declared) > maxBytes
      )
        throw new Error(
          `terms declare ${declared} bytes > ${maxBytes} (fail-loud): ${url}`,
        );
      const buf = await readCapped(res);
      const terms: FetchedTerms = {
        bytes: buf,
        format: res.headers.get("content-type") ?? "application/octet-stream",
        fetchedAt: cfg.now(),
      };
      cache.set(url, { at: nowS, terms });
      if (cache.size > maxEntries) {
        const oldest = cache.keys().next().value;
        if (oldest !== undefined) cache.delete(oldest);
      }
      return terms;
    },
  };
}
