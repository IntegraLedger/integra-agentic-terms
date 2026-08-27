import { describe, expect, it } from "vitest";
import { makeCachingFetcher, nodeDnsLookup } from "../src/fetch.js";

/** These suites exercise cache/scheme/cap discipline, not the host guard — resolve public every time. */
const publicHost = async () => [{ address: "93.184.216.34", family: 4 }];

describe("makeCachingFetcher — LCP §2.6 cache discipline + HTTPS-only", () => {
  it("re-fetches after cache expiry (MUST) and serves from cache within the window (SHOULD)", async () => {
    let calls = 0;
    let t = 0;
    const raw = async (): Promise<Response> => {
      calls++;
      return new Response("terms", {
        headers: { "content-type": "text/markdown" },
      });
    };
    const f = makeCachingFetcher({
      httpFetch: raw as never,
      now: () => new Date(t * 1000).toISOString(),
      lookup: publicHost,
      maxAgeSeconds: 60,
    });
    await f.fetch("https://s.example/terms");
    expect(calls).toBe(1);
    t = 30;
    await f.fetch("https://s.example/terms");
    expect(calls).toBe(1); // within window → cached
    t = 61;
    await f.fetch("https://s.example/terms");
    expect(calls).toBe(2); // expired → MUST re-fetch
  });
  it("rejects a non-HTTPS url (SSRF posture)", async () => {
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response("x")) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
    });
    await expect(f.fetch("http://s.example/terms")).rejects.toThrow(/https/i);
  });
  describe("an IPv6 literal reaches the guard, and the guard decides", () => {
    // `new URL("https://[::1]/x").hostname` keeps the BRACKETS, which are URL syntax rather than address
    // syntax. `node:dns` answers a bracketed host with ENOTFOUND, so before this every IPv6-literal URL
    // failed the same way — loopback and public alike. That was not a log-message defect: no seller
    // publishing an IPv6 literal worked at all, against a package whose claim is that it works with any
    // seller. `isUnicastPublic` was always IPv6-aware; it simply never received an address to judge.
    //
    // `nodeDnsLookup` is used for real here rather than a stub, because a stub would prove the test's own
    // normalisation and nothing about the shipped path.
    const fetcherWith = (httpFetch: unknown) =>
      makeCachingFetcher({
        httpFetch: httpFetch as never,
        now: () => "2025-01-01T00:00:00Z",
        lookup: nodeDnsLookup,
      });

    it.each([
      ["loopback", "[::1]"],
      ["loopback, expanded", "[0:0:0:0:0:0:0:1]"],
      ["unique-local", "[fd00::1]"],
      ["link-local", "[fe80::1]"],
      ["IPv4-mapped loopback", "[::ffff:127.0.0.1]"],
      ["IPv4-mapped RFC1918", "[::ffff:10.0.0.1]"],
      ["unspecified", "[::]"],
      ["NAT64-wrapped loopback", "[64:ff9b::7f00:1]"],
    ])(
      "refuses %s as an SSRF refusal, not a DNS error",
      async (_label, host) => {
        const reached = { http: false };
        const f = fetcherWith(async () => {
          reached.http = true;
          return new Response("t");
        });
        // The message is the point: a buyer reports this to a seller, and "resolves to a non-public address"
        // is actionable where "getaddrinfo ENOTFOUND" sends them to look at their DNS.
        await expect(f.fetch(`https://${host}/terms`)).rejects.toThrow(
          /non-public address .* refused \(SSRF guard\)/,
        );
        expect(reached.http).toBe(false);
      },
    );

    it.each([
      ["an ordinary hostname", "s.example", "s.example"],
      ["an IPv4 literal", "93.184.216.34", "93.184.216.34"],
      [
        "a bracketed IPv6 literal",
        "[2606:4700:4700::1111]",
        "2606:4700:4700::1111",
      ],
    ])(
      "hands the resolver exactly the host it should: %s",
      async (_label, hostname, expected) => {
        // The ASSERTION the other suites cannot make, because their `lookup` stub ignores its argument:
        // normalisation must strip a matching bracket pair and touch nothing else. Without this, a rule
        // that always stripped would mangle `s.example` into `.exampl` and every stubbed test would still
        // pass.
        const seen: string[] = [];
        const f = makeCachingFetcher({
          httpFetch: (async () => new Response("t")) as never,
          now: () => "2025-01-01T00:00:00Z",
          lookup: async (h: string) => {
            seen.push(h);
            return [{ address: "93.184.216.34", family: 4 }];
          },
        });
        await f.fetch(`https://${hostname}/terms`);
        expect(seen).toEqual([expected]);
      },
    );

    it.each([
      ["Cloudflare", "[2606:4700:4700::1111]"],
      ["Google", "[2001:4860:4860::8888]"],
    ])(
      "ALLOWS a public %s literal — the fix is not a blanket IPv6 refusal",
      async (_l, host) => {
        let seen = "";
        const f = fetcherWith(async (u: string) => {
          seen = u;
          return new Response("terms");
        });
        const got = await f.fetch(`https://${host}/terms`);
        expect(new TextDecoder().decode(got.bytes)).toBe("terms");
        // The brackets are stripped only for the LOOKUP; the URL fetched is the one the seller published.
        expect(seen).toBe(`https://${host}/terms`);
      },
    );
  });

  it("requests redirect:error on every fetch (redirect SSRF bypass posture)", async () => {
    let init: RequestInit | undefined;
    const raw = async (_u: string, i?: RequestInit): Promise<Response> => {
      init = i;
      return new Response("t");
    };
    const f = makeCachingFetcher({
      httpFetch: raw as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
    });
    await f.fetch("https://s.example/terms");
    expect(init).toEqual({ redirect: "error" });
  });
  it("rejects on declared Content-Length over cap before reading the body", async () => {
    const raw = async (): Promise<Response> =>
      new Response("x", {
        headers: { "content-length": String(2 * 1024 * 1024) },
      });
    const f = makeCachingFetcher({
      httpFetch: raw as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
      maxBytes: 1024,
    });
    await expect(f.fetch("https://s.example/terms")).rejects.toThrow(/bytes/);
  });
  it("evicts the oldest cache entry once maxEntries is exceeded", async () => {
    let calls = 0;
    const raw = async (): Promise<Response> => {
      calls++;
      return new Response("t");
    };
    const f = makeCachingFetcher({
      httpFetch: raw as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
      maxEntries: 1,
    });
    await f.fetch("https://s.example/a");
    expect(calls).toBe(1);
    await f.fetch("https://s.example/b"); // evicts a
    expect(calls).toBe(2);
    await f.fetch("https://s.example/a"); // must re-fetch: a was evicted
    expect(calls).toBe(3);
  });
});

describe("makeCachingFetcher — the unicast SSRF guard (the seller controls this URL)", () => {
  const publicLookup = async () => [{ address: "93.184.216.34", family: 4 }];
  const never = (async () => {
    throw new Error("fetch must NOT be reached for a refused host");
  }) as never;

  it("REFUSES a hostname that resolves into the private range, before fetching", async () => {
    const f = makeCachingFetcher({
      httpFetch: never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: async () => [{ address: "10.0.0.5", family: 4 }],
    });
    await expect(f.fetch("https://internal.evil/terms")).rejects.toThrow(
      /non-public|unicast/i,
    );
  });

  it("REFUSES a literal loopback host", async () => {
    const f = makeCachingFetcher({
      httpFetch: never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: async () => [{ address: "127.0.0.1", family: 4 }],
    });
    await expect(f.fetch("https://127.0.0.1/terms")).rejects.toThrow(
      /non-public|unicast/i,
    );
  });

  it("REFUSES when ANY resolved address is private (a split-horizon answer)", async () => {
    const f = makeCachingFetcher({
      httpFetch: never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "169.254.169.254", family: 4 },
      ],
    });
    await expect(f.fetch("https://mixed.evil/terms")).rejects.toThrow(
      /non-public|unicast/i,
    );
  });

  it("allows a public host and still serves the terms", async () => {
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response("terms")) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicLookup,
    });
    const t = await f.fetch("https://s.example/terms");
    expect(new TextDecoder().decode(t.bytes)).toBe("terms");
  });

  it("re-checks the host on EVERY re-fetch, not just the first (rebinding window)", async () => {
    // A host that was public when first fetched flips private once the cache entry expires. Validating
    // once per URL would grandfather it forever; the guard must run again on the re-fetch the MUST forces.
    let t = 0;
    let lookups = 0;
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response("terms")) as never,
      now: () => new Date(t * 1000).toISOString(),
      maxAgeSeconds: 1,
      lookup: async () => {
        lookups += 1;
        return lookups === 1
          ? [{ address: "93.184.216.34", family: 4 }]
          : [{ address: "10.0.0.5", family: 4 }];
      },
    });
    await f.fetch("https://flip.evil/terms"); // public at t=0
    t = 5; // cache expired → MUST re-fetch, and therefore MUST re-check
    await expect(f.fetch("https://flip.evil/terms")).rejects.toThrow(
      /non-public|unicast/i,
    );
    expect(lookups).toBe(2);
  });

  it("caps an UNDECLARED body while streaming — never buffers past the cap", async () => {
    // No content-length: the pre-check cannot fire, so the cap must be enforced chunk by chunk. A
    // post-read check would have already materialised the whole body in memory.
    let pushed = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        // Bounded so an unguarded reader terminates instead of OOMing the worker — a real hostile
        // server would simply not stop.
        if (pushed >= 256 * 1024) return c.close();
        pushed += 1024;
        c.enqueue(new Uint8Array(1024));
      },
    });
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response(body)) as never,
      now: () => "2025-01-01T00:00:00Z",
      maxBytes: 4096,
      lookup: publicLookup,
    });
    await expect(f.fetch("https://s.example/terms")).rejects.toThrow(/bytes/);
    expect(pushed).toBeLessThan(64 * 1024); // aborted early, not drained
  });
});

/**
 * The BOUNDARIES and the fallbacks. The suites above prove each guard fires; these pin exactly WHERE it
 * fires and what happens when an input is merely absent rather than hostile. The distinctions are one
 * character wide — `>` vs `>=` on the byte cap, the cache window and the eviction threshold; `-` vs `+` on
 * the cache-age arithmetic; the `??` fallback for a missing content-type — and each is the difference
 * between a cap that admits its own limit and one that rejects it.
 */
describe("makeCachingFetcher — the exact boundaries", () => {
  const at = (n: number) => new Uint8Array(n);

  it("a body EXACTLY at maxBytes is accepted; one byte more is refused", async () => {
    const mk = (size: number) =>
      makeCachingFetcher({
        httpFetch: (async () => new Response(at(size))) as never,
        now: () => "2025-01-01T00:00:00Z",
        maxBytes: 1000,
        lookup: publicHost,
      });
    const ok = await mk(1000).fetch("https://s.example/a");
    expect(ok.bytes.length).toBe(1000);
    await expect(mk(1001).fetch("https://s.example/b")).rejects.toThrow(
      /1000 bytes/,
    );
  });

  it("a DECLARED content-length exactly at maxBytes is accepted; one more is refused pre-read", async () => {
    const mk = (declared: string) =>
      makeCachingFetcher({
        httpFetch: (async () =>
          new Response(at(10), {
            headers: { "content-length": declared },
          })) as never,
        now: () => "2025-01-01T00:00:00Z",
        maxBytes: 1000,
        lookup: publicHost,
      });
    await expect(
      mk("1000").fetch("https://s.example/a"),
    ).resolves.toBeDefined();
    await expect(mk("1001").fetch("https://s.example/b")).rejects.toThrow(
      /declare 1001/,
    );
  });

  it("a non-numeric content-length is ignored rather than refused — the streaming cap still governs", async () => {
    // Number("banana") is NaN, so the pre-check must fall through to the stream cap instead of throwing
    // on a header the server got wrong.
    const f = makeCachingFetcher({
      httpFetch: (async () =>
        new Response(at(10), {
          headers: { "content-length": "banana" },
        })) as never,
      now: () => "2025-01-01T00:00:00Z",
      maxBytes: 1000,
      lookup: publicHost,
    });
    await expect(f.fetch("https://s.example/a")).resolves.toBeDefined();
  });

  it("an ABSENT content-length is fine — the guard requires the header, not its presence", async () => {
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response(at(10))) as never,
      now: () => "2025-01-01T00:00:00Z",
      maxBytes: 1000,
      lookup: publicHost,
    });
    await expect(f.fetch("https://s.example/a")).resolves.toBeDefined();
  });

  it("a cache entry exactly AT maxAge is stale — the window is strictly less-than", async () => {
    let calls = 0;
    let t = 0;
    const f = makeCachingFetcher({
      httpFetch: (async () => {
        calls++;
        return new Response(at(4));
      }) as never,
      now: () => new Date(t * 1000).toISOString(),
      maxAgeSeconds: 100,
      lookup: publicHost,
    });
    await f.fetch("https://s.example/a");
    expect(calls).toBe(1);
    t = 99; // inside the window
    await f.fetch("https://s.example/a");
    expect(calls).toBe(1);
    t = 100; // exactly at it — MUST re-fetch
    await f.fetch("https://s.example/a");
    expect(calls).toBe(2);
  });

  it("cache age is elapsed time, not a sum — a later clock must not read as fresher", async () => {
    // `nowS + hit.at` instead of `nowS - hit.at` would make every entry look instantly stale (or fresh,
    // depending on epoch), which no existing test distinguishes because both clocks start near zero.
    let calls = 0;
    let t = 1_000_000;
    const f = makeCachingFetcher({
      httpFetch: (async () => {
        calls++;
        return new Response(at(4));
      }) as never,
      now: () => new Date(t * 1000).toISOString(),
      maxAgeSeconds: 100,
      lookup: publicHost,
    });
    await f.fetch("https://s.example/a");
    t = 1_000_050; // 50s later, well inside a 100s window
    await f.fetch("https://s.example/a");
    expect(calls).toBe(1);
  });

  it("keeps exactly maxEntries and evicts only once the count EXCEEDS it", async () => {
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response(at(4))) as never,
      now: () => "2025-01-01T00:00:00Z",
      maxEntries: 2,
      lookup: publicHost,
    });
    await f.fetch("https://s.example/1");
    await f.fetch("https://s.example/2");
    // Both still cached: a third fetch of /1 must not hit the network.
    let networked = 0;
    const g = makeCachingFetcher({
      httpFetch: (async () => {
        networked++;
        return new Response(at(4));
      }) as never,
      now: () => "2025-01-01T00:00:00Z",
      maxEntries: 2,
      lookup: publicHost,
    });
    await g.fetch("https://s.example/1");
    await g.fetch("https://s.example/2");
    await g.fetch("https://s.example/1");
    expect(networked).toBe(2); // /1 served from cache, not evicted at exactly maxEntries
  });
});

describe("makeCachingFetcher — absent and degenerate responses", () => {
  it("defaults the format when the server sends no content-type", async () => {
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response(new Uint8Array(4))) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
    });
    const terms = await f.fetch("https://s.example/a");
    expect(terms.format).toBe("application/octet-stream");
  });

  it("carries the server's content-type through when it sends one", async () => {
    const f = makeCachingFetcher({
      httpFetch: (async () =>
        new Response(new Uint8Array(4), {
          headers: { "content-type": "application/json" },
        })) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
    });
    expect((await f.fetch("https://s.example/a")).format).toBe(
      "application/json",
    );
  });

  it("a null body yields zero bytes rather than throwing", async () => {
    // A 204 has no body at all. Refusing it would be wrong; mis-assembling it would be worse.
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response(null, { status: 204 })) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
    });
    expect((await f.fetch("https://s.example/a")).bytes).toEqual(
      new Uint8Array(0),
    );
  });

  it("a non-ok response fails loudly with its status", async () => {
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response("nope", { status: 503 })) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
    });
    await expect(f.fetch("https://s.example/a")).rejects.toThrow(/503/);
  });

  it("a host that resolves to NO address is refused, not treated as public", async () => {
    // An empty answer means the guard proved nothing. Falling through would invert the whole posture:
    // the loop over addresses is vacuously satisfied by an empty list.
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response(new Uint8Array(4))) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: async () => [],
    });
    await expect(f.fetch("https://s.example/a")).rejects.toThrow(/no address/);
  });

  it("reassembles a multi-chunk body in order", async () => {
    // The copy loop advances an offset per chunk; a sign flip or a wrong stride corrupts the bytes while
    // still producing a correctly-sized buffer, which no length assertion would catch.
    const parts = [
      Uint8Array.of(1, 2),
      Uint8Array.of(3, 4, 5),
      Uint8Array.of(6),
    ];
    let i = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(c) {
        const p = parts[i++];
        if (p === undefined) return c.close();
        c.enqueue(p);
      },
    });
    const f = makeCachingFetcher({
      httpFetch: (async () => new Response(body)) as never,
      now: () => "2025-01-01T00:00:00Z",
      lookup: publicHost,
    });
    const terms = await f.fetch("https://s.example/a");
    expect(Array.from(terms.bytes)).toEqual([1, 2, 3, 4, 5, 6]);
  });
});

describe("nodeDnsLookup — the Node adapter for the host guard", () => {
  it("resolves a real public hostname to at least one address", async () => {
    // The lazy `node:dns/promises` import is the whole point of this export: the gate must stay
    // runtime-neutral, so the module is pulled only when a Node deployment actually calls this.
    const addrs = await nodeDnsLookup("localhost");
    expect(Array.isArray(addrs)).toBe(true);
    expect(addrs.length).toBeGreaterThan(0);
    expect(typeof addrs[0]?.address).toBe("string");
  });
});
