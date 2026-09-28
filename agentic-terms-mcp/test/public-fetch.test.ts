// The binary's fetch. Which addresses are public comes from the IANA IPv4 and IPv6 Special-Purpose Address Registries
// (RFC 6890 and its updates): every block whose "Globally Reachable" is False, with the private-use blocks of RFC 1918,
// the shared space of RFC 6598, the unique-local block of RFC 4193, and the link-local, loopback and multicast blocks of
// RFC 4291 and RFC 5771. The public examples are addresses outside every such block. The loopback servers stand in for
// services on the host's own addresses.
import { createServer as createHttpServer, request as httpRequest, type Server } from "node:http";
import { createServer as createTcpServer, type AddressInfo, type LookupFunction, type Server as TcpServer } from "node:net";
import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { confirm } from "@integraledger/terms";
import { exactEip3009 } from "@integraledger/lcp/x402";
import { fetchVia, isPublicAddress, publicFetch, publicLookup, type Resolve } from "../src/public-fetch.js";

const NOT_PUBLIC = [
  "0.0.0.0", "0.255.255.255", // "this network"
  "10.0.0.1", "10.255.255.255", // private-use
  "100.64.0.1", "100.127.255.255", // shared address space
  "127.0.0.1", "127.255.255.254", // loopback
  "169.254.169.254", // link-local
  "172.16.0.1", "172.31.255.255", // private-use
  "192.0.0.8", // IETF protocol assignments
  "192.0.2.1", "198.51.100.7", "203.0.113.9", // documentation
  "192.88.99.1", // 6to4 relay anycast
  "192.168.1.1", // private-use
  "198.18.0.1", "198.19.255.255", // benchmarking
  "224.0.0.1", "239.255.255.250", // multicast
  "240.0.0.1", "255.255.255.255", // reserved, limited broadcast
  "::", "::1", // unspecified, loopback
  "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:a9fe:a9fe", // IPv4-mapped non-public addresses
  "64:ff9b::a00:1", "64:ff9b::7f00:1", // NAT64 of non-public IPv4 addresses
  "64:ff9b:1::1", // local-use NAT64
  "100::1", // discard-only
  "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", // IETF protocol assignments, Teredo
  "2001:db8::1", "3fff::1", // documentation
  "2002:c000:204::1", // 6to4
  "fc00::1", "fd12:3456:789a::1", // unique-local
  "fe80::1", "febf::1", // link-local
  "fec0::1", // site-local
  "ff02::1", // multicast
];
const PUBLIC = [
  "1.1.1.1", "8.8.8.8", "9.9.9.9",
  "100.63.255.255", "100.128.0.0", // either side of the shared address space
  "172.15.255.255", "172.32.0.0", // either side of 172.16.0.0/12
  "192.167.255.255", "192.169.0.0", // either side of 192.168.0.0/16
  "2606:4700:4700::1111", "2001:4860:4860::8888",
  "2001:200::1", // just past 2001::/23
  "::ffff:1.1.1.1", "::ffff:101:101", // IPv4-mapped public addresses
  "64:ff9b::101:101", // NAT64 of 1.1.1.1
];

describe("isPublicAddress", () => {
  it.each(NOT_PUBLIC)("%s is not public", (address) => expect(isPublicAddress(address)).toBe(false));
  it.each(PUBLIC)("%s is public", (address) => expect(isPublicAddress(address)).toBe(true));
  it.each(["localhost", "atr.seller.example", "", "1.1.1", "fe80::1%eth0", "[::1]"])(
    "%j is not an address, so not public",
    (text) => expect(isPublicAddress(text)).toBe(false),
  );
});

/** A resolver that answers `addresses` for every host. */
const resolving = (...addresses: string[]): Resolve => (_host, _options, callback) =>
  callback(null, addresses.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));

/** The lookup's answer: its error, or what it resolved to. */
function answerOf(lookup: LookupFunction, all: boolean): Promise<{ err: Error | null; address: unknown; family: number | undefined }> {
  return new Promise((resolve) =>
    lookup("atr.seller.example", { all }, (err, address, family) => resolve({ err, address, family })),
  );
}

describe("publicLookup", () => {
  it("answers every address when each is public", async () => {
    const lookup = publicLookup(resolving("1.1.1.1", "2606:4700:4700::1111"));
    expect(await answerOf(lookup, true)).toMatchObject({
      err: null,
      address: [{ address: "1.1.1.1", family: 4 }, { address: "2606:4700:4700::1111", family: 6 }],
    });
    expect(await answerOf(lookup, false)).toMatchObject({ err: null, address: "1.1.1.1", family: 4 });
  });

  it.each([["10.0.0.1"], ["1.1.1.1", "127.0.0.1"], ["2606:4700:4700::1111", "fd00::1"], []])(
    "refuses a host that resolves to %j",
    async (...addresses) => {
      const { err } = await answerOf(publicLookup(resolving(...addresses)), true);
      expect(err).toBeInstanceOf(Error);
      expect((err as NodeJS.ErrnoException).code).toBe("ENOTPUBLIC");
    },
  );

  it("passes a resolver's error through", async () => {
    const failing: Resolve = (_h, _o, callback) => callback(Object.assign(new Error("no such host"), { code: "ENOTFOUND" }), []);
    expect((await answerOf(publicLookup(failing), false)).err).toMatchObject({ code: "ENOTFOUND" });
  });
});

describe("publicFetch", () => {
  let tcp: TcpServer;
  let port = 0;
  let connections = 0;
  beforeAll(async () => {
    tcp = createTcpServer((socket) => {
      connections++;
      socket.destroy();
    });
    await new Promise<void>((resolve) => tcp.listen(0, "127.0.0.1", resolve));
    port = (tcp.address() as AddressInfo).port;
  });
  afterAll(() => new Promise<void>((resolve) => tcp.close(() => resolve())));

  const init = () => ({ method: "GET" as const, redirect: "manual" as const, signal: AbortSignal.timeout(5_000) });

  it.each(["https://127.0.0.1:PORT/atr", "https://[::1]:PORT/atr", "https://[::ffff:127.0.0.1]:PORT/atr", "https://0x7f.1:PORT/atr"])(
    "refuses %s before any connection",
    async (link) => {
      const before = connections;
      await expect(publicFetch(link.replace("PORT", String(port)), init())).rejects.toMatchObject({ code: "ENOTPUBLIC" });
      expect(connections).toBe(before);
    },
  );

  it("refuses a host name that resolves to loopback before any connection", async () => {
    const before = connections;
    await expect(publicFetch(`https://localhost:${port}/atr`, init())).rejects.toMatchObject({ code: "ENOTPUBLIC" });
    expect(connections).toBe(before);
  });

  it("refuses any scheme but https", async () => {
    await expect(publicFetch(`http://localhost:${port}/atr`, init())).rejects.toBeInstanceOf(TypeError);
  });

  it("gives the gate a link it cannot fetch: atr-unfetchable, with no connection made", async () => {
    const before = connections;
    const h = "0x8b1e122580ae3f6a8c3d36a24294e1260a87bde70f597279b973e39310072938";
    const offer = {
      x402Version: 2,
      resource: { url: "https://api.seller.example/v1/quote" },
      accepts: [
        {
          scheme: "exact",
          network: "eip155:84532",
          amount: "10000",
          asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          payTo: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
          maxTimeoutSeconds: 60,
          extra: { name: "USDC", version: "2" },
        },
      ],
      extensions: {
        legalContext: { info: { type: "sha256", value: h, legalContextUrl: `https://localhost:${port}/${h}` }, schema: {} },
      },
    };
    const out = await confirm(offer, exactEip3009, "eip155:84532:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", publicFetch);
    expect(out).toEqual({ decline: { code: "atr-unfetchable", detail: "The ATR could not be fetched from the link." } });
    expect(connections).toBe(before);
  });
});

describe("fetchVia", () => {
  const ATR = new TextEncoder().encode('{"atrVersion":"1"}');
  let server: Server;
  let base = "";
  const seen: { acceptEncoding: string | undefined }[] = [];
  beforeAll(async () => {
    server = createHttpServer((req, res) => {
      seen.push({ acceptEncoding: req.headers["accept-encoding"] });
      if (req.url === "/gzip") {
        res.writeHead(200, { "content-encoding": "gzip", "x-served": "gzip" });
        res.end(gzipSync(ATR));
      } else if (req.url === "/moved") {
        res.writeHead(302, { location: "/atr" });
        res.end();
      } else if (req.url === "/empty") {
        res.writeHead(204);
        res.end();
      } else if (req.url === "/hang") {
        res.writeHead(200);
        res.write("{");
      } else {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(ATR);
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => {
    server.closeAllConnections();
    return new Promise<void>((resolve) => server.close(() => resolve()));
  });

  // Over plain http to a loopback address, which no lookup is asked about: this block reads how a response is
  // converted. `via` resolves every host name to loopback, which its lookup refuses.
  const via = fetchVia(httpRequest as never, publicLookup(resolving("127.0.0.1")));
  const plain = fetchVia(httpRequest as never, publicLookup());
  const init = (headers?: Record<string, string>) => ({
    method: "GET" as const,
    redirect: "manual" as const,
    signal: AbortSignal.timeout(5_000),
    ...(headers === undefined ? {} : { headers }),
  });

  it("uses the lookup it is given for a host name", async () => {
    await expect(via(`http://seller.test:1/atr`, init())).rejects.toMatchObject({ code: "ENOTPUBLIC" });
  });

  it("returns the status, headers and body as sent, with the request's own headers", async () => {
    const r = await plain(`${base}/atr`, init({ "Accept-Encoding": "identity" }));
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("application/json");
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(ATR);
    expect(seen.at(-1)!.acceptEncoding).toBe("identity");
  });

  it("decodes nothing: a gzip body arrives as the gzip bytes, with its Content-Encoding", async () => {
    const r = await plain(`${base}/gzip`, init({ "Accept-Encoding": "identity" }));
    expect(r.headers.get("content-encoding")).toBe("gzip");
    expect(new Uint8Array(await r.arrayBuffer())).toEqual(new Uint8Array(gzipSync(ATR)));
  });

  it("returns a redirect unfollowed, and a 204 with no body", async () => {
    const moved = await plain(`${base}/moved`, init());
    expect(moved.status).toBe(302);
    expect(moved.headers.get("location")).toBe("/atr");
    const empty = await plain(`${base}/empty`, init());
    expect(empty.status).toBe(204);
    expect(empty.body).toBeNull();
  });

  it("rejects when the signal aborts, before or during the body", async () => {
    const aborted = AbortSignal.abort(new Error("stop"));
    await expect(plain(`${base}/atr`, { method: "GET", redirect: "manual", signal: aborted })).rejects.toThrow("stop");
    const controller = new AbortController();
    const r = await plain(`${base}/hang`, { method: "GET", redirect: "manual", signal: controller.signal });
    const reading = r.arrayBuffer();
    controller.abort(new Error("deadline"));
    await expect(reading).rejects.toBeDefined();
  });
});
