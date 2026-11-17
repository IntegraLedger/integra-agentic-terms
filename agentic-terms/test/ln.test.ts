// x402/exact/lnbtc/payment-hash's buyer piece, and the summary of the bolt11-pay request the Lightning pairings hand the
// buyer's node, over the protocol package's x402-exact-lnbtc.json, mpp-charge-lightning.json and
// mpp-session-lightning.json. Every input and expected value is those files': x402's scheme text (the option, its
// invoice, the buyer's request, the preimage, the payment, the validation time and the client's refusals) and invoices
// bolt11 1.4.1 wrote and signed and light-bolt11-decoder 3.2.0 read back, with the fields they were written with and the
// key that signed them. The request is given as the piece's `request` input: the file's request, its body as `0x` hex.
import { afterEach, describe, expect, it } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { exactLnbtcPaymentHash } from "@integraledger/lcp/lightning";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { finish, type Binding, type Inputs, type Presented } from "../src/index.js";
import { summaryOf } from "../src/summary.js";
import { ABC, buildAndSign, isDeclined, LINK, pieceConfirm, vectors, type Pairing } from "./support.js";

type Request = Record<string, unknown>;
interface Lnbtc {
  fixed: {
    H: AtrHash;
    now: number;
    payee: string;
    preimage: string;
    request: Request;
    x402Invoice: string;
    O: PaymentRequirements;
    required: PaymentRequired;
    P: Presented;
  };
  build: {
    rows: { case: string; set: Record<string, unknown>; expect: string }[];
    complete: { case: string; preimage: string; expect: string }[];
  };
  invoices: Record<string, { case: string; encode: Encoded; invoice: string; signer: string }>;
  L4: Decoded & { invoice: string };
}
interface Encoded {
  bech32: string;
  millisatoshis: string;
  timestamp: number;
  tags: { tagName: string; data: unknown }[];
}
interface Decoded {
  expect: { currency: string; amountMsat: string; timestamp: number; expiry: number };
  expectPayee: string;
}

const V = vectors<Lnbtc>("x402-exact-lnbtc.json");
const L2 = vectors<{ L2: Decoded & { invoice: string } }>("mpp-charge-lightning.json").L2;
const S1 = vectors<{ S1: { request: { depositInvoice: string } } }>("mpp-session-lightning.json").S1;
const f = V.fixed;
const binding = exactLnbtcPaymentHash as unknown as Binding;
const MAINNET = "lnbtc:000000000019d6689c085ae165831e93";
const ACCOUNT = `${MAINNET}:${f.payee}`;

/** The file's request as the piece's `request` input: its `bodyHex` as `body`, `0x` hex. */
function input(request: Request): Inputs {
  const { bodyHex, ...rest } = request;
  return { request: (bodyHex === undefined ? rest : { ...rest, body: `0x${bodyHex as string}` }) as never };
}

/** `value` with the member at the dotted `path` set to `to`. */
function set<T>(value: T, path: string, to: unknown): T {
  const [head, ...rest] = path.split(".");
  const v = value as Record<string, unknown>;
  return { ...v, [head!]: rest.length === 0 ? to : set(v[head!], rest.join("."), to) } as T;
}

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});
const at = (now: number) => {
  Date.now = () => now * 1000;
};

describe("x402/exact/lnbtc/payment-hash: the client's checks before the node pays, through the piece", () => {
  for (const row of V.build.rows) {
    it(`${row.case}: ${row.expect}`, async () => {
      let given = { now: f.now, request: f.request, required: f.required as unknown };
      for (const [path, to] of Object.entries(row.set)) given = set(given, path, to);
      at(given.now);
      const out = await pieceConfirm(structuredClone(given.required), binding, ACCOUNT, input(given.request));
      if (row.expect === "served") {
        if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
        expect(out.request).toEqual({ kind: "bolt11-pay", invoice: f.x402Invoice });
      } else {
        expect(isDeclined(out) ? out.decline.detail : "served").toBe(row.expect);
      }
    });
  }

  it("the node's preimage completes fixed.P; each complete row's preimage is refused, the payment kept as moved", async () => {
    at(f.now);
    const out = await pieceConfirm(structuredClone(f.required), binding, ACCOUNT, input(f.request));
    if (isDeclined(out)) throw new Error(out.decline.code);
    const paid = await finish(ABC, out.chosen, f.preimage, binding);
    expect(paid).toEqual({ signed: f.P, h: f.H });
    for (const row of V.build.complete) {
      const refused = await finish(ABC, out.chosen, row.preimage, binding);
      if (!isDeclined(refused)) throw new Error(`${row.case}: completed`);
      expect([refused.decline.code, refused.decline.detail, refused.moved?.signed]).toEqual(["signed-not-bound", row.expect, row.preimage]);
    }
  });
});

describe("x402/exact/lnbtc/payment-hash: B6 by its own steps, then through the gate over A", () => {
  const placed = (h: AtrHash): unknown => {
    const doc = { x402Version: 2, resource: f.required.resource, accepts: [f.O] };
    const out = (exactLnbtcPaymentHash.advertise as (...a: unknown[]) => unknown)(doc, h, LINK, f.O);
    if (isDeclined(out) || (typeof out === "object" && out !== null && "refused" in out)) throw new Error(JSON.stringify(out));
    return out;
  };
  const p: Pairing = {
    binding,
    doc: f.required,
    placed,
    account: ACCOUNT,
    inputs: input(f.request),
    answer: async () => f.preimage,
  };
  it("the node is handed the scheme's invoice; its preimage completes fixed.P, bound to H", async () => {
    at(f.now);
    const { signed } = await buildAndSign(p, (r) => expect(r).toEqual({ kind: "bolt11-pay", invoice: f.x402Invoice }));
    expect(signed).toEqual(f.P);
  });
});

describe("bolt11-pay's summary", () => {
  /** The summary bolt11 1.4.1's encode inputs give: its amount, its signer, its creation time and expiry. */
  const fromEncode = (e: Encoded, signer: string) => {
    const expiry = e.tags.find((t) => t.tagName === "expire_time")!.data as number;
    return {
      amount: e.millisatoshis,
      payees: [{ account: signer, amount: e.millisatoshis }],
      asset: "BTC",
      network: MAINNET,
      validity: { notBefore: String(e.timestamp), notAfter: String(e.timestamp + expiry), unit: "seconds" },
      atr: ABC,
    };
  };
  const fromDecoded = (d: Decoded) => ({
    amount: d.expect.amountMsat,
    payees: [{ account: d.expectPayee, amount: d.expect.amountMsat }],
    asset: "BTC",
    network: MAINNET,
    validity: { notBefore: String(d.expect.timestamp), notAfter: String(d.expect.timestamp + d.expect.expiry), unit: "seconds" },
    atr: ABC,
  });
  const show = (pairing: string, invoice: string) => summaryOf(pairing, { kind: "bolt11-pay", invoice } as never, ABC, MAINNET);

  for (const [name, row] of Object.entries(V.invoices).filter(([name]) => name !== "noS")) {
    it(`x402-exact-lnbtc.json invoices.${name}: ${row.case}`, async () => {
      expect(row.encode.bech32).toBe("bc");
      expect(await show("x402/exact/lnbtc/payment-hash", row.invoice)).toEqual(fromEncode(row.encode, row.signer));
    });
  }
  it("x402-exact-lnbtc.json invoices.noS, which the decoder refuses (ln/invoice-malformed): none", async () => {
    expect(await show("x402/exact/lnbtc/payment-hash", V.invoices["noS"]!.invoice)).toBeUndefined();
  });
  it("x402-exact-lnbtc.json L4, its m field H: its decoded fields and payee", async () => {
    expect(V.L4.expect.currency).toBe("bc");
    expect(await show("x402/exact/lnbtc/payment-hash", V.L4.invoice)).toEqual(fromDecoded(V.L4));
  });
  it("mpp-charge-lightning.json L2, the charge's invoice: its decoded fields and payee", async () => {
    expect(L2.expect.currency).toBe("bc");
    expect(await show("mpp/charge/lightning", L2.invoice)).toEqual(fromDecoded(L2));
  });
  it("mpp-session-lightning.json S1's deposit invoice, L2: as the charge's, its amount the deposit", async () => {
    expect(S1.request.depositInvoice).toBe(L2.invoice);
    expect(await show("mpp/session/lightning", S1.request.depositInvoice)).toEqual({ ...fromDecoded(L2), deposit: L2.expect.amountMsat });
  });
});
