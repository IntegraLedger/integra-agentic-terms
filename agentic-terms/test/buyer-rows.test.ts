// Every vector file's `buyer` group, run through the gate. B2, the plant: `transact` with a counting signer over the
// row's document, account, inputs and clock, the link serving the planted ATR, declines hash-mismatch and never calls
// the signer; `confirm` declines the same and returns no request. B6: `check` over the file's signed payment gives H
// for the ATR and declines signed-not-bound for the planted ATR. Every expected value, and every input, is the row's.
//
// buyer.json's rows that call one gate function (B19 to B22) and its within rows (BW1 to BW4), each found by its name:
// the documents, holds and signers are those the rows name, and a row's cases share its input and expect except where
// a case gives its own. A BW row's hold is what openChannel gives for the row's ATR and the opening it names.
import { readdirSync, readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import {
  check,
  confirm,
  finish,
  openChannel,
  transact,
  within,
  type Binding,
  type ChannelHold,
  type Declined,
  type Fetch,
  type Inputs,
  type Presented,
  type Signature,
} from "../src/index.js";
import { counting, vectors } from "./support.js";

interface Row {
  name: string;
  pairing: string;
  input: {
    doc?: unknown;
    servesHex?: string;
    account?: string;
    inputs?: Inputs;
    now?: number;
    presented?: unknown;
    check?: { bytesHex: string }[];
  };
  expect: unknown;
}

const dir = new URL("../node_modules/@integraledger/lcp/vectors/", import.meta.url);
const rows: { file: string; row: Row }[] = readdirSync(dir)
  .filter((n) => n.endsWith(".json"))
  .sort()
  .flatMap((file) => {
    const data = JSON.parse(readFileSync(new URL(file, dir), "utf8")) as { buyer?: { rows: Row[] } };
    return (data.buyer?.rows ?? []).map((row) => ({ file, row }));
  });
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, "hex"));
const bindingOf = (id: string): Binding => {
  const b = BINDINGS.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};

/** A fetch that serves `bytes` for every URL and counts its calls. */
function serving(bytes: Uint8Array): Fetch & { calls: number } {
  const f = (async () => {
    f.calls++;
    return new Response(new Uint8Array(bytes), { status: 200 });
  }) as unknown as Fetch & { calls: number };
  f.calls = 0;
  return f;
}

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

describe("every vector file's buyer rows, through the gate", () => {
  it("the files hold a B2 for every pairing the protocol package serves", () => {
    const b2 = new Set(rows.filter(({ row }) => row.name === "B2").map(({ row }) => row.pairing));
    expect([...b2].sort()).toEqual(BINDINGS.map((b) => b.id as string).sort());
  });

  for (const { file, row } of rows.filter(({ row }) => row.name === "B2")) {
    it(`${file} B2 ${row.pairing}: hash-mismatch, and the signer is never called`, async () => {
      if (row.input.now !== undefined) {
        const now = row.input.now;
        Date.now = () => now * 1000;
      }
      const binding = bindingOf(row.pairing);
      const inputs = row.input.inputs ?? {};
      const signer = counting(row.input.account!, async () => {
        throw new Error("the signer is never called on a plant");
      });
      const served = fromHex(row.input.servesHex!);
      const out = await transact(structuredClone(row.input.doc), binding, signer, serving(served), { inputs });
      const expected = row.expect as { decline: string; signCalls: number };
      expect("decline" in out ? out.decline.code : "signed").toBe(expected.decline);
      expect(signer.requests.length).toBe(expected.signCalls);
      const fetch = serving(served);
      const confirmed = await confirm(structuredClone(row.input.doc), binding, row.input.account!, fetch, inputs);
      expect("decline" in confirmed ? confirmed.decline.code : "confirmed").toBe(expected.decline);
      expect(confirmed).not.toHaveProperty("request");
      expect(fetch.calls).toBe(1);
    });
  }

  for (const { file, row } of rows.filter(({ row }) => row.name === "B6")) {
    it(`${file} B6 ${row.pairing}: check gives H for the ATR, and signed-not-bound for the planted ATR`, async () => {
      const binding = bindingOf(row.pairing);
      const got = [];
      for (const c of row.input.check!) {
        const out = await check(fromHex(c.bytesHex), structuredClone(row.input.presented), binding);
        got.push("decline" in out ? { decline: out.decline.code } : out);
      }
      expect(got).toEqual(row.expect);
    });
  }
});

type Expect = { decline?: string; detail?: string; fetches?: number; signCalls?: number; signedPayload?: Record<string, string> };
interface EntryRow {
  name: string;
  input: {
    entry?: string;
    pairing?: string;
    doc?: unknown;
    hold?: { opening: string; atrHex: string; network: string; channel: string } | string;
    now?: number;
    opaqueText?: string;
    refund?: { amount?: string };
    inputs?: unknown;
    cases?: ({ case: string; expect?: Expect } & Record<string, unknown>)[];
  } & Record<string, unknown>;
  expect: Expect;
  control?: { input: Record<string, unknown>; expect: Expect } | string;
}

const BUYER = vectors<{ rows: EntryRow[]; fixed: Record<string, any> }>("buyer.json");
const named = (name: string): EntryRow => {
  const found = BUYER.rows.find((r) => r.name === name);
  if (found === undefined) throw new Error(`buyer.json holds no row ${name}`);
  return found;
};
const D = BUYER.fixed["D"];
const A = fromHex(BUYER.fixed["A"]);
const B6_SIGNATURE = (named("B6").expect as { signature: Signature }).signature;
/** A file's buyer row of `pairing`, by its name. */
const buyerRow = (file: string, pairing: string, name: string): Row => {
  const found = rows.find((r) => r.file === file && r.row.pairing === pairing && r.row.name === name);
  if (found === undefined) throw new Error(`${file} holds no buyer row ${name} for ${pairing}`);
  return found.row;
};

/** A signer whose every answer is a stand-in of a signature's form, recording each request: the rows count its calls.
 * An EIP-712 answer is 65 bytes of hex; any other is 64 zero bytes in base58. */
function standIn(account: string) {
  const one = (r: { kind: string }): Signature => (r.kind === "eip712" ? `0x${"11".repeat(65)}` : "1".repeat(64)) as Signature;
  return counting(account, async (r) => (r.kind === "batch" ? (r.requests.map(one) as unknown as Signature) : one(r)));
}

/** Each run a row asks for: every case, or the row itself, with the case's members over the row's. */
function runsOf(r: EntryRow): { case: string; input: EntryRow["input"]; expect: Expect }[] {
  const { cases, ...shared } = r.input;
  return (cases ?? [{ case: r.name }]).map(({ case: label, expect: own, ...given }) => ({
    case: label,
    input: { ...shared, ...given },
    expect: { ...r.expect, ...own },
  }));
}

/** The decline's code and detail, the fetches and the signer calls a row expects, against what the call did. */
function compare(where: string, e: Expect, out: unknown, fetches: number, signCalls: number): void {
  const reason = (out as Declined).decline;
  expect(reason?.code, where).toBe(e.decline);
  if (e.detail !== undefined) expect(reason?.detail, where).toBe(e.detail);
  if (e.fetches !== undefined) expect(fetches, where).toBe(e.fetches);
  if (e.signCalls !== undefined) expect(signCalls, where).toBe(e.signCalls);
}

describe("buyer.json's rows through one gate function", () => {
  const account: string = BUYER.fixed["account"];

  it("B19: finish compares chosen's pairing with the binding before it rebuilds anything", async () => {
    const r = named("B19");
    expect([r.input.entry, r.input["binding"]]).toEqual(["finish", "x402/exact/eip155/permit2"]);
    const confirmed = await confirm(structuredClone(D), bindingOf("x402/exact/eip155/eip3009"), account, serving(A));
    if ("decline" in confirmed) throw new Error(confirmed.decline.code);
    const signer = standIn(account);
    const out = await finish(A, confirmed.chosen, B6_SIGNATURE, bindingOf(r.input["binding"] as string));
    compare("B19", r.expect, out, 0, signer.requests.length);
  });

  it("B20: confirm declines inputs given and not an object before the link is fetched", async () => {
    const r = named("B20");
    expect(r.input.entry).toBe("confirm");
    const runs = runsOf(r);
    expect(runs.length).toBeGreaterThan(0);
    for (const run of runs) {
      const fetch = serving(A);
      const signer = standIn(account);
      const out = await confirm(structuredClone(D), bindingOf("x402/exact/eip155/eip3009"), account, fetch, run.input.inputs as Inputs);
      compare(`B20, ${run.case}`, run.expect, out, fetch.calls, signer.requests.length);
    }
  });

  // B21's and B22's documents are D as each row describes it: its one option on eip155:0, and its link 2049 UTF-16
  // code units long, 2048 code points, ending in U+10000.
  const link22 = `https://atr.seller.example/${"a".repeat(2020)}\u{10000}`;
  const docs: Record<string, () => unknown> = {
    B21: () => ({ ...D, accepts: [{ ...D.accepts[0], network: "eip155:0" }] }),
    B22: () => {
      const lc = D.extensions.legalContext;
      return { ...D, extensions: { ...D.extensions, legalContext: { ...lc, info: { ...lc.info, legalContextUrl: link22 } } } };
    },
  };
  it("B22's link is 2049 UTF-16 code units and 2048 code points", () => {
    expect([link22.length, [...link22].length]).toEqual([2049, 2048]);
  });
  for (const name of ["B21", "B22"]) {
    it(`${name}: transact declines the offer before any fetch or signer call`, async () => {
      const r = named(name);
      const fetch = serving(A);
      const signer = standIn(account);
      const out = await transact(docs[name]!(), bindingOf("x402/exact/eip155/eip3009"), signer, fetch);
      compare(name, r.expect, out, fetch.calls, signer.requests.length);
    });
  }
});

describe("buyer.json's within rows", () => {
  /** The hold a BW row names, and the row that gives it, with its network and channel as the row states them. */
  async function holdOf(r: EntryRow): Promise<{ hold: ChannelHold; binding: Binding }> {
    const spec = (typeof r.input.hold === "string" ? named(r.input.hold.replace(/^as /, "")).input.hold : r.input.hold) as {
      opening: string;
      atrHex: string;
      network: string;
      channel: string;
    };
    const [file, , , name] = spec.opening.split(" ");
    const binding = bindingOf(r.input.pairing!);
    const opening = buyerRow(file!, r.input.pairing!, name!.replace(/,$/, "")).input.presented as Presented;
    const hold = await openChannel(fromHex(spec.atrHex), structuredClone(opening), binding);
    if ("decline" in hold) throw new Error(hold.decline.code);
    expect([hold.network, hold.channel]).toEqual([spec.network, spec.channel]);
    return { hold, binding };
  }

  /** The document a BW row's run names: its own challenges, whose opaque is its opaqueText, or the x402 document of
   * the buyer row it names. */
  function docOf(r: EntryRow, input: EntryRow["input"]): unknown {
    if (Array.isArray(input.doc)) {
      const opaque = (input.doc as { opaque: string }[])[0]!.opaque;
      expect(Buffer.from(opaque, "base64url").toString("utf8")).toBe(input.opaqueText);
      return structuredClone(input.doc);
    }
    const [file, , , name] = (input.doc as string).split(" ");
    return structuredClone(buyerRow(file!, r.input.pairing!, name!).input.doc);
  }

  async function play(r: EntryRow, where: string, input: EntryRow["input"], e: Expect & { signedPayload?: Record<string, string> }) {
    const { hold, binding } = await holdOf(r);
    const signer = standIn(BUYER.fixed["account"]);
    const realNow = Date.now;
    if (input.now !== undefined) Date.now = () => input.now! * 1000;
    try {
      const out = await within(docOf(r, input), hold, binding, signer, input.refund, input.inputs as Inputs);
      compare(where, e, out, 0, signer.requests.length);
      if (e.signedPayload !== undefined) {
        expect((out as { signed: { payload: unknown } }).signed.payload, where).toMatchObject(e.signedPayload);
      }
    } finally {
      Date.now = realNow;
    }
  }

  for (const name of ["BW1", "BW2", "BW3", "BW4"]) {
    it(`${name}: within declines before the build and the signer call`, async () => {
      const r = named(name);
      const runs = runsOf(r);
      expect(runs.length).toBeGreaterThan(0);
      for (const run of runs) await play(r, `${name}, ${run.case}`, run.input, run.expect);
    });
  }

  for (const name of ["BW1", "BW3"]) {
    it(`${name}'s control: within signs once`, async () => {
      const r = named(name);
      const control = r.control as { input: Record<string, unknown>; expect: Expect };
      const { cases: _, ...shared } = r.input;
      await play(r, `${name} control`, { ...shared, ...control.input }, control.expect);
    });
  }
});
