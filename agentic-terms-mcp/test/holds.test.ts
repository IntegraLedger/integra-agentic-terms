// Channel openings and holds over MCP. A channel pairing's signed opening, returned by `atr_transact` or `atr_finish`,
// comes with `mac`, and every hold the server returns carries `mac`: each an HMAC-SHA-256 (RFC 2104 with SHA-256: a
// 32-byte tag) under a key of the server's own process. `atr_channel_open` takes an opening only when its `mac`
// verifies, and declines any other `opening-unverified`; `atr_channel_within` and `atr_channel_record_charge` use a hold
// only when its `mac` verifies: a hold with any member changed, added or removed, or one another process returned, is
// declined `hold-unverified`. The signer is never called for either. JSON objects are unordered (RFC 8259 §4), so a hold
// whose members arrive in another order is the same hold. A voucher's
// `maxClaimableAmount` is the recorded charge plus the option's amount (x402 batch-settlement's client rule:
// "`chargedCumulativeAmount + amount`"). The ATR, its hash and the batch-settlement opening's signatures are the lcp
// vector files'.
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Fetch, Signer, SigningRequest } from "@integraledger/terms";
import { BINDINGS } from "../src/index.js";
import { at, connect, spawnBin } from "./stdio.js";

const vectors = (name: string) =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
const BV = vectors("x402-batch-settlement.json");
const EV = BV.fixed.evm;
const M = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };

/** `abc`, whose SHA-256 (FIPS 180-2) is the hash the batch-settlement vectors carry, and its link. */
const ABC = new TextEncoder().encode("abc");
const H_ABC = "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const LINK_ABC = `https://atr.seller.example/${H_ABC}`;
const atr = Buffer.from(ABC).toString("base64");

const pairing = "x402/batch-settlement/eip155";
type Advertises = { advertise(d: object, h: string, l: string, o: object): object };
const document = () =>
  (BINDINGS.find((b) => b.id === pairing) as unknown as Advertises).advertise(
    { x402Version: 2, resource: BV.fixed.resource, accepts: [EV.option] },
    H_ABC,
    LINK_ABC,
    EV.option,
  );
const account = `eip155:84532:${EV.payer}`;
const inputs = { payerAuthorizer: EV.payerAuthorizer, deposit: EV.deposit, authSalt: EV.authSalt };

const fetch = (async (url: string) =>
  url === LINK_ABC ? new Response(new Uint8Array(ABC), { status: 200 }) : new Response(null, { status: 404 })) as unknown as Fetch;

type Recording = Signer & { requests: SigningRequest[] };
/** The payer signs the deposit authorization (EB3) and the payer authorizer the first voucher (EB2). */
function recording(): Recording {
  const s: Recording = {
    account,
    requests: [],
    async sign(r: SigningRequest) {
      s.requests.push(r);
      return (r.kind === "batch" && r.requests.length === 2 ? [BV.EB3.signature, BV.EB2.signature] : [BV.EB2.signature]) as never;
    },
  };
  return s;
}

type Connection = { request(method: string, params?: object): Promise<unknown> };
const call = (c: Connection, name: string, args: object) => c.request("tools/call", { name, arguments: args, _meta: M });

type Opened = { signed: { payload: { voucher: Record<string, unknown> } }; mac: string };

/** The signed opening and its `mac`, from `atr_transact` on `c` with the vector signatures. */
async function openedOn(c: Connection): Promise<Opened> {
  const opened = await call(c, "atr_transact", { pairing, document: document(), inputs });
  expect(at(opened, "result.isError")).toBeUndefined();
  return at(opened, "result.structuredContent") as Opened;
}

/** A hold returned by `atr_channel_open` on `c`, from an opening and its `mac` this process returned. */
async function holdFrom(c: Connection): Promise<Record<string, unknown>> {
  const opener = connect({ fetch, signer: recording() });
  const { signed, mac } = await openedOn(opener);
  await opener.close();
  const held = await call(c, "atr_channel_open", { pairing, atr, signed, mac });
  expect(at(held, "result.isError")).toBeUndefined();
  return at(held, "result.structuredContent.hold") as Record<string, unknown>;
}

describe("channel openings and holds over MCP carry this process's mac", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(EV.now * 1000);
  });
  afterEach(() => vi.useRealTimers());

  it("atr_transact returns a channel opening with a mac beside signed, a 32-byte tag in 0x hex", async () => {
    const c = connect({ fetch, signer: recording() });
    const opened = await openedOn(c);
    await c.close();
    expect(opened.mac).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("atr_channel_open declines opening-unverified, and returns no hold, for an opening whose voucher ceiling is raised with its signatures kept", async () => {
    const signer = recording();
    const c = connect({ fetch, signer });
    const { signed, mac } = await openedOn(c);
    const before = signer.requests.length;
    const raised = { ...signed, payload: { ...signed.payload, voucher: { ...signed.payload.voucher, maxClaimableAmount: "1000000000000" } } };
    const m = await call(c, "atr_channel_open", { pairing, atr, signed: raised, mac });
    await c.close();
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent.decline.code")).toBe("opening-unverified");
    expect(at(m, "result.structuredContent")).not.toHaveProperty("hold");
    expect(signer.requests.length - before).toBe(0);
  });

  it("atr_channel_open declines opening-unverified for an opening under another pairing, with another mac, or with a hold's mac", async () => {
    const c = connect({ fetch, signer: recording() });
    const { signed, mac } = await openedOn(c);
    const hold = await holdFrom(c);
    const codes = [];
    for (const args of [
      { pairing: "x402/batch-settlement/solana", atr, signed, mac },
      { pairing, atr, signed, mac: `0x${"00".repeat(32)}` },
      { pairing, atr, signed, mac: hold["mac"] },
    ]) {
      codes.push(at(await call(c, "atr_channel_open", args), "result.structuredContent.decline.code"));
    }
    await c.close();
    expect(codes).toEqual(["opening-unverified", "opening-unverified", "opening-unverified"]);
  });

  it("atr_channel_open returns a hold whose mac is a 32-byte tag in 0x hex, beside the members the gate returned", async () => {
    const c = connect({ fetch });
    const hold = await holdFrom(c);
    await c.close();
    expect(hold["mac"]).toMatch(/^0x[0-9a-f]{64}$/);
    expect(hold).toMatchObject({ pairing, h: H_ABC, atr, charged: "0", signedMax: BV.EB2.maxClaimableAmount });
    expect(Object.keys(hold).sort()).toEqual(["atr", "channel", "charged", "h", "mac", "network", "opening", "pairing", "signedMax"]);
  });

  it("atr_channel_within declines hold-unverified, and never calls the signer, for a hold whose charged is raised above what was signed", async () => {
    const signer = recording();
    const c = connect({ fetch, signer });
    const hold = await holdFrom(c);
    const m = await call(c, "atr_channel_within", { pairing, hold: { ...hold, charged: "1000000000000" }, document: document() });
    await c.close();
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent.decline.code")).toBe("hold-unverified");
    expect(at(m, "result.structuredContent")).not.toHaveProperty("signed");
    expect(signer.requests).toHaveLength(0);
  });

  it("atr_channel_within declines hold-unverified, and never calls the signer, for a hold whose charged and signedMax are both raised", async () => {
    const signer = recording();
    const c = connect({ fetch, signer });
    const hold = await holdFrom(c);
    const edited = { ...hold, charged: "1000000000000", signedMax: "1000000000000" };
    const m = await call(c, "atr_channel_within", { pairing, hold: edited, document: document() });
    await c.close();
    expect(at(m, "result.structuredContent.decline.code")).toBe("hold-unverified");
    expect(signer.requests).toHaveLength(0);
  });

  it("atr_channel_within declines hold-unverified for a hold with any one member changed, added or removed", async () => {
    const signer = recording();
    const c = connect({ fetch, signer });
    const hold = await holdFrom(c);
    const without = (k: string) => Object.fromEntries(Object.entries(hold).filter(([m]) => m !== k));
    const opening = hold["opening"] as { payload: { voucher: Record<string, unknown> } };
    const edits: Record<string, unknown>[] = [
      { ...hold, pairing: "x402/batch-settlement/solana" },
      { ...hold, network: "eip155:8453" },
      { ...hold, channel: `0x${"00".repeat(32)}` },
      { ...hold, h: `0x${"00".repeat(32)}` },
      { ...hold, atr: Buffer.from("abd").toString("base64") },
      { ...hold, charged: "1" },
      { ...hold, signedMax: String(BigInt(BV.EB2.maxClaimableAmount) + 1n) },
      { ...hold, opening: { ...opening, payload: { ...opening.payload, voucher: { ...opening.payload.voucher, maxClaimableAmount: "1000000000000" } } } },
      { ...hold, mac: `0x${"00".repeat(32)}` },
      { ...hold, extra: "1" },
      without("mac"),
      without("charged"),
    ];
    const codes: unknown[] = [];
    for (const edited of edits) {
      const m = await call(c, "atr_channel_within", { pairing, hold: edited, document: document() });
      codes.push(at(m, "result.structuredContent.decline.code"));
    }
    await c.close();
    expect(codes).toEqual(edits.map(() => "hold-unverified"));
    expect(signer.requests).toHaveLength(0);
  });

  it("atr_channel_record_charge declines hold-unverified for an edited hold, so an edited hold is never returned with a mac", async () => {
    const c = connect({ fetch });
    const hold = await holdFrom(c);
    const edited = { ...hold, signedMax: "1000000000000" };
    const m = await call(c, "atr_channel_record_charge", { hold: edited, charged: "1000000000000" });
    await c.close();
    expect(at(m, "result.isError")).toBe(true);
    expect(at(m, "result.structuredContent.decline.code")).toBe("hold-unverified");
    expect(at(m, "result.structuredContent")).not.toHaveProperty("hold");
  });

  it("a hold whose members arrive in another order is the same hold: atr_channel_within signs at the recorded charge plus the option's amount", async () => {
    const signer = recording();
    const c = connect({ fetch, signer });
    const hold = await holdFrom(c);
    const reordered = Object.fromEntries(Object.entries(hold).reverse());
    const m = await call(c, "atr_channel_within", { pairing, hold: reordered, document: document() });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(at(m, "result.structuredContent.signed.payload.voucher.maxClaimableAmount")).toBe(EV.option.amount);
    expect(at(m, "result.structuredContent.hold.mac")).toMatch(/^0x[0-9a-f]{64}$/);
    expect(signer.requests).toHaveLength(1);
  });

  it("a hold one server of this process returned is accepted by another server of the same process", async () => {
    const opener = connect({ fetch });
    const hold = await holdFrom(opener);
    await opener.close();
    const signer = recording();
    const c = connect({ fetch, signer });
    const m = await call(c, "atr_channel_within", { pairing, hold, document: document() });
    await c.close();
    expect(at(m, "result.isError")).toBeUndefined();
    expect(signer.requests).toHaveLength(1);
  });

  it("an opening and a hold the terms-mcp binary returned in its own process are declined here, and accepted by that process", async () => {
    const confirmer = connect({ fetch });
    const confirmed = await call(confirmer, "atr_confirm", { pairing, document: document(), account, inputs });
    await confirmer.close();
    const other = spawnBin();
    const finished = await call(other, "atr_finish", {
      pairing,
      atr,
      chosen: at(confirmed, "result.structuredContent.chosen"),
      signature: [BV.EB3.signature, BV.EB2.signature],
    });
    expect(at(finished, "result.isError")).toBeUndefined();
    const opening = { pairing, atr, signed: at(finished, "result.structuredContent.signed"), mac: at(finished, "result.structuredContent.mac") };
    const held = await call(other, "atr_channel_open", opening);
    const hold = at(held, "result.structuredContent.hold") as Record<string, unknown>;
    const there = await call(other, "atr_channel_record_charge", { hold, charged: "0" });
    await other.close();
    expect(at(held, "result.isError")).toBeUndefined();
    expect(at(there, "result.isError")).toBeUndefined();

    const c0 = connect({ fetch });
    const here = await call(c0, "atr_channel_open", opening);
    await c0.close();
    expect(at(here, "result.structuredContent.decline.code")).toBe("opening-unverified");

    const signer = recording();
    const c = connect({ fetch, signer });
    const within = await call(c, "atr_channel_within", { pairing, hold, document: document() });
    const record = await call(c, "atr_channel_record_charge", { hold, charged: "0" });
    await c.close();
    expect(at(within, "result.structuredContent.decline.code")).toBe("hold-unverified");
    expect(at(record, "result.structuredContent.decline.code")).toBe("hold-unverified");
    expect(signer.requests).toHaveLength(0);
  });
});
