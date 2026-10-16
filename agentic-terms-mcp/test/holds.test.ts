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
import { randomUUID } from "node:crypto";
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
const LINK_ABC: string = vectors("mpp-challenge.json").fixed.link;
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

  it("a chosen, an opening and a hold this process returned are declined by the terms-mcp binary in its own process, and used here", async () => {
    const c = connect({ fetch, signer: recording() });
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account, inputs });
    const chosen = at(confirmed, "result.structuredContent.chosen");
    const { signed, mac } = await openedOn(c);
    const hold = await holdFrom(c);
    const other = spawnBin();
    const finished = await call(other, "atr_finish", { pairing, atr, chosen, signature: [BV.EB3.signature, BV.EB2.signature] });
    const opened = await call(other, "atr_channel_open", { pairing, atr, signed, mac });
    const recorded = await call(other, "atr_channel_record_charge", { hold, charged: "0" });
    await other.close();
    expect(at(finished, "result.structuredContent.decline.code")).toBe("chosen-unverified");
    expect(at(opened, "result.structuredContent.decline.code")).toBe("opening-unverified");
    expect(at(recorded, "result.structuredContent.decline.code")).toBe("hold-unverified");

    const here = await call(c, "atr_finish", { pairing, atr, chosen, signature: [BV.EB3.signature, BV.EB2.signature] });
    const kept = await call(c, "atr_channel_record_charge", { hold, charged: "0" });
    await c.close();
    expect(at(here, "result.isError")).toBeUndefined();
    expect(at(kept, "result.isError")).toBeUndefined();
  });
});

// `chosen` carries this process's `mac` too. For a pairing with a channel, `atr_finish` returns the opening with a
// `mac` that `atr_channel_open` holds, and a hold's `signedMax` bounds the vouchers signed later in the channel, so
// `atr_finish` reads such a `chosen` only when its `mac` verifies: a `chosen` with its amount, deposit or payee
// changed, or with its `mac` replaced or removed, is declined `chosen-unverified` before the gate is called, and no
// opening or `mac` is returned. The unchanged `chosen` opens the channel EB2's voucher opened: `signedMax` is EB2's
// `maxClaimableAmount`.
describe("atr_finish of a channel pairing reads chosen only when its mac verifies", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(EV.now * 1000);
  });
  afterEach(() => vi.useRealTimers());

  type Choice = { accepted: Record<string, unknown>; required: { accepts: unknown[] }; deposit: string };
  type Chosen = { choice: Choice; mac: string } & Record<string, unknown>;
  /** `chosen` with the option it pays changed the same way where the choice holds it and in the document beside it. */
  const withOption = (chosen: Chosen, change: Record<string, unknown>): Chosen => {
    const accepted = { ...chosen.choice.accepted, ...change };
    return { ...chosen, choice: { ...chosen.choice, accepted, required: { ...chosen.choice.required, accepts: [accepted] } } };
  };
  const signature = [BV.EB3.signature, BV.EB2.signature];

  async function chosenOn(c: Connection): Promise<Chosen> {
    const confirmed = await call(c, "atr_confirm", { pairing, document: document(), account, inputs });
    expect(at(confirmed, "result.isError")).toBeUndefined();
    return at(confirmed, "result.structuredContent.chosen") as Chosen;
  }

  it("the chosen atr_confirm returned, unchanged: the opening and its mac, held with EB2's signedMax", async () => {
    const c = connect({ fetch });
    const chosen = await chosenOn(c);
    const finished = await call(c, "atr_finish", { pairing, atr, chosen, signature });
    expect(at(finished, "result.isError")).toBeUndefined();
    const { signed, mac } = at(finished, "result.structuredContent") as Opened;
    const held = await call(c, "atr_channel_open", { pairing, atr, signed, mac });
    await c.close();
    expect(at(held, "result.structuredContent.hold.signedMax")).toBe(BV.EB2.maxClaimableAmount);
  });

  it("a chosen with its amount, deposit or payee changed, its mac kept, is declined chosen-unverified with no opening", async () => {
    const c = connect({ fetch });
    const chosen = await chosenOn(c);
    expect(chosen.choice.accepted["amount"]).toBe(EV.option.amount);
    expect(chosen.choice.deposit).toBe(EV.deposit);
    expect(chosen.choice.accepted["payTo"]).toBe(EV.option.payTo);
    const edits: Chosen[] = [
      withOption(chosen, { amount: "999999999999" }),
      { ...chosen, choice: { ...chosen.choice, deposit: "999999999999" } },
      withOption(chosen, { payTo: EV.payer }),
    ];
    const answers = [];
    for (const edited of edits) answers.push(await call(c, "atr_finish", { pairing, atr, chosen: edited, signature }));
    await c.close();
    for (const m of answers) {
      expect(at(m, "result.isError")).toBe(true);
      expect(at(m, "result.structuredContent.decline.code")).toBe("chosen-unverified");
      expect(at(m, "result.structuredContent")).not.toHaveProperty("signed");
      expect(at(m, "result.structuredContent")).not.toHaveProperty("mac");
    }
  });

  it("a chosen whose mac is replaced or removed is declined chosen-unverified", async () => {
    const c = connect({ fetch });
    const { mac: _mac, ...bare } = await chosenOn(c);
    const forged = await call(c, "atr_finish", { pairing, atr, chosen: { ...bare, mac: `0x${"00".repeat(32)}` }, signature });
    const missing = await call(c, "atr_finish", { pairing, atr, chosen: bare, signature });
    await c.close();
    expect(at(forged, "result.structuredContent.decline.code")).toBe("chosen-unverified");
    expect(at(missing, "result.structuredContent.decline.code")).toBe("chosen-unverified");
  });

  it("mpp/session/evm: a chosen with its deposit changed is declined chosen-unverified at each step; the unchanged one opens", async () => {
    const SE = vectors("mpp-session-evm.json");
    const MC = vectors("mpp-challenge.json");
    const session = "mpp/session/evm";
    const issued = {
      realm: MC.fixed.realm,
      method: "evm",
      intent: "session",
      request: Buffer.from(SE.fixed.request, "utf8").toString("base64url"),
      expires: MC.fixed.expires,
    };
    const doc = (BINDINGS.find((b) => b.id === session) as unknown as Advertises).advertise([issued], H_ABC, LINK_ABC, issued);
    const sessionInputs = { deposit: SE.fixed.deposit, credentialType: "authorization", tokenDomain: SE.fixed.tokenDomain };
    /** A 65-byte answer of the form the funding and the voucher take; no signature is verified by the gate. */
    const answer = `0x${"11".repeat(65)}`;
    vi.setSystemTime(SE.fixed.now * 1000);
    const c = connect({ fetch });
    const confirmed = await call(c, "atr_confirm", {
      pairing: session,
      document: doc,
      account: `eip155:84532:${SE.fixed.payer}`,
      inputs: sessionInputs,
    });
    const chosen = at(confirmed, "result.structuredContent.chosen") as Chosen;
    expect(chosen.choice.deposit).toBe(SE.fixed.deposit);
    const edited = { ...chosen, choice: { ...chosen.choice, deposit: "999999999999" } };
    const first = await call(c, "atr_finish", { pairing: session, atr, chosen: edited, signature: answer });
    const second = await call(c, "atr_finish", { pairing: session, atr, chosen: edited, signature: [answer, answer] });
    const next = await call(c, "atr_finish", { pairing: session, atr, chosen, signature: answer });
    const opened = await call(c, "atr_finish", { pairing: session, atr, chosen, signature: [answer, answer] });
    await c.close();
    expect(at(first, "result.structuredContent.decline.code")).toBe("chosen-unverified");
    expect(at(second, "result.structuredContent.decline.code")).toBe("chosen-unverified");
    expect(at(next, "result.structuredContent.next.kind")).toBe("eip712");
    expect(at(opened, "result.isError")).toBeUndefined();
    expect(at(opened, "result.structuredContent.mac")).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

// mpp/session/hedera's opening is bound by its escrow log, which only the landed receipt carries, so `atr_transact`
// returns `landed` beside `signed`, and the opening's `mac` covers the pairing, the opening and that receipt.
// `atr_channel_open` takes `landed` back with them and passes it to the gate, so the session is held, the hold keeping
// the opening as signed and the receipt as its own `landed` member; an edited receipt, or the opening passed without
// the receipt its `mac` covers, is declined `opening-unverified`. The challenge,
// opening, escrow log and channel id are mpp-session-hedera-solana-xrpl.json's SS1 and HS1 to HS3.
describe("mpp/session/hedera is held over MCP with its landed receipt", () => {
  const V = vectors("mpp-session-hedera-solana-xrpl.json");
  const session = "mpp/session/hedera";
  const AGREEMENT = `https://api.seller.example/agreement/${randomUUID()}`;
  const challenge = V.SS1.hedera.challenge;
  const doc = () =>
    (BINDINGS.find((b) => b.id === session) as unknown as { advertise(d: object, h: string, l: string, o: object, a: string): object }).advertise(
      [challenge],
      H_ABC,
      LINK_ABC,
      challenge,
      AGREEMENT,
    );
  const landed = { transaction: V.HS3.txHash, blockNumber: "47312717", logs: [V.HS3.log] };
  const receipt = { atrHash: H_ABC, agreed: true, network: "eip155:296", transaction: `0x${"cd".repeat(32)}` };
  const seller = (async (url: string) => {
    if (url === LINK_ABC) return new Response(new Uint8Array(ABC), { status: 200 });
    if (url === AGREEMENT) return new Response(JSON.stringify(receipt), { status: 200 });
    return new Response(null, { status: 404 });
  }) as unknown as Fetch;
  /** The payer funds the escrow and signs the first voucher: the opening's hash, a 65-byte signature, the receipt. */
  const hedera: Signer = {
    account: `hedera:testnet:${V.fixed.payer}`,
    async sign() {
      return { openTx: V.HS3.txHash, signature: `0x${"11".repeat(65)}`, landed } as never;
    },
  };
  type Opened = { signed: unknown; landed: unknown; mac: string };
  async function opened(c: Connection): Promise<Opened> {
    const m = await call(c, "atr_transact", { pairing: session, document: doc(), inputs: { deposit: V.HS2.deposit } });
    expect(at(m, "result.isError")).toBeUndefined();
    return at(m, "result.structuredContent") as Opened;
  }

  it("atr_transact returns landed beside the opening, and atr_channel_open holds HS1's channel with it", async () => {
    const c = connect({ fetch: seller, signer: hedera });
    const o = await opened(c);
    const held = await call(c, "atr_channel_open", { pairing: session, atr, signed: o.signed, landed: o.landed, mac: o.mac });
    await c.close();
    expect(o.landed).toEqual(landed);
    expect(at(held, "result.isError")).toBeUndefined();
    expect(at(held, "result.structuredContent.hold")).toMatchObject({ pairing: session, channel: V.HS1.expectChannelId, h: H_ABC });
    expect(at(held, "result.structuredContent.hold.opening")).toEqual(o.signed);
    expect(at(held, "result.structuredContent.hold.landed")).toEqual(landed);
  });

  it("an edited receipt, or the opening without the receipt its mac covers, is declined opening-unverified", async () => {
    const c = connect({ fetch: seller, signer: hedera });
    const o = await opened(c);
    const edited = await call(c, "atr_channel_open", {
      pairing: session,
      atr,
      signed: o.signed,
      landed: { ...landed, blockNumber: "47312718" },
      mac: o.mac,
    });
    const without = await call(c, "atr_channel_open", { pairing: session, atr, signed: o.signed, mac: o.mac });
    await c.close();
    expect(at(edited, "result.structuredContent.decline.code")).toBe("opening-unverified");
    expect(at(without, "result.structuredContent.decline.code")).toBe("opening-unverified");
  });
});
