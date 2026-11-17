// The four pairings whose wallet builds the transaction and picks its expiry (terms' profile buyer-gate.md, rule 8):
// x402/exact/aptos, x402/exact/cardano (and its script lock), x402/exact/sui and x402/exact/polkadot/lcp-assets-remark.
// The gate hands the wallet the pairing's ceiling as the latest deadline it may sign and shows it as the validity's end;
// after the wallet signs and before the payment is returned, it reads the deadline the signed transaction signs with
// the protocol package's own `reference` and holds it to that latest deadline. Every option, signed payment and expected
// deadline is a row of the pairing's vectors file: its options, its B6 rows' payments, Sui's V2 and V3 transactions
// (built with @mysten/sui 2.35.0), Polkadot's eraNonce rows (each era as @polkadot/types 17.0.1 decodes it) and Aptos's
// fixture F (a mainnet transaction's fields, expiring at 1790300895). The ATR paid through the gate is buyer.json's A.
import { createHash, generateKeyPairSync, sign as ed25519Sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { exactAptos } from "@integraledger/lcp/aptos";
import { exactCardano, exactCardanoLock } from "@integraledger/lcp/cardano";
import { exactPolkadotRemark } from "@integraledger/lcp/polkadot";
import { exactSui } from "@integraledger/lcp/sui";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import type { AtrHash } from "@integraledger/lcp";
import { check, confirm, finish, transact, type Binding, type Ceilings, type Chosen, type Inputs, type Signature, type SigningRequest } from "../src/index.js";
import { A, ABC, CONFIRMING, GATE, HA, LINK, code, counting, offered, serving, vectors } from "./support.js";

/** The seller's document for `option`, as the pairing's own `advertise` places HA and the link. */
function placed(binding: Binding, option: PaymentRequirements, resource: { url: string }, ...rest: unknown[]): unknown {
  const base = { x402Version: 2, resource, accepts: [option] } as PaymentRequired;
  const doc = (binding as unknown as { advertise(d: PaymentRequired, h: AtrHash, l: string, o: unknown, ...r: unknown[]): unknown })
    .advertise(base, HA, LINK, option, ...rest);
  if (typeof doc === "object" && doc !== null && "refused" in doc) throw new Error(JSON.stringify(doc));
  return doc;
}

/** Freezes the clock at `now` seconds, and restores it. */
async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

/** `confirm` over A, the document placed for HA: the request handed to the wallet, its summary and the choice kept. */
async function confirmed(
  binding: Binding,
  doc: unknown,
  account: string,
  inputs: Inputs = {},
  ceilings?: Ceilings,
): Promise<{ request: SigningRequest; validity: unknown; network: string | null; payees: unknown; chosen: Chosen }> {
  const out = await confirm(doc, binding, account, serving(A), { ...CONFIRMING, inputs, ...(ceilings === undefined ? {} : { ceilings }) });
  if ("decline" in out) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
  if (out.request === null || out.summary === undefined) throw new Error("nothing to sign");
  return { request: out.request, validity: out.summary.validity, network: out.summary.network, payees: out.summary.payees, chosen: out.chosen };
}

/**
 * `finish` over the vectors' ATR `abc`, the hash the vectors' signed payment carries, with the choice `confirm` kept
 * and the wallet's answer: the payment, or the decline, which must carry nothing of the payment.
 */
async function finished(binding: Binding, chosen: Chosen, answer: Signature): Promise<{ returned: boolean; decline?: unknown }> {
  const out = await finish(ABC, JSON.parse(JSON.stringify(chosen)) as Chosen, answer, binding);
  if ("signed" in out) return { returned: true };
  if (!("decline" in out)) throw new Error("a later step");
  expect(Object.keys(out)).toEqual(["decline"]);
  return { returned: false, decline: out.decline.code };
}

// ── x402/exact/cardano and its script lock: the TTL, a slot, counted from the slot the caller gives.

const ADA = vectors<{
  fixed: { O: PaymentRequirements; OLock: PaymentRequirements; nonce: string; resource: { url: string } };
  V8: { coinsPerUtxoByte: string };
  buyer: { rows: { name: string; pairing: string; input: { presented?: { payload: { transaction: string; nonce: string } } } }[] };
}>("x402-exact-cardano.json");
const adaB6 = ADA.buyer.rows.find((r) => r.name === "B6" && r.pairing === "x402/exact/cardano")!.input.presented!.payload;
/** The B6 row's transaction's TTL, as the protocol package's reference reads it. */
const ADA_TTL = 134620000;
const adaAccount = (network: string) => `${network}:${ADA.fixed.O.payTo.replace("_", "%5F")}`;
const coins = BigInt(ADA.V8.coinsPerUtxoByte);

describe("x402/exact/cardano: the wallet is handed the latest TTL it may sign", () => {
  const doc = placed(exactCardano, ADA.fixed.O, ADA.fixed.resource, coins);

  it("the request carries maxTtl, the slot the caller gives plus the 600 s ceiling at one slot a second, shown as the validity's end", async () => {
    const c = await confirmed(exactCardano, doc, adaAccount(ADA.fixed.O.network), { currentSlot: ADA_TTL - 600 });
    expect((c.request as { maxTtl?: string }).maxTtl).toBe(String(ADA_TTL));
    expect(c.validity).toEqual({ notBefore: null, notAfter: String(ADA_TTL), unit: "slot" });
    expect(c.chosen.deadline).toBe(String(ADA_TTL));
  });

  it("without the slot the caller read, the option is no-payable-option, cardano/input-missing", async () => {
    const out = await confirm(doc, exactCardano, adaAccount(ADA.fixed.O.network), serving(A), CONFIRMING);
    expect(out).toEqual({ decline: { code: "no-payable-option", detail: "cardano/input-missing" } });
  });

  it("an option on the network's CIP-34 alias (cip34:0-1, preprod) is shown, its network as the option names it", async () => {
    const O = { ...ADA.fixed.O, network: "cip34:0-1" };
    const c = await confirmed(exactCardano, placed(exactCardano, O, ADA.fixed.resource, coins), adaAccount("cip34:0-1"), {
      currentSlot: ADA_TTL - 600,
    });
    expect([c.network, c.validity]).toEqual(["cip34:0-1", { notBefore: null, notAfter: String(ADA_TTL), unit: "slot" }]);
  });

  it("the B6 payment, TTL 134620000, is returned where the latest TTL is that slot, and discarded past-ceiling one slot earlier", async () => {
    const answer = { transaction: adaB6.transaction, nonce: adaB6.nonce };
    const within = await confirmed(exactCardano, doc, adaAccount(ADA.fixed.O.network), { currentSlot: ADA_TTL - 600 });
    expect(await finished(exactCardano, within.chosen, answer)).toEqual({ returned: true });
    const past = await confirmed(exactCardano, doc, adaAccount(ADA.fixed.O.network), { currentSlot: ADA_TTL - 601 });
    expect(await finished(exactCardano, past.chosen, answer)).toEqual({ returned: false, decline: "past-ceiling" });
  });

  it("the script lock is shown as the address method is, its payee the contract its payTo names", async () => {
    const lock = exactCardanoLock as unknown as Binding;
    const c = await confirmed(lock, placed(lock, ADA.fixed.OLock, ADA.fixed.resource), adaAccount(ADA.fixed.OLock.network), {
      currentSlot: ADA_TTL - 600,
    });
    expect([c.payees, c.validity]).toEqual([
      [{ account: ADA.fixed.OLock.payTo, amount: ADA.fixed.OLock.amount }],
      { notBefore: null, notAfter: String(ADA_TTL), unit: "slot" },
    ]);
  });
});

// ── x402/exact/sui: the expiration epoch, which admits the whole of its epoch.

const SUI = vectors<{
  fixed: { sender: string; O: PaymentRequirements; resource: { url: string } };
  V2: { tx: { transactionBase64: string } };
  V3: { case: string; tx?: { transactionBase64: string } }[];
}>("x402-exact-sui.json");
/** V2's expiration epoch, as the protocol package's reference reads it. */
const SUI_EPOCH = 1234;
const suiAccount = `${SUI.fixed.O.network}:${SUI.fixed.sender}`;
const suiAnswer = (transaction: string) => ({ signature: Buffer.alloc(97).toString("base64"), transaction });
const noExpiration = SUI.V3.find((r) => r.case.startsWith("setExpiration({None: true})"))!.tx!.transactionBase64;

describe("x402/exact/sui: the wallet is handed the latest expiration epoch it may sign", () => {
  const doc = placed(exactSui, SUI.fixed.O, SUI.fixed.resource);
  const day: Ceilings = { "x402/exact/sui": 86_400 };

  it("at the 600 s ceiling no epoch fits, an epoch lasting 86,400 s: past-ceiling before anything is signed", async () => {
    const out = await confirm(doc, exactSui, suiAccount, serving(A), { ...CONFIRMING, inputs: { currentEpoch: SUI_EPOCH } });
    expect(code(out)).toBe("past-ceiling");
  });

  it("raised to a day, the request carries maxEpoch, the epoch the caller gives, shown as the validity's end", async () => {
    const c = await confirmed(exactSui, doc, suiAccount, { currentEpoch: SUI_EPOCH }, day);
    expect((c.request as { maxEpoch?: string }).maxEpoch).toBe(String(SUI_EPOCH));
    expect(c.validity).toEqual({ notBefore: null, notAfter: String(SUI_EPOCH), unit: "epoch" });
  });

  it("V2, expiring at epoch 1234, is returned where that is the latest epoch, and discarded past-ceiling where 1233 is", async () => {
    const within = await confirmed(exactSui, doc, suiAccount, { currentEpoch: SUI_EPOCH }, day);
    expect(await finished(exactSui, within.chosen, suiAnswer(SUI.V2.tx.transactionBase64))).toEqual({ returned: true });
    const past = await confirmed(exactSui, doc, suiAccount, { currentEpoch: SUI_EPOCH - 1 }, day);
    expect(await finished(exactSui, past.chosen, suiAnswer(SUI.V2.tx.transactionBase64))).toEqual({ returned: false, decline: "past-ceiling" });
  });

  it("V3's transaction with no expiration is discarded no-end", async () => {
    const c = await confirmed(exactSui, doc, suiAccount, { currentEpoch: SUI_EPOCH }, day);
    expect(await finished(exactSui, c.chosen, suiAnswer(noExpiration))).toEqual({ returned: false, decline: "no-end" });
  });
});

// ── x402/exact/polkadot/lcp-assets-remark: the mortal era's period, counted from the era's birth.

const DOT = vectors<{
  fixed: { O: PaymentRequirements; resource: { url: string } };
  V3: { extrinsic: string };
  eraNonce: { rows: { case: string; extrinsic: string; expect: { era: unknown } }[] };
}>("x402-exact-polkadot-lcp-assets-remark.json");
/** The payer of V3's extrinsic: SS58 of the public key its signature preamble names. */
const dotAccount = `${DOT.fixed.O.network}:16SYiSu5tWgdV4sWiaxir7GYEiFfTc9GYnRd34PDGCUMgkmP`;
const eraRow = (start: string) => {
  const r = DOT.eraNonce.rows.find((row) => row.case.startsWith(start))!;
  return { extrinsic: r.extrinsic === "V3" ? DOT.V3.extrinsic : r.extrinsic, era: r.expect.era };
};

describe("x402/exact/polkadot/lcp-assets-remark: the wallet is handed the longest era it may sign", () => {
  const doc = placed(exactPolkadotRemark, DOT.fixed.O, DOT.fixed.resource);

  it("the request carries maxEraPeriod 64, the longest power of two within 600 s at 6 s a block, shown as 0 to 64 blocks", async () => {
    const c = await confirmed(exactPolkadotRemark, doc, dotAccount);
    expect((c.request as { maxEraPeriod?: string }).maxEraPeriod).toBe("64");
    expect(c.validity).toEqual({ notBefore: "0", notAfter: "64", unit: "block" });
  });

  it("V3, era period 64, is returned; its immortal form is discarded no-end; its 65,536-block era past-ceiling", async () => {
    const c = await confirmed(exactPolkadotRemark, doc, dotAccount);
    const v3 = eraRow("V3: era bytes a502");
    const immortal = eraRow("V3 with an immortal era");
    const longest = eraRow("V3 with era bytes 0f10");
    expect([v3.era, immortal.era, longest.era]).toEqual([{ period: 64, phase: 42 }, "immortal", { period: 65536, phase: expect.any(Number) }]);
    expect(await finished(exactPolkadotRemark, c.chosen, v3.extrinsic)).toEqual({ returned: true });
    expect(await finished(exactPolkadotRemark, c.chosen, immortal.extrinsic)).toEqual({ returned: false, decline: "no-end" });
    expect(await finished(exactPolkadotRemark, c.chosen, longest.extrinsic)).toEqual({ returned: false, decline: "past-ceiling" });
  });
});

// ── x402/exact/aptos: expiration_timestamp_secs, in Unix seconds, through the gate over A.

const APT = vectors<{
  fixed: {
    O: PaymentRequirements;
    resource: { url: string };
    fixtureF: {
      sender: string;
      sequenceNumber: string;
      maxGasAmount: string;
      gasUnitPrice: string;
      expiresAt: string;
      chainId: number;
      metadata: string;
      recipient: string;
      amount: string;
    };
  };
}>("x402-exact-aptos.json");
const F = APT.fixed.fixtureF;

const uleb = (n: number): Buffer => {
  const out: number[] = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
  } while (n !== 0);
  return Buffer.from(out);
};
const u64 = (n: string): Buffer => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
};
const bcsStr = (s: string): Buffer => Buffer.concat([uleb(Buffer.byteLength(s)), Buffer.from(s)]);
const addr32 = (a: string): Buffer => Buffer.from(a.slice(2).padStart(64, "0"), "hex");
const bcsBytes = (b: Buffer): Buffer => Buffer.concat([uleb(b.length), b]);

/** Fixture F's SignedTransaction: its RawTransaction in BCS and an Ed25519 authenticator from a key generated here. */
function fixtureF(): string {
  const raw = Buffer.concat([
    addr32(F.sender),
    u64(F.sequenceNumber),
    uleb(2),
    addr32("0x1"),
    bcsStr("primary_fungible_store"),
    bcsStr("transfer"),
    uleb(1),
    uleb(7),
    addr32("0x1"),
    bcsStr("fungible_asset"),
    bcsStr("Metadata"),
    uleb(0),
    uleb(3),
    bcsBytes(addr32(F.metadata)),
    bcsBytes(addr32(F.recipient)),
    bcsBytes(u64(F.amount)),
    u64(F.maxGasAmount),
    u64(F.gasUnitPrice),
    u64(F.expiresAt),
    Buffer.from([F.chainId]),
  ]);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const prefix = createHash("sha3-256").update("APTOS::RawTransaction").digest();
  const signature = ed25519Sign(null, Buffer.concat([prefix, raw]), privateKey);
  const pk = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return Buffer.concat([raw, uleb(0), bcsBytes(pk), bcsBytes(signature)]).toString("base64");
}

describe("x402/exact/aptos: the wallet is handed the latest expiration_timestamp_secs it may sign", () => {
  const binding = offered(exactAptos as unknown as Binding);
  const doc = placed(exactAptos as unknown as Binding, APT.fixed.O, APT.fixed.resource);
  const expiresAt = Number(F.expiresAt);
  const pay = (now: number) =>
    at(now, async () => {
      const signer = counting(`${APT.fixed.O.network}:${F.sender}`, async (r) => {
        expect((r as { maxExpirationTimestampSecs?: string }).maxExpirationTimestampSecs).toBe(String(now + 600));
        return { transaction: fixtureF() };
      });
      return { out: await transact(doc, binding, signer, serving(A), GATE), calls: signer.requests.length };
    });

  it("fixture F, expiring at 1790300895, is returned where the gate's clock is 600 s before it", async () => {
    const { out, calls } = await pay(expiresAt - 600);
    if (!("signed" in out) || out.signed === null) throw new Error(JSON.stringify(out));
    expect(calls).toBe(1);
    expect(await check(A, out.signed, exactAptos as unknown as Binding)).toEqual({ h: HA });
  });

  it("signed 300,895 s before it expires, it is discarded past-ceiling after the one signing, nothing of it returned", async () => {
    const { out, calls } = await pay(expiresAt - 300_895);
    expect(calls).toBe(1);
    expect(Object.keys(out)).toEqual(["decline"]);
    expect(code(out)).toBe("past-ceiling");
  });
});
