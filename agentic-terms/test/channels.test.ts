// The buyer's channel steps: a channel opened for a compared ATR is held with its bytes, later vouchers are signed only under
// that hold, and the recorded charge stays within what was signed. Expected digests, signatures, messages and channel
// ids are the vector files' (the batch-settlement file's EB1-EB6 and ES1-ES4; the Tempo session file's TS3); the
// arithmetic of the voucher ceiling is x402 batch-settlement's client rule: "the client sets the voucher's
// `maxClaimableAmount` to `chargedCumulativeAmount + amount`".
import { createHash, createPrivateKey, sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { concat, hashTypedData, keccak256, recoverTypedDataAddress, toHex, toRlp, type Hex, type TypedDataDefinition } from "viem";
import { privateKeyToAccount, sign } from "viem/accounts";
import type { AtrHash } from "@integraledger/lcp";
import { sessionTempo, type MppChallenge } from "@integraledger/lcp/mpp";
import { decodeSvmTx } from "@integraledger/lcp/svm";
import { batchCloudflare, batchEvm, batchSvm } from "@integraledger/lcp/x402-batch-settlement";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { refuse as refusal } from "../src/pairings/common.js";
import {
  openChannel,
  recordCharge,
  transact,
  within,
  type Binding,
  type ChannelHold,
  type Declined,
  type Presented,
  type Signature,
  type SigningRequest,
  type ToApprove,
} from "../src/index.js";
import { ABC, ABD, code, counting, H, isDeclined, LINK, serving, vectors } from "./support.js";

type BatchVectors = {
  fixed: {
    Hprime: Hex;
    resource: { url: string };
    evm: {
      payer: Hex;
      payerKey: Hex;
      payerAuthorizer: Hex;
      payerAuthorizerKey: Hex;
      deposit: string;
      authSalt: Hex;
      now: number;
      option: PaymentRequirements;
    };
    svm: {
      payer: string;
      payerSeed: string;
      salt: string;
      openSlot: string;
      deposit: string;
      blockhash: string;
      tokenProgram: string;
      option: PaymentRequirements;
    };
  };
  EB1: { channelId: string; withHprime: string };
  EB2: { digest: string; signature: string };
  EB6: {
    expectRef: { network: string; channel: string };
    expectKindVoucher: string;
    expectBoundWithin: string;
    expectKindRefund: string;
    refundAmount: string;
    expectKindPartialRefund: string;
    plant: { matchedChannelId: string; expectBoundWithinMatched: string };
  };
  ES1: { channelPda: string };
  ES3: { message: string; signaturePrefix: string; signatureSuffix: string };
  ES4: { expectRef: { network: string; channel: string }; closeWireBase64: string; expectCloseKind: string };
  ES6: {
    cooperative: { payloadMembers: string[]; expectKind: string };
    withMemo: { payloadMembers: string[]; expectKind: string };
  };
};
const BV = vectors<BatchVectors>("x402-batch-settlement.json");

async function at<T>(now: number, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

const typedDataOf = (td: unknown) => td as TypedDataDefinition;
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");

function x402Doc(binding: Binding, option: PaymentRequirements, h: string = H): PaymentRequired {
  const base = { x402Version: 2, resource: BV.fixed.resource, accepts: [option] } as PaymentRequired;
  const link = `https://atr.seller.example/${h}`;
  const placed = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(base, h, link, option);
  if (typeof placed === "object" && placed !== null && "refused" in placed) throw new Error(JSON.stringify(placed));
  return placed as PaymentRequired;
}

function unwrap<T extends object>(v: T): Exclude<T, Declined | ToApprove> {
  if (isDeclined(v)) throw new Error(`${v.decline.code}: ${v.decline.detail}`);
  if ("approve" in v) throw new Error("an agreement payment to approve");
  return v as Exclude<T, Declined | ToApprove>;
}

// ── EVM ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

const E = BV.fixed.evm;
const evmDoc = x402Doc(batchEvm, E.option);
const evmAccount = `eip155:84532:${E.payer}`;
const evmInputs = { payerAuthorizer: E.payerAuthorizer, deposit: E.deposit, authSalt: E.authSalt };

/** The payer signs the deposit authorization; the payer authorizer signs every voucher. */
async function evmAnswer(r: SigningRequest): Promise<Signature> {
  if (r.kind !== "batch") throw new Error(`not batch: ${r.kind}`);
  const keys = r.requests.length === 2 ? [E.payerKey, E.payerAuthorizerKey] : [E.payerAuthorizerKey];
  return Promise.all(r.requests.map((q, i) => privateKeyToAccount(keys[i]!).signTypedData(typedDataOf((q as { typedData: unknown }).typedData))));
}

/** A channel opened through the gate over `abc`, and held. */
async function evmHold(): Promise<{ hold: ChannelHold; opening: Presented }> {
  const opened = unwrap(await transact(evmDoc, batchEvm, counting(evmAccount, evmAnswer), serving(ABC), { inputs: evmInputs }));
  const opening = opened.signed!;
  const hold = unwrap(await openChannel(opened.bytes, opening, batchEvm));
  return { hold: JSON.parse(JSON.stringify(hold)), opening };
}

const voucherOf = (signed: Presented) =>
  (signed as unknown as { payload: { type: string; voucher: { maxClaimableAmount: string; signature: Hex }; amount?: string } }).payload;

describe("x402/batch-settlement/eip155: the channel hold", () => {
  it("openChannel holds the ATR's bytes with the opening and EB1's channel; charged 0, signed max EB2's 1000", () =>
    at(E.now, async () => {
      const { hold } = await evmHold();
      expect(hold).toMatchObject({
        pairing: "x402/batch-settlement/eip155",
        network: BV.EB6.expectRef.network,
        channel: BV.EB6.expectRef.channel,
        h: H,
        atr: Buffer.from(ABC).toString("base64"),
        charged: "0",
        signedMax: "1000",
      });
    }));

  it("within at charged 0: EB2's voucher digest and signature by the payer authorizer; kind within, boundWithin H", () =>
    at(E.now, async () => {
      const { hold } = await evmHold();
      const signer = counting(evmAccount, evmAnswer);
      const out = unwrap(await within(evmDoc, hold, batchEvm, signer));
      expect(signer.requests.length).toBe(1);
      const r = signer.requests[0]!;
      if (r.kind !== "batch" || r.requests.length !== 1 || r.requests[0]!.kind !== "eip712") throw new Error("request");
      expect(hashTypedData(typedDataOf(r.requests[0]!.typedData))).toBe(BV.EB2.digest);
      const payload = voucherOf(out.signed);
      expect(payload.type).toBe("voucher");
      expect(payload.voucher.signature).toBe(BV.EB2.signature);
      expect(batchEvm.channel.kind(out.signed as never)).toBe(BV.EB6.expectKindVoucher);
      expect(await batchEvm.channel.boundWithin(out.signed as never)).toBe(BV.EB6.expectBoundWithin);
      expect(out.hold.signedMax).toBe("1000");
    }));

  it("after recordCharge(1000) the next voucher's maxClaimableAmount is 1000 + 1000, signed by the payer authorizer", () =>
    at(E.now, async () => {
      const { hold } = await evmHold();
      const first = unwrap(await within(evmDoc, hold, batchEvm, counting(evmAccount, evmAnswer)));
      const charged = unwrap(recordCharge(first.hold, "1000"));
      expect(charged.charged).toBe("1000");
      const signer = counting(evmAccount, evmAnswer);
      const next = unwrap(await within(evmDoc, charged, batchEvm, signer));
      const r = signer.requests[0]!;
      if (r.kind !== "batch") throw new Error(r.kind);
      const td = typedDataOf((r.requests[0] as { typedData: unknown }).typedData);
      expect((td.message as { maxClaimableAmount: string }).maxClaimableAmount).toBe("2000");
      const payload = voucherOf(next.signed);
      expect(payload.voucher.maxClaimableAmount).toBe("2000");
      expect(await recoverTypedDataAddress({ ...td, signature: payload.voucher.signature } as never)).toBe(E.payerAuthorizer);
      expect(next.hold.signedMax).toBe("2000");
    }));

  it("EB6's kinds: a full refund is close, a partial refund of 1500 is within", () =>
    at(E.now, async () => {
      const { hold } = await evmHold();
      const full = unwrap(await within(evmDoc, hold, batchEvm, counting(evmAccount, evmAnswer), {}));
      expect(voucherOf(full.signed).type).toBe("refund");
      expect(batchEvm.channel.kind(full.signed as never)).toBe(BV.EB6.expectKindRefund);
      const partial = unwrap(await within(evmDoc, hold, batchEvm, counting(evmAccount, evmAnswer), { amount: BV.EB6.refundAmount }));
      expect(voucherOf(partial.signed).amount).toBe(BV.EB6.refundAmount);
      expect(batchEvm.channel.kind(partial.signed as never)).toBe(BV.EB6.expectKindPartialRefund);
    }));

  it("a refund's voucher claims the recorded charge, not the charge plus the option's amount", () =>
    at(E.now, async () => {
      const { hold } = await evmHold();
      const first = unwrap(await within(evmDoc, hold, batchEvm, counting(evmAccount, evmAnswer)));
      const charged = unwrap(recordCharge(first.hold, "1000"));
      for (const refund of [{}, { amount: BV.EB6.refundAmount }]) {
        const signer = counting(evmAccount, evmAnswer);
        const out = unwrap(await within(evmDoc, charged, batchEvm, signer, refund));
        const r = signer.requests[0]!;
        if (r.kind !== "batch") throw new Error(r.kind);
        const td = typedDataOf((r.requests[0] as { typedData: unknown }).typedData);
        expect((td.message as { maxClaimableAmount: string }).maxClaimableAmount).toBe("1000");
        expect(voucherOf(out.signed).voucher.maxClaimableAmount).toBe("1000");
        expect(out.hold.signedMax).toBe(charged.signedMax);
      }
      const none = unwrap(await within(evmDoc, hold, batchEvm, counting(evmAccount, evmAnswer), {}));
      expect(voucherOf(none.signed).voucher.maxClaimableAmount).toBe("0");
    }));

  // The refund values and the retry code are the Solana scheme's (x402's scheme_batch_settlement_svm.md): an EVM batch
  // refund reads none of them, and answers exactly as with none given.
  it("an EVM refund given a Solana refund value or the Solana retry code answers as with none given", () =>
    at(E.now, async () => {
      const { hold } = await evmHold();
      const RETRY = "invalid_batch_settlement_svm_receiver_binding_unavailable";
      const plain = counting(evmAccount, evmAnswer);
      const expected = voucherOf(unwrap(await within(evmDoc, hold, batchEvm, plain, {})).signed);
      const settled = { success: false, errorReason: RETRY };
      const cases: [unknown, object, object][] = [
        [evmDoc, {}, { computeUnitLimit: -1 }],
        [{ ...evmDoc, error: RETRY }, {}, {}],
        [evmDoc, { paymentResponse: settled }, {}],
        [evmDoc, { paymentResponse: "not an object" }, { recentBlockhash: 7 }],
      ];
      for (const [d, refund, given] of cases) {
        const signer = counting(evmAccount, evmAnswer);
        const out = unwrap(await within(d, hold, batchEvm, signer, refund as never, given as never));
        expect(signer.requests).toEqual(plain.requests);
        expect(voucherOf(out.signed)).toEqual(expected);
      }
    }));

  it("recordCharge: a decimal between the charge recorded and the largest amount signed", () =>
    at(E.now, async () => {
      const { hold } = await evmHold();
      expect(unwrap(recordCharge(hold, "1000")).charged).toBe("1000");
      expect(unwrap(recordCharge(hold, "0")).charged).toBe("0");
      expect(code(recordCharge(hold, "1001"))).toBe("offer-unreadable");
      expect(code(recordCharge(hold, "1e3"))).toBe("offer-unreadable");
      expect(code(recordCharge(hold, "-1"))).toBe("offer-unreadable");
      const at500 = unwrap(recordCharge(hold, "500"));
      expect(code(recordCharge(at500, "499"))).toBe("offer-unreadable");
    }));

  describe("plant: a voucher is signed only under the held agreement", () => {
    it("a within challenge advertising H′, another ATR's hash: hash-mismatch, 0 signer calls", () =>
      at(E.now, async () => {
        const { hold } = await evmHold();
        const signer = counting(evmAccount, evmAnswer);
        expect(code(await within(x402Doc(batchEvm, E.option, BV.fixed.Hprime), hold, batchEvm, signer))).toBe("hash-mismatch");
        expect(signer.requests.length).toBe(0);
      }));
    it("a hold whose channel was edited to H′'s channel: signed-not-bound, 0 signer calls", () =>
      at(E.now, async () => {
        const { hold } = await evmHold();
        const signer = counting(evmAccount, evmAnswer);
        expect(code(await within(evmDoc, { ...hold, channel: BV.EB1.withHprime }, batchEvm, signer))).toBe("signed-not-bound");
        expect(signer.requests.length).toBe(0);
      }));
    it("a hold whose ATR bytes were edited: hash-mismatch, 0 signer calls", () =>
      at(E.now, async () => {
        const { hold } = await evmHold();
        const signer = counting(evmAccount, evmAnswer);
        expect(code(await within(evmDoc, { ...hold, atr: Buffer.from(ABD).toString("base64") }, batchEvm, signer))).toBe(
          "hash-mismatch",
        );
        expect(signer.requests.length).toBe(0);
      }));
    // A hold's `atr` is read as padded standard base64 in its canonical form only (RFC 4648 sections 3.5 and 4), as the
    // protocol package reads a rail's base64. Each other spelling of the held bytes is unreadable before any signer call,
    // and none throws: bits set past the last byte ("QR==" for "A", "YWJ=" for "ab"), padding missing or one too many,
    // whitespace, the URL-safe alphabet ("Pz8-" for "??>") and a character outside Latin-1. The canonical spelling signs.
    it.each([
      ["A", "QQ==", ["QR==", "QQ=", "QQ"]],
      ["ab", "YWI=", ["YWJ=", "YWI", "YWI==", "YW\nI=", "YW I=", "YWI=\t", " YWI="]],
      ["??>", "Pz8+", ["Pz8-", "Pz8+=", "Pz8\u0100"]],
    ] as [string, string, string[]][])(
      "the ATR %j held in a spelling other than %s: signed-not-bound, the held ATR unreadable, 0 signer calls",
      (text, canonical, others) =>
        at(E.now, async () => {
          const atr = new TextEncoder().encode(text);
          const doc = x402Doc(batchEvm, E.option, `0x${createHash("sha256").update(atr).digest("hex")}`);
          const opened = unwrap(await transact(doc, batchEvm, counting(evmAccount, evmAnswer), serving(atr), { inputs: evmInputs }));
          const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchEvm));
          expect(hold.atr).toBe(canonical);
          for (const other of others) {
            const signer = counting(evmAccount, evmAnswer);
            const out = await within(doc, { ...hold, atr: other }, batchEvm, signer);
            expect(isDeclined(out) && out.decline, other).toEqual({ code: "signed-not-bound", detail: "The held ATR is unreadable." });
            expect(signer.requests.length).toBe(0);
          }
          const signer = counting(evmAccount, evmAnswer);
          unwrap(await within(doc, hold, batchEvm, signer));
          expect(signer.requests.length).toBe(1);
        }),
    );
    it("a hold whose opening was edited to EB6's plant (salt H′, channel id matched): signed-not-bound, 0 signer calls", () =>
      at(E.now, async () => {
        const { hold } = await evmHold();
        const opening = JSON.parse(JSON.stringify(hold.opening));
        opening.payload.channelConfig.salt = BV.fixed.Hprime;
        opening.payload.voucher.channelId = BV.EB6.plant.matchedChannelId;
        const signer = counting(evmAccount, evmAnswer);
        expect(code(await within(evmDoc, { ...hold, opening }, batchEvm, signer))).toBe("signed-not-bound");
        expect(signer.requests.length).toBe(0);
      }));
    /** batchEvm, with a buildWithin whose payment names salt and channelId once `when` holds for the answers. */
    const plantedEvm = (salt: string, channelId: string, when: (s: readonly string[]) => boolean): Binding =>
      ({
        ...batchEvm,
        buildWithin: async (w: never, h: never) => {
          const u = (await batchEvm.buildWithin(w, h)) as { requests: unknown[]; complete(s: readonly string[]): unknown };
          return {
            ...u,
            complete: (s: readonly string[]) => {
              if (!when(s)) return u.complete(s);
              const p = JSON.parse(JSON.stringify(u.complete(s)));
              p.payload.channelConfig.salt = salt;
              p.payload.voucher.channelId = channelId;
              return p;
            },
          };
        },
      }) as unknown as Binding;
    const zero = `0x${"00".repeat(65)}`;

    it("a voucher whose payment would commit to another agreement (EB6's plant) is refused before the signer is called", () =>
      at(E.now, async () => {
        const { hold } = await evmHold();
        const plants: [string, string, string, string][] = [
          [BV.fixed.Hprime, BV.EB1.channelId, "offer-unreadable", "x402/channel-id-mismatch"],
          [BV.fixed.Hprime, BV.EB6.plant.matchedChannelId, "no-payable-option", ""],
        ];
        for (const [salt, channelId, decline, detail] of plants) {
          const signer = counting(evmAccount, evmAnswer);
          const out = await within(evmDoc, hold, plantedEvm(salt, channelId, () => true), signer);
          expect(code(out)).toBe(decline);
          if (detail !== "") expect((out as Declined).decline.detail).toBe(detail);
          expect(signer.requests.length).toBe(0);
        }
        const signer = counting(evmAccount, evmAnswer);
        const late = plantedEvm(BV.fixed.Hprime, BV.EB6.plant.matchedChannelId, (s) => s[0] !== zero);
        const out = await within(evmDoc, hold, late, signer);
        expect(code(out)).toBe("signed-not-bound");
        expect(out).not.toHaveProperty("signed");
        expect(signer.requests.length).toBe(1);
        const matched = { ...(hold.opening as object) } as never;
        expect(await batchEvm.channel.boundWithin({
          ...(matched as object),
          payload: {
            type: "voucher",
            channelConfig: { ...((hold.opening as { payload: { channelConfig: object } }).payload.channelConfig), salt: BV.fixed.Hprime },
            voucher: { channelId: BV.EB6.plant.matchedChannelId, maxClaimableAmount: "1000", signature: BV.EB2.signature },
          },
        } as never)).toBe(BV.EB6.plant.expectBoundWithinMatched);
      }));
  });

  it("openChannel refuses other bytes, a payment that is not an opening, and a pairing with no channel", () =>
    at(E.now, async () => {
      const { hold, opening } = await evmHold();
      expect(code(await openChannel(ABD, opening, batchEvm))).toBe("signed-not-bound");
      const voucher = unwrap(await within(evmDoc, hold, batchEvm, counting(evmAccount, evmAnswer)));
      expect(code(await openChannel(ABC, voucher.signed, batchEvm))).toBe("signed-not-bound");
      expect(code(await openChannel(ABC, opening, batchCloudflare))).toBe("pairing-not-supported");
    }));

  // RFC 8259 §6 permits no NaN or Infinity in JSON: the hold records the opening as JSON, so an opening holding such a
  // number is not held, as Python's json.dumps(allow_nan=False) refuses it, where JSON.stringify would write null.
  it("openChannel declines an opening holding a number that is not finite: signed-not-bound", () =>
    at(E.now, async () => {
      const { opening } = await evmHold();
      const held = unwrap(await openChannel(ABC, { ...(opening as object), extensions: { n: 1 } } as Presented, batchEvm));
      expect((held.opening as { extensions: unknown }).extensions).toEqual({ n: 1 });
      for (const n of [NaN, Infinity, -Infinity, new Number(NaN)]) {
        const out = await openChannel(ABC, { ...(opening as object), extensions: { n } } as Presented, batchEvm);
        expect(isDeclined(out) && out.decline).toEqual({ code: "signed-not-bound", detail: "The opening is not plain JSON." });
      }
    }));

  // The protocol package writes and reads no JSON whose arrays and objects nest more than 64 levels: the hold records
  // the opening as JSON, so an opening nested deeper is not held, at any depth, as the Python gate declines it.
  it("openChannel holds an opening nested 64 levels and declines one nested 65 or 100,000: signed-not-bound", () =>
    at(E.now, async () => {
      const { opening } = await evmHold();
      // The opening is level 1 and its extensions level 2, so `levels` arrays below them reach level `levels` + 2.
      const nested = (levels: number): Presented => {
        let n: unknown = 0;
        for (let i = 0; i < levels; i++) n = [n];
        return { ...(opening as object), extensions: { n } } as Presented;
      };
      const held = unwrap(await openChannel(ABC, nested(62), batchEvm));
      expect(JSON.stringify((held.opening as { extensions: unknown }).extensions)).toBe(
        `{"n":${"[".repeat(62)}0${"]".repeat(62)}}`,
      );
      for (const levels of [63, 100_000]) {
        const out = await openChannel(ABC, nested(levels), batchEvm);
        expect(isDeclined(out) && out.decline).toEqual({ code: "signed-not-bound", detail: "The opening is not plain JSON." });
      }
    }));
});

// EB9: the protocol package's EVM buildWithin over EB1's channel with EB2's maxClaimableAmount, its one request
// completed with EB2's signature: the payment's type and amount, or the refusal.
type Eb9Row = { case: string; refund?: { amount?: string | null } | null; expect: Record<string, unknown> };
it("x402-batch-settlement.json EB9: the file holds rows, and the EVM within's refund answers each", async () => {
  const v = vectors<{ fixed: { evm: { config: unknown } }; EB2: { maxClaimableAmount: string; signature: Hex }; EB9?: { rows: Eb9Row[] } }>(
    "x402-batch-settlement.json",
  );
  const rows = v.EB9?.rows ?? [];
  expect(rows.length, "EB9 rows").toBeGreaterThan(0);
  for (const r of rows) {
    const refund =
      r.refund === undefined || r.refund === null || typeof r.refund.amount !== "string" ? r.refund : { ...r.refund, amount: BigInt(r.refund.amount) };
    const u = await batchEvm.buildWithin(
      {
        required: evmDoc,
        accepted: evmDoc.accepts[0]!,
        channelConfig: v.fixed.evm.config as never,
        maxClaimableAmount: BigInt(v.EB2.maxClaimableAmount),
        ...(r.refund !== undefined ? { refund: refund as never } : {}),
      },
      H as AtrHash,
    );
    if ("refused" in u) {
      expect(u, r.case).toEqual(r.expect);
      continue;
    }
    const p = u.complete([v.EB2.signature]);
    if ("refused" in p) throw new Error(`${r.case}: ${JSON.stringify(p)}`);
    const payload = p.payload as { type: string; amount?: string; voucher: { signature: string } };
    expect(payload.voucher.signature, r.case).toBe(v.EB2.signature);
    expect({ type: payload.type, ...(payload.amount !== undefined ? { amount: payload.amount } : {}) }, r.case).toEqual(r.expect);
  }
});

// ── SVM ──────────────────────────────────────────────────────────────────────────────────────────────────────────────

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = "";
  while (n > 0n) {
    s = B58[Number(n % 58n)]! + s;
    n /= 58n;
  }
  for (const x of b) {
    if (x !== 0) break;
    s = "1" + s;
  }
  return s;
}
function ed25519(seedHex: string, message: Uint8Array): Uint8Array {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  return new Uint8Array(edSign(null, message, createPrivateKey({ key: der, format: "der", type: "pkcs8" })));
}

/** A message's fee payer, blockhash, and each instruction's program, data and sorted accounts, as base58 and hex. */
function shape(message: Uint8Array) {
  const required = message[1]!;
  const wire = new Uint8Array(1 + 64 * required + message.length);
  wire[0] = required;
  wire.set(message, 1 + 64 * required);
  const tx = decodeSvmTx(wire);
  if ("refused" in tx) throw new Error(tx.code);
  return {
    feePayer: base58(tx.keys[0]!),
    blockhash: base58(tx.blockhash),
    instructions: tx.instructions.map((ix) => ({
      program: base58(tx.keys[ix.program]!),
      accounts: ix.accounts.map((i) => base58(tx.keys[i]!)).sort(),
      data: hex(ix.data),
    })),
  };
}

describe("x402/batch-settlement/solana: the channel hold", () => {
  const S = BV.fixed.svm;
  const doc = x402Doc(batchSvm, S.option);
  const account = `solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:${S.payer}`;
  const inputs = {
    payerAuthorizer: S.payer,
    deposit: S.deposit,
    openSlot: S.openSlot,
    tokenProgram: S.tokenProgram,
    recentBlockhash: S.blockhash,
    salt: S.salt,
  };
  async function answer(r: SigningRequest): Promise<Signature> {
    if (r.kind !== "batch") throw new Error(r.kind);
    return r.requests.map((q) => base58(ed25519(S.payerSeed, (q as { message: Uint8Array }).message)));
  }

  it("openChannel holds ES1's channel; within at charged 0 signs ES3's voucher message; kind within, same channel", async () => {
    const opened = unwrap(await transact(doc, batchSvm, counting(account, answer), serving(ABC), { inputs }));
    const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchSvm));
    expect(hold).toMatchObject({ network: BV.ES4.expectRef.network, channel: BV.ES1.channelPda, h: H, charged: "0", signedMax: "1000" });
    const signer = counting(account, answer);
    const out = unwrap(await within(doc, JSON.parse(JSON.stringify(hold)), batchSvm, signer));
    const r = signer.requests[0]!;
    if (r.kind !== "batch" || r.requests[0]!.kind !== "ed25519-raw") throw new Error("request");
    expect(hex(r.requests[0]!.message)).toBe(BV.ES3.message);
    const sig = hex(ed25519(S.payerSeed, r.requests[0]!.message));
    expect(sig.startsWith(BV.ES3.signaturePrefix) && sig.endsWith(BV.ES3.signatureSuffix)).toBe(true);
    expect(batchSvm.channel.kind(out.signed as never)).toBe("within");
    expect(await batchSvm.channel.ref(out.signed as never)).toEqual(BV.ES4.expectRef);
    const other = { ...hold, channel: "87anxbpY5qDH7q8d8p9sV7iQGWnhP3DUHYaBvcpz4cxZ" };
    const refused = counting(account, answer);
    expect(code(await within(doc, other, batchSvm, refused))).toBe("signed-not-bound");
    expect(refused.requests.length).toBe(0);
  });

  // A payment for a channel the buyer never opened is refused, and nothing is signed. On Solana the channel address is
  // derived from the option's `feePayer` as well as the held channel configuration, so a within challenge naming
  // another fee payer asks for a voucher or a refund in another channel.
  it("a within challenge naming another feePayer: no-payable-option, and the signer is never called", async () => {
    const opened = unwrap(await transact(doc, batchSvm, counting(account, answer), serving(ABC), { inputs }));
    const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchSvm));
    const option = { ...S.option, extra: { ...(S.option.extra as object), feePayer: BV.ES1.channelPda } } as PaymentRequirements;
    const other = x402Doc(batchSvm, option);
    const signer = counting(account, answer);
    expect(code(await within(other, JSON.parse(JSON.stringify(hold)), batchSvm, signer))).toBe("no-payable-option");
    expect(code(await within(other, hold, batchSvm, signer, {}, { recentBlockhash: S.blockhash }))).toBe("no-payable-option");
    const retry = { ...other, error: "invalid_batch_settlement_svm_receiver_binding_unavailable" };
    expect(code(await within(retry, hold, batchSvm, signer, {}, { recentBlockhash: S.blockhash }))).toBe("no-payable-option");
    expect(signer.requests.length).toBe(0);
  });

  // ES6 (the Solana refund, x402's scheme_batch_settlement_svm.md): the refund is the voucher for the recorded charge
  // alone (ES6.cooperative), and only the refund taken again under a payment request whose `error` is
  // `invalid_batch_settlement_svm_receiver_binding_unavailable` also carries the payer-signed `request_close`
  // (ES6.withMemo), built with the buyer's `recentBlockhash`. At a recorded charge of 1000 the voucher's message is ES3's,
  // and the `request_close` message holds the fee payer, blockhash and instructions of the one inside ES4's close wire
  // (the rail does not fix key order inside a category). The inputs here are the opening's, blockhash included.
  const RETRY = "invalid_batch_settlement_svm_receiver_binding_unavailable";
  async function charged1000(): Promise<ChannelHold> {
    const opened = unwrap(await transact(doc, batchSvm, counting(account, answer), serving(ABC), { inputs }));
    const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchSvm));
    return unwrap(recordCharge(hold, "1000"));
  }
  const members = (signed: Presented): string[] => Object.keys((signed as { payload: object }).payload).sort();

  it("a full refund is ES6's cooperative form: ES3's voucher alone, kind close, the held channel", async () => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    const out = unwrap(await within(doc, hold, batchSvm, signer, {}, inputs));
    const r = signer.requests[0]!;
    if (signer.requests.length !== 1 || r.kind !== "batch" || r.requests.length !== 1) throw new Error("request");
    expect(r.requests[0]!.kind).toBe("ed25519-raw");
    expect(hex((r.requests[0] as { message: Uint8Array }).message)).toBe(BV.ES3.message);
    expect(members(out.signed)).toEqual([...BV.ES6.cooperative.payloadMembers].sort());
    expect(batchSvm.channel.kind(out.signed as never)).toBe(BV.ES6.cooperative.expectKind);
    expect(await batchSvm.channel.ref(out.signed as never)).toEqual(BV.ES4.expectRef);
  });

  it("the refund taken again after the binding is unavailable is ES6.withMemo's: ES4's close message, then the voucher", async () => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    const out = unwrap(await within({ ...doc, error: RETRY }, hold, batchSvm, signer, {}, inputs));
    const r = signer.requests[0]!;
    if (signer.requests.length !== 1 || r.kind !== "batch" || r.requests.length !== 2) throw new Error("request");
    expect(r.requests.map((q) => q.kind)).toEqual(["solana-message", "ed25519-raw"]);
    const close = decodeSvmTx(Uint8Array.from(Buffer.from(BV.ES4.closeWireBase64, "base64")));
    if ("refused" in close) throw new Error(close.code);
    expect(shape((r.requests[0] as { message: Uint8Array }).message)).toEqual(shape(close.message));
    expect(hex((r.requests[1] as { message: Uint8Array }).message)).toBe(BV.ES3.message);
    expect(members(out.signed)).toEqual([...BV.ES6.withMemo.payloadMembers].sort());
    expect(batchSvm.channel.kind(out.signed as never)).toBe(BV.ES6.withMemo.expectKind);
    expect(await batchSvm.channel.ref(out.signed as never)).toEqual(BV.ES4.expectRef);
  });

  // x402's reference client takes the refund again when the settle failure's PAYMENT-RESPONSE carries `errorReason`
  // invalid_batch_settlement_svm_receiver_binding_unavailable, read first, or else when the 402 payment request's
  // `error` does (x402's TypeScript client, `client/refund.ts`; its Go client, `refund.go`, reads the `error` only when
  // no PAYMENT-RESPONSE is given, so a PAYMENT-RESPONSE without `errorReason` follows `refund.ts`).
  // `refund.paymentResponse` carries the decoded PAYMENT-RESPONSE, here in the HTTP transport's settle-failure form.
  const failure = (errorReason?: string) => ({
    success: false,
    ...(errorReason === undefined ? {} : { errorReason }),
    transaction: "",
    network: S.option.network,
    payer: S.payer,
  });
  const kinds = (r: SigningRequest | undefined): string[] => (r?.kind === "batch" ? r.requests.map((q) => q.kind) : []);

  it("the code only in the PAYMENT-RESPONSE's errorReason: the refund taken again, built with the given recentBlockhash", async () => {
    const hold = await charged1000();
    for (const [d, refund] of [
      [doc, { paymentResponse: failure(RETRY) }],
      [{ ...doc, error: RETRY }, { paymentResponse: failure() }],
    ] as const) {
      const signer = counting(account, answer);
      const out = unwrap(await within(d, hold, batchSvm, signer, refund, inputs));
      expect(signer.requests.length).toBe(1);
      expect(kinds(signer.requests[0])).toEqual(["solana-message", "ed25519-raw"]);
      const r = signer.requests[0] as unknown as { requests: { message: Uint8Array }[] };
      expect(shape(r.requests[0]!.message).blockhash).toBe(S.blockhash);
      expect(hex(r.requests[1]!.message)).toBe(BV.ES3.message);
      expect(members(out.signed)).toEqual([...BV.ES6.withMemo.payloadMembers].sort());
    }
  });

  it("the code in neither the errorReason nor the error, or another errorReason read first: the voucher alone", async () => {
    const hold = await charged1000();
    for (const [d, refund] of [
      [doc, { paymentResponse: failure("insufficient_funds") }],
      [doc, { paymentResponse: failure() }],
      [{ ...doc, error: RETRY }, { paymentResponse: failure("insufficient_funds") }],
    ] as const) {
      const signer = counting(account, answer);
      const out = unwrap(await within(d, hold, batchSvm, signer, refund, inputs));
      expect(kinds(signer.requests[0])).toEqual(["ed25519-raw"]);
      expect(members(out.signed)).toEqual([...BV.ES6.cooperative.payloadMembers].sort());
    }
  });

  it("the code in the errorReason with no recentBlockhash: no-payable-option, x402/input-missing, and nothing is signed", async () => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    const { recentBlockhash: _, ...rest } = inputs;
    const out = await within(doc, hold, batchSvm, signer, { paymentResponse: failure(RETRY) }, rest);
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-missing" });
    expect(signer.requests.length).toBe(0);
  });

  it.each([
    ["a string", "eyJzdWNjZXNzIjpmYWxzZX0="],
    ["null", null],
    ["a list", []],
  ])("a paymentResponse that is %s: no-payable-option, x402/input-malformed, and nothing is signed", async (_, given) => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    const out = await within(doc, hold, batchSvm, signer, { paymentResponse: given as never }, inputs);
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    expect(signer.requests.length).toBe(0);
  });

  // A SettlementResponse's `errorReason` is a string where it is given (x402's core specification v2, §5.3.2).
  it.each([
    ["a number", 5],
    ["a boolean", true],
    ["a list", [RETRY]],
    ["an object", { code: RETRY }],
  ])("an errorReason that is %s, with the code in the error: no-payable-option, x402/input-malformed, and nothing is signed", async (_, given) => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    const refund = { paymentResponse: { ...failure(), errorReason: given } };
    const out = await within({ ...doc, error: RETRY }, hold, batchSvm, signer, refund as never, inputs);
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    expect(signer.requests.length).toBe(0);
  });

  it("the refund taken again with no recentBlockhash: no-payable-option, x402/input-missing, and nothing is signed", async () => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    const { recentBlockhash: _, ...rest } = inputs;
    const out = await within({ ...doc, error: RETRY }, hold, batchSvm, signer, {}, rest);
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-missing" });
    expect(signer.requests.length).toBe(0);
  });

  // The build here stands in for the package's: it records what the gate hands it and completes with the held
  // channel's configuration. The refund hands it `w.refund = {}` and none of the buyer's request_close values; the
  // refund taken again hands it all three.
  it("a full refund hands buildWithin refund {}, and the request_close values only for the refund taken again", async () => {
    const opened = unwrap(await transact(doc, batchSvm, counting(account, answer), serving(ABC), { inputs }));
    const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchSvm));
    const handed: Record<string, unknown>[] = [];
    const binding = {
      ...batchSvm,
      async buildWithin(w: Record<string, unknown> & { accepted: unknown; channelConfig: unknown }) {
        handed.push(w);
        return {
          requests: [{ kind: "ed25519-raw", message: new Uint8Array([1, 2, 3]), signer: S.payer }],
          complete: () => ({ x402Version: 2, accepted: w.accepted, payload: { type: "refund", channelConfig: w.channelConfig } }),
        };
      },
    } as unknown as typeof batchSvm;
    const given = { ...inputs, computeUnitLimit: 300000, computeUnitPrice: "2" };
    for (const d of [doc, { ...doc, error: RETRY }]) {
      const out = unwrap(await within(d, hold, binding, counting(account, async () => ["1".repeat(64)]), {}, given));
      expect(batchSvm.channel.kind(out.signed as never)).toBe("close");
    }
    const values = ["recentBlockhash", "computeUnitLimit", "computeUnitPrice"];
    expect(handed.map((w) => [w["refund"], values.map((k) => w[k])])).toEqual([
      [{}, [undefined, undefined, undefined]],
      [{}, [S.blockhash, 300000, 2n]],
    ]);
    expect(handed[0]!["channelConfig"]).toEqual((hold.opening as { payload: { channelConfig: unknown } }).payload.channelConfig);
  });

  // buyer.json's BW3: a refund value given in a form the request_close does not take is declined no-payable-option
  // with x402/input-malformed, before the build and the signer call, never dropped; BW3's control signs. The forms are
  // the rail's: a base58 blockhash, a u32 computeUnitLimit and a u64 computeUnitPrice written in decimal.
  it.each([
    ["computeUnitLimit -1", { computeUnitLimit: -1 }],
    ["computeUnitLimit 4294967296, past a u32", { computeUnitLimit: 4294967296 }],
    ["computeUnitLimit 1.5", { computeUnitLimit: 1.5 }],
    ["computeUnitLimit a string", { computeUnitLimit: "200000" }],
    ["computeUnitLimit a boolean", { computeUnitLimit: true }],
    ["computeUnitPrice 1.5, not a decimal integer string", { computeUnitPrice: "1.5" }],
    ["computeUnitPrice a number", { computeUnitPrice: 1 }],
    ["computeUnitPrice 2^64, past a u64", { computeUnitPrice: "18446744073709551616" }],
    ["recentBlockhash 7, not a string", { recentBlockhash: 7 }],
    ["recentBlockhash outside the base58 alphabet", { recentBlockhash: "0".repeat(44) }],
  ])("a refund with %s: no-payable-option, x402/input-malformed, nothing signed", async (_, given) => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    for (const d of [doc, { ...doc, error: RETRY }]) {
      const out = await within(d, hold, batchSvm, signer, {}, given as never);
      expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    }
    expect(signer.requests.length).toBe(0);
  });

  it("BW3's control: well-formed refund values, and the refund is signed with one signer call", async () => {
    const hold = await charged1000();
    const signer = counting(account, answer);
    const given = { computeUnitLimit: 200000, computeUnitPrice: "1", recentBlockhash: "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k" };
    unwrap(await within(doc, hold, batchSvm, signer, {}, given));
    expect(signer.requests.length).toBe(1);
  });

  // buyer.json's BW4: within declines inputs given and not an object with no-payable-option and x402/input-malformed,
  // for a refund and for a voucher, before the build and the signer call.
  it.each([
    ["a string", "x"],
    ["a number", 5],
    ["a list", []],
    ["null", null],
  ])("inputs that are %s: within declines before the build and the signer call", async (_, given) => {
    const opened = unwrap(await transact(doc, batchSvm, counting(account, answer), serving(ABC), { inputs }));
    const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchSvm));
    let builds = 0;
    const binding = {
      ...batchSvm,
      buildWithin: (...args: Parameters<typeof batchSvm.buildWithin>) => (builds++, batchSvm.buildWithin(...args)),
    } as unknown as typeof batchSvm;
    const signer = counting(account, answer);
    for (const refund of [{}, undefined]) {
      const out = await within(doc, hold, binding, signer, refund, given as never);
      expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    }
    expect([builds, signer.requests.length]).toEqual([0, 0]);
  });
});

// ── MPP session ──────────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/session/tempo: the channel hold", () => {
  const T = vectors<{
    fixed: { payerKey: Hex; payer: Hex; now: number; requestV2: string; deposit: string; pathUSD: Hex; escrowV2: Hex };
    TS3: { expectChannelId: string };
  }>("mpp-session-tempo.json");
  const MC = vectors<{ fixed: { realm: string; expires: string } }>("mpp-challenge.json");
  const f = T.fixed;
  const challenge = {
    realm: MC.fixed.realm,
    method: "tempo",
    intent: "session",
    request: Buffer.from(f.requestV2, "utf8").toString("base64url"),
    expires: MC.fixed.expires,
  } as MppChallenge;
  const doc = sessionTempo.advertise([challenge], H, LINK, challenge) as MppChallenge[];
  const account = `eip155:42431:${f.payer}`;
  const num = (n: number | bigint): Hex => (BigInt(n) === 0n ? "0x" : toHex(BigInt(n)));
  async function answer(r: SigningRequest): Promise<Signature> {
    if (r.kind !== "tempo-call") throw new Error(r.kind);
    const fields = [num(r.chainId), num(1), num(2), num(200000), [[r.call.to, "0x", r.call.data]], [], toHex((1n << 256n) - 1n), "0x", num(r.validBefore), "0x", f.pathUSD, "0x", []] as const;
    const s = await sign({ hash: keccak256(concat(["0x76", toRlp(fields as never)])), privateKey: f.payerKey });
    return concat(["0x76", toRlp([...fields, concat([s.r, s.s, toHex(Number(s.v), { size: 1 })])] as never)]);
  }

  /**
   * A wallet signs an EIP-712 address by its value; viem refuses the vectors' escrow `0x4D505…`, whose case is not
   * EIP-55's, so this test wallet writes it in lower case before signing. The digest is the same.
   */
  const walletTypedData = (td: unknown): TypedDataDefinition => {
    const t = td as TypedDataDefinition & { domain: { verifyingContract?: string } };
    const vc = t.domain.verifyingContract;
    return vc === undefined ? t : ({ ...t, domain: { ...t.domain, verifyingContract: vc.toLowerCase() } } as TypedDataDefinition);
  };
  const walletAnswer = async (r: SigningRequest): Promise<Signature> => {
    const key = privateKeyToAccount(f.payerKey);
    if (r.kind === "eip712") return key.signTypedData(walletTypedData(r.typedData));
    if (r.kind === "batch") return Promise.all(r.requests.map((q) => key.signTypedData(walletTypedData((q as { typedData: unknown }).typedData))));
    return answer(r);
  };

  /**
   * The session binding whose `buildWithin` records the `SessionWithin` the gate hands it (the in-channel payment:
   * the within challenge, the held opening, the cumulative amount and the action) before building, or returns a
   * refusal with the code `refuse`.
   */
  function withBuildWithin(refuse?: string) {
    const seen: { challenge: MppChallenge; opening: unknown; cumulativeAmount: bigint; action: string }[] = [];
    const binding = {
      ...sessionTempo,
      async buildWithin(w: (typeof seen)[number], h: AtrHash) {
        seen.push(w);
        if (refuse !== undefined) return refusal(refuse);
        return sessionTempo.buildWithin(w as never, h);
      },
    } as unknown as typeof sessionTempo;
    return { binding, seen };
  }

  it("openChannel holds TS3's channel; a pairing with no buildWithin has no in-channel payment, and nothing is signed", () =>
    at(f.now, async () => {
      const opened = unwrap(await transact(doc, sessionTempo, counting(account, walletAnswer), serving(ABC), { inputs: { deposit: f.deposit } }));
      const hold = unwrap(await openChannel(opened.bytes, opened.signed!, sessionTempo));
      expect(hold).toMatchObject({ network: "eip155:42431", channel: T.TS3.expectChannelId, h: H, charged: "0", signedMax: "0" });
      const signer = counting(account, walletAnswer);
      const withoutWithin = { ...sessionTempo, buildWithin: undefined } as unknown as typeof sessionTempo;
      const out = await within(doc, hold, withoutWithin, signer);
      expect(code(out)).toBe("pairing-not-supported");
      expect(signer.requests.length).toBe(0);
    }));

  it("within hands buildWithin the within challenge, the held opening, the charge plus the amount, and the voucher action", () =>
    at(f.now, async () => {
      const opened = unwrap(await transact(doc, sessionTempo, counting(account, walletAnswer), serving(ABC), { inputs: { deposit: f.deposit } }));
      const { binding, seen } = withBuildWithin();
      const hold = unwrap(await openChannel(opened.bytes, opened.signed!, binding));
      const charged = unwrap(recordCharge({ ...hold, signedMax: "500" }, "300"));
      const signer = counting(account, walletAnswer);
      const out = unwrap(await within(doc, charged, binding, signer));
      expect(seen).toEqual([{ challenge: doc[0], opening: hold.opening, cumulativeAmount: 400n, action: "voucher" }]);
      expect(signer.requests.map((r) => r.kind)).toEqual(["batch"]);
      // The Tempo v2 voucher (MPP's in-channel session payment): "TIP20 Channel Reserve", version "1", the
      // chain and the escrow of the opening, over the held channel and the cumulative amount.
      const voucher = (signer.requests[0] as unknown as { requests: { kind: string; typedData: TypedDataDefinition }[] }).requests[0]!;
      expect(voucher.kind).toBe("eip712");
      expect(voucher.typedData.domain).toMatchObject({ name: "TIP20 Channel Reserve", version: "1", chainId: 42431 });
      expect((voucher.typedData.domain as { verifyingContract: string }).verifyingContract.toLowerCase()).toBe(f.escrowV2.toLowerCase());
      expect(voucher.typedData.message).toEqual({ channelId: T.TS3.expectChannelId, cumulativeAmount: 400n });
      expect((out.signed as { payload: { action: string; cumulativeAmount: string } }).payload).toMatchObject({
        action: "voucher",
        cumulativeAmount: "400",
      });
      expect(out.hold).toEqual({ ...charged, signedMax: "500" });

      const closing = withBuildWithin();
      const closed = unwrap(await within(doc, charged, closing.binding, counting(account, walletAnswer), {}));
      expect(closing.seen.map((w) => [w.action, w.cumulativeAmount])).toEqual([["close", 300n]]);
      expect((closed.signed as { payload: { action: string } }).payload.action).toBe("close");
    }));

  it("a partial refund, and an action buildWithin does not build, are pairing-not-supported; nothing is signed", () =>
    at(f.now, async () => {
      const opened = unwrap(await transact(doc, sessionTempo, counting(account, walletAnswer), serving(ABC), { inputs: { deposit: f.deposit } }));
      const hold = unwrap(await openChannel(opened.bytes, opened.signed!, sessionTempo));
      const signer = counting(account, walletAnswer);
      const partial = await within(doc, hold, withBuildWithin().binding, signer, { amount: "5" });
      expect(isDeclined(partial) && [partial.decline.code, partial.decline.detail]).toEqual([
        "pairing-not-supported",
        "mpp/within-action-not-built",
      ]);
      const refused = await within(doc, hold, withBuildWithin("mpp/within-action-not-built").binding, signer);
      expect(isDeclined(refused) && [refused.decline.code, refused.decline.detail]).toEqual([
        "pairing-not-supported",
        "mpp/within-action-not-built",
      ]);
      expect(signer.requests.length).toBe(0);
    }));

  // The seller's own challenge on the live channel: it issues it itself, with its own id, no ATR, and the channel
  // named in `methodDetails.channelId`. The gate signs only for a channel it opened for an ATR it compared, and only when the
  // within challenge's legal context is absent or names that H. The challenge is the issued request with
  // `methodDetails.channelId` added, a fresh id, and no `opaque` unless a legal context is given.
  function own(o: { channelId?: string | undefined; legalContext?: AtrHash | undefined }): MppChallenge {
    const request = JSON.parse(f.requestV2) as { methodDetails: Record<string, unknown> };
    if (o.channelId !== undefined) request.methodDetails["channelId"] = o.channelId;
    const c: MppChallenge = {
      realm: MC.fixed.realm,
      method: "tempo",
      intent: "session",
      request: Buffer.from(JSON.stringify(request), "utf8").toString("base64url"),
      expires: MC.fixed.expires,
      id: "sellerOwnChallengeId-0123456789abcdef",
    } as MppChallenge;
    if (o.legalContext === undefined) return c;
    const opaque = JSON.stringify({ legalContext: `lcp:sha256:${o.legalContext}`, legalContextUrl: LINK });
    return { ...c, opaque: Buffer.from(opaque, "utf8").toString("base64url") } as MppChallenge;
  }
  const H_OTHER = `0x${"11".repeat(32)}` as AtrHash;
  const held = () =>
    at(f.now, async () => {
      const opened = unwrap(await transact(doc, sessionTempo, counting(account, walletAnswer), serving(ABC), { inputs: { deposit: f.deposit } }));
      return unwrap(await openChannel(opened.bytes, opened.signed!, sessionTempo));
    });

  it.each([
    ["the held channelId and no legal context", { channelId: "held" }],
    ["the held channelId and a legal context naming the held H", { channelId: "held", legalContext: H }],
    ["no channelId and no legal context", {}],
  ] as [string, { channelId?: string; legalContext?: AtrHash }][])("the seller's own challenge with %s: one voucher request", async (_, o) => {
    const hold = await held();
    const challenge = own({ ...o, channelId: o.channelId === "held" ? T.TS3.expectChannelId : o.channelId });
    const signer = counting(account, walletAnswer);
    const out = unwrap(await at(f.now, () => within([challenge], hold, sessionTempo, signer)));
    expect(signer.requests.map((r) => r.kind)).toEqual(["batch"]);
    const signed = out.signed as { challenge: MppChallenge; payload: { action: string; channelId: string } };
    expect(signed.challenge).toEqual(challenge);
    expect([signed.payload.action, signed.payload.channelId.toLowerCase()]).toEqual(["voucher", T.TS3.expectChannelId]);
  });

  it("the seller's own challenge naming another channelId declines before any signer call", async () => {
    const hold = await held();
    const signer = counting(account, walletAnswer);
    const out = await within([own({ channelId: `0x${"22".repeat(32)}` })], hold, sessionTempo, signer);
    expect(isDeclined(out) && out.decline).toEqual({ code: "no-payable-option", detail: "The challenge names a channel this hold did not open." });
    expect(signer.requests.length).toBe(0);
  });

  it("the seller's own challenge whose legal context names another hash declines before any signer call", async () => {
    const hold = await held();
    const signer = counting(account, walletAnswer);
    for (const c of [own({ channelId: T.TS3.expectChannelId, legalContext: H_OTHER }), own({ legalContext: H_OTHER })]) {
      expect(code(await within([c], hold, sessionTempo, signer))).toBe("hash-mismatch");
    }
    expect(signer.requests.length).toBe(0);
  });

  // MPP's opaque is a flat string-to-string map (draft-httpauth-payment-01, lines 348-352), read as the protocol
  // package reads one: base64url without padding whose final character's unused bits are zero (RFC 4648 section 3.5),
  // at most 8 KiB decoded, UTF-8 with a leading byte order mark kept as a character. An opaque that is not one declines
  // offer-unreadable, mpp/opaque-malformed, before any signer call: buyer.json's BW1 and BW2 opaques among them, whose
  // expected decline is that row's.
  const withOpaque = (text: string, encoded?: string): MppChallenge => ({
    ...own({ channelId: T.TS3.expectChannelId }),
    opaque: encoded ?? Buffer.from(text, "utf8").toString("base64url"),
  });
  const LCP = `{"legalContext":"lcp:sha256:${H}","legalContextUrl":"https://atr.seller.example/7c8acfa2-f800-4192-89e9-1cef9833180f"}`;
  const seller = (bytes: number) => `{"seller":"${"x".repeat(bytes - 13)}"}`;
  /** The LCP members and one more: 193 bytes, so the base64url's final character carries unused bits. */
  const LCP_ODD = `${LCP.slice(0, -1)},"seller":"x"}`;
  /** `text`'s base64url with its final character's lowest unused bit set: the same bytes, written another way. */
  function bent(text: string): string {
    const o = Buffer.from(text, "utf8").toString("base64url");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    return o.slice(0, -1) + alphabet[alphabet.indexOf(o.at(-1)!) | 1]!;
  }
  it.each([
    ["BW1: a legalContext member that is null", '{"legalContext":null}'],
    ["BW2: the LCP members naming the held H, and a member seller whose value is the number 1", `${LCP.slice(0, -1)},"seller":1}`],
    ["BW2: only a member seller whose value is the number 1", '{"seller":1}'],
    ["a member whose value is an object", '{"seller":{"a":"b"}}'],
    ["a byte order mark before the object", `\uFEFF${LCP}`],
    ["a member whose value is an escaped lone surrogate, which has no RFC 8785 form", '{"seller":"\\ud800"}'],
    ["8193 bytes decoded", seller(8193)],
    ["a final character with a non-zero unused bit, over the LCP members and one more", LCP_ODD, bent(LCP_ODD)],
  ] as [string, string, string?][])("an opaque with %s: offer-unreadable, mpp/opaque-malformed, and no signer call", async (_, text, encoded) => {
    const hold = await held();
    const signer = counting(account, walletAnswer);
    const out = await at(f.now, () => within([withOpaque(text, encoded)], hold, sessionTempo, signer));
    expect(isDeclined(out) && out.decline).toEqual({ code: "offer-unreadable", detail: "mpp/opaque-malformed" });
    expect(signer.requests.length).toBe(0);
  });

  it("an opaque written with base64 padding is mpp/opaque-malformed; a legalContext that is not an LCP string is mpp/legal-context-malformed", async () => {
    const hold = await held();
    const signer = counting(account, walletAnswer);
    const padded = `${Buffer.from(LCP, "utf8").toString("base64url")}=`;
    const outs = [
      await at(f.now, () => within([withOpaque(LCP, padded)], hold, sessionTempo, signer)),
      await at(f.now, () => within([withOpaque('{"legalContext":"not-an-lcp-string"}')], hold, sessionTempo, signer)),
    ];
    expect(outs.map((o) => isDeclined(o) && o.decline.detail)).toEqual(["mpp/opaque-malformed", "mpp/legal-context-malformed"]);
    expect(signer.requests.length).toBe(0);
  });

  it("an opaque of 8192 bytes decoded, BW1's control naming the held H, and the LCP members and one more written canonically, are read: one voucher request each", async () => {
    expect(bent(LCP_ODD)).not.toBe(Buffer.from(LCP_ODD, "utf8").toString("base64url"));
    expect(Buffer.from(bent(LCP_ODD), "base64url")).toEqual(Buffer.from(LCP_ODD, "utf8"));
    for (const text of [seller(8192), LCP, LCP_ODD]) {
      expect(Buffer.from(text, "utf8").length).toBeLessThanOrEqual(8192);
      const hold = await held();
      const signer = counting(account, walletAnswer);
      unwrap(await at(f.now, () => within([withOpaque(text)], hold, sessionTempo, signer)));
      expect(signer.requests.map((r) => r.kind)).toEqual(["batch"]);
    }
  });
});
