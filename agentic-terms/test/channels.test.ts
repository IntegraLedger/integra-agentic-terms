// The buyer's channel steps: a channel opened for a compared ATR is held with its bytes, later vouchers are signed only under
// that hold, and the recorded charge stays within what was signed. Expected digests, signatures, messages and channel
// ids are the vector files' (the batch-settlement file's EB1-EB6 and ES1-ES4; the Tempo session file's TS3); the
// arithmetic of the voucher ceiling is x402 batch-settlement's client rule: "the client sets the voucher's
// `maxClaimableAmount` to `chargedCumulativeAmount + amount`".
import { createPrivateKey, sign as edSign } from "node:crypto";
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

function unwrap<T extends object>(v: T): Exclude<T, Declined> {
  if (isDeclined(v)) throw new Error(`${v.decline.code}: ${v.decline.detail}`);
  return v as Exclude<T, Declined>;
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
    it("a signed voucher that commits to another agreement (EB6's plant) is dropped: signed-not-bound", () =>
      at(E.now, async () => {
        const { hold } = await evmHold();
        const plants: [string, string][] = [
          [BV.fixed.Hprime, BV.EB1.channelId],
          [BV.fixed.Hprime, BV.EB6.plant.matchedChannelId],
        ];
        for (const [salt, channelId] of plants) {
          const planted = {
            ...batchEvm,
            buildWithin: async (w: never, h: never) => {
              const u = (await batchEvm.buildWithin(w, h)) as { requests: unknown[]; complete(s: readonly string[]): unknown };
              return {
                ...u,
                complete: (s: readonly string[]) => {
                  const p = JSON.parse(JSON.stringify(u.complete(s)));
                  p.payload.channelConfig.salt = salt;
                  p.payload.voucher.channelId = channelId;
                  return p;
                },
              };
            },
          } as unknown as Binding;
          const signer = counting(evmAccount, evmAnswer);
          const out = await within(evmDoc, hold, planted, signer);
          expect(code(out)).toBe("signed-not-bound");
          expect(out).not.toHaveProperty("signed");
          expect(signer.requests.length).toBe(1);
        }
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

  it("openChannel refuses bytes the opening does not carry, a payment that is not an opening, and a pairing with no channel", () =>
    at(E.now, async () => {
      const { hold, opening } = await evmHold();
      expect(code(await openChannel(ABD, opening, batchEvm))).toBe("signed-not-bound");
      const voucher = unwrap(await within(evmDoc, hold, batchEvm, counting(evmAccount, evmAnswer)));
      expect(code(await openChannel(ABC, voucher.signed, batchEvm))).toBe("signed-not-bound");
      expect(code(await openChannel(ABC, opening, batchCloudflare))).toBe("pairing-not-supported");
    }));
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

  // ES6 (the Solana refund): the protocol package's build of `request_close` for a full
  // refund, with the recent blockhash from the buyer's inputs; its message holds the fee payer, blockhash and
  // instructions of the one inside ES4's close wire (the rail does not fix key order inside a category), and the
  // payment is a close of the held channel.
  it("a full refund through the protocol package's buildWithin: ES4's close message, kind close, the held channel", async () => {
    const opened = unwrap(await transact(doc, batchSvm, counting(account, answer), serving(ABC), { inputs }));
    const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchSvm));
    const signer = counting(account, answer);
    const out = unwrap(await within(doc, hold, batchSvm, signer, {}, { recentBlockhash: S.blockhash }));
    const r = signer.requests[0]!;
    if (r.kind !== "batch" || r.requests.length !== 1 || r.requests[0]!.kind !== "solana-message") throw new Error("request");
    const built = shape((r.requests[0] as { message: Uint8Array }).message);
    const wire = Uint8Array.from(Buffer.from(BV.ES4.closeWireBase64, "base64"));
    const close = decodeSvmTx(wire);
    if ("refused" in close) throw new Error(close.code);
    expect(built).toEqual(shape(close.message));
    expect(batchSvm.channel.kind(out.signed as never)).toBe(BV.ES4.expectCloseKind);
    expect(await batchSvm.channel.ref(out.signed as never)).toEqual(BV.ES4.expectRef);
  });

  // The Solana refund: `within(doc, hold, binding, signer, {})` calls the protocol package's `buildWithin` with
  // `w.refund = {}`, which builds the `request_close` transaction itself and returns one `solana-message` request, whose
  // completion is `{x402Version: 2, accepted, payload: {type: "refund", channelConfig, transaction}}`; the gate checks
  // that its kind is `close` and that it names the held channel. The build here stands in for the package's: it records
  // what the gate hands it and completes with the held channel's configuration, without the transaction the package's
  // completion carries.
  it("a full refund hands buildWithin refund {} and returns the close payment for the held channel", async () => {
    const opened = unwrap(await transact(doc, batchSvm, counting(account, answer), serving(ABC), { inputs }));
    const hold = unwrap(await openChannel(opened.bytes, opened.signed!, batchSvm));
    const handed: { refund?: unknown; channelConfig?: unknown; accepted?: unknown }[] = [];
    const message = new Uint8Array([1, 2, 3]);
    const binding = {
      ...batchSvm,
      async buildWithin(w: { refund?: unknown; channelConfig?: unknown; accepted: unknown; required: unknown }) {
        handed.push(w);
        return {
          requests: [{ kind: "solana-message", message }],
          complete: () => ({ x402Version: 2, accepted: w.accepted, payload: { type: "refund", channelConfig: w.channelConfig } }),
        };
      },
    } as unknown as typeof batchSvm;
    const signer = counting(account, async () => ["0x00"]);
    const out = unwrap(await within(doc, hold, binding, signer, {}));
    expect(handed.map((w) => w.refund)).toEqual([{}]);
    expect(handed[0]!.channelConfig).toEqual((hold.opening as { payload: { channelConfig: unknown } }).payload.channelConfig);
    expect(signer.requests).toEqual([{ kind: "batch", requests: [{ kind: "solana-message", message }] }]);
    expect(batchSvm.channel.kind(out.signed as never)).toBe("close");
    expect(await batchSvm.channel.ref(out.signed as never)).toEqual(BV.ES4.expectRef);
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
});
