// The buyer pieces of mpp/charge/solana/unsponsored and mpp/subscription/solana, over the protocol package's
// mpp-charge-solana.json and mpp-subscription-solana.json. The unsponsored charge is held to that file's `unsponsored`
// credential, whose transaction is the stock @solana/mpp 0.7.0 client's composition for the placed challenge, computed
// with @solana/kit 8.4.0 and not by the protocol package's builder: the payer pays its own fee, and the transfer and
// memo it signs are the stock client's. The payer's key is x402-exact-solana.json's fixed.payerSeed, whose address is
// the file's payer. The subscription's activation is the stock client's to compose and sign, so the gate hands the
// signer nothing: its challenge is the file's, placed by the pairing's own advertise over buyer.json's ATR A. The
// account and inputs are each file's B2 row's.
import { createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { chargeSolanaUnsponsored, subscriptionSolana, type MppChallenge, type MppCredential } from "@integraledger/lcp/mpp";
import { COMPUTE_BUDGET, decodeSvmTx } from "@integraledger/lcp/svm";
import { confirm, transact, type Binding, type Inputs } from "../src/index.js";
import { base58 } from "../src/summary/encode.js";
import {
  A,
  buildAndSign,
  CONFIRMING,
  counting,
  fromHex,
  GATE,
  HA,
  isDeclined,
  LINK,
  serving,
  toHex,
  vectors,
  type Pairing,
} from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Loose = any;
interface B2 {
  input: { account: string; inputs?: Inputs };
}

const S = vectors<Loose>("mpp-charge-solana.json");
const X = vectors<Loose>("x402-exact-solana.json");
const SUB = vectors<Loose>("mpp-subscription-solana.json");

/** The value at an RFC 6901 JSON Pointer into `doc`. */
const pointer = (doc: Loose, path: string): Loose =>
  path
    .split("/")
    .slice(1)
    .reduce((at, k) => at[k.replace(/~1/g, "/").replace(/~0/g, "~")], doc);

/** A file's buyer row of `pairing`, by its name. */
function buyerRow(file: Loose, pairing: string, name: string): B2 {
  const found = (file.buyer.rows as { pairing: string; name: string }[]).find((r) => r.pairing === pairing && r.name === name);
  if (found === undefined) throw new Error(`no buyer row ${name} for ${pairing}`);
  return found as unknown as B2;
}

/** The challenges as the pairing's own `advertise` places `h` and the link over the issued challenge `c`. */
function placedFor(binding: unknown, c: MppChallenge, h: AtrHash): MppChallenge[] {
  const placed = (binding as { advertise(d: unknown, h: string, l: string, o: unknown, p: number): unknown }).advertise([c], h, LINK, c, 0);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

/** An Ed25519 key from its 32-byte seed. */
function ed25519(seed: Uint8Array) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return { sign: (m: Uint8Array) => Uint8Array.from(sign(null, m, privateKey)) };
}

/** A v0 message's fee payer and instructions: program, accounts with their signer and writable flags, and data. */
function decompile(message: Uint8Array) {
  const [signers, readonlySigned, readonlyUnsigned] = [message[1]!, message[2]!, message[3]!];
  const wire = new Uint8Array(1 + 64 * signers + message.length);
  wire[0] = signers;
  wire.set(message, 1 + 64 * signers);
  const tx = decodeSvmTx(wire);
  if ("refused" in tx) throw new Error(tx.code);
  const n = tx.keys.length;
  const flags = (i: number) => ({
    signer: i < signers,
    writable: i < signers ? i < signers - readonlySigned : i < n - readonlyUnsigned,
  });
  return {
    feePayer: base58(tx.keys[0]!),
    instructions: tx.instructions.map((ix) => ({
      program: base58(tx.keys[ix.program]!),
      accounts: ix.accounts.map((a) => ({ address: base58(tx.keys[a]!), ...flags(a) })),
      data: Buffer.from(ix.data).toString("hex"),
    })),
  };
}

/** The instructions other than the Compute Budget program's, whose prices and limits are each client's own. */
const beyondBudget = (ixs: { program: string }[]) => ixs.filter((ix) => ix.program !== COMPUTE_BUDGET);

describe("mpp/charge/solana/unsponsored", () => {
  const U = S.unsponsored;
  const b2 = buyerRow(S, "mpp/charge/solana/unsponsored", "B2");
  const landed = decodeSvmTx(Uint8Array.from(Buffer.from(pointer(S, U.credential).payload.transaction, "base64")));
  if ("refused" in landed) throw new Error(landed.code);
  const stock = decompile(landed.message);
  const payer = ed25519(fromHex(X.fixed.payerSeed));
  const p: Pairing = {
    binding: chargeSolanaUnsponsored as unknown as Binding,
    doc: [U.placed],
    placed: (h) => placedFor(chargeSolanaUnsponsored, U.challenge, h),
    account: b2.input.account,
    inputs: b2.input.inputs ?? {},
    answer: async (r) => {
      if (r.kind !== "solana-message") throw new Error(r.kind);
      return toHex(payer.sign(r.message));
    },
  };

  it("the payer is the fee payer, and the transfer and memo are the stock client's; its signature completes a transaction credential bound to H", async () => {
    expect(beyondBudget(stock.instructions).length).toBeGreaterThan(0);
    const { signed } = await buildAndSign(p, (r) => {
      if (r.kind !== "solana-message") throw new Error(r.kind);
      const m = decompile(r.message);
      expect([m.feePayer, stock.feePayer]).toEqual([U.expectReferenceFeePayer, U.expectReferenceFeePayer]);
      expect(beyondBudget(m.instructions)).toEqual(beyondBudget(stock.instructions));
    });
    expect((signed as MppCredential).payload["type"]).toBe("transaction");
  });
});

describe("mpp/subscription/solana", () => {
  const b2 = buyerRow(SUB, "mpp/subscription/solana", "B2");
  const binding = subscriptionSolana as unknown as Binding;
  const doc = placedFor(subscriptionSolana, SUB.challenge, HA);

  it("confirm only: on a match nothing is handed to the signer, and transact pays nothing", async () => {
    const confirmed = await confirm(doc, binding, b2.input.account, serving(A), CONFIRMING);
    if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
    expect(confirmed).toMatchObject({ chosen: { pairing: "mpp/subscription/solana" }, request: null, bytes: A, h: HA });
    const signer = counting(b2.input.account, async () => {
      throw new Error("the signer was called");
    });
    expect(await transact(doc, binding, signer, serving(A), GATE)).toEqual({ signed: null, bytes: A, h: HA });
    expect(signer.requests).toEqual([]);
  });
});
