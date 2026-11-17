// The buyer pieces of mpp/session/solana/memo and mpp/session/solana/stock, over the protocol package's
// mpp-session-solana.json, whose memo opening was composed with @solana/kit 8.4.0 and not by the protocol package's
// builder. The memo piece's build, given the file's choice, hands the payer the file's message, and the payer's
// signature with the key of 32 bytes 0x01, the file's payer, completes the file's credential; the opening holds the
// file's channel; and the piece pays the challenge placed for buyer.json's ATR A through the gate. The stock session's
// opening is the buyer's stock client's, so the gate hands the signer nothing.
import { createPrivateKey, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { sessionSolanaMemo, sessionSolanaStock, type MppChallenge } from "@integraledger/lcp/mpp";
import { confirm, openChannel, type Binding, type Presented } from "../src/index.js";
import { A, AGREEMENT_URL, buildAndSign, CONFIRMING, HA, isDeclined, LINK, serving, toHex, vectors, type Pairing } from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Loose = any;
const V = vectors<Loose>("mpp-session-solana.json");
const DEVNET = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/** The value at an RFC 6901 JSON Pointer into the file. */
const pointer = (path: string): Loose => path.split("/").slice(1).reduce((at: Loose, k) => at[k], V);
const row = (pairing: string, name: string): Loose => V.buyer.rows.find((r: Loose) => r.pairing === pairing && r.name === name);

/** The challenge as issued: the placed one without the id and `opaque` that carry H. */
function issued(placed: MppChallenge): MppChallenge {
  const { id: _id, opaque: _opaque, ...rest } = placed as MppChallenge & { opaque?: string };
  return rest as MppChallenge;
}

/** The challenges as the pairing's own `advertise` places `h`, the link and, where given, the agreement URL. */
function placedFor(binding: unknown, c: MppChallenge, h: AtrHash, agreementUrl?: string): MppChallenge[] {
  const advertise = (binding as { advertise(...a: unknown[]): unknown }).advertise;
  const placed = advertise([c], h, LINK, c, 0, undefined, agreementUrl);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

/** The payer's Ed25519 key, the seed of 32 bytes 0x01. */
const payerKey = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 1)]),
  format: "der",
  type: "pkcs8",
});

describe("mpp/session/solana/memo", () => {
  const b2 = row("mpp/session/solana/memo", "B2");
  const binding = sessionSolanaMemo as unknown as Binding;
  const credential = pointer(V.memo.credential);
  const { payer: _payer, ...choice } = V.memo.choice;
  const p: Pairing = {
    binding,
    doc: b2.input.doc,
    placed: (h) => placedFor(sessionSolanaMemo, issued(b2.input.doc[0]), h),
    account: b2.input.account,
    inputs: choice,
    answer: async (r) => {
      if (r.kind !== "solana-session-open") throw new Error(r.kind);
      return toHex(Uint8Array.from(sign(null, r.message, payerKey)));
    },
  };

  it("the build hands the payer the file's open message, size and channel; its signature completes the file's credential", async () => {
    expect(`${DEVNET}:${V.fixed.payer}`).toBe(b2.input.account);
    const { signed } = await buildAndSign(p, (r) => {
      if (r.kind !== "solana-session-open") throw new Error(r.kind);
      expect([Buffer.from(r.message).toString("base64"), r.size, r.channel]).toEqual([
        V.memo.expectMessageBase64,
        V.memo.expectSize,
        V.memo.expectChannel,
      ]);
    });
    expect(signed).toEqual(credential);
  });

  it("the signed opening holds the file's channel on the session's network", async () => {
    const hold = await openChannel(new TextEncoder().encode("abc"), credential as Presented, binding);
    if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
    expect([hold.pairing, hold.network, hold.channel, hold.h]).toEqual(["mpp/session/solana/memo", DEVNET, V.memo.expectChannel, V.fixed.H]);
  });
});

describe("mpp/session/solana/stock", () => {
  const b2 = row("mpp/session/solana/stock", "B2");
  const binding = sessionSolanaStock as unknown as Binding;

  it("confirm only: on a match nothing is handed to the signer, and the challenge stays in the choice for the agreement", async () => {
    const doc = placedFor(sessionSolanaStock, issued(b2.input.doc[0]), HA, AGREEMENT_URL);
    const confirmed = await confirm(doc, binding, b2.input.account, serving(A), CONFIRMING);
    if (isDeclined(confirmed)) throw new Error(`${confirmed.decline.code}: ${confirmed.decline.detail}`);
    expect(confirmed).toMatchObject({ chosen: { pairing: "mpp/session/solana/stock", agreement: AGREEMENT_URL }, request: null, bytes: A, h: HA });
    expect((confirmed.chosen.choice as Loose).challenge).toEqual(doc[0]);
  });
});
