// The buyer pieces of mpp/charge/tempo/split-memo and mpp/charge/tempo/split-memo/push, over the protocol package's
// mpp-charge-tempo-split-memo.json. The buyer's stock MPP client builds and signs the Tempo transaction from the placed
// challenge, so the gate hands the signer nothing: each file's issued challenge (`offer`) is placed by the pairing's own
// advertise over buyer.json's ATR A, and confirm and transact over it hand the signer no request. The payments are the
// file's: the Authorization header the stock mppx 0.17.6 client returned for each placed challenge (pull with the fee
// paid for the payer, in a 0x78 envelope; pull with the payer paying it, in a 0x76 envelope; push, which the client
// broadcast and names by its hash), and, for push, the read of the named transaction (`fetched`) its server holds.
// check gives the file's `expect.bound` for each; the push payment is read with that read as the landed receipt the
// caller's own reader read, and without it the push payment is not yet bound. The account is each file's B2 row's.
//
// mpp/session/tempo's opening, a tempo-call request, is shown from mpp-session-tempo.json's L1, a live open on Tempo
// Moderato recorded with its receipt: the request is the call its signed bytes make, read with the protocol package's
// decodeTempoTx, and every member the summary shows is the receipt's own: the token's Transfer of the deposit from the
// payer to the escrow, and the escrow's ChannelOpened (topics: event, channel id, payer, payee; data: operator, token,
// authorizedSigner, salt, expiring nonce hash, deposit).
import { describe, expect, it } from "vitest";
import type { AtrHash } from "@integraledger/lcp";
import { tempoSplitMemo, tempoSplitMemoPush, type MppChallenge } from "@integraledger/lcp/mpp";
import { decodeTempoTx } from "@integraledger/lcp/tempo";
import { summaryOf } from "../src/summary.js";
import type { SigningRequest } from "../src/types.js";
import { check, confirm, transact, type Binding } from "../src/index.js";
import { A, ABC, code, CONFIRMING, counting, fromHex, GATE, HA, isDeclined, LINK, serving, toHex, vectors } from "./support.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type Loose = any;

const V = vectors<Loose>("mpp-charge-tempo-split-memo.json");

/** The credential an Authorization header value carries: the base64url JSON after "Payment ". */
const credentialOf = (authorization: string): Loose => {
  const [scheme, value] = authorization.split(" ");
  if (scheme !== "Payment" || value === undefined) throw new Error(authorization);
  return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
};

/** A file's buyer row of `pairing`, by its name. */
const buyerRow = (pairing: string, name: string): Loose => {
  const found = (V.buyer.rows as Loose[]).find((r) => r.pairing === pairing && r.name === name);
  if (found === undefined) throw new Error(`no buyer row ${name} for ${pairing}`);
  return found;
};

/** The challenges as the pairing's own `advertise` places `h` and the link over the issued challenge `c`. */
function placedFor(binding: unknown, c: MppChallenge, h: AtrHash): MppChallenge[] {
  const placed = (binding as { advertise(d: unknown, h: string, l: string, o: unknown, p: number): unknown }).advertise([c], h, LINK, c, 0);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

const FORMS = [
  { name: "pullSponsored", binding: tempoSplitMemo },
  { name: "pullPayerPays", binding: tempoSplitMemo },
  { name: "push", binding: tempoSplitMemoPush },
] as const;

describe("mpp/charge/tempo/split-memo and its push form", () => {
  for (const { name, binding: b } of FORMS) {
    const binding = b as unknown as Binding;
    const v = V[name];
    const account = buyerRow(v.pairing, "B2").input.account as string;

    it(`${name}: confirm only over A: nothing is handed to the signer, and transact pays nothing`, async () => {
      expect(binding.id).toBe(v.pairing);
      const doc = placedFor(b, v.offer, HA);
      const confirmed = await confirm(doc, binding, account, serving(A), CONFIRMING);
      if (isDeclined(confirmed)) throw new Error(confirmed.decline.detail);
      expect(confirmed).toMatchObject({ chosen: { pairing: v.pairing }, request: null, bytes: A, h: HA });
      const signer = counting(account, async () => {
        throw new Error("the signer was called");
      });
      expect(await transact(doc, binding, signer, serving(A), GATE)).toEqual({ signed: null, bytes: A, h: HA });
      expect(signer.requests).toEqual([]);
    });

    it(`${name}: check reads the file's bound hash from the stock client's payment`, async () => {
      const credential = credentialOf(v.authorization);
      expect(credential.challenge).toEqual(v.placed);
      expect(await check(ABC, credential, binding, v.fetched)).toEqual({ h: v.expect.bound });
      if (v.fetched !== undefined) {
        // The push payment moved before it was presented: until the caller's reader has read the named transaction,
        // nothing it holds carries H.
        expect(code(await check(ABC, credential, binding))).toBe("signed-not-bound");
      }
    });
  }
});

describe("mpp/session/tempo's opening: the tempo-call summary", () => {
  const L1 = vectors<Loose>("mpp-session-tempo.json").L1;
  const word = (data: string, i: number): string => data.slice(2 + 64 * i, 66 + 64 * i);
  const addressOf = (w: string): string => `0x${w.slice(-40)}`;

  it("L1: the payee, token, deposit, escrow and signer the summary shows are the receipt's", async () => {
    const tx = decodeTempoTx(fromHex(L1.raw));
    if ("code" in tx) throw new Error(tx.code);
    expect(tx.calls.length).toBe(1);
    const call = tx.calls[0]!;
    const request = {
      kind: "tempo-call",
      chainId: Number(tx.chainId),
      call: { to: call.to, data: toHex(call.input) },
      validBefore: Number(tx.validBefore),
      broadcast: false,
    } as unknown as SigningRequest;
    const [transfer, opened] = L1.receipt.logs as { address: string; topics: string[]; data: string }[];
    expect(transfer!.topics.slice(1).map(addressOf)).toEqual([L1.sender, opened!.address]);
    const deposit = BigInt(transfer!.data).toString();
    expect(await summaryOf("mpp/session/tempo", request, A)).toEqual({
      payees: [{ account: addressOf(opened!.topics[3]!), amount: deposit }],
      asset: transfer!.address,
      network: "eip155:42431",
      validity: { notBefore: null, notAfter: String(tx.validBefore), unit: "seconds" },
      deposit: BigInt(`0x${word(opened!.data, 5)}`).toString(),
      grant: { escrow: opened!.address, authorizedSigner: addressOf(word(opened!.data, 2)) },
      atr: A,
    });
    expect(BigInt(`0x${word(opened!.data, 0)}`)).toBe(0n);
    expect(addressOf(word(opened!.data, 1))).toBe(transfer!.address);
  });
});
