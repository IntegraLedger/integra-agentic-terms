// The seller's own within challenge on a held Hedera, Solana or XRPL session: it issues it itself, with its own id, no
// legal context, and the held channel named where each session draft names a channel in the challenge:
// - Hedera: `methodDetails.channelId`, "Channel ID if resuming" (draft-hedera-session-00; "Existing channel
//   (`channelId` provided)"), a bytes32 in hex;
// - Solana: `methodDetails.channelId`, "Existing channel identifier to resume" (draft-solana-session-00), the base58
//   channel address, with `recentBlockhash` and `recentSlot` absent "when resuming";
// - XRPL: the request's `channelId`, "64-hex channel ID, or `""` on an open" (draft-xrpl-session-00), empty "when the
//   server names no channel", and "two spellings of one channel are one channel".
// The gate pays such a challenge naming the held channel with one voucher, and declines one naming another channel
// before any signer call. The openings, channels and challenges are the vector file's SS1, HS1-HS3, SV2 and XS2; the
// Hedera signer is the published Anvil key #0, and the Solana signer the seed of 32 bytes 0x01, the SV2 opening's
// signer.
import { createPrivateKey, sign as edSign } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sessionHedera, sessionSolana, sessionXrpl, type MppChallenge } from "@integraledger/lcp/mpp";
import { openChannel, within, type Binding, type ChannelHold, type Presented, type SigningRequest } from "../src/index.js";
import { ABC, counting, isDeclined, vectors } from "./support.js";

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;
const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
const OWN_ID = "sellerOwnChallengeId-0123456789abcdef";
const OTHER_DECLINE = { code: "no-payable-option", detail: "The challenge names a channel this hold did not open." };

/** The issued challenge with its request changed by `edit`, a fresh id, and no `opaque`. */
function own(issued: MppChallenge, edit: (request: Record<string, any>) => void): MppChallenge {
  const request = JSON.parse(Buffer.from(issued.request as string, "base64url").toString("utf8")) as Record<string, any>;
  edit(request);
  const { opaque: _opaque, ...rest } = issued as MppChallenge & { opaque?: string };
  return { ...rest, request: Buffer.from(JSON.stringify(request), "utf8").toString("base64url"), id: OWN_ID } as MppChallenge;
}

async function held(opening: unknown, binding: Binding, landed?: unknown): Promise<ChannelHold> {
  const hold = await openChannel(ABC, opening as Presented, binding, landed);
  if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
  return hold;
}

type Signed = { challenge: MppChallenge; payload: { action: string; channelId: string } };

// ── Hedera ───────────────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/session/hedera: the seller's own challenge naming the channel in methodDetails.channelId", () => {
  const anvil = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const opening = {
    challenge: V.SS1.hedera.placed,
    payload: { action: "open", channelId: V.HS1.expectChannelId, txHash: V.HS3.txHash, cumulativeAmount: "0", signature: "0x00" },
  };
  const landed = { transaction: V.HS3.txHash, blockNumber: "47312717", logs: [V.HS3.log] };
  const naming = (channelId: string) =>
    own(V.SS1.hedera.challenge, (r) => {
      r.methodDetails.channelId = channelId;
      delete r.suggestedDeposit;
    });
  const signer = () =>
    counting(`hedera:testnet:${V.fixed.payer}`, async (r: SigningRequest) =>
      Promise.all(
        (r as unknown as { requests: { typedData: TypedDataDefinition & { domain: { verifyingContract: string } } }[] }).requests.map((q) =>
          anvil.signTypedData({
            ...q.typedData,
            domain: { ...q.typedData.domain, verifyingContract: q.typedData.domain.verifyingContract.toLowerCase() as `0x${string}` },
          }),
        ),
      ),
    );

  it("naming the held channel: paid with one voucher on that channel", async () => {
    const hold = await held(opening, sessionHedera, landed);
    const challenge = naming(V.HS1.expectChannelId);
    const s = signer();
    const out = await within([challenge], hold, sessionHedera, s);
    if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
    expect(s.requests.map((r) => r.kind)).toEqual(["batch"]);
    const signed = out.signed as unknown as Signed;
    expect(signed.challenge).toEqual(challenge);
    expect([signed.payload.action, signed.payload.channelId]).toEqual(["voucher", V.HS1.expectChannelId]);
  });

  it("naming another channel: declined before any signer call", async () => {
    const hold = await held(opening, sessionHedera, landed);
    const s = signer();
    const out = await within([naming(`0x${"22".repeat(32)}`)], hold, sessionHedera, s);
    expect(isDeclined(out) && out.decline).toEqual(OTHER_DECLINE);
    expect(s.requests.length).toBe(0);
  });
});

// ── Solana ───────────────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/session/solana: the seller's own challenge naming the channel in methodDetails.channelId", () => {
  const opening = { challenge: V.SS1.solana.placed, payload: { action: "open", channelId: V.SV2.channel, transaction: V.SV2.wireBase64 } };
  const naming = (channelId: string) =>
    own(V.SS1.solana.challenge, (r) => {
      r.methodDetails.channelId = channelId;
      delete r.methodDetails.recentBlockhash;
      delete r.methodDetails.recentSlot;
    });
  const seed = Buffer.alloc(32, 1);
  const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const base58 = (b: Uint8Array): string => {
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
  };
  const signer = () =>
    counting(`solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:${V.SV3.payer}`, async (r: SigningRequest) =>
      (r as unknown as { requests: { message: Uint8Array }[] }).requests.map((q) => base58(new Uint8Array(edSign(null, q.message, key)))),
    );

  it("naming the held channel: paid with one voucher on that channel", async () => {
    const hold = await held(opening, sessionSolana);
    const challenge = naming(V.SV2.channel);
    const s = signer();
    const out = await within([challenge], hold, sessionSolana, s);
    if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
    expect(s.requests.map((r) => r.kind)).toEqual(["batch"]);
    const signed = out.signed as unknown as Signed;
    expect(signed.challenge).toEqual(challenge);
    expect([signed.payload.action, signed.payload.channelId]).toEqual(["voucher", V.SV2.channel]);
  });

  it("naming another channel: declined before any signer call", async () => {
    const hold = await held(opening, sessionSolana);
    const s = signer();
    const out = await within([naming(V.plants.solana.channel)], hold, sessionSolana, s);
    expect(isDeclined(out) && out.decline).toEqual(OTHER_DECLINE);
    expect(s.requests.length).toBe(0);
  });
});

// ── XRPL ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

describe("mpp/session/xrpl: the seller's own challenge naming the channel in the request's channelId", () => {
  const opening = { challenge: V.SS1.xrpl.placed, payload: { action: "open", transaction: V.XS2.blob, amount: "100", signature: "00" } };
  const naming = (channelId: string) => own(V.SS1.xrpl.challenge, (r) => void (r.channelId = channelId));
  const signer = () =>
    counting(`xrpl:1:${V.XS2.account}`, async (r: SigningRequest) =>
      (r as unknown as { requests: unknown[] }).requests.map(() => "C0".repeat(64)),
    );

  it.each([
    ["in upper case", V.XS2.expectChannel as string],
    ["in lower case", (V.XS2.expectChannel as string).toLowerCase()],
  ])("naming the held channel %s: paid with one voucher on that channel", async (_, channelId) => {
    const hold = await held(opening, sessionXrpl);
    const challenge = naming(channelId);
    const s = signer();
    const out = await within([challenge], hold, sessionXrpl, s);
    if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
    expect(s.requests.map((r) => r.kind)).toEqual(["batch"]);
    const signed = out.signed as unknown as Signed;
    expect(signed.challenge).toEqual(challenge);
    expect([signed.payload.action, signed.payload.channelId]).toEqual(["voucher", V.XS2.expectChannel]);
  });

  it("naming another channel: declined before any signer call", async () => {
    const hold = await held(opening, sessionXrpl);
    const s = signer();
    const out = await within([naming(V.XS1.expect)], hold, sessionXrpl, s);
    expect(isDeclined(out) && out.decline).toEqual(OTHER_DECLINE);
    expect(s.requests.length).toBe(0);
  });
});
