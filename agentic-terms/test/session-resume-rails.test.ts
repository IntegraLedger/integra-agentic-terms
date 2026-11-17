// The seller's own within challenge on a held XRPL session: it issues it itself, with its own id, no legal context, and
// the held channel named where the session draft names a channel in the challenge: the request's `channelId`, "64-hex
// channel ID, or `""` on an open" (draft-xrpl-session-00), empty "when the server names no channel", and "two spellings
// of one channel are one channel". The gate pays such a challenge naming the held channel with one voucher, and declines
// one naming another channel before any signer call. The opening, channel and challenge are the vector file's SS1 and
// XS2.
import { describe, expect, it } from "vitest";
import { sessionXrpl, type MppChallenge } from "@integraledger/lcp/mpp";
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
