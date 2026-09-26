// The gate holds the Hedera session it opened: `transact` returns the opening's landed receipt beside the payment in
// a JSON-safe form, integers as decimal strings as lcp's vectors write `landed.blockNumber`, and `openChannel` takes it,
// so `bound` reads the escrow log that carries the channel's salt. The opening, the log and the channel id are the
// vector file's HS1 to HS3; the signer is the published Anvil key #0, the vectors' payer.
import { describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sessionHedera, type MppChallenge } from "@integraledger/lcp/mpp";
import { openChannel, transact, type Binding, type SigningRequest } from "../src/index.js";
import { ABC, counting, H, isDeclined, LINK, offered, serving, vectors } from "./support.js";

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;

function docOf(binding: Binding, c: MppChallenge): MppChallenge[] {
  const placed = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise([c], H, LINK, c);
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

describe("mpp/session/hedera: the channel the gate opened is held with its landed receipt", () => {
  const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
  const anvil = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const doc = docOf(sessionHedera, V.SS1.hedera.challenge);
  const account = `hedera:testnet:${V.fixed.payer}`;
  const inputs = { deposit: V.HS2.deposit };
  const BLOCK = 47312717;
  const signer = () =>
    counting(account, async (r: SigningRequest) => ({
      openTx: V.HS3.txHash,
      signature: await anvil.signTypedData((r as unknown as { voucher: TypedDataDefinition }).voucher),
      landed: { transaction: V.HS3.txHash, blockNumber: String(BLOCK), logs: [V.HS3.log] },
    }));

  it("transact returns landed as JSON, its block number a decimal string", async () => {
    const out = await transact(doc, offered(sessionHedera), signer(), serving(ABC), { inputs });
    if (isDeclined(out)) throw new Error(out.decline.detail);
    expect(out.landed).toEqual({ transaction: V.HS3.txHash, blockNumber: String(BLOCK), logs: [V.HS3.log] });
    expect(JSON.parse(JSON.stringify(out.landed))).toEqual(out.landed);
  });

  it("openChannel(bytes, transact().signed, binding, transact().landed) holds the session", async () => {
    const out = await transact(doc, offered(sessionHedera), signer(), serving(ABC), { inputs });
    if (isDeclined(out)) throw new Error(out.decline.detail);
    const hold = await openChannel(out.bytes, out.signed!, sessionHedera, out.landed);
    if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
    expect([hold.pairing, hold.channel, hold.h]).toEqual(["mpp/session/hedera", V.HS1.expectChannelId, H]);
    expect(JSON.parse(JSON.stringify(hold))).toEqual(hold);
  });

  it("without the landed receipt the opening cannot be held: bound has no log to read", async () => {
    const out = await transact(doc, offered(sessionHedera), signer(), serving(ABC), { inputs });
    if (isDeclined(out)) throw new Error(out.decline.detail);
    const hold = await openChannel(out.bytes, out.signed!, sessionHedera);
    expect(isDeclined(hold) && hold.decline).toEqual({ code: "signed-not-bound", detail: "The opening does not carry the hash of these bytes." });
  });
});
