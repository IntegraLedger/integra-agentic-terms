// `mpp/session/hedera` is a pairing whose signer moves value before the gate's `finish`: it broadcasts the approve and
// the escrow `open`, then signs the zero voucher. Expected values: the signer broadcasts the two calls in order and signs
// the voucher, and `complete({openTx, signature})` returns `{challenge, payload: {action: "open", channelId, txHash:
// openTx, cumulativeAmount: "0", signature}}`; `Signer.sign` returns JSON in the form the build's `complete` takes; the
// vector file's HS1 and HS3. When the signer moved the payment and `bound` cannot read it (that form carries no landed
// log), the gate answers `{decline, moved}`, where `moved.signed` is the credential in the protocol's own form, with no
// `landed` member. The pairing has no public proof, so the offer names the agreement URL.
import { describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sessionHedera, type MppChallenge, type MppCredential } from "@integraledger/lcp/mpp";
import { transact, type Binding, type SigningRequest } from "../src/index.js";
import { ABC, counting, H, isDeclined, LINK, offered, serving, vectors } from "./support.js";

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;

function docOf(binding: Binding, c: MppChallenge): MppChallenge[] {
  const placed = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(
    [c],
    H,
    LINK,
    c,
  );
  if (!Array.isArray(placed)) throw new Error(JSON.stringify(placed));
  return placed as MppChallenge[];
}

describe("mpp/session/hedera: the deposit moves before the gate can bind it", () => {
  const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
  const f = V.fixed;
  // The published Anvil key #0, whose address is the vectors' payer.
  const anvil = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const doc = docOf(sessionHedera, V.SS1.hedera.challenge);
  const account = `hedera:testnet:${f.payer}`;
  const inputs = { deposit: V.HS2.deposit };
  const voucher = async (r: SigningRequest) =>
    anvil.signTypedData((r as unknown as { voucher: TypedDataDefinition }).voucher);

  it("a signer answering {openTx, signature} after broadcasting keeps the open credential", async () => {
    const signer = counting(account, async (r) => ({ openTx: V.HS3.txHash, signature: await voucher(r) }));
    const out = await transact(doc, offered(sessionHedera), signer, serving(ABC), { inputs });
    expect(signer.requests.map((r) => r.kind)).toEqual(["hedera-session-open"]);
    if (!isDeclined(out)) throw new Error("bound read no landed log, so the gate cannot confirm H");
    expect(out.decline.code).toBe("signed-not-bound");
    const moved = out.moved!;
    expect(moved.h).toBe(H);
    expect(moved.bytes).toEqual(ABC);
    expect(Object.keys(moved.signed as object).sort()).toEqual(["challenge", "payload"]);
    const payload = (moved.signed as MppCredential).payload;
    expect(payload["txHash"]).toBe(V.HS3.txHash);
    expect(payload["channelId"]).toBe(V.HS1.expectChannelId);
  });

  it("the credential the gate returns to be sent is `{challenge, payload}`", async () => {
    const signer = counting(account, async (r) => ({
      openTx: V.HS3.txHash,
      signature: await voucher(r),
      landed: { transaction: V.HS3.txHash, blockNumber: "1", logs: [V.HS3.log] },
    }));
    const out = await transact(doc, offered(sessionHedera), signer, serving(ABC), { inputs });
    if (isDeclined(out)) throw new Error(out.decline.code);
    expect(Object.keys(out.signed as object).sort()).toEqual(["challenge", "payload"]);
  });
});
