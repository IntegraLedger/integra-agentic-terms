// The gate holds the Hedera session it opened: `transact` returns the opening's landed receipt beside the payment in
// a JSON-safe form, integers as decimal strings as lcp's vectors write `landed.blockNumber`, and `openChannel` takes it,
// so `bound` reads the escrow log that carries the channel's salt. The opening, the log and the channel id are the
// vector file's HS1 to HS3; the signer is the published Anvil key #0, the vectors' payer.
import { describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { FETCHED, sessionHedera, sessionSolana, type MppChallenge } from "@integraledger/lcp/mpp";
import {
  check,
  openChannel,
  transact,
  within,
  type Binding,
  type ChannelHold,
  type Presented,
  type SigningRequest,
} from "../src/index.js";
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
    if ("approve" in out) throw new Error("an agreement payment to approve");
    expect(out.landed).toEqual({ transaction: V.HS3.txHash, blockNumber: String(BLOCK), logs: [V.HS3.log] });
    expect(JSON.parse(JSON.stringify(out.landed))).toEqual(out.landed);
  });

  it("openChannel(bytes, transact().signed, binding, transact().landed) holds the session", async () => {
    const out = await transact(doc, offered(sessionHedera), signer(), serving(ABC), { inputs });
    if (isDeclined(out)) throw new Error(out.decline.detail);
    if ("approve" in out) throw new Error("an agreement payment to approve");
    const hold = await openChannel(out.bytes, out.signed!, sessionHedera, out.landed);
    if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
    expect([hold.pairing, hold.channel, hold.h]).toEqual(["mpp/session/hedera", V.HS1.expectChannelId, H]);
    expect(JSON.parse(JSON.stringify(hold))).toEqual(hold);
  });

  it("without the landed receipt the opening cannot be held: bound has no log to read", async () => {
    const out = await transact(doc, offered(sessionHedera), signer(), serving(ABC), { inputs });
    if (isDeclined(out)) throw new Error(out.decline.detail);
    if ("approve" in out) throw new Error("an agreement payment to approve");
    const hold = await openChannel(out.bytes, out.signed!, sessionHedera);
    expect(isDeclined(hold) && hold.decline).toEqual({ code: "signed-not-bound", detail: "The pairing does not read the hash of the compared bytes from the opening." });
  });

  // The receipt is read only as given beside the opening: the hold keeps the opening as signed and the receipt as the
  // hold's own `landed` member, an opening that carries it as a member of its own is not held, and `check` takes it
  // beside the payment and declines one that is not a JSON object.
  it("the landed receipt is read beside the opening, never as a member of its own", async () => {
    const out = await transact(doc, offered(sessionHedera), signer(), serving(ABC), { inputs });
    if (isDeclined(out)) throw new Error(out.decline.detail);
    if ("approve" in out) throw new Error("an agreement payment to approve");
    const hold = await openChannel(out.bytes, out.signed!, sessionHedera, out.landed);
    if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
    expect(hold.opening).toEqual(out.signed);
    expect(hold.landed).toEqual(out.landed);
    const inside = await openChannel(out.bytes, { ...(out.signed as object), landed: out.landed } as never, sessionHedera);
    expect(isDeclined(inside) && inside.decline.code).toBe("signed-not-bound");
    expect(await check(out.bytes, out.signed, sessionHedera, out.landed)).toEqual({ h: H });
    const notObject = { decline: { code: "signed-not-bound", detail: "The landed receipt is not a JSON object beside the payment." } };
    expect(await check(out.bytes, out.signed, sessionHedera, "landed")).toEqual(notObject);
    expect(await check(out.bytes, "payment", sessionHedera, out.landed)).toEqual(notObject);
  });
});

// The hold keeps the read made for a channel's opening as its own `landed` member, beside the opening as signed: the
// `landed` given, else the read the opening holds under its own `FETCHED` member, as `@integraledger/lcp`'s
// `fetchPresented` returns it. `within` holds that read under the opening's own `FETCHED` member, as `bound` and
// `buildWithin` read it. A member of the opening's own, `landed`, `tables` or any other, is never read as the read: an
// opening carrying one gives the answer the same opening without it gives. The openings, receipts, tables and signers
// are the vector file's: HS1 and HS3 for Hedera; for Solana, SV6's one row naming a signer, whose opening names its
// voucher signer (account 4) through an address lookup table, with the tables a reader gives for it, and SV2.

/** The issued challenge with its request changed by `edit`, the seller's own id, and no `opaque`. */
function own(issued: MppChallenge, edit: (request: Loose) => void): MppChallenge {
  const request = JSON.parse(Buffer.from(issued.request as string, "base64url").toString("utf8")) as Loose;
  edit(request);
  const { opaque: _opaque, ...rest } = issued as MppChallenge & { opaque?: string };
  return { ...rest, request: Buffer.from(JSON.stringify(request), "utf8").toString("base64url"), id: "sellerOwnChallengeId-0123456789abcdef" } as MppChallenge;
}

describe("mpp/session/hedera: the read made for the opening is the hold's own landed member", () => {
  const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
  const anvil = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
  const opening = {
    challenge: V.SS1.hedera.placed,
    payload: { action: "open", channelId: V.HS1.expectChannelId, txHash: V.HS3.txHash, cumulativeAmount: "0", signature: "0x00" },
  };
  const landed = { transaction: V.HS3.txHash, blockNumber: "47312717", logs: [V.HS3.log] };
  const challenge = own(V.SS1.hedera.challenge, (r) => {
    r.methodDetails.channelId = V.HS1.expectChannelId;
    delete r.suggestedDeposit;
  });
  const wallet = () =>
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
  /** The voucher `within` signs on the hold, or its decline. */
  async function paid(hold: ChannelHold | unknown): Promise<unknown> {
    if (isDeclined(hold)) return hold.decline;
    const out = await within([challenge], hold as ChannelHold, sessionHedera, wallet());
    return isDeclined(out) ? out.decline : out.signed;
  }

  it("an opening holding its receipt under FETCHED, given no landed, is held with it and paid as with landed given", async () => {
    const voucher = await paid(await openChannel(ABC, opening as Presented, sessionHedera, landed));
    expect((voucher as { payload: { action: string; channelId: string } }).payload).toMatchObject({ action: "voucher", channelId: V.HS1.expectChannelId });
    const hold = await openChannel(ABC, { ...opening, [FETCHED]: landed } as Presented, sessionHedera);
    if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
    expect(await paid(hold)).toEqual(voucher);
    expect(await paid(JSON.parse(JSON.stringify(hold)))).toEqual(voucher);
    expect(hold.opening).toEqual(opening);
    expect(hold.landed).toEqual(landed);
  });

  it("a landed member of the opening's own is never read: the hold keeps it as signed and pays as without it", async () => {
    const voucher = await paid(await openChannel(ABC, opening as Presented, sessionHedera, landed));
    const carrying = { ...opening, landed: { ...landed, logs: [] } };
    const bare = await openChannel(ABC, carrying as Presented, sessionHedera);
    expect(isDeclined(bare) && bare.decline.code).toBe("signed-not-bound");
    const hold = await openChannel(ABC, { ...carrying, [FETCHED]: landed } as Presented, sessionHedera);
    if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
    expect(await paid(hold)).toEqual(voucher);
    expect(hold.opening).toEqual(carrying);
    expect(hold.landed).toEqual(landed);
  });
});

describe("mpp/session/solana: the tables read for an opening with lookups are the hold's own landed member", () => {
  const V = vectors<Loose>("mpp-session-hedera-solana-xrpl.json");
  const at = (path: string): Loose =>
    path.split(".").reduce((o: Loose, part) => {
      const m = /^([^[]+)(?:\[(\d+)\])?$/.exec(part)!;
      return m[2] === undefined ? o[m[1]!] : o[m[1]!][Number(m[2])];
    }, V);
  const rows = (V.SV6.rows as Loose[]).filter((r) => "signer" in r);
  const row = rows[0];
  const source = at(row.opening);
  // SS1's placed Solana challenge, which the row answers as C_S, with its client voucher signer.
  const opening = { challenge: V.SS1.solana.placed, payload: { action: "open", channelId: source.channel, transaction: source.wireBase64 } };
  const tables = { tables: row.expect.tables };
  // The same tables naming another key at each read-only index: the channel of the other table row, which names its
  // channel elsewhere.
  const another = (V.agreedRefusals.rows as Loose[]).filter((r) => "wireBase64" in r && "channel" in r && r.channel !== source.channel)[0].channel;
  const forged = { tables: row.expect.tables.map((t: Loose) => ({ ...t, readonly: t.readonly.map(() => another) })) };
  const named = (channelId: string) =>
    own(V.SS1.solana.challenge, (r) => {
      r.methodDetails.channelId = channelId;
      delete r.methodDetails.recentBlockhash;
      delete r.methodDetails.recentSlot;
    });
  /** The keys `within` asks the signer to sign for, a voucher and a close, or the open's decline. */
  async function signers(hold: ChannelHold | unknown, channel = source.channel): Promise<unknown> {
    if (isDeclined(hold)) return hold.decline.code;
    const out: unknown[] = [];
    for (const refund of [undefined, {}]) {
      const s = counting(`solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1:${V.SV3.payer}`, async (r: SigningRequest) =>
        (r as unknown as { requests: unknown[] }).requests.map(() => "1".repeat(64)),
      );
      const w = await within([named(channel)], hold as ChannelHold, sessionSolana, s, refund);
      out.push(isDeclined(w) ? w.decline.code : s.requests.flatMap((q) => (q as unknown as { requests: { signer: string }[] }).requests.map((x) => x.signer)));
    }
    return out;
  }

  it("the row names one signer, account 4, read through the tables a reader gives", () => {
    expect(rows.length).toBe(1);
    expect(row.challenges).toContain("C_S");
    expect(another).not.toBe(row.signer);
  });

  it("given as landed, or held under FETCHED with no landed, the tables are the hold's landed: within signs for their signer", async () => {
    const given = await openChannel(ABC, opening as Presented, sessionSolana, tables);
    const fetched = await openChannel(ABC, { ...opening, [FETCHED]: tables } as Presented, sessionSolana);
    for (const hold of [given, fetched]) {
      if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
      expect(await signers(hold)).toEqual([[row.signer], [row.signer]]);
      expect(await signers(JSON.parse(JSON.stringify(hold)))).toEqual([[row.signer], [row.signer]]);
      expect([hold.opening, hold.landed]).toEqual([opening, tables]);
    }
  });

  it("held under FETCHED, with other tables as its own landed or tables member: the held tables alone are read", async () => {
    for (const member of ["landed", "tables"]) {
      const carrying = { ...opening, [member]: member === "landed" ? forged : forged.tables };
      const hold = await openChannel(ABC, { ...carrying, [FETCHED]: tables } as Presented, sessionSolana);
      if (isDeclined(hold)) throw new Error(`${member}: ${hold.decline.code}: ${hold.decline.detail}`);
      expect(await signers(hold)).toEqual([[row.signer], [row.signer]]);
      expect([hold.opening, hold.landed]).toEqual([carrying, tables]);
    }
  });

  it("the tables as the opening's own landed or tables member, and no read: declined at the opening", async () => {
    for (const carrying of [{ ...opening, landed: tables }, { ...opening, tables: tables.tables }, opening]) {
      const hold = await openChannel(ABC, carrying as Presented, sessionSolana);
      expect(isDeclined(hold) && hold.decline.code).toBe("signed-not-bound");
    }
  });

  it("an opening without lookups carrying a landed member, given no landed, is held with no landed and paid as without it", async () => {
    const sv2 = { challenge: V.SS1.solana.placed, payload: { action: "open", channelId: V.SV2.channel, transaction: V.SV2.wireBase64 } };
    const plain = await openChannel(ABC, sv2 as Presented, sessionSolana);
    const carrying = { ...sv2, landed: forged };
    const hold = await openChannel(ABC, carrying as Presented, sessionSolana);
    if (isDeclined(hold)) throw new Error(`${hold.decline.code}: ${hold.decline.detail}`);
    expect("landed" in hold).toBe(false);
    expect(hold.opening).toEqual(carrying);
    expect(await signers(hold, V.SV2.channel)).toEqual(await signers(plain, V.SV2.channel));
  });
});
