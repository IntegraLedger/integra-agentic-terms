// terms' own gate vectors (vectors/buyer-gate.json, terms' profile buyer-gate.md) through the tools. Each row's
// document is its own, as written, or the file's fixed document for its pairing advertising the row's ATR; the row's
// link, or the file's, serves the row's bytes; the account is the row's, or the file's; the clock is the file's; and the
// request is the row's, its body's bytes as base64. The host gives the
// row's ceilings as `ceilings` and its floor input through `floors`; the agent approves where the row's approver does.
// The payer's signature is lcp's buyer.json B6 signature, the file's payer key over the same request. Over MCP the
// approval is the agent's: `atr_transact` returns each signing as `approve` and signs nothing, and signs it only when
// called again with it approved, unchanged (profile rule 16). The return value is lcp's legal-context-return.json's.
// A row whose pairing has no buyer piece yet answers pairing-not-supported, the gate's first check, with no call,
// asserted and never skipped, as the gate's own run of these rows does.
import { readFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Fetch, Signer, SigningRequest } from "@integraledger/terms";
import { createBuyerServer, type Floors } from "../src/index.js";
import { PIECES } from "../../agentic-terms/src/pairings/index.js";
import { at, connect, spawnBin, type Message } from "./stdio.js";

type Loose = any;
const V: Loose = JSON.parse(readFileSync(new URL("../../agentic-terms/vectors/buyer-gate.json", import.meta.url), "utf8"));
const vectors = (name: string): Loose =>
  JSON.parse(readFileSync(new URL(`../node_modules/@integraledger/lcp/vectors/${name}`, import.meta.url), "utf8"));
const B = vectors("buyer.json");
const RETURN = vectors("legal-context-return.json");
const S: string = B.rows.find((r: { name: string }) => r.name === "B6").input.then.finish.signature;
const M = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
const rowOf = (name: string): Loose => V.rows.find((r: { name: string }) => r.name === name);

type Counted = Signer & { requests: SigningRequest[] };
function signer(account: string = V.fixed.account): Counted {
  const s: Counted = {
    account,
    requests: [],
    async sign(r: SigningRequest) {
      s.requests.push(JSON.parse(JSON.stringify(r, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v))));
      return S;
    },
  };
  return s;
}

type Served = Fetch & { calls: number };
/** The row's link, or the file's, serving the row's bytes, counting every fetch; any other URL answers 404. */
function serving(row: Loose): Served {
  const link: string = row.link ?? V.fixed.link;
  const f = (async (url: string) => {
    f.calls++;
    return url === link ? new Response(Buffer.from(row.atr.hex, "hex"), { status: 200 }) : new Response(null, { status: 404 });
  }) as unknown as Served;
  f.calls = 0;
  return f;
}

/** The row's tool arguments: its pairing, its document advertising its ATR, and its request. */
function argsOf(row: Loose): { pairing: string; document: object; resourceRequest: object } {
  const document = structuredClone(row.document ?? V.fixed.documents[row.pairing]);
  if (row.document === undefined) document.extensions.legalContext.info.value = row.atr.sha256;
  const { method, target, bodyUtf8 } = row.resourceRequest;
  return { pairing: row.pairing, document, resourceRequest: { method, target, body: Buffer.from(bodyUtf8, "utf8").toString("base64") } };
}

/** The host's options for the row: its ceilings, and its floor inputs answered by `floors` for its pairing. */
function hostOf(row: Loose): { ceilings: Loose; floors: Floors } {
  const floors: Floors = (pairing) => (pairing === row.pairing && Object.keys(row.inputs).length > 0 ? row.inputs : undefined);
  return { ceilings: row.ceilings, floors };
}

/** The decline a row ends at before the approver: its own, or pairing-not-supported while its pairing has no piece. */
const endOf = (row: Loose): string | null =>
  !PIECES.has(row.pairing) ? "pairing-not-supported" : row.expect.approverCalls === 0 ? row.expect.decline : null;

const call = (c: { request(method: string, params?: object): Promise<unknown> }, name: string, args: object) =>
  c.request("tools/call", { name, arguments: args, _meta: M }) as Promise<Message>;
const code = (m: Message) => at(m, "result.structuredContent.decline.code");

describe("buyer-gate.json rows through the tools", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(V.fixed.now * 1000);
  });
  afterEach(() => vi.useRealTimers());

  // atr_confirm makes the checks before the signer; a row the gate passes them on returns the request and its summary.
  for (const row of V.rows as Loose[]) {
    const declined = endOf(row);
    it(`atr_confirm, ${row.name}: ${declined ?? "the request and its summary"}`, async () => {
      const fetch = serving(row);
      const c = connect({ fetch, ...hostOf(row) });
      const m = await call(c, "atr_confirm", { ...argsOf(row), account: row.account ?? V.fixed.account });
      await c.close();
      expect(code(m)).toBe(declined ?? undefined);
      if (declined === row.expect.decline && row.expect.detail !== undefined) {
        expect(at(m, "result.structuredContent.decline.detail")).toBe(row.expect.detail);
      }
      if (declined !== null) {
        expect(at(m, "result.structuredContent")).not.toHaveProperty("request");
        return;
      }
      expect(at(m, "result.structuredContent.request")).toBeTypeOf("object");
      expect(at(m, "result.structuredContent.summary.atr")).toEqual(at(m, "result.structuredContent.atr"));
      expect(at(m, "result.structuredContent.atr.base64")).toBe(Buffer.from(row.atr.hex, "hex").toString("base64"));
    });
  }

  // atr_transact: where the gate would ask the approver, the signing is returned as `approve` and nothing is signed; the
  // row whose approver approves is signed once the agent calls again with that `approve`.
  for (const row of V.rows as Loose[]) {
    const declined = endOf(row);
    it(`atr_transact, ${row.name}: ${declined ?? (row.approves ? "approved, then signed" : "shown, nothing signed")}`, async () => {
      const s = signer(row.account);
      const c = connect({ fetch: serving(row), signer: s, ...hostOf(row) });
      const args = argsOf(row);
      const m = await call(c, "atr_transact", args);
      if (declined !== null) {
        await c.close();
        expect(code(m)).toBe(declined);
        if (declined === row.expect.decline && row.expect.detail !== undefined) {
          expect(at(m, "result.structuredContent.decline.detail")).toBe(row.expect.detail);
        }
        expect(s.requests).toHaveLength(0);
        return;
      }
      const approve = at(m, "result.structuredContent.approve") as { signings: Loose[] };
      expect(at(m, "result.isError")).toBeUndefined();
      expect(at(m, "result.structuredContent")).not.toHaveProperty("signed");
      expect(s.requests).toHaveLength(0);
      const asked = row.expect.asked ?? [{ act: "payment", pairing: row.pairing, step: { index: 0, count: 1 } }];
      expect(approve.signings.map(({ act, pairing, step }) => ({ act, pairing, step }))).toEqual(asked);
      expect(approve.signings[0].summary.atr).toEqual(at(m, "result.structuredContent.atr"));
      if (!row.approves) return c.close();

      const signed = await call(c, "atr_transact", { ...args, approved: approve });
      await c.close();
      expect(at(signed, "result.isError")).toBeUndefined();
      expect(s.requests).toEqual([approve.signings[0].request]);
      expect(at(signed, "result.structuredContent.signed.payload.signature")).toBe(S);
      expect(at(signed, "result.structuredContent.signed.payload.authorization.nonce")).toBe(row.atr.sha256);
    });
  }

  it("atr_transact signs no approval that was changed: the signing is returned again, and nothing is signed", async () => {
    const row = rowOf("approved");
    const s = signer();
    const c = connect({ fetch: serving(row), signer: s });
    const args = argsOf(row);
    const first = await call(c, "atr_transact", args);
    const approve = at(first, "result.structuredContent.approve") as { signings: Loose[] };
    const [signing] = approve.signings;
    const changed = [
      { ...signing, summary: { ...signing.summary, amount: "1" } },
      { ...signing, request: { ...signing.request, typedData: { ...signing.request.typedData, message: { ...signing.request.typedData.message, to: V.fixed.account.split(":")[2] } } } },
    ];
    const answers: Message[] = [];
    for (const edited of changed) answers.push(await call(c, "atr_transact", { ...args, approved: { signings: [edited] } }));
    await c.close();
    for (const m of answers) {
      expect(at(m, "result.structuredContent")).not.toHaveProperty("signed");
      expect(at(m, "result.structuredContent.approve.signings.1")).toEqual(signing);
    }
    expect(s.requests).toHaveLength(0);
  });

  it("the terms-mcp binary, which takes no options, declines floor-missing even where the tool's inputs name the floor", async () => {
    const given = rowOf("floor-given");
    const bin = spawnBin();
    const m = await call(bin, "atr_confirm", { ...argsOf(given), account: V.fixed.account, inputs: given.inputs });
    await bin.close();
    if (!PIECES.has(given.pairing)) {
      expect(code(m)).toBe("pairing-not-supported");
      return;
    }
    expect(code(m)).toBe("floor-missing");
    expect(at(m, "result.structuredContent.decline.detail")).toBe("minValiditySeconds");
  });

  // Profile rules 9 and 16: a floor input is the host's, never a tool input. mpp/charge/usdc/gateway's three floor
  // inputs, given in the tool's `inputs` with no `floors`, are dropped, and the gate declines floor-missing naming the
  // first of them in rule 9's order, before it reads the offer. The values are lcp's mpp-charge-usdc-gateway.json
  // ceiling.good.
  it("mpp/charge/usdc/gateway's floor inputs in a tool's inputs reach no gate: floor-missing, sourceNetwork", async () => {
    const { sourceNetwork, burnIntentExpirationHeight, withdrawalDelay } = vectors("mpp-charge-usdc-gateway.json").ceiling.good;
    const fetch = serving(rowOf("floor-given"));
    const c = connect({ fetch });
    const m = await call(c, "atr_confirm", {
      pairing: "mpp/charge/usdc/gateway",
      document: {},
      account: `${sourceNetwork}:${V.fixed.account.split(":")[2]}`,
      resourceRequest: argsOf(rowOf("floor-given")).resourceRequest,
      inputs: { sourceNetwork, burnIntentExpirationHeight, withdrawalDelay },
    });
    await c.close();
    expect([code(m), at(m, "result.structuredContent.decline.detail"), fetch.calls]).toEqual(["floor-missing", "sourceNetwork", 0]);
  });

  it("createBuyerServer as the binary calls it, with no ceilings, declines no-end; a floors that throws gives no floor", async () => {
    const raised = rowOf("no-end-raised");
    const plain = connect({ fetch: serving(raised) }, (options) => createBuyerServer({ fetch: options.fetch }));
    const noEnd = await call(plain, "atr_confirm", { ...argsOf(raised), account: V.fixed.account });
    await plain.close();
    expect(code(noEnd)).toBe("no-end");
    const given = rowOf("floor-given");
    const throwing = connect({
      fetch: serving(given),
      floors: () => {
        throw new Error("the payment service did not answer");
      },
    });
    const m = await call(throwing, "atr_confirm", { ...argsOf(given), account: V.fixed.account, inputs: given.inputs });
    await throwing.close();
    expect(code(m)).toBe(PIECES.has(given.pairing) ? "floor-missing" : "pairing-not-supported");
  });

  // The first response's return value, atr_transact's `legalContext`: each string lcp's reader refuses is declined
  // offer-unreadable with its code, and any other value fails the tool's input schema, each before any fetch or signer
  // call; one naming another H is hash-mismatch.
  const refusals: [string, Loose][] = RETURN.readRefusals.map((r: Loose) => [r.case, r]);
  it.each(refusals)("legalContext %s: refused before any fetch", async (_, r) => {
    const row = rowOf("approved");
    const s = signer();
    const fetch = serving(row);
    const c = connect({ fetch, signer: s });
    const m = await call(c, "atr_transact", { ...argsOf(row), legalContext: r.value });
    await c.close();
    if (typeof r.value === "string") {
      expect([code(m), at(m, "result.structuredContent.decline.detail")]).toEqual(["offer-unreadable", r.expect.code]);
    } else {
      expect(at(m, "result.isError")).toBe(true);
      expect(at(m, "result")).not.toHaveProperty("structuredContent");
    }
    expect([fetch.calls, s.requests.length]).toEqual([0, 0]);
  });

  it(`legalContext "H alone", another ATR's H: hash-mismatch, and nothing is signed`, async () => {
    const row = rowOf("approved");
    const s = signer();
    const c = connect({ fetch: serving(row), signer: s });
    const value = RETURN.read.find((r: Loose) => r.case === "H alone").value;
    const m = await call(c, "atr_transact", { ...argsOf(row), legalContext: value });
    await c.close();
    expect(code(m)).toBe("hash-mismatch");
    expect(s.requests).toHaveLength(0);
  });
});
