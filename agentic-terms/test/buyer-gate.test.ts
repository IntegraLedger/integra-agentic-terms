// The gate's own vectors, terms' profile buyer-gate.md (vectors/buyer-gate.json). Each row runs through `transact` with
// the row's pairing, document, ATR bytes, request, inputs and ceilings, the clock at the file's `now`, an approver that
// answers the row's `approves`, and a signer that is the file's payer key where the row is signed; the decline, the
// signer's and the approver's call counts and what the approver was asked are the row's. A row whose pairing has no
// buyer piece yet answers pairing-not-supported, the gate's first check, with no call, asserted and never skipped. The parse's rows are the
// file's and the protocol package's check-8 rows in core-vectors.json (refusals answered core/content-not-json, and
// jsonDepth), which the profile names as the parse's rows too. Every input and expected value is the vector files'.
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { BINDINGS } from "@integraledger/lcp";
import { isOneJsonText } from "../src/checks.js";
import { transact, type Binding, type Ceilings, type Inputs, type SigningRequest, type ToSign } from "../src/index.js";
import { PIECES } from "../src/pairings/index.js";
import { counting, fromHex, vectors } from "./support.js";

// The vector file is read as loose JSON data; each use names the fields it reads.
type Loose = any;

const V: Loose = JSON.parse(readFileSync(new URL("../vectors/buyer-gate.json", import.meta.url), "utf8"));
const CORE: Loose = vectors("core-vectors.json");

const bindingOf = (id: string): Binding => {
  const b = BINDINGS.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};

/** The link serving the row's bytes with status 200 and no content coding; any other URL answers 404. */
function serving(link: string, bytes: Uint8Array) {
  const f = (async (url: string) => {
    f.calls++;
    return url === link ? new Response(new Uint8Array(bytes), { status: 200 }) : new Response(null, { status: 404 });
  }) as unknown as Parameters<typeof transact>[3] & { calls: number };
  f.calls = 0;
  return f;
}

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

describe("buyer-gate.json rows, through transact", () => {
  for (const row of V.rows as Loose[]) {
    const pending = !PIECES.has(row.pairing);
    const label = pending ? "pending, pairing-not-supported" : `${row.expect.decline ?? "signed"}, signer ${row.expect.signerCalls}, approver ${row.expect.approverCalls}`;
    it(`${row.name} (${row.pairing}): ${label}`, async () => {
      Date.now = () => V.fixed.now * 1000;
      const doc = structuredClone(V.fixed.documents[row.pairing]);
      doc.extensions.legalContext.info.value = row.atr.sha256;
      const bytes = fromHex(row.atr.hex);
      const payer = privateKeyToAccount(V.fixed.payerKey);
      const signer = counting(V.fixed.account, async (r: SigningRequest) => {
        if (row.expect.signerCalls === 0) throw new Error("the signer is not called on this row");
        return payer.signTypedData((r as { typedData: unknown }).typedData as TypedDataDefinition);
      });
      const asked: ToSign[] = [];
      const approver = (toSign: ToSign): boolean => {
        asked.push(toSign);
        return row.approves;
      };
      const resourceRequest = {
        method: row.resourceRequest.method,
        target: row.resourceRequest.target,
        body: new TextEncoder().encode(row.resourceRequest.bodyUtf8),
      };
      const options = {
        approver,
        resourceRequest,
        inputs: row.inputs as Inputs,
        ...(row.ceilings === undefined ? {} : { ceilings: row.ceilings as Ceilings }),
      };
      const fetch = serving(V.fixed.link, bytes);
      const out = await transact(doc, bindingOf(row.pairing), signer, fetch, options);
      if (pending) {
        expect("decline" in out ? out.decline.code : null).toBe("pairing-not-supported");
        expect([signer.requests.length, asked.length, fetch.calls]).toEqual([0, 0, 0]);
        return;
      }

      expect("decline" in out ? out.decline.code : null).toBe(row.expect.decline);
      if (row.expect.detail !== undefined) expect("decline" in out && out.decline.detail).toBe(row.expect.detail);
      expect([signer.requests.length, asked.length]).toEqual([row.expect.signerCalls, row.expect.approverCalls]);
      if (row.expect.asked !== undefined) {
        expect(asked.map(({ act, pairing, step }) => ({ act, pairing, step }))).toEqual(row.expect.asked);
        asked.forEach((a, i) => {
          expect(a.request).toEqual(signer.requests[i]);
          expect(a.summary.atr).toEqual(bytes);
        });
      }
    });
  }
});

describe("the parse refuses exactly what the protocol package's check 8 refuses", () => {
  for (const row of V.parse.rows as Loose[]) {
    it(`buyer-gate.json ${row.name}: ${row.accept ? "parses" : "refused"}`, () => {
      expect(isOneJsonText(fromHex(row.hex))).toBe(row.accept);
    });
  }
  const refused = (CORE.refusals as Loose[]).filter((r) => r.expect === "core/content-not-json" && typeof r.contentHex === "string");
  it("core-vectors.json holds check-8 refusals with bytes", () => {
    expect(refused.length).toBeGreaterThan(0);
  });
  for (const row of refused) {
    it(`core-vectors.json ${row.name}: refused`, () => {
      expect(isOneJsonText(fromHex(row.contentHex))).toBe(false);
    });
  }
  for (const row of CORE.jsonDepth.rows as Loose[]) {
    it(`core-vectors.json ${row.name}: ${row.accept ? "parses" : "refused"}`, () => {
      expect(isOneJsonText(new TextEncoder().encode(row.text))).toBe(row.accept);
    });
  }
});

// The first response's return value, transact's `legalContext`: each value of the protocol package's
// legal-context-return.json readRefusals is declined offer-unreadable with its code before any fetch, approver or signer
// call; its read row "H alone", whose H is not the ATR's the link serves, is declined hash-mismatch before the approver.
// The document, ATR and request are buyer-gate.json's row "approved".
describe("the return value transact is given", () => {
  const RETURN: Loose = vectors("legal-context-return.json");
  const row = (V.rows as Loose[]).find((r) => r.name === "approved");
  const run = async (legalContext: string) => {
    Date.now = () => V.fixed.now * 1000;
    const doc = structuredClone(V.fixed.documents[row.pairing]);
    const bytes = fromHex(row.atr.hex);
    const fetch = serving(V.fixed.link, bytes);
    const signer = counting(V.fixed.account, async () => {
      throw new Error("the signer is not called on these rows");
    });
    let asked = 0;
    const approver = (): boolean => {
      asked++;
      return true;
    };
    const resourceRequest = { method: row.resourceRequest.method, target: row.resourceRequest.target, body: new TextEncoder().encode(row.resourceRequest.bodyUtf8) };
    const out = await transact(doc, bindingOf(row.pairing), signer, fetch, { approver, resourceRequest, legalContext });
    return { out, calls: [fetch.calls, asked, signer.requests.length] };
  };

  // A value that is not a string is no `legalContext` of the profile's form: no-payable-option, x402/input-malformed.
  for (const r of RETURN.readRefusals as Loose[]) {
    const expected = typeof r.value === "string" ? { code: "offer-unreadable", detail: r.expect.code } : { code: "no-payable-option", detail: "x402/input-malformed" };
    it(`readRefusals "${r.case}": ${expected.code}, ${expected.detail}, before any fetch`, async () => {
      const { out, calls } = await run(r.value);
      expect("decline" in out && out.decline).toEqual(expected);
      expect(calls).toEqual([0, 0, 0]);
    });
  }

  it(`read "H alone": an H not the ATR's is hash-mismatch, before the approver`, async () => {
    const r = (RETURN.read as Loose[]).find((x) => x.case === "H alone");
    const { out, calls } = await run(r.value);
    expect("decline" in out && out.decline.code).toBe("hash-mismatch");
    expect(calls).toEqual([1, 0, 0]);
  });
});
