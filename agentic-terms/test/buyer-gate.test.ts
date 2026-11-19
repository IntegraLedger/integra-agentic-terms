// The gate's own vectors, terms' profile buyer-gate.md (vectors/buyer-gate.json). Each row runs through `transact` with
// the row's pairing, document, link, account, ATR bytes, request, inputs and ceilings (a row's own document, link and
// account where it names them, else the file's), the clock at the file's `now`, an approver that
// answers the row's `approves`, and a signer that is the file's payer key where the row is signed; the decline, the
// signer's and the approver's call counts and what the approver was asked are the row's. A row whose pairing has no
// buyer piece yet answers pairing-not-supported, the gate's first check, with no call, asserted and never skipped. The parse's rows are the
// file's and the protocol package's check-8 rows in core-vectors.json (refusals answered core/content-not-json, and
// jsonDepth), which the profile names as the parse's rows too. Every input and expected value is the vector files'.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { afterEach, describe, expect, it } from "vitest";
import type { TypedDataDefinition } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { BINDINGS } from "@integraledger/lcp";
import { exactEip3009, requestCommitment, tie } from "@integraledger/lcp/x402";
import { isOneJsonText } from "../src/checks.js";
import { confirm, transact, type Binding, type Ceilings, type Inputs, type SigningRequest, type ToSign } from "../src/index.js";
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

/** The row's document: its own, as written, or the file's for its pairing advertising the row's ATR. */
function documentOf(row: Loose): Loose {
  if (row.document !== undefined) return structuredClone(row.document);
  const doc = structuredClone(V.fixed.documents[row.pairing]);
  doc.extensions.legalContext.info.value = row.atr.sha256;
  return doc;
}

describe("buyer-gate.json rows, through transact", () => {
  for (const row of V.rows as Loose[]) {
    const pending = !PIECES.has(row.pairing);
    const label = pending ? "pending, pairing-not-supported" : `${row.expect.decline ?? "signed"}, signer ${row.expect.signerCalls}, approver ${row.expect.approverCalls}`;
    it(`${row.name} (${row.pairing}): ${label}`, async () => {
      Date.now = () => V.fixed.now * 1000;
      const doc = documentOf(row);
      const bytes = fromHex(row.atr.hex);
      const payer = privateKeyToAccount(V.fixed.payerKey);
      const signer = counting(row.account ?? V.fixed.account, async (r: SigningRequest) => {
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
      const fetch = serving(row.link ?? V.fixed.link, bytes);
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
          if (i < signer.requests.length) expect(a.request).toEqual(signer.requests[i]);
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

// A ceiling given for the pairing paid, in no form rule 8 admits, is declined no-payable-option with the namespace's
// input-malformed before anything is fetched (the profile's rule 1); here `0`, not a positive safe integer, over row
// "approved".
describe("ceilings of another form", () => {
  it(`"approved" with ceilings {pairing: 0}: no-payable-option, x402/input-malformed, before any fetch`, async () => {
    const row = (V.rows as Loose[]).find((r) => r.name === "approved");
    Date.now = () => V.fixed.now * 1000;
    const doc = structuredClone(V.fixed.documents[row.pairing]);
    doc.extensions.legalContext.info.value = row.atr.sha256;
    const fetch = serving(V.fixed.link, fromHex(row.atr.hex));
    const signer = counting(V.fixed.account, async () => {
      throw new Error("the signer is not called on this row");
    });
    let asked = 0;
    const approver = (): boolean => {
      asked++;
      return true;
    };
    const resourceRequest = { method: row.resourceRequest.method, target: row.resourceRequest.target, body: new TextEncoder().encode(row.resourceRequest.bodyUtf8) };
    const out = await transact(doc, bindingOf(row.pairing), signer, fetch, { approver, resourceRequest, ceilings: { [row.pairing]: 0 } });
    expect("decline" in out && out.decline).toEqual({ code: "no-payable-option", detail: "x402/input-malformed" });
    expect([fetch.calls, asked, signer.requests.length]).toEqual([0, 0, 0]);
  });
});

// A first response whose agreement option names the charges it serves in no form the protocol package's
// legal-context-return.md admits is declined offer-unreadable with its code, return/serves-malformed, before any fetch,
// never read as a charge. Each x402 option of legal-context-return.json's servesRefusals read without an ATR is the first
// response's one option, in row "approved"'s document, paid through a pairing at coverage none
// (x402/exact/eip155/erc7710), the one kind of pairing that is paid after its agreement. A name refused only against an
// ATR's bytes is buyer-gate.json's row serves-not-in-atr.
describe("an agreement option whose serves member is malformed", () => {
  const RETURN: Loose = vectors("legal-context-return.json");
  const row = (V.rows as Loose[]).find((r) => r.name === "approved");
  for (const r of (RETURN.servesRefusals as Loose[]).filter((x) => typeof x.option?.scheme === "string" && x.atr === undefined)) {
    it(`servesRefusals "${r.case}": offer-unreadable, ${r.expect.code}, before any fetch`, async () => {
      Date.now = () => V.fixed.now * 1000;
      const doc = structuredClone(V.fixed.documents[row.pairing]);
      doc.extensions.legalContext.info.value = row.atr.sha256;
      doc.accepts = [r.option];
      const fetch = serving(V.fixed.link, fromHex(row.atr.hex));
      const signer = counting(V.fixed.account, async () => {
        throw new Error("the signer is not called on these rows");
      });
      let asked = 0;
      const approver = (): boolean => {
        asked++;
        return false;
      };
      const resourceRequest = { method: row.resourceRequest.method, target: row.resourceRequest.target, body: new TextEncoder().encode(row.resourceRequest.bodyUtf8) };
      const out = await transact(doc, bindingOf("x402/exact/eip155/erc7710"), signer, fetch, { approver, resourceRequest });
      expect("decline" in out && out.decline).toEqual({ code: "offer-unreadable", detail: r.expect.code });
      expect([fetch.calls, asked, signer.requests.length]).toEqual([0, 0, 0]);
    });
  }
});

// An approval answered after the clock has moved: row "approved"'s request, as confirm builds it at the file's `now`, is
// approved by an approver that approves that request alone, and transact, called 5 seconds later with confirm's
// `chosen`, rebuilds that exact request and signs it once.
describe("an approval answered after the clock moves", () => {
  it(`"approved": transact given confirm's chosen 5 s later signs the request confirm built`, async () => {
    const row = (V.rows as Loose[]).find((r) => r.name === "approved");
    const doc = structuredClone(V.fixed.documents[row.pairing]);
    doc.extensions.legalContext.info.value = row.atr.sha256;
    const bytes = fromHex(row.atr.hex);
    const resourceRequest = { method: row.resourceRequest.method, target: row.resourceRequest.target, body: new TextEncoder().encode(row.resourceRequest.bodyUtf8) };
    Date.now = () => V.fixed.now * 1000;
    const confirmed = await confirm(doc, bindingOf(row.pairing), V.fixed.account, serving(V.fixed.link, bytes), { resourceRequest });
    if ("decline" in confirmed) throw new Error(confirmed.decline.code);
    Date.now = () => (V.fixed.now + 5) * 1000;
    const payer = privateKeyToAccount(V.fixed.payerKey);
    const signer = counting(V.fixed.account, async (r: SigningRequest) => payer.signTypedData((r as { typedData: unknown }).typedData as TypedDataDefinition));
    let asked = 0;
    const approver = (toSign: ToSign): boolean => {
      asked++;
      return isDeepStrictEqual(toSign.request, confirmed.request);
    };
    const chosen = JSON.parse(JSON.stringify(confirmed.chosen));
    const out = await transact(doc, bindingOf(row.pairing), signer, serving(V.fixed.link, bytes), { approver, resourceRequest, chosen });
    expect("decline" in out ? out.decline : null).toBe(null);
    expect([signer.requests.length, asked]).toEqual([1, 1]);
    expect(signer.requests[0]).toEqual(confirmed.request);
  });
});

// The return after an agreement makes checks 9 to 11 on the charge it chooses before it pays that charge's agreement
// (the profile's rule 3: each check answers before the signer is called for the signing it concerns). The first
// response's one option is the agreement option naming x402/0 alone of the protocol package's legal-context-return.json
// servesRefusals row that refuses it against the file's card ATR, which holds no x402 slot; against this ATR, whose x402
// slot holds the charge at index 0, it resolves. It is placed by the package's own seller half (`advertise`) for the
// ATR's hash, buyer.json's link and its agreement URL. The ATR is buyer.json's fixed.A with its x402 slot as the package's `tie` writes it over
// x402-exact-eip155-erc7710.json's option and row "no-end"'s request. That charge signs no end: with no ceiling raised it
// is declined no-end, and the agreement is never fetched, asked or signed; with its ceiling raised to "no-end", the
// agreement is asked of the approver, which here declines it.
describe("the return after an agreement checks the charge before paying the agreement", () => {
  const RETURN: Loose = vectors("legal-context-return.json");
  const BUYER: Loose = vectors("buyer.json");
  const E: Loose = vectors("x402-exact-eip155-erc7710.json");
  const row = (V.rows as Loose[]).find((r) => r.name === "no-end");
  const agreementOption = (RETURN.servesRefusals as Loose[]).find((r) => r.atr !== undefined && isDeepStrictEqual(r.option?.extra?.legalContextServes, ["x402/0"])).option;
  const resourceRequest = { method: row.resourceRequest.method, target: row.resourceRequest.target, body: new TextEncoder().encode(row.resourceRequest.bodyUtf8) };
  const account = `${E.fixed.option.network}:${E.fixed.payer}`;

  const run = async (ceilings: Ceilings | undefined) => {
    Date.now = () => E.fixed.now * 1000;
    const commitment = await requestCommitment(resourceRequest);
    if ("refused" in commitment) throw new Error(commitment.code);
    const atr = JSON.parse(new TextDecoder().decode(fromHex(BUYER.fixed.A)));
    atr.x402 = tie([E.fixed.option], commitment)[1];
    const bytes = new TextEncoder().encode(JSON.stringify(atr));
    const h: `0x${string}` = `0x${createHash("sha256").update(bytes).digest("hex")}`;
    const first = { x402Version: 2, resource: E.fixed.resource, accepts: [agreementOption] };
    const doc = exactEip3009.advertise(first as never, h, BUYER.fixed.link, agreementOption, BUYER.fixed.agreement.url);
    if ("refused" in doc) throw new Error(doc.code);
    const fetch = serving(BUYER.fixed.link, bytes);
    const signer = counting(account, async () => {
      throw new Error("the signer is not called here");
    });
    const asked: ToSign[] = [];
    const approver = (toSign: ToSign): boolean => {
      asked.push(toSign);
      return false;
    };
    const out = await transact(doc, bindingOf("x402/exact/eip155/erc7710"), signer, fetch, {
      approver,
      resourceRequest,
      ...(ceilings === undefined ? {} : { ceilings }),
    });
    return { out, fetched: fetch.calls, asked: asked.map((a) => a.act), signed: signer.requests.length };
  };

  it("an erc7710 charge with no ceiling raised: no-end, the agreement never asked or paid", async () => {
    const { out, fetched, asked, signed } = await run(undefined);
    expect(["decline" in out && out.decline.code, fetched, asked, signed]).toEqual(["no-end", 1, [], 0]);
  });
  it(`the same with its ceiling raised to "no-end": the agreement is asked of the approver`, async () => {
    const { out, asked, signed } = await run({ "x402/exact/eip155/erc7710": "no-end" });
    expect(["decline" in out && out.decline.code, asked, signed]).toEqual(["not-approved", ["agreement"], 0]);
  });
});
