// A placed MPP challenge that the protocol package's checks do not name for a pairing offers that pairing nothing, so
// the gate has no challenge it can pay: it declines no-payable-option, mpp/no-payable-option, before any fetch and with
// no signer call, as buyer.json's BX1 answers for a placed challenge those checks refuse. The subjects are each vector
// file's boundChallenge rows, each a challenge placed with the id and opaque of the file's B2 document and not named
// for the row's pairing, given as the sole challenge with that B2 row's account, inputs and time. The card and Stripe
// files hold no such rows: their subjects are B2's challenge with the member each pairing's checks read set to a value
// they refuse (card: `externalId`, absent or a string; Stripe: `methodDetails.metadata`, an object within Stripe's
// bounds). The link serves `abc`, whose SHA-256 (FIPS 180-2 B.1) is each document's H. Every expected value is lcp's:
// BX1's decline, each row's own refusal and `pairingsOf`'s answer for the changed card and Stripe challenges.
import { readdirSync } from "node:fs";
import { afterEach, describe, expect, it } from "vitest";
import { BINDINGS } from "@integraledger/lcp";
import { pairingsOf, pairingsOfPlaced, type MppChallenge } from "@integraledger/lcp/mpp";
import { confirm, transact, type Binding, type Inputs } from "../src/index.js";
import { ABC, counting, serving, vectors } from "./support.js";

interface B2 {
  name: string;
  pairing: string;
  input: { doc: MppChallenge[]; account: string; inputs?: Inputs; now?: number };
}
interface BoundRow {
  case: string;
  pairing: string;
  challenge: MppChallenge;
  expect: string;
}
interface File {
  buyer?: { rows: B2[] };
  boundChallenge?: { rows: BoundRow[] };
}

const FILES = readdirSync(new URL("../node_modules/@integraledger/lcp/vectors/", import.meta.url))
  .filter((f) => f.startsWith("mpp-") && f.endsWith(".json"))
  .sort();
const b2Of = (file: string, pairing: string): B2 => {
  const rows = (vectors<File>(file).buyer?.rows ?? []).filter((r) => r.name === "B2" && r.pairing === pairing);
  if (rows.length !== 1) throw new Error(`${file}: ${rows.length} B2 rows for ${pairing}`);
  return rows[0]!;
};
const bindingOf = (id: string): Binding => {
  const b = BINDINGS.find((x) => x.id === id);
  if (b === undefined) throw new Error(`no pairing ${id}`);
  return b as unknown as Binding;
};
const b64u = (v: unknown): string => Buffer.from(JSON.stringify(v), "utf8").toString("base64url");
const requestOf = (c: MppChallenge): Record<string, unknown> =>
  JSON.parse(Buffer.from(c.request as string, "base64url").toString("utf8")) as Record<string, unknown>;
const issued = (c: MppChallenge): MppChallenge => {
  const { id: _id, opaque: _opaque, ...rest } = c;
  return rest as MppChallenge;
};

const realNow = Date.now;
afterEach(() => {
  Date.now = realNow;
});

/** The gate given `challenge` as the sole challenge, with the B2 row's account, inputs and time. */
async function offeredAlone(b2: B2, challenge: MppChallenge): Promise<void> {
  const now = b2.input.now;
  if (now !== undefined) Date.now = () => now * 1000;
  const binding = bindingOf(b2.pairing);
  const inputs = b2.input.inputs ?? {};
  const fetch = serving(ABC);
  const signer = counting(b2.input.account, async () => {
    throw new Error("the signer was called");
  });
  const out = await transact([structuredClone(challenge)], binding, signer, fetch, { inputs });
  expect("decline" in out && out.decline).toEqual({ code: "no-payable-option", detail: "mpp/no-payable-option" });
  expect(signer.requests).toEqual([]);
  const confirmed = await confirm([structuredClone(challenge)], binding, b2.input.account, fetch, inputs);
  expect("decline" in confirmed && confirmed.decline).toEqual({ code: "no-payable-option", detail: "mpp/no-payable-option" });
  expect(fetch.calls).toBe(0);
}

describe("a placed challenge the pairing's checks refuse is no payable option", () => {
  const rows = FILES.flatMap((file) => (vectors<File>(file).boundChallenge?.rows ?? []).map((row) => [file, row] as const));

  it("the vector files' boundChallenge rows are read", () => {
    expect(rows.length).toBeGreaterThan(0);
  });

  it.each(rows.map(([file, row]) => [`${file}: ${row.case}`, file, row] as const))("%s", async (_name, file, row) => {
    const b2 = b2Of(file, row.pairing);
    expect(row.challenge.id).toBe(b2.input.doc[0]!.id);
    expect(row.challenge.opaque).toBe(b2.input.doc[0]!.opaque);
    expect(pairingsOfPlaced(b2.input.doc[0]!)).toContain(row.pairing);
    expect(pairingsOfPlaced(row.challenge)).not.toContain(row.pairing);
    await offeredAlone(b2, row.challenge);
  });

  const changed: [string, string, string, (r: Record<string, unknown>) => void, string][] = [
    ["mpp-charge-card.json", "mpp/charge/card", "externalId 5", (r) => (r["externalId"] = 5), "mpp/request-malformed"],
    [
      "mpp-charge-stripe.json",
      "mpp/charge/stripe",
      "methodDetails.metadata a string",
      (r) => ((r["methodDetails"] as Record<string, unknown>)["metadata"] = "abc"),
      "mpp/metadata-malformed",
    ],
    [
      "mpp-subscription-stripe.json",
      "mpp/subscription/stripe",
      "methodDetails.metadata a string",
      (r) => ((r["methodDetails"] as Record<string, unknown>)["metadata"] = "abc"),
      "mpp/metadata-malformed",
    ],
  ];
  it.each(changed)("%s %s: B2's challenge with %s", async (file, pairing, _case, change, code) => {
    const b2 = b2Of(file, pairing);
    const own = b2.input.doc[0]!;
    expect(pairingsOfPlaced(own)).toContain(pairing);
    const request = requestOf(own);
    change(request);
    const challenge = { ...own, request: b64u(request) };
    expect(pairingsOf(issued(challenge))).toEqual({ refused: true, code });
    expect(pairingsOfPlaced(challenge)).toEqual([]);
    await offeredAlone(b2, challenge);
  });
});
