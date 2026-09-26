// MPP Lightning: the challenge's invoice is paid only on the account's own network, read through the invoice's BOLT11
// currency. Expected values: BOLT11's currency prefixes (`bc` mainnet, `tb` testnet, `tbs` signet, `bcrt` regtest),
// with `tb` for testnet3 and testnet4 accounts, and MPP Lightning's network names (`mainnet` `bc`, `signet` `tbs`,
// `regtest` `bcrt`); the `lnbtc` CAIP-2 reference is the first 32 hex characters of the network's
// genesis block hash, as x402's lnbtc scheme defines it. The genesis hashes are those of the genesis block headers of
// each network, hashed with double SHA-256 (mainnet 000000000019d668…, testnet3 000000000933ea01…, testnet4
// 00000000da84f2ba…, signet 00000008819873e9…, regtest 0f9188f13cb7b2c7…). The invoices are the session vector's
// deposit invoice with its human-readable part's currency changed and its BIP-173 checksum recomputed; the decoder
// verifies no signature.
import { describe, expect, it } from "vitest";
import { sessionLightning } from "@integraledger/lcp/lightning";
import type { MppChallenge } from "@integraledger/lcp/mpp";
import { confirm, type Binding } from "../src/index.js";
import { ABC, code, H, isDeclined, LINK, offered, serving, vectors } from "./support.js";

const NOW = 1_790_000_000;
async function at<T>(run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  Date.now = () => NOW * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

const INVOICES = {
  tb: "lntb250n1p4tzwuqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5hfupd0u0q8875s2pgr09mt3zywcqxcdrjcth4895zrlkrusqzkksxqzfv9qrsgq00s4xjxtrutvzp7yzmdyyqpykvvnnxg6vacmn44nqlqqsepw6vy8kjvq5s8jrxq8ayy3pa7xrwz0zx8angk20ttn0awxumjskmaxf0qq432lkn",
  tbs: "lntbs250n1p4tzwuqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5hfupd0u0q8875s2pgr09mt3zywcqxcdrjcth4895zrlkrusqzkksxqzfv9qrsgq00s4xjxtrutvzp7yzmdyyqpykvvnnxg6vacmn44nqlqqsepw6vy8kjvq5s8jrxq8ayy3pa7xrwz0zx8angk20ttn0awxumjskmaxf0qqcmqsva",
  bcrt: "lnbcrt250n1p4tzwuqpp54y3u9s8ylemsv8l3ewyzzu0klhujvuvmkl6llchq23vy8rzjsf0qsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp5hfupd0u0q8875s2pgr09mt3zywcqxcdrjcth4895zrlkrusqzkksxqzfv9qrsgq00s4xjxtrutvzp7yzmdyyqpykvvnnxg6vacmn44nqlqqsepw6vy8kjvq5s8jrxq8ayy3pa7xrwz0zx8angk20ttn0awxumjskmaxf0qq7wjywa",
} as const;

const NETWORKS = {
  mainnet: "lnbtc:000000000019d6689c085ae165831e93",
  testnet3: "lnbtc:000000000933ea01ad0ee984209779ba",
  testnet4: "lnbtc:00000000da84f2bafbbc53dee25a72ae",
  signet: "lnbtc:00000008819873e925422c1ff0f99f7c",
  regtest: "lnbtc:0f9188f13cb7b2c71f2a335e3a4fc328",
} as const;

type LnMpp = { challenge: Omit<MppChallenge, "request">; request: { depositInvoice: string } & object };
const b64u = (s: string) => Buffer.from(s, "utf8").toString("base64url");
function challengeWith(binding: Binding, row: LnMpp, depositInvoice: string): MppChallenge {
  const issued = { ...row.challenge, request: b64u(JSON.stringify({ ...row.request, depositInvoice })) } as MppChallenge;
  const out = (binding as unknown as { advertise(d: unknown, h: string, l: string, o: unknown): unknown }).advertise(
    [issued],
    H,
    LINK,
    issued,
  );
  if (!Array.isArray(out)) throw new Error(JSON.stringify(out));
  return out[0] as MppChallenge;
}

describe("mpp/session/lightning: the invoice's BOLT11 currency is the account's network's", () => {
  const C = vectors<{ fixed: { payee: string } }>("mpp-charge-lightning.json");
  const S = vectors<{ fixed: { returnInvoice: string }; S1: LnMpp }>("mpp-session-lightning.json");
  const binding = offered(sessionLightning as unknown as Binding);
  const inputs = { returnInvoice: S.fixed.returnInvoice };
  const mainnetChallenge = () => challengeWith(sessionLightning as unknown as Binding, S.S1, S.S1.request.depositInvoice);
  const testChallenge = () => challengeWith(sessionLightning as unknown as Binding, S.S1, INVOICES.tb);
  const signetChallenge = () => challengeWith(sessionLightning as unknown as Binding, S.S1, INVOICES.tbs);
  const regtestChallenge = () => challengeWith(sessionLightning as unknown as Binding, S.S1, INVOICES.bcrt);
  const account = (network: string) => `${network}:${C.fixed.payee}`;

  it.each([
    ["mainnet", NETWORKS.mainnet, "bc"],
    ["testnet3", NETWORKS.testnet3, "tb"],
    ["testnet4", NETWORKS.testnet4, "tb"],
    ["signet", NETWORKS.signet, "tbs"],
    ["regtest", NETWORKS.regtest, "bcrt"],
  ] as const)("a %s account (%s) pays the %s invoice of four offered, and no other", (_name, network, currency) =>
    at(async () => {
      const doc = [mainnetChallenge(), testChallenge(), signetChallenge(), regtestChallenge()];
      const out = await confirm(doc, binding, account(network), serving(ABC), inputs);
      if (isDeclined(out)) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
      const expected = currency === "bc" ? S.S1.request.depositInvoice : INVOICES[currency];
      expect(out.request).toEqual({ kind: "bolt11-pay", invoice: expected });
    }));

  it.each([
    ["a mainnet account offered only testnet and regtest invoices", NETWORKS.mainnet, () => [testChallenge(), regtestChallenge()]],
    ["a signet account offered only a mainnet invoice", NETWORKS.signet, () => [mainnetChallenge()]],
    ["a signet account offered only a testnet invoice", NETWORKS.signet, () => [testChallenge()]],
    ["a testnet4 account offered only a signet invoice", NETWORKS.testnet4, () => [signetChallenge()]],
    ["a testnet3 account offered only a regtest invoice", NETWORKS.testnet3, () => [regtestChallenge()]],
    ["a regtest account offered only a testnet invoice", NETWORKS.regtest, () => [testChallenge()]],
    ["an account on an lnbtc network no BOLT11 currency names", "lnbtc:00000000000000000000000000000000", () => [mainnetChallenge()]],
  ] as const)("%s: no-payable-option before any fetch", (_case, network, doc) =>
    at(async () => {
      const fetch = serving(ABC);
      const out = await confirm(doc(), binding, account(network), fetch, inputs);
      expect(code(out)).toBe("no-payable-option");
      expect(isDeclined(out) && out.decline.detail).toBe("mpp/no-payable-option");
      expect(fetch.calls).toBe(0);
    }));
});
