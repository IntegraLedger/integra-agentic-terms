// The lcp MPP method's charge on Hedera, mpp/charge/lcp/hedera, through its buyer piece. Each build row of
// mpp-method-lcp-hedera.json, under the challenge mpp-method-lcp.json holds for its request: the piece's choice from the
// buyer's inputs gives the body hiero-sdk-python 0.2.10 froze, and the payer's Ed25519 signature from the file's seed
// completes the credential whose transaction is the one the SDK signed. The payment is then paid through the gate over
// A, its challenge placed for HA by the pairing's own advertise: while SUMMARY_PENDING lists the pairing, the gate
// declines it summary-missing before any signer call. Every expected value is the files'.
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import type { AtrHash } from "@integraledger/lcp";
import { chargeLcpHedera, type MppChallenge } from "@integraledger/lcp/mpp";
import { describe, expect, it } from "vitest";
import type { Binding } from "../src/index.js";
import { buildAndSign, LINK, toHex, vectors, type Pairing } from "./support.js";

// Vector files are read as loose JSON data; each row names the fields it uses.
type Loose = any;

const V = vectors<Loose>("mpp-method-lcp-hedera.json");
const C = vectors<Loose>("mpp-method-lcp.json");
const f = V.fixed;
const binding = chargeLcpHedera as unknown as Binding;

/** The challenge mpp-method-lcp.json holds, placed for H, for each of the hedera file's requests. */
const CHALLENGE: Record<string, MppChallenge> = {
  settlerPays: C.challenges.hedera.wire,
  buyerPays: C.challenges.hederaBuyerPays.wire,
  token: C.challenges.hederaToken.wire,
};

/** The same challenge as issued, before the pairing's `advertise` places a hash and a link in its id and opaque. */
function issued(c: MppChallenge): MppChallenge {
  const { id: _id, opaque: _opaque, ...rest } = c;
  return rest as MppChallenge;
}

/** The challenge placed for `h` by the pairing's own `advertise`. */
function placed(c: MppChallenge, h: AtrHash): MppChallenge[] {
  const binding = chargeLcpHedera as unknown as { advertise(d: unknown, h: string, l: string, o: unknown, p: number): unknown };
  const out = binding.advertise([issued(c)], h, LINK, issued(c), 0);
  if (!Array.isArray(out)) throw new Error(JSON.stringify(out));
  return out as MppChallenge[];
}

/** The payer's Ed25519 key from the file's 32-byte seed. */
function ed25519(seedHex: string) {
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seedHex, "hex")]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  return {
    publicKey: Uint8Array.from(Buffer.from(jwk.x, "base64url")),
    sign: (m: Uint8Array) => Uint8Array.from(sign(null, m, privateKey)),
  };
}
const payer = ed25519(f.seed);

describe("mpp/charge/lcp/hedera", () => {
  it("the payer's key is the file's public key, and each request's challenge holds that request", () => {
    expect(toHex(payer.publicKey)).toBe(`0x${f.publicKey}`);
    for (const [name, c] of Object.entries(CHALLENGE)) {
      expect(JSON.parse(Buffer.from(c.request, "base64url").toString("utf8"))).toEqual(f.requests[name]);
    }
  });

  for (const row of V.build as Loose[]) {
    it(`build row: ${row.case}: the SDK's body, and the SDK's signed transaction as the credential`, async () => {
      const challenge = CHALLENGE[row.request]!;
      const p: Pairing = {
        binding,
        doc: [challenge],
        placed: (h) => placed(challenge, h),
        account: `${f.requests[row.request].methodDetails.network}:${row.payer}`,
        inputs: {
          node: f.node,
          validStart: f.validStart,
          maxFee: f.maxFee,
          ...(row.decimals === undefined ? {} : { decimals: row.decimals }),
        },
        answer: async (r) => {
          if (r.kind !== "hedera-body") throw new Error(r.kind);
          return { publicKey: toHex(payer.publicKey), signature: toHex(payer.sign(r.bodyBytes)), type: "ed25519" };
        },
      };
      const { signed } = await buildAndSign(p, (r) => {
        if (r.kind !== "hedera-body") throw new Error(r.kind);
        expect(Buffer.from(r.bodyBytes).toString("hex")).toBe(row.expectBodyBytes);
      });
      expect(signed).toEqual({ challenge, payload: { type: "transaction", transaction: row.expectTransactionBase64 } });
    });
  }
});
