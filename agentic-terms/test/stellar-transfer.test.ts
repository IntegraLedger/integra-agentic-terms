// The Stellar builds compare the buyer's simulated transfer with the option before anything reaches the signer. x402's
// scheme_exact_stellar: "Argument 2 (amount): MUST equal `requirements.amount` exactly", on the SEP-41 token of
// `requirements.asset`; MPP's Stellar charge: a transfer on the contract matching `currency`. The payer is the account
// whose key signs, so the transfer's `from` must be the signer's account. The edited envelopes are built here with
// @stellar/stellar-sdk 17.1.0 from x402-exact-stellar.json's V2 simulated envelope, changing the transfer alike in the
// operation and in the payer's authorization entry; the other token contract is the contract strkey of 32 bytes of 07
// and the other payer the account of the Ed25519 seed of 32 bytes of 08. The refusal codes are @integraledger/lcp's.
import { readFileSync } from "node:fs";
import { Address, Keypair, nativeToScVal, StrKey, xdr } from "@stellar/stellar-sdk";
import { describe, expect, it } from "vitest";
import { chargeStellar, type MppChallenge } from "@integraledger/lcp/mpp";
import type { PaymentRequired, PaymentRequirements } from "@integraledger/lcp/x402";
import { exactStellar } from "@integraledger/lcp/x402-exact-stellar";
import { confirm, transact, type Binding, type Declined } from "../src/index.js";
import { ABC, counting, H, LINK, serving, vectors } from "./support.js";

type Stellar = {
  fixed: { payer: string; option: PaymentRequirements; resource: { url: string } };
  V2: { simulatedXdr: string; currentLedger: number };
};
const X = vectors<Stellar>("x402-exact-stellar.json");
const V = vectors<{ challenge: MppChallenge; fixed: { expires: string } }>("mpp-charge-stellar.json");

const OTHER_ASSET = StrKey.encodeContract(Buffer.alloc(32, 7));
const OTHER_PAYER = Keypair.fromRawEd25519Seed(Buffer.alloc(32, 8)).publicKey();

/** The members of the SDK's decoded envelope that the edit reads and replaces, as the SDK names them. */
interface Call {
  args: unknown[];
  contractAddress: unknown;
}
interface Envelope {
  v1: {
    tx: {
      operations: {
        body: {
          invokeHostFunctionOp: {
            hostFunction: { invokeContract: Call };
            auth: { credentials: { address: { address: unknown } }; rootInvocation: { function: { contractFn: Call } } }[];
          };
        };
      }[];
    };
  };
  toXDR(format: "base64"): string;
}

/** V2's simulated envelope with the transfer's amount, token contract or `from` changed in the operation and the entry. */
function edited(change: { amount?: bigint; asset?: string; from?: string }): string {
  const env = xdr.TransactionEnvelope.fromXDR(X.V2.simulatedXdr, "base64") as unknown as Envelope;
  const op = env.v1.tx.operations[0]!.body.invokeHostFunctionOp;
  const apply = (call: Call): void => {
    if (change.from !== undefined) call.args[0] = new Address(change.from).toScVal();
    if (change.amount !== undefined) call.args[2] = nativeToScVal(change.amount, { type: "i128" });
    if (change.asset !== undefined) call.contractAddress = new Address(change.asset).toScAddress();
  };
  apply(op.hostFunction.invokeContract);
  for (const entry of op.auth) {
    if (change.from !== undefined) entry.credentials.address.address = new Address(change.from).toScAddress();
    apply(entry.rootInvocation.function.contractFn);
  }
  return env.toXDR("base64");
}

const CASES: { case: string; simulatedXdr: string; expect: string }[] = [
  { case: "amount 1000000000000, not the option's 10000000", simulatedXdr: edited({ amount: 1_000_000_000_000n }), expect: "stellar/amount-mismatch" },
  { case: "the token contract of 07x32, not the option's asset", simulatedXdr: edited({ asset: OTHER_ASSET }), expect: "stellar/asset-mismatch" },
  {
    case: "the token contract of 07x32 and amount 1000000000000",
    simulatedXdr: edited({ asset: OTHER_ASSET, amount: 1_000_000_000_000n }),
    expect: "stellar/asset-mismatch",
  },
  { case: "from the account of seed 08x32, not the payer", simulatedXdr: edited({ from: OTHER_PAYER }), expect: "stellar/payer-mismatch" },
];

function x402Doc(): PaymentRequired {
  const base = { x402Version: 2, resource: X.fixed.resource, accepts: [X.fixed.option] } as PaymentRequired;
  return exactStellar.advertise(base, H, LINK, X.fixed.option) as PaymentRequired;
}
function mppDoc(): MppChallenge[] {
  return chargeStellar.advertise([V.challenge], H, LINK, V.challenge) as MppChallenge[];
}

const PAIRINGS: { name: string; binding: Binding; doc: () => unknown; now?: number }[] = [
  { name: "x402/exact/stellar", binding: exactStellar as unknown as Binding, doc: x402Doc },
  // The entry's expiration is currentLedger + ceil((expires − now) / 5): 988 + 12 = V2's expiration 1000.
  { name: "mpp/charge/stellar", binding: chargeStellar as unknown as Binding, doc: mppDoc, now: Date.parse(V.fixed.expires) / 1000 - 60 },
];
const ACCOUNT = `stellar:testnet:${X.fixed.payer}`;

async function at<T>(now: number | undefined, run: () => Promise<T>): Promise<T> {
  const real = Date.now;
  if (now !== undefined) Date.now = () => now * 1000;
  try {
    return await run();
  } finally {
    Date.now = real;
  }
}

describe("the Stellar simulated transfer", () => {
  it("the Python gate's stellar_transfers.json holds these envelopes, and V2 rebuilds unchanged", () => {
    expect(edited({})).toBe(X.V2.simulatedXdr);
    const fixture = JSON.parse(
      readFileSync(new URL("../../agentic-terms-py/tests/stellar_transfers.json", import.meta.url), "utf8"),
    ) as { otherAsset: string; otherPayer: string; rows: { simulatedXdr: string; expect: string }[] };
    expect([fixture.otherAsset, fixture.otherPayer]).toEqual([OTHER_ASSET, OTHER_PAYER]);
    expect(fixture.rows.map((r) => [r.simulatedXdr, r.expect])).toEqual(CASES.map((c) => [c.simulatedXdr, c.expect]));
  });

  for (const p of PAIRINGS) {
    it(`${p.name}: V2's envelope reaches the signer once, as stellar-auth, with the account as the choice's payer`, () =>
      at(p.now, async () => {
        const out = await confirm(p.doc(), p.binding, ACCOUNT, serving(ABC), {
          simulatedXdr: X.V2.simulatedXdr,
          currentLedger: X.V2.currentLedger,
        });
        if ("decline" in out) throw new Error(`${out.decline.code}: ${out.decline.detail}`);
        expect((out.chosen.choice as { payer?: unknown }).payer).toBe(X.fixed.payer);
        const signer = counting(ACCOUNT, async () => {
          throw new Error("the control stops at the signer");
        });
        await transact(p.doc(), p.binding, signer, serving(ABC), {
          inputs: { simulatedXdr: X.V2.simulatedXdr, currentLedger: X.V2.currentLedger },
        });
        expect(signer.requests.map((r) => r.kind)).toEqual(["stellar-auth"]);
      }));

    for (const c of CASES) {
      it(`${p.name}: ${c.case}: offer-unreadable ${c.expect}, and the signer is never called`, () =>
        at(p.now, async () => {
          const inputs = { simulatedXdr: c.simulatedXdr, currentLedger: X.V2.currentLedger };
          const signer = counting(ACCOUNT, async () => {
            throw new Error("the signer is never called");
          });
          const out = await transact(p.doc(), p.binding, signer, serving(ABC), { inputs });
          expect((out as Declined).decline).toMatchObject({ code: "offer-unreadable", detail: c.expect });
          expect(signer.requests.length).toBe(0);
          const confirmed = await confirm(p.doc(), p.binding, ACCOUNT, serving(ABC), inputs);
          expect((confirmed as Declined).decline).toMatchObject({ code: "offer-unreadable", detail: c.expect });
        }));
    }
  }
});
