import type { Assurance } from "@integraledger/lcp-authority";
import type {
  SettlementRef,
  VerifierPorts,
  WeldAdapter,
} from "@integraledger/lcp-binding-core";
import {
  type RecordIdentity,
  type TransactionClass,
  type VerificationReport,
  verify,
} from "@integraledger/lcp-verify";

/** Inputs for the post-settlement mechanical verify. `verifierPorts` (chain + artifacts) is INJECTED, which is
 *  what keeps the gate viem-free. `atrBytes` is the fetched ATR; `coverage` matches verify's shape. */
export interface MechanicalPorts {
  readonly verifierPorts: VerifierPorts;
  readonly atrBytes: Uint8Array;
  readonly asOf: string;
  readonly coverage: { ports: string[]; bindings: string[] };
  readonly claimedClass?: TransactionClass;
  /**
   * The parties as the buyer resolved them (IDN-1/3). TC-1 and up require the attribution rung, so a
   * record verified without this reads honestly as unverified — the gate KNOWS both sides at this point
   * (it holds the seller's stated assurance from the proposal and it is itself the payer), so it says so.
   */
  readonly identity: {
    readonly sellerAssurance: Assurance;
    readonly payer: string;
  };
}

/** Turn a settled receipt into a TC-2/TC-3 *transaction* record: recover the on-chain atrHash via the injected
 *  binding adapter, then run `verify({depth:"mechanical"})` — `verified` is raised honestly iff the ATR bytes
 *  hash to the recovered atrHash (and the class-required steps hold). A refused recovery leaves settledAtrHash
 *  absent → the fingerprint is indeterminate → verified stays false. */
export async function verifySettled(
  ref: SettlementRef,
  adapter: Pick<WeldAdapter, "recover">,
  ports: MechanicalPorts,
): Promise<VerificationReport> {
  const recovered = await adapter.recover(ref, ports.verifierPorts);
  // The buyer resolves the seller at the assurance the proposal stated, and itself at the level the rail
  // actually supports: a wallet signature. Stating the low level honestly is conformant (IDN-3); claiming
  // a level the rail cannot support would not be.
  const identity: RecordIdentity = {
    seller: {
      subject: "seller",
      assurance: ports.identity.sellerAssurance,
      chain: [{ via: "domain-control" }],
    },
    buyer: {
      subject: ports.identity.payer,
      assurance: "wallet-signature-only",
      chain: [{ via: "key" }],
    },
  };
  const base = {
    depth: "mechanical" as const,
    atrBytes: ports.atrBytes,
    coverage: ports.coverage,
    claimedClass: ports.claimedClass ?? ("TC-2" as TransactionClass),
    asOf: ports.asOf,
    // The settlement the buyer just made IS the enumeration it can honestly attest to (PAY).
    settlements: [ref],
    identity,
  };
  return verify(
    "ok" in recovered ? { ...base, settledAtrHash: recovered.value } : base,
  );
}
