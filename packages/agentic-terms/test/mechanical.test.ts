import type {
  SettlementRef,
  VerifierPorts,
  WeldAdapter,
} from "@integraledger/lcp-binding-core";
import { hashAtr } from "@integraledger/lcp-kernel";
import { describe, expect, it } from "vitest";
import { verifySettled } from "../src/mechanical.js";

const enc = (s: string): Uint8Array => new TextEncoder().encode(s);
const noPorts: VerifierPorts = {
  chain: {
    getLogs: async () => [],
    getTransactionLogs: async () => [],
    readContract: async () => null,
    blockTime: async () => 0n,
  },
  artifacts: { resolve: async () => null },
};

describe("verifySettled — post-settlement mechanical verify (turns a receipt into a TC-2 record)", () => {
  it("verified:true for a genuinely welded settlement (recovered atrHash == hash of the ATR)", async () => {
    const atrBytes = enc("# Terms\nlcp: 0.3\n");
    const atrHash = await hashAtr(atrBytes);
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(_ref: SettlementRef, _p: VerifierPorts) {
        return { ok: true as const, value: atrHash };
      },
    };
    const report = await verifySettled(
      { chainId: 84532, txHash: `0x${"aa".repeat(32)}`, logIndex: 0 },
      adapter,
      {
        verifierPorts: noPorts,
        atrBytes,
        asOf: "2025-10-09T00:00:00Z",
        coverage: { ports: ["chain"], bindings: ["evm:x402"] },
        claimedClass: "TC-2",
        identity: { sellerAssurance: "legal-party", payer: "0xb15d" },
      },
    );
    expect(report.verified).toBe(true);
    expect(report.supportedClass).toBe("TC-2");
  });

  it("verified:false when recover refuses (no on-chain atrHash → fingerprint indeterminate)", async () => {
    const atrBytes = enc("# Terms\n");
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(_ref: SettlementRef, _p: VerifierPorts) {
        return {
          refused: true as const,
          haltClass: "verification-failure" as const,
          code: "recover/none",
        };
      },
    };
    const report = await verifySettled({ chainId: 84532 }, adapter, {
      verifierPorts: noPorts,
      atrBytes,
      asOf: "t",
      coverage: { ports: ["chain"], bindings: [] },
      claimedClass: "TC-2",
      identity: { sellerAssurance: "legal-party", payer: "0xb15d" },
    });
    expect(report.verified).toBe(false);
  });

  it("verified:false when the recovered atrHash is NOT the hash of these ATR bytes", async () => {
    // The wrong-record case, which is different from the no-record case above and was untested: recovery
    // succeeds, so `settledAtrHash` is threaded, but it belongs to some other agreement. A gate that only
    // checked "did recovery succeed" would proceed here, which is precisely the drift it exists to catch.
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(_ref: SettlementRef, _p: VerifierPorts) {
        return { ok: true as const, value: `0x${"cd".repeat(32)}` as const };
      },
    };
    const report = await verifySettled(
      { chainId: 84532, txHash: `0x${"aa".repeat(32)}`, logIndex: 0 },
      adapter,
      {
        verifierPorts: noPorts,
        atrBytes: enc("# Terms\nlcp: 0.3\n"),
        asOf: "2025-10-09T00:00:00Z",
        coverage: { ports: ["chain"], bindings: ["evm:x402"] },
        claimedClass: "TC-2",
        identity: { sellerAssurance: "legal-party", payer: "0xb15d" },
      },
    );
    expect(report.verified).toBe(false);
  });

  it("defaults the claimed class to TC-2 when the caller states none", async () => {
    // Every other test in this file passes `claimedClass` explicitly, so the `?? "TC-2"` default was never
    // exercised: a default of `"TC-1"` would be a strictly weaker claim, and must not pass unnoticed.
    const atrBytes = enc("# Terms\nlcp: 0.3\n");
    const atrHash = await hashAtr(atrBytes);
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(_ref: SettlementRef, _p: VerifierPorts) {
        return { ok: true as const, value: atrHash };
      },
    };
    const report = await verifySettled(
      { chainId: 84532, txHash: `0x${"aa".repeat(32)}`, logIndex: 0 },
      adapter,
      {
        verifierPorts: noPorts,
        atrBytes,
        asOf: "2025-10-09T00:00:00Z",
        coverage: { ports: ["chain"], bindings: ["evm:x402"] },
        identity: { sellerAssurance: "legal-party", payer: "0xb15d" },
      },
    );
    expect(report.supportedClass).toBe("TC-2");
    expect(report.verified).toBe(true);
  });

  it("carries a HIGHER claimed class through unchanged — it must not be quietly rewritten to one that passes", async () => {
    // The `??` default must yield to a caller's claim, not override or rewrite it. Every other test either
    // omits `claimedClass` or passes "TC-2", so nothing distinguished `?? "TC-2"` from an expression that
    // collapses ANY claim to "TC-2" — and that difference is the whole no-inflation property. A record with
    // only TC-2 evidence, claimed at TC-3, must report the claim VERBATIM and refuse it: `claimedClass`
    // reads "TC-3" and `verified` is false. Collapsing the claim to TC-2 would report `verified: true`
    // instead, turning an unsupported claim into a passing verdict.
    //
    // `supportedClass` is the other half and answers a different question — what the record actually
    // reaches, computed from the steps — so it reads TC-2 here. The two together are the finding: aimed at
    // TC-3, carries TC-2. It read TC-3 while the class echoed the claim, which is exactly the inflation
    // this test was written to catch, showing up in the field that was supposed to be the honest one.
    const atrBytes = enc("# Terms\nlcp: 0.3\n");
    const atrHash = await hashAtr(atrBytes);
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(_r: SettlementRef, _p: VerifierPorts) {
        return { ok: true as const, value: atrHash };
      },
    };
    const report = await verifySettled(
      { chainId: 84532, txHash: `0x${"aa".repeat(32)}`, logIndex: 0 },
      adapter,
      {
        verifierPorts: noPorts,
        atrBytes,
        asOf: "2025-10-09T00:00:00Z",
        coverage: { ports: ["chain"], bindings: ["evm:x402"] },
        // TC-3 requires buyer-acceptance, authority-attenuation, commitment-vs-leaf and recourse-elections
        // on top of TC-2 — none of which this post-settlement gate can prove.
        claimedClass: "TC-3",
        identity: { sellerAssurance: "legal-party", payer: "0xb15d" },
      },
    );
    expect(report.claimedClass).toBe("TC-3");
    expect(report.supportedClass).toBe("TC-2");
    expect(report.verified).toBe(false);
  });

  it("passes the settlement ref straight through to the adapter and into the attested enumeration", async () => {
    // The buyer can honestly attest only to the settlement it just made (PAY). Pins both that the ref
    // reaches `recover` unchanged and that it is the one enumerated.
    const ref: SettlementRef = {
      chainId: 84532,
      txHash: `0x${"ab".repeat(32)}`,
      logIndex: 7,
    };
    const atrBytes = enc("# Terms\nlcp: 0.3\n");
    const atrHash = await hashAtr(atrBytes);
    let seen: SettlementRef | undefined;
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(r: SettlementRef, _p: VerifierPorts) {
        seen = r;
        return { ok: true as const, value: atrHash };
      },
    };
    await verifySettled(ref, adapter, {
      verifierPorts: noPorts,
      atrBytes,
      asOf: "2025-10-09T00:00:00Z",
      coverage: { ports: ["chain"], bindings: ["evm:x402"] },
      identity: { sellerAssurance: "legal-party", payer: "0xb15d" },
    });
    expect(seen).toEqual(ref);
  });

  it("hands the injected verifier ports to the adapter — the gate stays viem-free", async () => {
    const atrBytes = enc("# Terms\nlcp: 0.3\n");
    const atrHash = await hashAtr(atrBytes);
    let seenPorts: VerifierPorts | undefined;
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(_r: SettlementRef, p: VerifierPorts) {
        seenPorts = p;
        return { ok: true as const, value: atrHash };
      },
    };
    await verifySettled(
      { chainId: 84532, txHash: `0x${"aa".repeat(32)}`, logIndex: 0 },
      adapter,
      {
        verifierPorts: noPorts,
        atrBytes,
        asOf: "2025-10-09T00:00:00Z",
        coverage: { ports: ["chain"], bindings: ["evm:x402"] },
        identity: { sellerAssurance: "legal-party", payer: "0xb15d" },
      },
    );
    expect(seenPorts).toBe(noPorts);
  });

  it("floors the record assurance at the buyer's own wallet-signature-only, whatever the seller states (IDN-3)", async () => {
    // The gate must not claim an identity level the rail cannot support. `verify` reads the identity rung
    // for TC-1-and-up, so an inflated buyer assurance would be a false attestation that still verifies.
    const atrBytes = enc("# Terms\nlcp: 0.3\n");
    const atrHash = await hashAtr(atrBytes);
    const adapter: Pick<WeldAdapter, "recover"> = {
      async recover(_r: SettlementRef, _p: VerifierPorts) {
        return { ok: true as const, value: atrHash };
      },
    };
    const run = (sellerAssurance: "legal-party" | "wallet-signature-only") =>
      verifySettled(
        { chainId: 84532, txHash: `0x${"aa".repeat(32)}`, logIndex: 0 },
        adapter,
        {
          verifierPorts: noPorts,
          atrBytes,
          asOf: "2025-10-09T00:00:00Z",
          coverage: { ports: ["chain"], bindings: ["evm:x402"] },
          identity: { sellerAssurance, payer: "0xPAYER" },
        },
      );

    // The record's stated assurance is the FLOOR across both parties, and the gate pins its own side at
    // wallet-signature-only because that is what the rail can actually support. So a `legal-party` seller
    // does NOT lift the record: raising the counterparty cannot raise what we are entitled to claim.
    const withLegalPartySeller = await run("legal-party");
    expect(withLegalPartySeller.assurance).toBe("wallet-signature-only");

    const withWalletSeller = await run("wallet-signature-only");
    expect(withWalletSeller.assurance).toBe("wallet-signature-only");

    // Both still verify — the floor is an honesty property of the readout, not a failure.
    expect(withLegalPartySeller.verified).toBe(true);
    expect(withWalletSeller.verified).toBe(true);
  });
});
