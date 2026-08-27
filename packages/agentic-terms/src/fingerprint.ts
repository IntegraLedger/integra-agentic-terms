import type { HaltClass } from "@integraledger/lcp-binding-core";
import { hashAtr } from "@integraledger/lcp-kernel";
export type FingerprintOutcome =
  | { readonly status: "proved"; readonly atrHash: `0x${string}` }
  | {
      readonly status: "failed";
      readonly haltClass: HaltClass;
      readonly recomputed: `0x${string}`;
      readonly advertised: string;
    };

/** The LCP §5.3 core: recompute SHA-256 over the fetched terms bytes and compare to the advertised atrHash. A
 *  mismatch is `failed(verification-failure)` — the caller MUST halt before invoking any signing key. */
export async function recomputeAndCompare(
  bytes: Uint8Array,
  advertisedAtrHash: string,
): Promise<FingerprintOutcome> {
  const recomputed = await hashAtr(bytes);
  return recomputed.toLowerCase() === advertisedAtrHash.toLowerCase()
    ? { status: "proved", atrHash: recomputed }
    : {
        status: "failed",
        haltClass: "verification-failure",
        recomputed,
        advertised: advertisedAtrHash,
      };
}
