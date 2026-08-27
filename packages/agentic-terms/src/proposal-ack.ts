/**
 * The ACK buyer surface: read an ACK-Pay `PaymentReceiptCredential` and say which rung of the record each
 * half of it feeds.
 *
 * **There is deliberately no `GateProposal` here, and that is a finding about ACK rather than a gap.** Every
 * other parser in this package turns a PROPOSAL into the typed inputs a buyer decides on. ACK has no
 * proposal-time carrier to turn: read live at `agentcommercekit/ack@main` on 2026-07-30,
 * `packages/ack-pay/src/schemas/valibot.ts` declares `paymentRequestSchema` as
 * `{ id, description?, serviceCallback?, expiresAt?, paymentOptions }` — no `metadata`, no open field, no
 * extension point anywhere on the request. The open map (`v.optional(v.record(v.string(), v.unknown()))`)
 * exists on `paymentReceiptClaimSchema` ALONE. So an LCP reference reaches an ACK document only at receipt
 * time, and manufacturing a `GateProposal` from a receipt would name a decision the buyer no longer has:
 * the payment has already settled. What the receipt genuinely supports is post-settlement verification, and
 * that is what this module produces.
 *
 * An ACK buyer that wants a decision BEFORE paying gets it the same way any Level 1–2 buyer does: from the
 * seller's `/.well-known/legal-context.json` (LCP §2), which is out of band from ACK entirely.
 */

import { readAtPath } from "@integraledger/lcp-binding-core";
import type { Artifact } from "@integraledger/lcp-evidence";
import { ACK_PLACEMENT, ackPlacement } from "@integraledger/lcp-placement-ack";

/**
 * The DID methods ACK's own resolver registers — `packages/did/src/did-resolvers/get-did-resolver.ts`
 * composes exactly four (`key-did-resolver`, `./web-did-resolver`, `jwks-did-resolver`,
 * `./pkh-did-resolver`), read live 2026-07-30. A receipt naming any other method is one ACK's own chain
 * could not have verified, so it is refused here rather than carried into a record as an identity nobody
 * can resolve. `did:jwks` was still pending when earlier surveys of ACK were written and has since landed,
 * which is why this list is cut from ACK's own resolver code rather than from any survey of it.
 */
export const ACK_DID_METHODS: readonly string[] = ["key", "web", "jwks", "pkh"];

/**
 * The leaf key names the LCP placement owns — DERIVED from the manifest so the two cannot drift.
 *
 * `readAlso` is OPTIONAL on `PlacementManifest` and manifests legitimately omit it, so `[]` is the CORRECT
 * value for "this placement owns no alias keys" — under it `siblingRefKeys` rightly reports the un-owned key
 * as one of ACK's own. Total handling of an optional field, not a fallback path: there is nothing here to
 * fail loudly about. `ACK_PLACEMENT` declares an alias today, which is why the arm is unreached.
 */
function lcpKeys(): string[] {
  const leaf = (path: string): string => path.slice(path.lastIndexOf(".") + 1);
  return [
    leaf(ACK_PLACEMENT.field),
    ...(ACK_PLACEMENT.readAlso ?? []).map((alias) => leaf(alias.path)),
  ];
}

function requireString(value: unknown, what: string): string {
  if (typeof value !== "string" || value === "")
    throw new Error(`ACK receipt: ${what} is absent or not a non-empty string`);
  return value;
}

/** What an issued ACK receipt yields, before anything is decided about it. */
export interface AckReceiptFacts {
  /** The reference recovered from `credentialSubject.metadata`, through the placement's own manifest. */
  readonly atrHash: `0x${string}`;
  /** ACK's join key: the signed payment request this receipt attests, and no other. */
  readonly paymentRequestToken: string;
  /** Which of the request's `paymentOptions` was taken. */
  readonly paymentOptionId: string;
  /** `credentialSubject.id` — the payer DID the receipt attributes the payment to. */
  readonly payerDid: string;
  /** The payer DID's method, narrowed to `ACK_DID_METHODS`. */
  readonly payerDidMethod: string;
  /** `issuer.id` — the receipt service that signed. Recorded; never mistaken for the payer. */
  readonly issuerDid: string;
  /**
   * The other keys ACK's own audit trail put in the same map, in wire order — `policyRef`, `mandateRef`,
   * `executionRef`, `executionReceiptHash`, `settlementNetwork`, `settlementReference` and whatever else a
   * deployment added. Reported because a record composer wants to know what else this receipt
   * cross-references, and because naming them is the honest form of "we are a guest in this map": we read
   * exactly one key and own none of the rest.
   */
  readonly siblingRefKeys: readonly string[];
}

/**
 * Parse an ISSUED `PaymentReceiptCredential` into its facts. Fail-fast on every departure from what ACK's
 * own code emits — a receipt this cannot read is one ACK's verification chain could not have produced.
 *
 * **The unissued receipt is refused, and it is the mirror of the seller's rule.**
 * `placement-ack.place` refuses a credential that ALREADY carries a `proof`, because a field added after
 * issuance either breaks the embedded signature or falls outside the JWT payload ACK treats as
 * authoritative. This refuses one that does NOT YET carry one, because a credential nobody signed attests
 * nothing and must not reach a record as evidence of a payment. Between the two rules the reference can
 * only ever ride a receipt the issuer signed over. The predicate is ACK's own — `isDecodedCredential`
 * accepts a value iff `"proof" in value && value.proof != null` — mirrored, so a `null` proof is unissued
 * by the host's rule and is unissued here.
 */
export function parseAckReceipt(credential: unknown): AckReceiptFacts {
  const proof = readAtPath(credential, "proof");
  if (proof === undefined || proof === null)
    throw new Error(
      "ack/receipt-not-issued: this credential carries no proof — a receipt nobody signed attests nothing, " +
        "and the reference it carries is outside anything ACK's verification chain would return",
    );

  const issuerDid = requireString(
    readAtPath(credential, "issuer.id"),
    "issuer.id (ACK's own createCredential emits `issuer: { id: issuer }`, never a bare string)",
  );
  const payerDid = requireString(
    readAtPath(credential, "credentialSubject.id"),
    "credentialSubject.id",
  );
  const [scheme, method] = payerDid.split(":");
  if (
    scheme !== "did" ||
    method === undefined ||
    !ACK_DID_METHODS.includes(method)
  )
    throw new Error(
      `ACK receipt: "${payerDid}" is not a did uri in a did method ACK resolves (${ACK_DID_METHODS.join(", ")})`,
    );
  const paymentRequestToken = requireString(
    readAtPath(credential, "credentialSubject.paymentRequestToken"),
    "credentialSubject.paymentRequestToken",
  );
  const paymentOptionId = requireString(
    readAtPath(credential, "credentialSubject.paymentOptionId"),
    "credentialSubject.paymentOptionId",
  );

  const extracted = ackPlacement.extract(credential);
  if (!("ok" in extracted))
    throw new Error(
      `ACK receipt carries no readable LCP reference (${extracted.haltClass}/${extracted.code})`,
    );
  if (extracted.value.ref.type !== "sha256")
    throw new Error(
      `ACK legalContext must be a sha256 carrier, got "${extracted.value.ref.type}" — a locator commits to nothing`,
    );

  const owned = lcpKeys();
  // `extract` above read the LCP key out of THIS map, so the map is an object and the narrowing cannot
  // fail. Asserted rather than branched: a defensive `typeof` ternary here would ship an else-arm no input
  // can reach, and its silent `[]` would under-report ACK's own refs on a receipt that has them.
  const metadata = readAtPath(
    credential,
    "credentialSubject.metadata",
  ) as Record<string, unknown>;
  const siblingRefKeys = Object.keys(metadata).filter(
    (k) => !owned.includes(k),
  );

  return {
    atrHash: extracted.value.ref.value as `0x${string}`,
    paymentRequestToken,
    paymentOptionId,
    payerDid,
    payerDidMethod: method,
    issuerDid,
    siblingRefKeys,
  };
}

/**
 * The receipt's contribution to a post-settlement `verify` call, with each field naming the rung it feeds.
 *
 * The first of ACK's two hard edges, answered in code rather than in prose: the `PaymentReceiptCredential` is
 * **both** an evidence artifact and an identity input, and the split is here.
 */
export interface AckReceiptContribution {
  /** Feeds `VerifyInput.placement` — the reference recovered from the host protocol's OWN document. */
  readonly placement: { readonly extracted: unknown };
  /**
   * RCS-4 → one `evidence.Artifact` under the `settlement` role.
   *
   * `settlement` rather than `attestation`: an ACK receipt IS ACK's settlement artifact — the credential
   * that attests the payment happened, carrying the `paymentRequestToken` it settled and, by convention,
   * ACK's own `settlementNetwork`/`settlementReference`. `settlement` is one of `RCS4_REQUIRED_ROLES`, so
   * filing it correctly is what lets an ACK record's evidence package be complete; filing it under
   * `attestation` would leave the settlement role empty while double-filling one that is already occupied
   * by the identity attestation.
   */
  readonly artifact: Artifact;
  /** IDN-1 → the payer `resolve-party` attributes the payment to. */
  readonly payerDid: string;
  /**
   * The payer DID's method — and NOT an assurance level.
   *
   * ACK's second hard edge: `did:web` / `did:jwks` resolution reuses the existing identity path rather than
   * minting a second one, and that path authors identity SELLER-side — the record's IDN content is
   * seller-authored. A buyer verifying a record reads the assurance the record already states; restating it
   * here would be a second authority on the same fact. The mapping from ACK's four DID methods to an
   * `authority.Assurance` therefore lives once, on the seller side, and this surface stops at the method.
   */
  readonly payerDidMethod: string;
  /** The receipt service that signed. Recorded on the record; never the payer. */
  readonly issuerDid: string;
  /** ACK's join key — the guard against reading a receipt against a payment request it never attested. */
  readonly paymentRequestToken: string;
}

/**
 * Split an issued receipt into its two rungs. `receiptBytes` are the retained credential exactly as it was
 * received — the artifact is the bytes, not a re-serialization of the parse, because what the evidence
 * package must hold is what the issuer signed.
 */
export function ackReceiptContribution(
  credential: unknown,
  receiptBytes: Uint8Array,
): AckReceiptContribution {
  const facts = parseAckReceipt(credential);
  return {
    placement: { extracted: { type: "sha256", value: facts.atrHash } },
    artifact: { role: "settlement", bytes: receiptBytes },
    payerDid: facts.payerDid,
    payerDidMethod: facts.payerDidMethod,
    issuerDid: facts.issuerDid,
    paymentRequestToken: facts.paymentRequestToken,
  };
}
