import type { ProtocolId } from "@integraledger/lcp-binding-core";
import { supportedProtocols } from "@integraledger/lcp-placements";
import { describe, expect, it } from "vitest";
import { parseProposalFromChallenge } from "../src/proposal.js";
import { parseProposalFromAcpCheckout } from "../src/proposal-acp.js";
import {
  ACP_SESSION_STATUS,
  detectProtocol,
  matchProtocols,
  PROPOSAL_PARSERS,
  PROTOCOL_DISCRIMINANTS,
  parseableProtocols,
  parseProposalUniversal,
  readAdvertisedTerms,
  VI_OPEN_MANDATE_VCT,
} from "../src/proposal-universal.js";

// The vector tree's two standing hashes. Two are needed and not one: every disagreement case below has to
// pin that the reader answered "these differ", which a single value cannot express.
const ATR =
  "0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069";
const OTHER_ATR =
  "0x3f786850e387550fdab836ed7e6dc881de23001b3f786850e387550fdab836ed";
const TERMS = "https://seller.example/terms/abc";
const NAMESPACE = { reverseDomain: "com.integraledger" };

/** The message a refusal actually carried. Fails loudly when nothing was refused at all. */
function messageOf(call: () => unknown): string {
  try {
    call();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected a refusal, and the call returned a value");
}

const ctx = {
  level: 2 as const,
  sellerAssurance: "domain-controlled" as const,
};

// --- one document per protocol, in the shape its own live specification declares -------------------------

/** x402 v2 PaymentRequired, advertising in BOTH Tier A carriers, agreeing. */
const x402Challenge = {
  x402Version: 2,
  accepts: [
    {
      amount: "1000",
      network: "base-sepolia",
      asset: "0xUSDC",
      extra: { atrHash: ATR, legalContextUrl: TERMS },
    },
  ],
  extensions: {
    legalContext: {
      info: { type: "sha256", value: ATR, legalContextUrl: TERMS },
      schema: {
        $ref: "https://legalcontextprotocol.org/schemas/lcp-extension.json",
      },
    },
  },
};

/** ACP CheckoutSession (stable 2026-04-17) — `totals` is an array of typed rows. */
const acpSession = {
  id: "checkout_session_1",
  status: "ready_for_payment",
  currency: "usd",
  line_items: [{ id: "li_1", quantity: 1 }],
  totals: [
    { type: "items_base_amount", display_text: "Items", amount: 1400 },
    { type: "tax", display_text: "Tax", amount: 100 },
    { type: "total", display_text: "Total", amount: 1500 },
  ],
  metadata: {
    legal_context: `lcp:sha256:${ATR}`,
    legal_context_url: TERMS,
  },
};

/** UCP checkout response — `ucp` is the required member no other protocol in the set carries. */
const ucpCheckout = {
  ucp: { version: "2026-04-08" },
  id: "checkout_1",
  status: "ready_for_payment",
  links: [{ type: "terms_of_service", url: TERMS, title: "Terms" }],
  // The integrity carrier is UCP's `policies[]` tagged array, NOT an `extensions` map — UCP defines no such
  // map, so the manifest declares the carrier the host actually has. Shape taken from the placement's own
  // `place()` output, `description` constant included, which is what a counterparty's writer emits.
  policies: [
    {
      description: {
        plain:
          "Terms of sale for this order, identified by a Legal Context Protocol reference. The reference identifies the exact terms document; it is not itself the terms.",
      },
      type: "com.integraledger.policy.legal_context",
      "com.integraledger.legal_context": { type: "sha256", value: ATR },
    },
  ],
};

/** A2A Task — `id` and `status` are its two REQUIRED members. */
const a2aTask = {
  id: "task_1",
  contextId: "ctx_1",
  status: { state: "TASK_STATE_SUBMITTED" },
  metadata: { legalContext: { type: "sha256", value: ATR } },
};

/** A2A Message — `messageId`, `role` and `parts` are its three REQUIRED members. */
const a2aMessage = {
  messageId: "msg_1",
  role: "ROLE_USER",
  parts: [{ text: "quote me" }],
  metadata: { legalContext: { type: "sha256", value: ATR } },
};

/** The AP2 v0.2 transport envelope — an A2A Message whose DataPart carries the mandate. */
const ap2Envelope = {
  messageId: "msg_2",
  role: "ROLE_USER",
  parts: [
    {
      data: { "ap2.mandates.CheckoutMandateSdJwt": "eyJhbGciOi.eyJzdWIi.sig~" },
    },
    { data: { risk_data: { score: 3 } } },
  ],
  metadata: { legalContext: { type: "sha256", value: ATR } },
};

/** The same envelope carrying AP2's OTHER mandate DataPart — both keys are declared, so both are read. */
const ap2PaymentEnvelope = {
  messageId: "msg_3",
  role: "ROLE_AGENT",
  parts: [
    {
      data: { "ap2.mandates.PaymentMandateSdJwt": "eyJhbGciOi.eyJzdWIi.sig~" },
    },
  ],
  metadata: { legalContext: { type: "sha256", value: ATR } },
};

/** An ACK-Pay receipt — a W3C credential typed PaymentReceiptCredential. */
const ackReceipt = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  type: ["VerifiableCredential", "PaymentReceiptCredential"],
  issuer: { id: "did:web:seller.example" },
  credentialSubject: {
    id: "did:web:buyer.example",
    paymentRequestToken: "tok_1",
    paymentOptionId: "opt_1",
    metadata: { legalContext: { type: "sha256", value: ATR } },
  },
  issuanceDate: "2026-07-30T00:00:00.000Z",
};

/** A Verifiable Intent Autonomous-mode open mandate. */
const viMandate = {
  vct: "mandate.checkout.open.1",
  cnf: { jwk: { kty: "EC", crv: "P-256" } },
  constraints: [
    { type: "mandate.payment.budget", currency: "USD", max: 10000 },
    { type: "com.integraledger.lcp_terms_hash", value: ATR },
  ],
};

/** A Visa TAP request, carrying the agent recognition signature and the advisory header beside it. */
const tapRequest = {
  headers: {
    "Signature-Input":
      'sig1=("@authority" "@path");created=1785000000;keyid="k1";alg="ecdsa-p256-sha256";nonce="n1";tag="agent-payer-auth"',
    Signature: "sig1=:MEUCIQ…:",
    "X-LCP-Hash": ATR,
  },
};

/** An MPP charge-intent `request` body, already decoded out of its auth-param. */
const mppRequest = {
  amount: "1000000",
  currency: "USDC",
  recipient: "0x000000000000000000000000000000000000dEaD",
  methodDetails: {
    chainId: 8453,
    atrHash: ATR,
    legalContextUrl: TERMS,
  },
};

/** Every registered protocol paired with a document that advertises `ATR` through its declared carrier. */
const DOCUMENTS: ReadonlyArray<readonly [ProtocolId, unknown]> = [
  ["x402", x402Challenge],
  ["mpp", mppRequest],
  ["ap2", ap2Envelope],
  ["ack", ackReceipt],
  ["acp", acpSession],
  ["ucp", ucpCheckout],
  ["visa-tap", tapRequest],
  ["mastercard-vi", viMandate],
  ["a2a", a2aTask],
];

describe("detectProtocol", () => {
  it("identifies an x402 challenge by its version discriminant", () => {
    expect(detectProtocol(x402Challenge)).toBe("x402");
  });

  it("identifies an ACP session by its top-level shape", () => {
    expect(detectProtocol(acpSession)).toBe("acp");
  });

  // The two host enums, restated as literals. These replace the deleted manifest pins, and they are a
  // WEAKER instrument on purpose-of-record: the manifest pin was a cross-check against a second, live
  // source, and protocol 0.9.0 publishes no `writeCondition` for either constant to be checked against.
  // What a literal restatement still buys is that neither list can be edited SILENTLY — a changed entry
  // fails here and has to be changed twice, deliberately.
  //
  // Iterating the constant and asserting each value is recognised does NOT do this job, and was tried:
  // `detectProtocol({...acpSession, status})` drawn from the same array passes whatever the array says, so
  // a corrupted entry proves itself. Mutation testing is what says so out loud — ten survivors in
  // `ACP_SESSION_STATUS` and one in `VI_OPEN_MANDATE_VCT` sat untouched through that loop.
  //
  // Neither form catches HOST drift. Re-derive against the live ACP schema and Mastercard's open-mandate
  // definitions when touching them; nothing here will tell you they moved.
  it("states ACP's eleven session statuses, so none can be edited silently", () => {
    expect(ACP_SESSION_STATUS).toEqual([
      "incomplete",
      "not_ready_for_payment",
      "requires_escalation",
      "authentication_required",
      "ready_for_payment",
      "pending_approval",
      "complete_in_progress",
      "completed",
      "canceled",
      "in_progress",
      "expired",
    ]);
  });

  it("states Verifiable Intent's two open-mandate types, on the same terms", () => {
    expect(VI_OPEN_MANDATE_VCT).toEqual([
      "mandate.checkout.open.1",
      "mandate.payment.open.1",
    ]);
  });

  it("identifies a UCP checkout response by the `ucp` metadata member", () => {
    // Deliberately WITHOUT the currency/totals/line_items trio, so this asserts the `ucp` rule alone rather
    // than passing because the document also happens to look like ACP (which the ambiguity test covers).
    expect(
      detectProtocol({ ucp: {}, id: "c_1", status: "open", links: [] }),
    ).toBe("ucp");
  });

  it("identifies an A2A task and an A2A message — both carry the metadata map", () => {
    expect(detectProtocol(a2aTask)).toBe("a2a");
    expect(detectProtocol(a2aMessage)).toBe("a2a");
  });

  it("identifies an ACK payment receipt by its credential type", () => {
    expect(detectProtocol(ackReceipt)).toBe("ack");
  });

  it("identifies a Verifiable Intent open mandate by `vct` plus `constraints`", () => {
    expect(detectProtocol(viMandate)).toBe("mastercard-vi");
  });

  it("identifies a Visa TAP request by the agent recognition signature's tag", () => {
    expect(detectProtocol(tapRequest)).toBe("visa-tap");
  });

  it("returns undefined for a wire it cannot identify — it never guesses", () => {
    expect(detectProtocol({ hello: "world" })).toBeUndefined();
  });

  it("returns undefined for shapes that are not documents at all", () => {
    expect(detectProtocol(null)).toBeUndefined();
    expect(detectProtocol("x402")).toBeUndefined();
    expect(detectProtocol([acpSession])).toBeUndefined();
  });

  it("does NOT identify a document merely because it carries an LCP reference", () => {
    // The whole reason detection is by discriminant. This object holds a perfectly good reference at the
    // exact path four manifests declare, and it is still not identifiable as any protocol.
    expect(
      detectProtocol({
        metadata: { legalContext: { type: "sha256", value: ATR } },
      }),
    ).toBeUndefined();
  });

  it("returns undefined for an MPP request body — the document carries nothing that names MPP", () => {
    expect(detectProtocol(mppRequest)).toBeUndefined();
    const row = PROTOCOL_DISCRIMINANTS.find((r) => r.protocol === "mpp");
    expect(row?.kind).toBe("undiscriminable");
  });

  it("returns undefined when TWO protocols match — a single value cannot say `ambiguous`", () => {
    expect(detectProtocol(ap2Envelope)).toBeUndefined();
    expect(matchProtocols(ap2Envelope).length).toBe(2);
  });

  it("rejects near-misses rather than stretching a rule to fit", () => {
    // x402: the version must be a NUMBER and `accepts` an array.
    expect(detectProtocol({ x402Version: "2", accepts: [] })).toBeUndefined();
    expect(detectProtocol({ x402Version: 2, accepts: {} })).toBeUndefined();
    // ACP: a status outside the closed enum is not an ACP session.
    expect(
      detectProtocol({ ...acpSession, status: "awaiting_shipment" }),
    ).toBeUndefined();
    // UCP: `ucp` must be an object — neither null nor an array is one.
    expect(
      detectProtocol({ ucp: null, id: "c", status: "open", links: [] }),
    ).toBeUndefined();
    expect(
      detectProtocol({ ucp: [], id: "c", status: "open", links: [] }),
    ).toBeUndefined();
    // ACK: the credential type list must actually name the receipt, and the subject must be an object.
    expect(
      detectProtocol({ ...ackReceipt, type: ["VerifiableCredential"] }),
    ).toBeUndefined();
    expect(
      detectProtocol({ ...ackReceipt, credentialSubject: [] }),
    ).toBeUndefined();
    // Verifiable Intent: an Immediate-mode mandate carries no constraints and is not this carrier's document.
    expect(
      detectProtocol({ ...viMandate, vct: "mandate.checkout.1" }),
    ).toBeUndefined();
    expect(
      detectProtocol({ vct: "mandate.payment.open.1", constraints: {} }),
    ).toBeUndefined();
    // TAP: a signed request whose tag is some other RFC 9421 application is not TAP.
    expect(
      detectProtocol({
        headers: {
          "Signature-Input": 'sig1=("@authority");created=1;tag="web-bot-auth"',
        },
      }),
    ).toBeUndefined();
    // A2A: a task needs `status.state`, a message needs ALL THREE of its required members — one case per
    // member, because a message missing any one of them is not a message and each check has to say so.
    expect(detectProtocol({ id: "t", status: {} })).toBeUndefined();
    expect(
      detectProtocol({ messageId: "m", role: "ROLE_USER" }),
    ).toBeUndefined();
    expect(detectProtocol({ messageId: "m", parts: [] })).toBeUndefined();
    expect(detectProtocol({ role: "ROLE_USER", parts: [] })).toBeUndefined();
  });

  it("identifies an AP2 envelope carrying EITHER declared mandate DataPart", () => {
    expect(matchProtocols(ap2Envelope)).toContain("ap2");
    expect(matchProtocols(ap2PaymentEnvelope)).toContain("ap2");
  });

  it("folds header case per RFC 9110 — `signature-input` and `Signature-Input` are one header", () => {
    const lower = {
      headers: {
        "signature-input": 'sig1=("@path");created=1;tag="agent-browser-auth"',
      },
    };
    expect(detectProtocol(lower)).toBe("visa-tap");
  });
});

describe("matchProtocols", () => {
  it("returns ALL matches, never the first — an AP2 envelope IS an A2A message", () => {
    expect(matchProtocols(ap2Envelope)).toEqual(["ap2", "a2a"]);
  });

  it("co-fires a2a on EVERY ap2 document — the ap2 rule is a strict subset, not a near-miss", () => {
    // `ap2` is `carriesAp2Mandate && isA2aMessage`; `a2a` is `isA2aTask || isA2aMessage`. The first implies
    // the second by construction, so no AP2 envelope is ever reachable through parseProposalUniversal and
    // registering an ap2 parser would not change that. Pinned over both declared mandate DataParts, and
    // pinned as the WHOLE list so a later negative term on the a2a row shows up here as a difference.
    expect(matchProtocols(ap2Envelope)).toEqual(["ap2", "a2a"]);
    expect(matchProtocols(ap2PaymentEnvelope)).toEqual(["ap2", "a2a"]);
    // The mandate part is what carries the implication: strip it and only the a2a row is left.
    expect(matchProtocols({ ...ap2Envelope, parts: [{ text: "hi" }] })).toEqual(
      ["a2a"],
    );
  });

  it("reports the ACP/UCP cousinhood rather than picking between them", () => {
    // A UCP checkout response carrying the same checkout members ACP requires satisfies both rules. That is
    // a fact about two closely related host protocols, not a defect, and the answer is both names.
    const cousin = {
      ...ucpCheckout,
      currency: "usd",
      totals: [{ type: "total", amount: 1500 }],
      line_items: [{ id: "li_1", quantity: 1 }],
    };
    expect(matchProtocols(cousin)).toEqual(["acp", "ucp"]);
  });

  it("returns an empty list rather than throwing on anything a wire can present", () => {
    for (const wire of [null, undefined, 7, "acp", [], {}, new Date()])
      expect(matchProtocols(wire)).toEqual([]);
  });
});

describe("the discriminant table", () => {
  it("has exactly one row for every protocol the placement registry supports", () => {
    const rows = PROTOCOL_DISCRIMINANTS.map((r) => r.protocol);
    expect([...rows].sort()).toEqual([...supportedProtocols()].sort());
    expect(new Set(rows).size).toBe(rows.length);
  });

  it("names no protocol the registry cannot place — `mcp` is absent from both", () => {
    expect(supportedProtocols()).not.toContain("mcp");
    expect(PROTOCOL_DISCRIMINANTS.map((r) => r.protocol)).not.toContain("mcp");
  });

  it("cites a source on every row, and states a reason on every undiscriminable one", () => {
    for (const row of PROTOCOL_DISCRIMINANTS) {
      expect(row.cite.length).toBeGreaterThan(0);
      if (row.kind === "undiscriminable")
        expect(row.reason.length).toBeGreaterThan(0);
    }
  });

  // The two enum-pin tests that lived here are DELETED, not loosened. They read
  // `manifest.writeCondition` (ACP through its `legal_context` alias, VI at the top level) and compared it
  // to this package's copy. As of protocol 0.9.0 NO manifest declares a `writeCondition` at all — ACP's
  // aliases carry `{path, encoding}` only, and mastercard-vi states "THERE IS NO writeCondition, BECAUSE
  // THERE IS NO WRITE" (declaration-only under LCP v1.38 §C.7). There is nothing left to pin against, and a
  // loosened assertion over an absent field would assert nothing while looking like a guard.
  //
  // CONSEQUENCE, recorded rather than hidden: `ACP_SESSION_STATUS` and `VI_OPEN_MANDATE_VCT` are now
  // hand-kept copies of host-protocol enums with NO automated drift guard. Both are still exercised as
  // discriminants by the `identifyProtocol` tests above, which catch a copy that stops matching the
  // FIXTURES — not one that stops matching the HOST.
});

describe("parseProposalUniversal", () => {
  it("routes an x402 challenge to the x402 parser and yields the same GateProposal", () => {
    expect(parseProposalUniversal(x402Challenge, ctx)).toEqual(
      parseProposalFromChallenge(x402Challenge, ctx),
    );
  });

  it("routes an ACP session to the ACP parser and yields the same GateProposal", () => {
    expect(parseProposalUniversal(acpSession, ctx)).toEqual(
      parseProposalFromAcpCheckout(acpSession, ctx),
    );
  });

  it("names the protocol it could not identify in the error", () => {
    expect(() => parseProposalUniversal({ hello: "world" }, ctx)).toThrow(
      /could not identify/,
    );
  });

  it("REFUSES an ambiguous wire that matches two protocols, naming both", () => {
    expect(() => parseProposalUniversal(ap2Envelope, ctx)).toThrow(/ambiguous/);
    expect(() => parseProposalUniversal(ap2Envelope, ctx)).toThrow(/ap2, a2a/);
    // And it is EVERY ap2 document, not this one: the refusal is structural, so `ap2` is a detect-and-name
    // protocol here and a parser for it would have to be called by name.
    expect(() => parseProposalUniversal(ap2PaymentEnvelope, ctx)).toThrow(
      /ambiguous/,
    );
    expect(parseableProtocols()).not.toContain("ap2");
  });

  it("refuses a protocol it can identify but cannot price, and says which it can", () => {
    expect(() => parseProposalUniversal(tapRequest, ctx)).toThrow(
      /no buyer proposal parser for visa-tap/,
    );
    expect(() => parseProposalUniversal(tapRequest, ctx)).toThrow(
      /this build parses x402, acp/,
    );
  });

  it("propagates the routed parser's own refusal rather than swallowing it", () => {
    const decimalAmount = structuredClone(x402Challenge);
    decimalAmount.accepts[0]!.amount = "10.00";
    expect(() => parseProposalUniversal(decimalAmount, ctx)).toThrow(
      /base-unit integer/,
    );
  });

  it("parses only protocols the build can also PLACE into — the round trip stays closed", () => {
    for (const id of parseableProtocols()) {
      expect(supportedProtocols()).toContain(id);
      expect(PROPOSAL_PARSERS[id]).toBeTypeOf("function");
    }
  });
});

describe("readAdvertisedTerms", () => {
  it("reads the reference out of EVERY registered protocol's document", () => {
    // The universality claim, stated as a loop rather than as prose. Nothing here lists a carrier: each
    // document is read through its own protocol's manifest, out of the registry.
    for (const [protocol, doc] of DOCUMENTS) {
      const terms = readAdvertisedTerms(protocol, doc, NAMESPACE);
      expect(terms.protocol).toBe(protocol);
      expect(terms.advertisedAtrHash).toBe(ATR);
    }
    expect(DOCUMENTS.length).toBe(supportedProtocols().length);
  });

  it("reads the terms URL from the field the manifest declares", () => {
    expect(readAdvertisedTerms("acp", acpSession).legalContextUrl).toEqual({
      kind: "read",
      url: TERMS,
    });
    expect(readAdvertisedTerms("x402", x402Challenge).legalContextUrl).toEqual({
      kind: "read",
      url: TERMS,
    });
    expect(readAdvertisedTerms("mpp", mppRequest).legalContextUrl).toEqual({
      kind: "read",
      url: TERMS,
    });
  });

  it("says NO FIELD DECLARED where the protocol has no room for a terms URL", () => {
    // A2A, ACK, Visa TAP and Mastercard VI declare no terms-URL slot at all. That is a fact about those
    // protocols, and it is a different fact from a document leaving a declared field empty.
    for (const terms of [
      readAdvertisedTerms("a2a", a2aTask),
      readAdvertisedTerms("ack", ackReceipt),
      readAdvertisedTerms("visa-tap", tapRequest),
      readAdvertisedTerms("mastercard-vi", viMandate, NAMESPACE),
    ])
      expect(terms.legalContextUrl).toEqual({ kind: "no-field-declared" });
  });

  it("READS the x402 §C.4 terms URL — the shortfall it used to report is fixed upstream", () => {
    // The v1.38 §C.4-illustrated challenge: reference and terms URL both in `accepts[].extra`, no
    // `extensions` block. This once reported `undeclared-at-answering-carrier` — the manifest's terms-URL
    // member was SINGULAR and named a path inside the canonical carrier, unreachable on a document that
    // used the alias, so the reader could not tell "no terms advertised" from "I cannot see where they
    // would be". `termsUrlFields` is now plural and declares BOTH slots, so the URL is simply read, and
    // the two entry points of this package answer the same bytes the same way rather than one of them
    // reporting that it cannot.
    const c4 = structuredClone(x402Challenge);
    // @ts-expect-error deleting an optional wire member the schema treats as optional
    delete c4.extensions;

    const terms = readAdvertisedTerms("x402", c4);
    expect(terms.advertisedAtrHash).toBe(ATR);
    expect(terms.legalContextUrl).toEqual({ kind: "read", url: TERMS });
    expect(parseProposalFromChallenge(c4, ctx).legalContextUrl).toBe(TERMS);
  });

  it("says EMPTY, not unknowable, when the CANONICAL carrier answered and its nested field is absent", () => {
    // The x402 document with BOTH declared slots empty. It once turned on which carrier answered — the
    // singular member reached only one of the two, so the same emptiness meant different things depending
    // on where the hash came from. With both slots declared and read there is one answer: the seller had
    // two places to put a locator and used neither, which is a choice about this document and is reported
    // as one. The case is kept because that emptiness is exactly what the old reader could not name.
    const extensionsOnly = structuredClone(x402Challenge);
    // @ts-expect-error deleting an optional wire member the schema treats as optional
    delete extensionsOnly.accepts[0].extra;
    // @ts-expect-error the terms URL is declared by the manifest, not required by the wire
    delete extensionsOnly.extensions.legalContext.info.legalContextUrl;

    const terms = readAdvertisedTerms("x402", extensionsOnly);
    expect(terms.advertisedAtrHash).toBe(ATR);
    expect(terms.legalContextUrl).toEqual({
      kind: "declared-fields-empty",
      fields: [
        "extensions.legalContext.info.legalContextUrl",
        "accepts.0.extra.legalContextUrl",
      ],
    });
  });

  it("still says EMPTY, not unknowable, when the declared field is a SIBLING of the carrier", () => {
    // ACP's `metadata.legal_context_url` sits beside `metadata.legal_context` rather than inside it, so it is
    // reachable whichever carrier answered and an empty one means empty. Answered here from the third alias,
    // with the canonical field absent — the exact condition that makes x402 unknowable.
    const aliasOnly = {
      ...acpSession,
      metadata: { legalContext: { type: "sha256", value: ATR } },
    };
    const terms = readAdvertisedTerms("acp", aliasOnly);
    expect(terms.advertisedAtrHash).toBe(ATR);
    expect(terms.legalContextUrl).toEqual({
      kind: "declared-fields-empty",
      fields: ["metadata.legal_context_url"],
    });
  });

  it("reads a protocol whose DOCUMENT cannot be identified, once the caller names it", () => {
    // MPP is the undiscriminable row, and it is fully readable — detection and reading are separate
    // capabilities, which is why the protocol is an argument here and a detection only in the parser.
    expect(readAdvertisedTerms("mpp", mppRequest).advertisedAtrHash).toBe(ATR);
  });

  it("accepts an x402 challenge advertising in only ONE of its two carriers, either one", () => {
    const extensionsOnly = structuredClone(x402Challenge);
    // @ts-expect-error deleting an optional wire member the schema treats as optional
    delete extensionsOnly.accepts[0].extra;
    expect(readAdvertisedTerms("x402", extensionsOnly).advertisedAtrHash).toBe(
      ATR,
    );

    const extraOnly = structuredClone(x402Challenge);
    // @ts-expect-error deleting an optional wire member the schema treats as optional
    delete extraOnly.extensions;
    expect(readAdvertisedTerms("x402", extraOnly).advertisedAtrHash).toBe(ATR);
  });

  it("REFUSES when two declared carriers disagree — preference would let a seller advertise twice", () => {
    const contradictory = structuredClone(x402Challenge);
    contradictory.accepts[0]!.extra.atrHash = OTHER_ATR;
    expect(() => readAdvertisedTerms("x402", contradictory)).toThrow(
      /carriers disagree/,
    );
    // The message must show BOTH values, or the reader cannot tell which counterparty said what.
    expect(() => readAdvertisedTerms("x402", contradictory)).toThrow(
      new RegExp(`${ATR}.*${OTHER_ATR}|${OTHER_ATR}.*${ATR}`),
    );
  });

  it("treats hex case as the same reference — it is a hash, not a string", () => {
    const mixedCase = structuredClone(x402Challenge);
    mixedCase.accepts[0]!.extra.atrHash = `0x${ATR.slice(2).toUpperCase()}`;
    expect(readAdvertisedTerms("x402", mixedCase).advertisedAtrHash).toBe(ATR);
  });

  it("refuses a document advertising nothing, naming EVERY carrier it looked at, in order", () => {
    // The list is the actionable half of the refusal: a seller reading it learns which three spellings its
    // session could have used. Pinned as the whole list, separators included — a message that named one of
    // them, or ran them together, would read as helpful and be wrong.
    expect(
      messageOf(() =>
        readAdvertisedTerms("acp", { ...acpSession, metadata: {} }),
      ),
    ).toContain(
      "(metadata.legal_context, legal_context, metadata.legalContext)",
    );
  });

  it("names only the INTEGRITY carriers it looked at — a discovery link was never a candidate", () => {
    const linkOnly = structuredClone(ucpCheckout);
    // @ts-expect-error removing the capability leaves only the terms_of_service link
    delete linkOnly.policies;
    const message = messageOf(() => readAdvertisedTerms("ucp", linkOnly));
    expect(message).toContain(
      "policies[type=com.integraledger.policy.legal_context]",
    );
    expect(message).not.toContain("links[type=terms_of_service]");
  });

  it("ignores a carrier whose type is outside the §8.2 registry rather than reporting it", () => {
    // `decodeDeclaredRead` answers `undefined` for an unrecognized type (LCP §8.2 says ignore), and a reader
    // that pushed that absence into the reconcile would compare a reference that is not there.
    const unknownType = {
      ...a2aTask,
      metadata: { legalContext: { type: "sha512", value: ATR } },
    };
    expect(() => readAdvertisedTerms("a2a", unknownType)).toThrow(
      /advertises no LCP reference/,
    );
  });

  it("never reads UCP's discovery carrier as a reference — a link locates, it does not attest", () => {
    const linkOnly = structuredClone(ucpCheckout);
    // @ts-expect-error removing the capability leaves only the terms_of_service link
    delete linkOnly.policies;
    expect(() => readAdvertisedTerms("ucp", linkOnly)).toThrow(
      /advertises no LCP reference/,
    );
    // And it never DISAGREES with the capability either — a discovery hit is not a second opinion.
    expect(readAdvertisedTerms("ucp", ucpCheckout).advertisedAtrHash).toBe(ATR);
  });

  it("compares two same-type carriers exactly, and reports both with a separator", () => {
    // Two URL carriers differing ONLY in host case. They are two different URLs — case is significant
    // outside the authority — so this must refuse; a reader that normalized them would agree with itself.
    const cased = {
      ...a2aTask,
      metadata: {
        legalContext: { type: "url", value: "https://seller.example/Terms" },
        legal_context: { type: "url", value: "https://seller.example/terms" },
      },
    };
    const message = messageOf(() => readAdvertisedTerms("a2a", cased));
    expect(message).toContain("carriers disagree");
    expect(message).toContain(
      "metadata.legalContext advertises lcp:url:https://seller.example/Terms, metadata.legal_context advertises lcp:url:https://seller.example/terms",
    );
  });

  it("refuses a non-sha256 carrier — the gate compares against a recomputed hash", () => {
    const urlCarrier = {
      ...a2aTask,
      metadata: { legalContext: { type: "url", value: TERMS } },
    };
    expect(() => readAdvertisedTerms("a2a", urlCarrier)).toThrow(
      /only a sha256 carrier/,
    );
  });

  it("compares carriers by type as well as value — a url and a hash are not one reference", () => {
    const mixed = {
      ...a2aTask,
      metadata: {
        legalContext: { type: "url", value: TERMS },
        legal_context: { type: "sha256", value: ATR },
      },
    };
    expect(() => readAdvertisedTerms("a2a", mixed)).toThrow(
      /carriers disagree/,
    );
    expect(() => readAdvertisedTerms("a2a", mixed)).toThrow(/lcp:url:/);
  });

  it("requires the deployment's namespace for a namespaced placement, and has no default", () => {
    expect(() => readAdvertisedTerms("mastercard-vi", viMandate)).toThrow();
    expect(
      readAdvertisedTerms("mastercard-vi", viMandate, NAMESPACE)
        .advertisedAtrHash,
    ).toBe(ATR);
  });

  it("reads a namespaced placement under the namespace it was GIVEN, not ours", () => {
    const theirs = {
      vct: "mandate.payment.open.1",
      constraints: [{ type: "dev.example.lcp_terms_hash", value: ATR }],
    };
    expect(
      readAdvertisedTerms("mastercard-vi", theirs, {
        reverseDomain: "dev.example",
      }).advertisedAtrHash,
    ).toBe(ATR);
    expect(() =>
      readAdvertisedTerms("mastercard-vi", theirs, NAMESPACE),
    ).toThrow(/advertises no LCP reference/);
  });

  it("refuses a protocol with no registered placement", () => {
    expect(() => readAdvertisedTerms("mcp", {})).toThrow(
      /no placement is registered for mcp/,
    );
  });

  it("refuses a terms URL that is not HTTPS, and one that is not a string", () => {
    // Both refusals are the PLACEMENT's, surfaced with its namespaced code rather than re-worded here. A
    // rewritten message would be a second statement of when the rule fires, and the code is what a caller
    // can actually match on.
    const insecure = structuredClone(acpSession);
    insecure.metadata.legal_context_url = "http://seller.example/terms";
    expect(() => readAdvertisedTerms("acp", insecure)).toThrow(
      /acp\/terms-url-malformed/,
    );

    const notAString = structuredClone(acpSession);
    // @ts-expect-error a hostile wire is not obliged to send a string
    notAString.metadata.legal_context_url = 7;
    expect(() => readAdvertisedTerms("acp", notAString)).toThrow(
      /acp\/terms-url-malformed/,
    );
  });

  it("says DECLARED-FIELD-EMPTY for a declared terms field the document simply omits", () => {
    const noUrl = structuredClone(acpSession);
    // @ts-expect-error the terms URL is declared by the manifest, not required by the wire
    delete noUrl.metadata.legal_context_url;
    expect(readAdvertisedTerms("acp", noUrl).legalContextUrl).toEqual({
      kind: "declared-fields-empty",
      fields: ["metadata.legal_context_url"],
    });
  });

  it("throws on a corrupt carrier rather than reporting an absence", () => {
    const corrupt = structuredClone(acpSession);
    corrupt.metadata.legal_context = "lcp:sha256:";
    expect(() => readAdvertisedTerms("acp", corrupt)).toThrow();
  });
});
