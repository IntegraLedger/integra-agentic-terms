import type { Assurance } from "@integraledger/lcp-authority";
import { describe, expect, it } from "vitest";
import {
  type ProposalContext,
  parseProposalFromChallenge,
} from "../src/proposal.js";

const atrHash = `0x${"ab".repeat(32)}`;
const ctx: ProposalContext = {
  level: 2,
  sellerAssurance: "wallet-signature-only" as Assurance,
};
const challenge = {
  x402Version: 2,
  accepts: [
    {
      scheme: "exact",
      network: "base-sepolia",
      payTo: "0xseller",
      asset: "0xUSDC",
      amount: "1000",
      extra: { atrHash, legalContextUrl: "https://s.example/terms" },
    },
  ],
  extensions: {
    legalContext: {
      info: {
        type: "sha256",
        value: atrHash,
        legalContextUrl: "https://s.example/terms",
      },
      schema: { $ref: "x" },
    },
  },
};

describe("parseProposalFromChallenge — typed GateProposal, LCP §12.7 boundary (no prose field)", () => {
  it("maps the x402 challenge into a typed GateProposal", () => {
    const p = parseProposalFromChallenge(challenge, ctx);
    expect(p.advertisedAtrHash).toBe(atrHash);
    expect(p.legalContextUrl).toBe("https://s.example/terms");
    expect(p.offer.amount).toBe("1000");
    expect(p.offer.unit).toBe("base-sepolia:0xUSDC");
    expect(p.level).toBe(2);
    expect(p.sellerAssurance).toBe("wallet-signature-only");
  });
  it("the GateProposal carries NO prose field (the LCP §12.7 boundary is a type)", () => {
    const p = parseProposalFromChallenge(challenge, ctx);
    expect(Object.keys(p).sort()).toEqual(
      [
        "advertisedAtrHash",
        "legalContextUrl",
        "level",
        "offer",
        "sellerAssurance",
      ].sort(),
    );
    expect(p).not.toHaveProperty("terms");
    expect(p).not.toHaveProperty("prose");
  });
  it("fail-fast: rejects an empty amount (trust-boundary validation — closes the empty→zero crack)", () => {
    const bad = {
      ...challenge,
      accepts: [{ ...challenge.accepts[0], amount: "" }],
    };
    expect(() => parseProposalFromChallenge(bad, ctx)).toThrow(/amount/i);
  });
  it("fail-fast: rejects a non-integer amount", () => {
    const bad = {
      ...challenge,
      accepts: [{ ...challenge.accepts[0], amount: "1.5" }],
    };
    expect(() => parseProposalFromChallenge(bad, ctx)).toThrow(/amount/i);
  });
  // DELETED: "fail-fast: rejects a non-HTTPS legalContextUrl". It downgraded only `extra` while the fixture's
  // extensions block kept the https URL, so once the two carriers are reconciled it threw `carriers disagree`
  // and matched /https/i purely because that message interpolates both URLs — green while asserting nothing
  // about the HTTPS guard. Replaced by the EITHER-carrier test in the G-A block below, which isolates each.
  it("fail-fast: rejects a malformed atrHash", () => {
    // `extensions` is dropped so this isolates the hash check. Corrupting only `extra` while the fixture's
    // extensions block still carries the VALID hash makes the challenge self-contradictory, and the
    // carriers-disagree refusal fires first — a correct answer to a different question than this test asks.
    const { extensions: _valid, ...extraOnly } = challenge;
    const bad = {
      ...extraOnly,
      accepts: [
        {
          ...challenge.accepts[0],
          extra: {
            atrHash: "0xnope",
            legalContextUrl: "https://s.example/terms",
          },
        },
      ],
    };
    expect(() => parseProposalFromChallenge(bad, ctx)).toThrow(/atrHash/i);
  });
  it("fail-fast: rejects a challenge with no accepted requirement", () => {
    expect(() => parseProposalFromChallenge({ accepts: [] }, ctx)).toThrow();
  });
});

describe("parseProposalFromChallenge — the atrHash regex is anchored at BOTH ends", () => {
  const challengeWith = (atrHash: string) => ({
    accepts: [
      {
        amount: "1000",
        network: "base-sepolia",
        asset: "0xUSDC",
        extra: { atrHash, legalContextUrl: "https://s.example/terms" },
      },
    ],
  });
  const ctx: ProposalContext = {
    level: 2,
    sellerAssurance: "wallet-signature-only" as Assurance,
  };

  it("accepts a well-formed hash", () => {
    expect(() =>
      parseProposalFromChallenge(challengeWith(`0x${"ab".repeat(32)}`), ctx),
    ).not.toThrow();
  });

  it("rejects trailing junk after the 64 hex chars (the ^ anchor alone would let this through)", () => {
    expect(() =>
      parseProposalFromChallenge(
        challengeWith(`0x${"ab".repeat(32)}EXTRA`),
        ctx,
      ),
    ).toThrow(/atrHash/);
  });

  it("rejects leading junk before the 0x (the $ anchor alone would let this through)", () => {
    expect(() =>
      parseProposalFromChallenge(
        challengeWith(`JUNK0x${"ab".repeat(32)}`),
        ctx,
      ),
    ).toThrow(/atrHash/);
  });

  it("rejects a hash one nibble short", () => {
    expect(() =>
      parseProposalFromChallenge(challengeWith(`0x${"a".repeat(63)}`), ctx),
    ).toThrow(/atrHash/);
  });

  it("requires at least one entry in accepts — an empty array is refused by the schema", () => {
    expect(() => parseProposalFromChallenge({ accepts: [] }, ctx)).toThrow();
  });

  it("refuses a challenge whose accepts entry is missing the extra block entirely", () => {
    expect(() =>
      parseProposalFromChallenge(
        { accepts: [{ amount: "1", network: "n", asset: "a" }] },
        ctx,
      ),
    ).toThrow();
  });
});

describe("x402 carries the reference in TWO places — a buyer that reads one is incomplete (G-A)", () => {
  // x402 v2 defines a top-level `extensions` map on the challenge alongside the per-requirement `extra`,
  // and BOTH are Tier A carriers. A conformant seller may emit both,
  // so a parser reading only `extra` rejects a spec-legal seller — and rejects a carrier we ourselves emit.
  const bare = {
    scheme: "exact",
    network: "base-sepolia",
    payTo: "0xseller",
    asset: "0xUSDC",
    amount: "1000",
  };

  it("parses a challenge that advertises ONLY in the top-level extensions map", () => {
    const p = parseProposalFromChallenge(
      { x402Version: 2, accepts: [bare], extensions: challenge.extensions },
      ctx,
    );
    expect(p.advertisedAtrHash).toBe(atrHash);
    expect(p.legalContextUrl).toBe("https://s.example/terms");
  });

  it("parses a challenge that advertises ONLY in accepts[].extra", () => {
    const { extensions: _dropped, ...noExtensions } = challenge;
    expect(
      parseProposalFromChallenge(noExtensions, ctx).advertisedAtrHash,
    ).toBe(atrHash);
  });

  it("prefers accepts[].extra when BOTH carriers are present and agree", () => {
    // The shape our seller actually emits. Both carry the same reference, so this must stay green.
    expect(parseProposalFromChallenge(challenge, ctx).advertisedAtrHash).toBe(
      atrHash,
    );
  });

  it("parses LCP v1.38 §C.4's canonical illustration verbatim — extensions.info carries NO url", () => {
    // The spec's own x402 example puts atrHash + legalContextUrl in `extra` while
    // `extensions.legalContext.info` carries only `type` + `value`. Treating each carrier as an atomic
    // {hash, url} pair rejected this outright. The two are reconciled FIELD by field for that reason.
    const specHash = `0x${"7f".repeat(32)}`;
    const p = parseProposalFromChallenge(
      {
        x402Version: 2,
        accepts: [
          {
            ...bare,
            extra: {
              atrHash: specHash,
              legalContextUrl:
                "https://example.com/.well-known/legal-context.json",
            },
          },
        ],
        extensions: {
          legalContext: {
            info: { type: "sha256", value: specHash },
            schema: { $ref: "https://example.com/schemas/lcp-extension.json" },
          },
        },
      },
      ctx,
    );
    expect(p.advertisedAtrHash).toBe(specHash);
    expect(p.legalContextUrl).toBe(
      "https://example.com/.well-known/legal-context.json",
    );
  });

  it("takes the hash from extensions and the url from extra when each carries only one", () => {
    const p = parseProposalFromChallenge(
      {
        x402Version: 2,
        accepts: [
          { ...bare, extra: { legalContextUrl: "https://s.example/terms" } },
        ],
        extensions: {
          legalContext: { info: { type: "sha256", value: atrHash } },
        },
      },
      ctx,
    );
    expect(p.advertisedAtrHash).toBe(atrHash);
    expect(p.legalContextUrl).toBe("https://s.example/terms");
  });

  it("throws when a hash is advertised with no terms URL anywhere", () => {
    expect(() =>
      parseProposalFromChallenge(
        {
          x402Version: 2,
          accepts: [bare],
          extensions: {
            legalContext: { info: { type: "sha256", value: atrHash } },
          },
        },
        ctx,
      ),
    ).toThrow(/no legalContextUrl/);
  });

  it("REFUSES when the two carriers disagree on the atrHash", () => {
    // Not a preference question. Silently picking one would let a seller advertise different terms to
    // different readers of the SAME document — the buyer would gate against terms the seller can disown.
    const other = `0x${"cd".repeat(32)}`;
    const contradictory = {
      ...challenge,
      extensions: {
        legalContext: {
          info: {
            type: "sha256",
            value: other,
            legalContextUrl: "https://s.example/terms",
          },
          schema: { $ref: "x" },
        },
      },
    };
    expect(() => parseProposalFromChallenge(contradictory, ctx)).toThrow(
      /carriers disagree/,
    );
  });

  it("REFUSES when the two carriers disagree on the terms URL", () => {
    // The URL is half the reference: same hash, different document to fetch is still two stories.
    const contradictory = {
      ...challenge,
      extensions: {
        legalContext: {
          info: {
            type: "sha256",
            value: atrHash,
            legalContextUrl: "https://other.example/terms",
          },
          schema: { $ref: "x" },
        },
      },
    };
    expect(() => parseProposalFromChallenge(contradictory, ctx)).toThrow(
      /carriers disagree/,
    );
  });

  it("throws on a non-HTTPS terms URL from EITHER carrier — the trust boundary is fail-fast", () => {
    // The x402 parser had no coverage for this at all, while its ACP sibling did. A plaintext terms URL is
    // a downgrade on the one document the buyer is about to be bound by.
    const { extensions: _dropped, ...extraOnly } = challenge;
    expect(() =>
      parseProposalFromChallenge(
        {
          ...extraOnly,
          accepts: [
            {
              ...challenge.accepts[0],
              extra: { atrHash, legalContextUrl: "http://s.example/terms" },
            },
          ],
        },
        ctx,
      ),
    ).toThrow(/HTTPS/);
    expect(() =>
      parseProposalFromChallenge(
        {
          x402Version: 2,
          accepts: [bare],
          extensions: {
            legalContext: {
              info: {
                type: "sha256",
                value: atrHash,
                legalContextUrl: "http://s.example/terms",
              },
              schema: { $ref: "x" },
            },
          },
        },
        ctx,
      ),
    ).toThrow(/HTTPS/);
  });

  it("throws when NEITHER carrier is present, naming both places it looked", () => {
    expect(() =>
      parseProposalFromChallenge({ x402Version: 2, accepts: [bare] }, ctx),
    ).toThrow(/extra.*extensions|extensions.*extra/);
  });

  it("refuses a non-sha256 extensions carrier rather than reading its value", () => {
    const wrongType = {
      x402Version: 2,
      accepts: [bare],
      extensions: {
        legalContext: {
          info: {
            type: "ipfs",
            value: "bafy...",
            legalContextUrl: "https://s.example/terms",
          },
          schema: { $ref: "x" },
        },
      },
    };
    expect(() => parseProposalFromChallenge(wrongType, ctx)).toThrow(/sha256/);
  });
});
