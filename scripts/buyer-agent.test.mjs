#!/usr/bin/env node --test
import assert from "node:assert/strict";
/**
 * The buyer agent, driven — **and the case that matters asserts a NON-event.**
 *
 * ⛔⛔ A buyer is not proved by paying. It is proved by not paying when it should not: the whole claim of
 * `@integraledger/agentic-terms` is *"halt before any signing key is invoked"*, and the only way to
 * demonstrate that is to tamper with the advertised terms and assert the wallet recorded **zero** signing
 * calls. A buyer that refused after signing would already have paid.
 *
 * ⚠️ Every case here is HERMETIC — a `node:http` server standing in for the appliance and a stub wallet.
 * `check:hermetic-tests` is why: this repository has no live-harness convention at all, and a file under
 * either sibling's spelling makes that gate REFUSE rather than choose. ⇒ The live Base Sepolia run is
 * `scripts/buyer-agent.mjs` driven by hand, and it is in no test by construction.
 */
import { createServer } from "node:http";
import { test } from "node:test";
import {
  authorizationFor,
  buy,
  eip712Domain,
  renderTranscript,
} from "./buyer-agent.mjs";

/**
 * ⭐⭐ THE FIXTURE TERMS AND THEIR REAL FINGERPRINT. `ATR` is `hashAtr(TERMS_BYTES)` — computed once and
 * pinned here, and **the control below is what proves it is right**: if this constant drifted from those
 * bytes the gate would Decline and the control would fail, which is exactly how a wrong constant announces
 * itself rather than quietly turning every case into the same answer.
 */
const TERMS_BYTES = new TextEncoder().encode(
  '{"terms":"https://seller.example/terms.txt"}',
);
const ATR =
  "0x0b88843f8fe53689c3c1fbe64e20e7f9e92051d8e84c5c156bc58dbf0402d246";
/** The same document with a clause category the buyer's policy forbids. */
const CLAUSED_BYTES = new TextEncoder().encode(
  '{"terms":"https://seller.example/terms.txt","clauseCategories":["arbitration"]}',
);
const CLAUSED_ATR =
  "0x4ae693b917004e701ccc2f2d7c975724aee6a6a6a684959be7ea6a0841c611a5";
const TAMPERED = `0x${"cd".repeat(32)}`;
const PAY_TO = `0x${"11".repeat(20)}`;
const ASSET = `0x${"22".repeat(20)}`;
const BUYER = `0x${"33".repeat(20)}`;
const TERMS_URL = "https://seller.example/.well-known/legal-context.json";

/**
 * One `accepts[]` entry, in the shape THE SELLER SERVES.
 *
 * ⛔ `amount`, not `maxAmountRequired`. The published gate's parser requires `accepts[].amount` and throws
 * without it — `packages/agentic-terms/src/proposal.ts:46` declares `amount: z.string()`, non-optional. A
 * fixture built from x402's spec spelling would have driven a runtime the parser rejects before it starts.
 */
const accepted = (over = {}) => ({
  scheme: "exact",
  network: "eip155:84532",
  amount: "1000",
  payTo: PAY_TO,
  asset: ASSET,
  extra: {
    name: "USDC",
    version: "2",
    atrHash: ATR,
    legalContextUrl: TERMS_URL,
    ...(over.extra ?? {}),
  },
  ...Object.fromEntries(Object.entries(over).filter(([k]) => k !== "extra")),
});

const challengeBody = (over = {}) => ({
  x402Version: 2,
  accepts: [accepted(over.accepted ?? {})],
});

/** A seller that challenges, then accepts one signed payment. */
async function seller(body) {
  const server = createServer((request, response) => {
    if (request.headers["payment-signature"] !== undefined) {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true }));
      return;
    }
    // ⛔⛔ THE HEADER, NOT THE BODY, and a first cut of this fixture served only the body. The published
    // decoder reads `payment-required` — base64 JSON — *"the carrier the host protocol defines; the body is
    // a convenience, and reading the body would consume a stream the caller may still want."* A fixture
    // that served the body alone drove nothing: every case died at the decoder, before the gate.
    response.writeHead(402, {
      "content-type": "application/json",
      "payment-required": Buffer.from(JSON.stringify(body), "utf8").toString(
        "base64",
      ),
    });
    response.end(JSON.stringify(body));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}/paid`,
    // ⛔ `closeAllConnections` FIRST: `server.close()` waits for open sockets and `fetch`'s agent keeps
    // them alive, so the close never resolves and the run hangs with every case already green.
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  };
}

/** A wallet that COUNTS. The count is the assertion in the case that matters. */
function wallet() {
  const calls = [];
  return {
    address: BUYER,
    calls,
    async signTypedData(typedData) {
      calls.push(typedData);
      return `0x${"ff".repeat(65)}`;
    },
  };
}

/**
 * The gate's ports.
 *
 * ⛔⛔ `fetcher` IS AN OBJECT WITH A `fetch` METHOD, and a first cut of this file made it a bare function.
 * That made every case take the same path — the gate could not fetch, so it Declined whatever the ATR was —
 * and the plant below "passed" while asserting nothing: **a control that cannot fail.** The `bytes` it
 * returns are what the fingerprint is recomputed over, so they are the fixture's real terms.
 */
const ports = (bytes = TERMS_BYTES) => ({
  fetch: (url, init) => fetch(url, init),
  now: () => new Date("2026-09-18T06:00:00Z").toISOString(),
  fetcher: {
    async fetch() {
      return {
        bytes,
        format: "application/json",
        fetchedAt: "2026-09-18T06:00:00Z",
      };
    },
  },
});

/**
 * ⛔⛔ THE POLICY LANE IS LIVE, AND IT WAS INERT.
 *
 * The first fixture's terms — a bare sentence — did not parse as `LegalContextJson`, so `evaluate`
 * short-circuited on the coverage gap and **four of these seven fields could not change any outcome**.
 * Driven at the time: a matching ATR signed for an amount of 999999999999999. The terms parse now, so the
 * policy is reached, and the cases below prove what the buyer's own stated bound actually does.
 *
 * ⚠️ `maxCommitment` is keyed by the offer's unit, which the parser derives as `<network>:<asset>` — not a
 * currency name. A cap filed under the wrong key is no cap: the gate declines for `policy/unit` instead,
 * which is a different refusal and would have read as this one working.
 */
const UNIT = `eip155:84532:${ASSET}`;
const POLICY = Object.freeze({
  requiredLevel: 1,
  acceptableJurisdictions: "any",
  acceptableDisputeMethods: "any",
  maxCommitment: { [UNIT]: "5000" },
  forbiddenClauseCategories: [],
  requiredAssurance: "any",
  // ⛔ `decline`, not `proceed`: unparseable terms must HALT. `proceed` here is what made the lane inert,
  // and the control below drives that this disposition is the thing doing the work.
  onNotAttempted: "decline",
});
const CONTEXT = Object.freeze({ level: 1, sellerAssurance: "self-asserted" });

/** An entry with `extra` REPLACED rather than merged — the negative cases are about a field being absent. */
const withExtra = (extra) => ({ ...accepted(), extra });

test("⭐ eip712Domain refuses every field it cannot read, by name", () => {
  assert.throws(
    () => eip712Domain(withExtra({ version: "2" })),
    /domain `name`/,
  );
  assert.throws(
    () => eip712Domain(withExtra({ name: "USDC" })),
    /domain `version`/,
  );
  assert.throws(
    () => eip712Domain({ ...accepted(), asset: "not-an-address" }),
    /verifyingContract/,
  );
  assert.throws(
    () => eip712Domain({ ...accepted(), network: "base-sepolia" }),
    /CAIP-2/,
  );
  assert.deepEqual(eip712Domain(accepted()), {
    name: "USDC",
    version: "2",
    chainId: 84532,
    verifyingContract: ASSET,
  });
});

test("⛔ an authorization with no payee, and one with a non-integer amount, are refused", () => {
  assert.throws(
    () =>
      authorizationFor({
        accepted: { ...accepted(), payTo: "" },
        from: BUYER,
        verifiedAtrHash: ATR,
        nowSeconds: 1,
        validitySeconds: 1,
      }),
    /will not sign a transfer with no payee/,
  );
  assert.throws(
    () =>
      authorizationFor({
        accepted: { ...accepted(), amount: "1.5" },
        from: BUYER,
        verifiedAtrHash: ATR,
        nowSeconds: 1,
        validitySeconds: 1,
      }),
    /integer in base units/,
  );
});

test("⭐ the weld rides as the nonce — the authorization's nonce IS the verified hash", () => {
  const authorization = authorizationFor({
    accepted: accepted(),
    from: BUYER,
    verifiedAtrHash: ATR,
    nowSeconds: 1_000_000,
    validitySeconds: 600,
  });
  assert.equal(authorization.nonce, ATR);
  assert.equal(authorization.to, PAY_TO);
  assert.equal(authorization.value, "1000");
  assert.equal(authorization.validBefore, "1000600");
});

test("⭐ the transcript prints `purpose` as UNRULED rather than inventing one", () => {
  const block = renderTranscript({
    host: "seller.example",
    transaction: "0xdead",
    amount: "1000",
    atrHash: ATR,
    drivenBy: "INTERIM: the buyer-agent runtime",
    buyer: "holding its own key",
  });
  assert.match(block, /purpose {6}UNRULED/);
  assert.match(block, /carried as the EIP-3009 nonce/);
  // ⛔ The acceptance clause asks for an INDEPENDENT verify at mechanical depth. `buy()` used to end at the
  // seller's 200 — the seller's own word that the seller was paid — while this module's head note claimed
  // the read. A transcript that omitted the line when the read did not happen would read as one where it
  // did, so the absence is printed.
  assert.match(block, /verified {5}NOT READ/);
  assert.match(
    renderTranscript({
      host: "seller.example",
      transaction: "0xdead",
      amount: "1000",
      atrHash: ATR,
      drivenBy: "x",
      buyer: "y",
      verification: { verified: true, supportedClass: "TC-2" },
    }),
    /verified {5}true \(TC-2\)/,
  );
});

test("⭐⭐ THE CONTROL — a matching fingerprint PROCEEDS, and the wallet IS called once", async () => {
  // ⛔ Without this, the plant below proves nothing: a gate that Declines everything would pass it. This is
  // the case that says the instrument can move — and it is also what pins `ATR` to `TERMS_BYTES`, because a
  // drifted constant Declines here.
  const s = await seller(challengeBody());
  const w = wallet();
  try {
    const result = await buy({
      resourceUrl: s.url,
      wallet: w,
      policy: POLICY,
      context: CONTEXT,
      ports: ports(),
    });
    assert.equal(
      result.kind,
      "settled",
      `expected a settlement: ${JSON.stringify(result.decision ?? {})}`,
    );
    assert.equal(w.calls.length, 1, "the signer must be reached exactly once");
    assert.equal(result.authorization.nonce, ATR);
    assert.equal(result.authorization.value, "1000");
    assert.equal(w.calls[0].primaryType, "TransferWithAuthorization");
    assert.equal(w.calls[0].domain.chainId, 84532);
  } finally {
    // ⛔ `finally`: a case that fails must still close its server, or the run hangs and the real failure is
    // buried under a timeout. Measured — an earlier version of this file had to be killed twice.
    await s.close();
  }
});

test("⛔⛔ THE PLANT — a TAMPERED advertised ATR, and the wallet is NEVER called", async () => {
  // The whole claim of the package this runtime is built on. The seller advertises a hash the fetched terms
  // do not produce; `evaluate` Declines, `transact` never reaches the signer, and the assertion is a COUNT
  // OF ZERO — because a buyer that refused after signing would already have paid.
  const s = await seller(
    challengeBody({ accepted: { extra: { atrHash: TAMPERED } } }),
  );
  const w = wallet();
  try {
    const result = await buy({
      resourceUrl: s.url,
      wallet: w,
      policy: POLICY,
      context: CONTEXT,
      ports: ports(),
    });
    assert.equal(result.kind, "halted", "a tampered ATR must halt");
    assert.equal(result.decision.kind, "decline");
    assert.equal(
      w.calls.length,
      0,
      "⛔ THE KEY WAS INVOKED ON A TAMPERED PROPOSAL",
    );
  } finally {
    // ⛔⛔ `finally` ON EVERY SERVER-USING CASE, AND THIS ONE LACKED IT. Measured: with a sign-before-gate
    // defect planted, this file never exited — killed at 45 s, a phantom eighth case, no verdict at all.
    // `test:scripts` carries `--test-timeout=0`, so the day this case reds in CI it would eat the job
    // budget as a timeout instead of reporting the defect it caught.
    await s.close();
  }
});

test("⛔⛔ POLICY — an amount over the buyer's own cap DECLINES, and the wallet is never called", async () => {
  // ⛔ This lane was INERT until the fixture's terms parsed: `evaluate` short-circuited on the coverage gap
  // and a matching ATR signed for 999999999999999. The cap is the buyer's own stated bound on what it will
  // put its key behind, and until now nothing proved it bounded anything.
  const s = await seller(challengeBody({ accepted: { amount: "5001" } }));
  const w = wallet();
  try {
    const result = await buy({
      resourceUrl: s.url,
      wallet: w,
      policy: POLICY,
      context: CONTEXT,
      ports: ports(),
    });
    assert.equal(result.kind, "halted");
    assert.match(JSON.stringify(result.decision), /exceeds cap/);
    assert.equal(w.calls.length, 0, "⛔ THE KEY WAS INVOKED OVER THE CAP");
  } finally {
    await s.close();
  }
});

test("⭐ …and one unit under the cap still signs — the bound is a bound, not a refusal", async () => {
  const s = await seller(challengeBody({ accepted: { amount: "5000" } }));
  const w = wallet();
  try {
    const result = await buy({
      resourceUrl: s.url,
      wallet: w,
      policy: POLICY,
      context: CONTEXT,
      ports: ports(),
    });
    assert.equal(result.kind, "settled");
    assert.equal(w.calls.length, 1);
  } finally {
    await s.close();
  }
});

test("⛔⛔ POLICY — a FORBIDDEN clause category DECLINES, and the wallet is never called", async () => {
  const s = await seller(
    challengeBody({ accepted: { extra: { atrHash: CLAUSED_ATR } } }),
  );
  const w = wallet();
  try {
    const result = await buy({
      resourceUrl: s.url,
      wallet: w,
      policy: { ...POLICY, forbiddenClauseCategories: ["arbitration"] },
      context: CONTEXT,
      ports: ports(CLAUSED_BYTES),
    });
    assert.equal(result.kind, "halted");
    assert.equal(
      w.calls.length,
      0,
      "⛔ THE KEY WAS INVOKED ON FORBIDDEN TERMS",
    );
  } finally {
    await s.close();
  }
});

test("⭐⭐ THE CONTROL FOR THE LANE — unparseable terms HALT under `onNotAttempted: decline`", async () => {
  // ⛔ The disposition is what makes the lane live. With `proceed` here — the first version — terms that do
  // not parse skip the policy entirely, which is how four of its fields came to decide nothing.
  const s = await seller(challengeBody());
  const w = wallet();
  try {
    const result = await buy({
      resourceUrl: s.url,
      wallet: w,
      policy: POLICY,
      context: CONTEXT,
      ports: ports(new TextEncoder().encode("not machine-readable")),
    });
    assert.equal(result.kind, "halted");
    assert.equal(w.calls.length, 0);
  } finally {
    await s.close();
  }
});

test("⛔ a clock that is not a clock is refused — `NaN` is not a validity window", () => {
  // ⛔ `ports.now()` was TRUSTED. A number, or a string that is not a date, made `Date.parse` yield `NaN`
  // and the authorization was signed with `validAfter: "NaN"` — driven, and the seller settled it.
  assert.throws(
    () =>
      authorizationFor({
        accepted: accepted(),
        from: BUYER,
        verifiedAtrHash: ATR,
        nowSeconds: Number.NaN,
        validitySeconds: 600,
      }),
    /not a whole number of seconds/,
  );
  assert.throws(
    () =>
      authorizationFor({
        accepted: accepted(),
        from: BUYER,
        verifiedAtrHash: ATR,
        nowSeconds: 1_000_000,
        validitySeconds: 0,
      }),
    /not a positive whole number/,
  );
});

test("⛔ a seller that does not challenge is refused — there is no offer to pay", async () => {
  const server = createServer((_request, response) => {
    response.writeHead(200);
    response.end("{}");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const w = wallet();
  try {
    await assert.rejects(
      buy({
        resourceUrl: `http://127.0.0.1:${port}/paid`,
        wallet: w,
        policy: POLICY,
        context: CONTEXT,
        ports: ports(),
      }),
      /there is no offer to pay/,
    );
    assert.equal(w.calls.length, 0);
  } finally {
    await new Promise((resolve) => {
      server.closeAllConnections();
      server.close(resolve);
    });
  }
});
