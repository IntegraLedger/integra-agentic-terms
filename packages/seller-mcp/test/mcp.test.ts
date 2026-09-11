/**
 * The MCP seller face.
 *
 * The properties under test are the ones a transport adapter can get wrong in ways nothing downstream
 * notices: whether the seller's handler runs before or after the irreversible burn, whether an unpaid call
 * is answered with the middleware's own challenge or a paraphrase of it, and whether a failure after
 * settlement is loud enough for a seller to reconcile a payment they have already taken.
 *
 * The middleware is a stub, deliberately: this package must not reimplement the settle path, so there is
 * nothing of it here to exercise. What is exercised is the translation.
 */

import { describe, expect, it, vi } from "vitest";
import {
  declaredX402Version,
  MCP_PAYMENT_META_KEY,
  MCP_PAYMENT_RESPONSE_META_KEY,
  type MiddlewareResultLike,
  paidTool,
  type SellerMiddlewareLike,
  SUPPORTED_X402_VERSION,
  type WeldFacts,
} from "../src/index.js";

const ATR = `0x${"ab".repeat(32)}`;

/** Only the fields this adapter reads; the rest of a real welded settlement is the middleware's business. */
const WELDED: WeldFacts = {
  atrHash: ATR,
  paymentIdentifier: "pay_01HZ",
};

const CHALLENGE = JSON.stringify({
  x402Version: 2,
  accepts: [{ price: "0.001" }],
});
/**
 * ⛔⛔ THE FIXTURE THAT DISGUISES A SUBSTITUTION BY PERFORMING IT.
 *
 * A stub whose 200 BODY is a settlement-response-shaped value named `RECEIPT` lets every assertion below
 * read "the receipt came back" while the adapter is in fact sending the response body under the receipt's
 * key. A seller middleware puts the host's settlement response on the `PAYMENT-RESPONSE` HEADER,
 * base64-encoded, and the body is the resource. The two are separate values here on purpose, with different
 * contents, so a reader that took the wrong one cannot pass.
 */
const RECEIPT = btoa(JSON.stringify({ success: true, transaction: "0xdead" }));

/**
 * What the middleware's 200 body is under an MCP mount: NOTHING.
 *
 * The MCP tool's answer is the seller's `fulfil` result, so the middleware's `Response` is never sent
 * anywhere and it produces no body rather than inventing one. A stub that returned bytes here would be
 * modelling a mount nobody makes; a stub that returned bytes AND called them a receipt is the trap above.
 */
const SERVED_BODY = null;

/** A middleware that never settles — every call is a challenge. */
function unpaidCore(seen: Request[] = []): SellerMiddlewareLike {
  return async (request: Request): Promise<MiddlewareResultLike> => {
    seen.push(request);
    return { response: new Response(CHALLENGE, { status: 402 }) };
  };
}

/**
 * A middleware that settles — `welded` present is the discriminator.
 *
 * Shaped as a real middleware shapes a welded response when the surface serves the answer itself: the
 * receipt on the `PAYMENT-RESPONSE` header, and no body.
 */
function settledCore(seen: Request[] = []): SellerMiddlewareLike {
  return async (request: Request): Promise<MiddlewareResultLike> => {
    seen.push(request);
    return {
      response: new Response(SERVED_BODY, {
        status: 200,
        headers: { "PAYMENT-RESPONSE": RECEIPT },
      }),
      welded: WELDED,
    };
  };
}

describe("an unpaid call", () => {
  it("returns the middleware's challenge VERBATIM rather than a paraphrase of it", async () => {
    // A rewritten challenge would have the client negotiating against our summary of the terms instead of
    // the terms, and the summary is the thing no counterparty agreed to.
    const tool = paidTool(
      unpaidCore(),
      { resourceUrl: "https://seller.example/t" },
      () => {
        throw new Error("fulfil must not run on an unpaid call");
      },
    );
    const result = await tool({}, {});
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toBe(CHALLENGE);
  });

  it("⭐ never runs the seller's handler", async () => {
    const fulfil = vi.fn();
    const tool = paidTool(
      unpaidCore(),
      { resourceUrl: "https://seller.example/t" },
      fulfil,
    );
    await tool({}, {});
    expect(fulfil).not.toHaveBeenCalled();
  });

  it("carries no settlement receipt", async () => {
    const tool = paidTool(
      unpaidCore(),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    const result = await tool({}, {});
    expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).toBeUndefined();
  });

  it("⛔ answers in a `text` block, and carries no `_meta` KEY at all", async () => {
    // Two shapes a client reads structurally, and `?.[key]` cannot tell either of them apart from a
    // malformed result. `type` is MCP's content-block discriminant: a block typed anything else is not
    // text any client will render, and the challenge is the one message a buyer must be able to read.
    // And an ABSENT receipt has to be an absent KEY rather than a key holding `undefined` — the unpaid
    // path states nothing about a settlement, and `_meta: undefined` is a claim shaped like the absence
    // of one. `result._meta?.[…] === undefined` passes for both.
    const tool = paidTool(
      unpaidCore(),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    const result = await tool({}, {});
    expect(result.content[0]?.type).toBe("text");
    expect(Object.hasOwn(result, "_meta")).toBe(false);
  });
});

describe("the translation onto the middleware's request", () => {
  it("puts the buyer's _meta payment on the header the x402 seller reads", async () => {
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    await tool({ a: 1 }, { _meta: { [MCP_PAYMENT_META_KEY]: "PRESENTED" } });
    expect(seen[0]?.headers.get("PAYMENT-SIGNATURE")).toBe("PRESENTED");
  });

  it("sends the tool arguments as the request body, so the record is minted against them", async () => {
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    await tool({ min: 1, max: 6 }, {});
    expect(await seen[0]?.text()).toBe(JSON.stringify({ min: 1, max: 6 }));
    expect(seen[0]?.url).toBe("https://seller.example/t");
  });

  it("⛔ reads the key an x402 client actually writes, spelled from the specification", async () => {
    // ⛔ EVERY OTHER CASE HERE WRITES THE KEY THROUGH THE EXPORTED CONSTANT, which is the same constant the
    // adapter reads — so the pair agrees with itself whatever the constant says, including nothing. A
    // buyer's client spells `x402/payment` from x402's specification; it has never seen our export. The
    // literal appears once, here and in the receipt case below, so a rename is caught rather than followed.
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    await tool({}, { _meta: { "x402/payment": "PRESENTED-BY-SPEC" } });
    expect(seen[0]?.headers.get("PAYMENT-SIGNATURE")).toBe("PRESENTED-BY-SPEC");
  });

  it("declares the body's content type — the middleware is handed a JSON POST", async () => {
    // The whole job of this package is producing the web-standard `Request` the middleware already takes,
    // and that request carries a JSON body. A body sent with no declared type, or an empty one, is a
    // request no server is obliged to parse as JSON — and nothing downstream of the adapter would say so.
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    await tool({ a: 1 }, {});
    expect(seen[0]?.headers.get("content-type")).toBe("application/json");
  });

  it("omits the header entirely when no payment was presented", async () => {
    const seen: Request[] = [];
    const tool = paidTool(
      unpaidCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    await tool({}, {});
    expect(seen[0]?.headers.get("PAYMENT-SIGNATURE")).toBeNull();
  });

  it("⭐ refuses a malformed payment rather than treating it as unpaid", async () => {
    // Answering a broken client with a challenge invites it to send the same broken call forever.
    const tool = paidTool(
      settledCore(),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    const result = await tool(
      {},
      { _meta: { [MCP_PAYMENT_META_KEY]: { not: "a string" } } },
    );
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain("must be a string");
  });
});

describe("a settled call", () => {
  it("runs the seller's handler and returns its content", async () => {
    const tool = paidTool(
      settledCore(),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [{ type: "text", text: "4" }],
      }),
    );
    const result = await tool({}, { _meta: { [MCP_PAYMENT_META_KEY]: "P" } });
    expect(result.isError).toBeUndefined();
    expect(result.content[0]?.text).toBe("4");
  });

  it("hands the weld to the seller, so a result can cite its own record", async () => {
    const tool = paidTool(
      settledCore(),
      { resourceUrl: "https://seller.example/t" },
      (_a, welded) => ({
        content: [{ type: "text", text: welded.atrHash }],
      }),
    );
    const result = await tool({}, {});
    expect(result.content[0]?.text).toBe(ATR);
  });

  it("⭐ a richer weld keeps every field of itself on the way to `fulfil`", async () => {
    // The structural typing must not FLATTEN the middleware's own welded settlement. A seller whose
    // middleware carries evidence beside the two facts this adapter reads still receives all of it —
    // otherwise the price of publishing this adapter would be a narrower API for every real mount.
    interface RichWeld extends WeldFacts {
      readonly evidence: { readonly role: string };
    }
    const rich: RichWeld = { ...WELDED, evidence: { role: "settlement" } };
    const core: SellerMiddlewareLike<RichWeld> = async () => ({
      response: new Response(null, {
        status: 200,
        headers: { "PAYMENT-RESPONSE": RECEIPT },
      }),
      welded: rich,
    });
    const tool = paidTool(
      core,
      { resourceUrl: "https://s.example/t" },
      (_a, welded) => ({
        content: [{ type: "text", text: welded.evidence.role }],
      }),
    );
    const result = await tool({}, {});
    expect(result.content[0]?.text).toBe("settlement");
  });

  it("returns the settlement receipt in _meta", async () => {
    const tool = paidTool(
      settledCore(),
      { resourceUrl: "https://seller.example/t" },
      () => ({
        content: [],
      }),
    );
    const result = await tool({}, {});
    expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).toBe(RECEIPT);
    // ⛔ And under the spelling the client reads it by. The line above writes and reads through the same
    // export, so it holds even if the key were renamed to something no counterparty looks for.
    expect(result._meta?.["x402/payment-response"]).toBe(RECEIPT);
  });

  it("surfaces the weld to the sink before fulfilling", async () => {
    const order: string[] = [];
    const tool = paidTool(
      settledCore(),
      {
        resourceUrl: "https://seller.example/t",
        onWeld: () => {
          order.push("weld");
        },
      },
      () => {
        order.push("fulfil");
        return { content: [] };
      },
    );
    await tool({}, {});
    // Evidence is recorded before the seller's own work, so a handler that dies still leaves the trail.
    expect(order).toStrictEqual(["weld", "fulfil"]);
  });

  it("⛔ a sink that THROWS never reaches the buyer, and never skips `fulfil`", async () => {
    // ⛔ TWO FAILURES IN ONE, and the second is the worse. The proposal is already burned, so a throw out
    // of the sink both answers a buyer who has paid with an error AND — because the sink runs before the
    // seller's handler — means they are never given what they paid for at all. The `try` below the sink
    // wraps `fulfil`; it has never wrapped this.
    const errors: string[] = [];
    const spy = vi
      .spyOn(console, "error")
      .mockImplementation((...args: unknown[]) => {
        errors.push(args.map((a) => String(a)).join(" "));
      });
    try {
      const tool = paidTool(
        settledCore(),
        {
          resourceUrl: "https://seller.example/t",
          onWeld: () => {
            throw new Error("evidence store down");
          },
        },
        () => ({ content: [{ type: "text", text: "the goods" }] }),
      );
      const result = await tool({}, {});
      expect(result.isError).toBeUndefined();
      expect(result.content[0]?.text).toBe("the goods");
      expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).toBe(RECEIPT);
      expect(errors.join("\n")).toContain(ATR);
      expect(errors.join("\n")).toContain("evidence store down");
    } finally {
      spy.mockRestore();
    }
  });

  it("⭐ and a sink that does NOT throw is reported on no channel at all", async () => {
    // The control for the case above. A `deliverWeld` that logged unconditionally would pass it while
    // reporting a failure on every successful sale.
    const errors: string[] = [];
    const spy = vi
      .spyOn(console, "error")
      .mockImplementation((...args: unknown[]) => {
        errors.push(args.map((a) => String(a)).join(" "));
      });
    try {
      const tool = paidTool(
        settledCore(),
        { resourceUrl: "https://seller.example/t", onWeld: () => undefined },
        () => ({ content: [] }),
      );
      await tool({}, {});
      expect(errors).toStrictEqual([]);
    } finally {
      spy.mockRestore();
    }
  });
});

describe("⛔ a failure AFTER settlement", () => {
  // The burn is irreversible and has already run. The buyer has paid.
  it("names the settlement so the seller can reconcile what they already took", async () => {
    const tool = paidTool(
      settledCore(),
      { resourceUrl: "https://seller.example/t" },
      () => {
        throw new Error("database down");
      },
    );
    const result = await tool({}, {});
    expect(result.isError).toBe(true);
    // In a `text` block, like every other message here: the one report a seller has to be able to READ is
    // the one telling them they owe against a payment they already took.
    expect(result.content[0]?.type).toBe("text");
    const text = result.content[0]?.text ?? "";
    expect(text).toContain("SETTLED");
    expect(text).toContain(ATR);
    expect(text).toContain("pay_01HZ");
    expect(text).toContain("database down");
  });

  it("still returns the receipt, because the payment happened", async () => {
    const tool = paidTool(
      settledCore(),
      { resourceUrl: "https://seller.example/t" },
      () => {
        throw new Error("boom");
      },
    );
    const result = await tool({}, {});
    expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).toBe(RECEIPT);
  });

  it("does not swallow it into an ordinary tool failure", async () => {
    const tool = paidTool(
      settledCore(),
      { resourceUrl: "https://seller.example/t" },
      () => {
        throw new Error("boom");
      },
    );
    const result = await tool({}, {});
    expect(result.content[0]?.text).not.toBe("Tool execution failed");
  });
});

describe("configuration intake", () => {
  it("refuses an empty resourceUrl at construction, not at the first call", () => {
    expect(() =>
      paidTool(settledCore(), { resourceUrl: "  " }, () => ({ content: [] })),
    ).toThrow(/resourceUrl is required/);
  });
});

describe("⭐ the protocol version is named, not left as a weld mismatch", () => {
  // MEASURED: x402-mcp declares `x402Version = 1`; this face declares and emits `x402Version: 2`. A
  // version 1 payment cannot settle either way — the weld rides `payload.authorization.nonce`, and a
  // version 1 payload yields no nonce, which matches no proposal. That refusal is SAFE but names the wrong
  // thing: a seller sees "weld mismatch" and goes looking for a corrupted record instead of a client
  // upgrade.
  const encode = (o: unknown): string => btoa(JSON.stringify(o));

  it("refuses a version 1 payment by NAME, before it becomes a weld failure", async () => {
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({ content: [] }),
    );
    const result = await tool(
      {},
      { _meta: { [MCP_PAYMENT_META_KEY]: encode({ x402Version: 1 }) } },
    );
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain("x402Version 1");
    expect(result.content[0]?.text).toContain(
      `x402 v${SUPPORTED_X402_VERSION}`,
    );
    // It never reached the middleware, so no proposal was touched.
    expect(seen).toHaveLength(0);
  });

  it("passes a version 2 payment straight through", async () => {
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({ content: [{ type: "text", text: "ok" }] }),
    );
    const payment = encode({ x402Version: 2 });
    const result = await tool(
      {},
      { _meta: { [MCP_PAYMENT_META_KEY]: payment } },
    );
    expect(result.isError).toBeUndefined();
    expect(seen[0]?.headers.get("PAYMENT-SIGNATURE")).toBe(payment);
  });

  it("⛔ forwards an UNREADABLE payment unchanged rather than judging it", async () => {
    // The one thing this check must never become is a second parser that can disagree with the middleware.
    // Anything it cannot read is the middleware's business.
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({ content: [] }),
    );
    const result = await tool(
      {},
      { _meta: { [MCP_PAYMENT_META_KEY]: "not-base64-json" } },
    );
    expect(result.isError).toBeUndefined();
    expect(seen[0]?.headers.get("PAYMENT-SIGNATURE")).toBe("not-base64-json");
  });

  it("forwards a payment that declares no version at all", async () => {
    const seen: Request[] = [];
    const tool = paidTool(
      settledCore(seen),
      { resourceUrl: "https://seller.example/t" },
      () => ({ content: [] }),
    );
    await tool(
      {},
      { _meta: { [MCP_PAYMENT_META_KEY]: encode({ payload: {} }) } },
    );
    expect(seen).toHaveLength(1);
  });

  it("declaredX402Version reads the field, or says it could not", () => {
    expect(declaredX402Version(encode({ x402Version: 2 }))).toBe(2);
    expect(declaredX402Version(encode({ x402Version: "2" }))).toBeNull();
    expect(declaredX402Version("garbage")).toBeNull();
  });

  it("⛔ says it could not for every payload that is not an object either", () => {
    // ⛔ THE CASES A SHAPE GUARD USED TO STAND IN FRONT OF, asserted instead of assumed. `null` throws on
    // the property read and the catch answers `null`; a number, string, boolean or array simply has no
    // `x402Version`. That is why the guard was four branches no input could tell apart — and if any of
    // these ever answered something other than `null`, this diagnosis would be refusing a payment on a
    // ground it cannot actually check, which is the one thing it must never do.
    expect(declaredX402Version(encode(null))).toBeNull();
    expect(declaredX402Version(encode(5))).toBeNull();
    expect(declaredX402Version(encode("x402Version"))).toBeNull();
    expect(declaredX402Version(encode(true))).toBeNull();
    expect(declaredX402Version(encode([{ x402Version: 1 }]))).toBeNull();
  });
});

/**
 * ⛔⛔ THE RECEIPT IS THE HEADER, NOT THE BODY.
 *
 * A seller middleware puts the host's settlement response on `PAYMENT-RESPONSE`, base64-encoded; the 200's
 * body is the resource. An adapter that sent `await response.text()` back under
 * `_meta["x402/payment-response"]` would hand an MCP buyer the thing they bought where the proof they
 * bought it belongs, and no proof at all.
 *
 * ⚠️ It is invisible to any suite whose stub returns a settlement-response-shaped body — a fixture
 * performing the substitution it was supposed to detect. ⇒ Every case below drives a response whose header
 * and body are DIFFERENT VALUES. A reader that took either one would pass a test where they agreed.
 */
describe("⛔ the receipt comes off the header, never off the body", () => {
  const BODY = JSON.stringify({ signals: [1, 2, 3] });

  /** A settled response carrying BOTH — the shape a fulfilment-port mount produces. */
  const bothCore = (): SellerMiddlewareLike => async () => ({
    response: new Response(BODY, {
      status: 200,
      headers: { "PAYMENT-RESPONSE": RECEIPT },
    }),
    welded: WELDED,
  });

  it("⛔ carries the PAYMENT-RESPONSE header, and not the resource the buyer bought", async () => {
    const tool = paidTool(
      bothCore(),
      { resourceUrl: "https://s.example/t" },
      () => ({
        content: [{ type: "text", text: "the goods" }],
      }),
    );
    const result = await tool({}, {});
    expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).toBe(RECEIPT);
    expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).not.toBe(BODY);
  });

  it("⛔ decodes as the host's own settlement response, which the body never would", async () => {
    // The property a counterparty actually depends on: what rides this key is base64 of a settlement
    // response. The wrong value decodes to nothing at all.
    const tool = paidTool(
      bothCore(),
      { resourceUrl: "https://s.example/t" },
      () => ({
        content: [],
      }),
    );
    const result = await tool({}, {});
    const meta = result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY];
    const decoded = JSON.parse(atob(String(meta))) as { success: boolean };
    expect(decoded.success).toBe(true);
  });

  it("⛔ the same on the settled-then-failed path — the buyer must still be able to prove it", async () => {
    const tool = paidTool(
      bothCore(),
      { resourceUrl: "https://s.example/t" },
      () => {
        throw new Error("boom");
      },
    );
    const result = await tool({}, {});
    expect(result.isError).toBe(true);
    expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).toBe(RECEIPT);
  });

  it('⛔ an ABSENT header stays absent — no `?? ""`, which would decode to nothing', async () => {
    // Unreachable against a real middleware, which sets the header unconditionally on the welded path. An
    // empty string here would be a receipt that looks like one and proves nothing, which is the silent
    // substitution this whole suite is about. Absence says "the middleware did not state one".
    const headerless: SellerMiddlewareLike = async () => ({
      response: new Response(null, { status: 200 }),
      welded: WELDED,
    });
    const tool = paidTool(
      headerless,
      { resourceUrl: "https://s.example/t" },
      () => ({
        content: [{ type: "text", text: "the goods" }],
      }),
    );
    const result = await tool({}, {});
    expect(result._meta?.[MCP_PAYMENT_RESPONSE_META_KEY]).toBeUndefined();
    // ⭐ And the buyer is still served: a missing receipt is a defect in the middleware, never a reason to
    // withhold what a settled payment bought.
    expect(result.content[0]?.text).toBe("the goods");
  });
});
